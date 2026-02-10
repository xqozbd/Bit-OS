#include "sys/fat32.h"

#include <stddef.h>
#include <stdint.h>

#include "lib/compat.h"
#include "kernel/block.h"
#include "kernel/partition.h"
#include "kernel/heap.h"
#include "kernel/slab.h"
#include "lib/log.h"
#include "lib/strutil.h"

extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);
extern void *memset(void *s, int c, size_t n);

#define FAT32_MAX_NODES 256
#define FAT32_MAX_NAME  64

struct fat32_bpb {
    uint8_t jmp[3];
    uint8_t oem[8];
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t num_fats;
    uint16_t root_entry_count;
    uint16_t total_sectors16;
    uint8_t media;
    uint16_t fat_size16;
    uint16_t sectors_per_track;
    uint16_t num_heads;
    uint32_t hidden_sectors;
    uint32_t total_sectors32;
    uint32_t fat_size32;
    uint16_t ext_flags;
    uint16_t fs_version;
    uint32_t root_cluster;
    uint16_t fs_info;
    uint16_t backup_boot;
    uint8_t reserved[12];
    uint8_t drive_number;
    uint8_t reserved1;
    uint8_t boot_sig;
    uint32_t volume_id;
    uint8_t volume_label[11];
    uint8_t fs_type[8];
} __attribute__((packed));

struct fat32_dirent {
    uint8_t name[11];
    uint8_t attr;
    uint8_t nt_res;
    uint8_t crt_time_tenth;
    uint16_t crt_time;
    uint16_t crt_date;
    uint16_t lst_acc_date;
    uint16_t fst_clus_hi;
    uint16_t wrt_time;
    uint16_t wrt_date;
    uint16_t fst_clus_lo;
    uint32_t file_size;
} __attribute__((packed));

struct fat32_node {
    uint32_t parent;
    uint32_t first_cluster;
    uint32_t size;
    uint8_t is_dir;
    char name[FAT32_MAX_NAME];
};

static int g_ready = 0;
static struct fat32_bpb g_bpb;
static const struct block_device *g_dev = NULL;
static struct partition_info g_part;
static uint32_t g_fat_lba = 0;
static uint32_t g_data_lba = 0;
static uint32_t g_clusters = 0;
static struct fat32_node *g_nodes[FAT32_MAX_NODES];
static uint32_t g_node_count = 0;
static uint8_t *g_read_buf = NULL;

static uint64_t part_lba(uint64_t lba) {
    return (uint64_t)g_part.first_lba + lba;
}

static int fat_read_sectors(uint64_t lba, uint32_t count, void *buf) {
    if (!g_dev) return -1;
    return block_read_cached(g_dev, part_lba(lba), count, buf);
}

static int fat_write_sectors(uint64_t lba, uint32_t count, const void *buf) {
    if (!g_dev) return -1;
    return block_write_cached(g_dev, part_lba(lba), count, buf);
}

static uint32_t fat_entry(uint32_t cluster) {
    uint32_t fat_offset = cluster * 4;
    uint32_t sector = g_fat_lba + (fat_offset / g_bpb.bytes_per_sector);
    uint32_t offset = fat_offset % g_bpb.bytes_per_sector;
    uint8_t tmp[512];
    if (fat_read_sectors(sector, 1, tmp) != 0) return 0x0FFFFFFF;
    uint32_t val = *(uint32_t *)(tmp + offset);
    return val & 0x0FFFFFFF;
}

static int fat_set_entry(uint32_t cluster, uint32_t value) {
    uint32_t fat_offset = cluster * 4;
    uint32_t sector = g_fat_lba + (fat_offset / g_bpb.bytes_per_sector);
    uint32_t offset = fat_offset % g_bpb.bytes_per_sector;
    uint8_t tmp[512];
    if (fat_read_sectors(sector, 1, tmp) != 0) return -1;
    uint32_t *entry = (uint32_t *)(tmp + offset);
    *entry = (*entry & 0xF0000000u) | (value & 0x0FFFFFFFu);
    for (uint8_t fat = 0; fat < g_bpb.num_fats; ++fat) {
        uint32_t fat_lba = g_fat_lba + (uint32_t)fat * g_bpb.fat_size32;
        if (fat_write_sectors(fat_lba + (fat_offset / g_bpb.bytes_per_sector), 1, tmp) != 0) {
            return -1;
        }
    }
    return 0;
}

static uint32_t cluster_to_lba(uint32_t cluster) {
    return g_data_lba + (cluster - 2) * g_bpb.sectors_per_cluster;
}

static int node_new(uint32_t parent, uint32_t first_cluster, uint32_t size, int is_dir,
                    const char *name) {
    if (g_node_count >= FAT32_MAX_NODES) return -1;
    uint32_t idx = g_node_count++;
    struct fat32_node *n = slab_alloc(sizeof(*n));
    if (!n) return -1;
    g_nodes[idx] = n;
    n->parent = parent;
    n->first_cluster = first_cluster;
    n->size = size;
    n->is_dir = (uint8_t)(is_dir != 0);
    memset(n->name, 0, sizeof(n->name));
    if (name) {
        size_t i = 0;
        for (; i + 1 < sizeof(n->name) && name[i]; ++i) n->name[i] = name[i];
        n->name[i] = '\0';
    }
    return (int)idx;
}

static int name_to_83(const char *name, uint8_t out[11]) {
    if (!name || !out) return 0;
    for (int i = 0; i < 11; ++i) out[i] = ' ';
    int part = 0;
    int pos = 0;
    for (size_t i = 0; name[i]; ++i) {
        char c = name[i];
        if (c == '/') return 0;
        if (c == '.') {
            if (part != 0) return 0;
            part = 1;
            pos = 0;
            continue;
        }
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        if (part == 0) {
            if (pos >= 8) return 0;
            out[pos++] = (uint8_t)c;
        } else {
            if (pos >= 3) return 0;
            out[8 + pos++] = (uint8_t)c;
        }
    }
    return 1;
}

static int fat_read_cluster(uint32_t cluster, uint8_t *buf, uint32_t bytes) {
    (void)bytes;
    uint32_t lba = cluster_to_lba(cluster);
    return fat_read_sectors(lba, g_bpb.sectors_per_cluster, buf);
}

static int fat_write_cluster(uint32_t cluster, const uint8_t *buf, uint32_t bytes) {
    (void)bytes;
    uint32_t lba = cluster_to_lba(cluster);
    return fat_write_sectors(lba, g_bpb.sectors_per_cluster, buf);
}

static uint32_t fat_alloc_cluster(void) {
    uint32_t entries_per_sector = g_bpb.bytes_per_sector / 4;
    uint8_t tmp[512];
    for (uint32_t s = 0; s < g_bpb.fat_size32; ++s) {
        if (fat_read_sectors(g_fat_lba + s, 1, tmp) != 0) return 0;
        for (uint32_t i = 0; i < entries_per_sector; ++i) {
            uint32_t cluster = s * entries_per_sector + i;
            if (cluster < 2 || cluster >= g_clusters + 2) continue;
            uint32_t val = *(uint32_t *)(tmp + i * 4);
            if ((val & 0x0FFFFFFF) == 0) {
                if (fat_set_entry(cluster, 0x0FFFFFFF) != 0) return 0;
                uint32_t cluster_bytes = g_bpb.bytes_per_sector * g_bpb.sectors_per_cluster;
                uint8_t *zero = (uint8_t *)kmalloc(cluster_bytes);
                if (zero) {
                    memset(zero, 0, cluster_bytes);
                    fat_write_cluster(cluster, zero, cluster_bytes);
                    kfree(zero);
                }
                return cluster;
            }
        }
    }
    return 0;
}

static void fat_free_chain(uint32_t cluster) {
    uint32_t cur = cluster;
    while (cur >= 2 && cur < 0x0FFFFFF8) {
        uint32_t next = fat_entry(cur);
        (void)fat_set_entry(cur, 0);
        if (next == cur) break;
        cur = next;
    }
}

static uint32_t fat_get_cluster_at(uint32_t start, uint32_t index, int alloc) {
    if (start < 2) {
        if (!alloc) return 0;
        start = fat_alloc_cluster();
        if (start < 2) return 0;
    }
    uint32_t cur = start;
    for (uint32_t i = 0; i < index; ++i) {
        uint32_t next = fat_entry(cur);
        if (next >= 0x0FFFFFF8 || next < 2) {
            if (!alloc) return 0;
            uint32_t newc = fat_alloc_cluster();
            if (newc < 2) return 0;
            (void)fat_set_entry(cur, newc);
            cur = newc;
        } else {
            cur = next;
        }
    }
    return cur;
}

static int fat_find_dirent(uint32_t dir_cluster, const uint8_t name83[11],
                           uint32_t *out_cluster, uint32_t *out_off,
                           struct fat32_dirent *out, int want_free) {
    uint32_t cluster = dir_cluster;
    uint32_t sector_size = g_bpb.bytes_per_sector;
    uint32_t cluster_bytes = g_bpb.sectors_per_cluster * sector_size;
    if (!g_read_buf) g_read_buf = (uint8_t *)kmalloc(cluster_bytes);
    if (!g_read_buf) return -1;

    while (cluster >= 2 && cluster < 0x0FFFFFF8) {
        if (fat_read_cluster(cluster, g_read_buf, cluster_bytes) != 0) return -1;
        for (uint32_t off = 0; off < cluster_bytes; off += sizeof(struct fat32_dirent)) {
            struct fat32_dirent *de = (struct fat32_dirent *)(g_read_buf + off);
            if (de->name[0] == 0x00) {
                if (want_free) {
                    if (out_cluster) *out_cluster = cluster;
                    if (out_off) *out_off = off;
                    if (out) *out = *de;
                    return 1;
                }
                return 0;
            }
            if (de->name[0] == 0xE5) {
                if (want_free) {
                    if (out_cluster) *out_cluster = cluster;
                    if (out_off) *out_off = off;
                    if (out) *out = *de;
                    return 1;
                }
                continue;
            }
            if (de->attr == 0x0F) continue;
            int match = 1;
            for (int i = 0; i < 11; ++i) {
                if (de->name[i] != name83[i]) { match = 0; break; }
            }
            if (match) {
                if (out_cluster) *out_cluster = cluster;
                if (out_off) *out_off = off;
                if (out) *out = *de;
                return 2;
            }
        }
        cluster = fat_entry(cluster);
    }
    return 0;
}

static int fat_write_dirent(uint32_t cluster, uint32_t off, const struct fat32_dirent *de) {
    uint32_t sector_size = g_bpb.bytes_per_sector;
    uint32_t cluster_bytes = g_bpb.sectors_per_cluster * sector_size;
    if (!g_read_buf) g_read_buf = (uint8_t *)kmalloc(cluster_bytes);
    if (!g_read_buf) return -1;
    if (fat_read_cluster(cluster, g_read_buf, cluster_bytes) != 0) return -1;
    memcpy(g_read_buf + off, de, sizeof(*de));
    return fat_write_cluster(cluster, g_read_buf, cluster_bytes);
}

static void name_from_83(const uint8_t name[11], char *out, size_t out_size) {
    size_t w = 0;
    for (int i = 0; i < 8 && w + 1 < out_size; ++i) {
        char c = (char)name[i];
        if (c == ' ') break;
        out[w++] = c;
    }
    int has_ext = 0;
    for (int i = 8; i < 11; ++i) {
        if (name[i] != ' ') { has_ext = 1; break; }
    }
    if (has_ext && w + 1 < out_size) out[w++] = '.';
    if (has_ext) {
        for (int i = 8; i < 11 && w + 1 < out_size; ++i) {
            char c = (char)name[i];
            if (c == ' ') break;
            out[w++] = c;
        }
    }
    out[w] = '\0';
}

static void scan_dir(uint32_t parent, uint32_t start_cluster) {
    uint32_t cluster = start_cluster;
    uint32_t sector_size = g_bpb.bytes_per_sector;
    uint32_t cluster_bytes = g_bpb.sectors_per_cluster * sector_size;
    if (!g_read_buf) g_read_buf = (uint8_t *)kmalloc(cluster_bytes);
    if (!g_read_buf) return;

    while (cluster >= 2 && cluster < 0x0FFFFFF8) {
        uint32_t lba = cluster_to_lba(cluster);
        if (fat_read_sectors(lba, g_bpb.sectors_per_cluster, g_read_buf) != 0) return;
        for (uint32_t off = 0; off < cluster_bytes; off += sizeof(struct fat32_dirent)) {
            struct fat32_dirent *de = (struct fat32_dirent *)(g_read_buf + off);
            if (de->name[0] == 0x00) return;
            if (de->name[0] == 0xE5) continue;
            if (de->attr == 0x0F) continue;
            if ((de->attr & 0x08) != 0) continue;

            char nm[FAT32_MAX_NAME];
            name_from_83(de->name, nm, sizeof(nm));
            if (nm[0] == '\0') continue;
            if (str_eq(nm, ".")) continue;
            if (str_eq(nm, "..")) continue;

            uint32_t first_cluster = ((uint32_t)de->fst_clus_hi << 16) | de->fst_clus_lo;
            int is_dir = (de->attr & 0x10) != 0;
            node_new(parent, first_cluster, de->file_size, is_dir, nm);
        }
        cluster = fat_entry(cluster);
    }
}

void fat32_ensure_scanned(int node) {
    if (!g_ready) return;
    if (node < 0 || (uint32_t)node >= g_node_count) return;
    struct fat32_node *n = g_nodes[node];
    if (!n || !n->is_dir) return;
    /* FAT32 directories are fully scanned at init; nothing else to do. */
    (void)n;
}

int fat32_init_from_partition(uint32_t part_index) {
    memset(&g_bpb, 0, sizeof(g_bpb));
    g_ready = 0;
    g_dev = NULL;
    memset(&g_part, 0, sizeof(g_part));
    for (uint32_t i = 0; i < g_node_count; ++i) {
        if (g_nodes[i]) {
            slab_free(g_nodes[i]);
            g_nodes[i] = NULL;
        }
    }
    g_node_count = 0;
    if (g_read_buf) {
        kfree(g_read_buf);
        g_read_buf = NULL;
    }

    const struct partition_info *p = partition_get(part_index);
    if (!p) return -1;
    const struct block_device *dev = block_get(p->device_index);
    if (!dev) return -1;
    g_part = *p;
    g_dev = dev;

    uint8_t sector[512];
    if (fat_read_sectors(0, 1, sector) != 0) return -1;
    memcpy(&g_bpb, sector, sizeof(g_bpb));
    if (g_bpb.bytes_per_sector == 0 || g_bpb.sectors_per_cluster == 0) return -1;
    if (g_bpb.fat_size32 == 0) return -1;

    uint32_t total_sectors = g_bpb.total_sectors16 ? g_bpb.total_sectors16 : g_bpb.total_sectors32;
    uint32_t first_data = g_bpb.reserved_sectors + (g_bpb.num_fats * g_bpb.fat_size32);
    g_fat_lba = g_bpb.reserved_sectors;
    g_data_lba = first_data;
    uint32_t data_sectors = total_sectors - first_data;
    g_clusters = data_sectors / g_bpb.sectors_per_cluster;
    if (g_clusters == 0) return -1;

    int root = node_new(0xFFFFFFFFu, g_bpb.root_cluster, 0, 1, "/");
    if (root < 0) return -1;
    scan_dir((uint32_t)root, g_bpb.root_cluster);

    g_ready = 1;
    log_printf("FAT32: mounted (cluster=%u, root=%u)\n",
               (unsigned)g_bpb.sectors_per_cluster, (unsigned)g_bpb.root_cluster);
    return 0;
}

int fat32_is_ready(void) {
    return g_ready;
}

int fat32_root(void) {
    return g_ready ? 0 : -1;
}

static int find_child(int dir, const char *name) {
    if (dir < 0 || (uint32_t)dir >= g_node_count) return -1;
    for (uint32_t i = 0; i < g_node_count; ++i) {
        if (!g_nodes[i]) continue;
        if (g_nodes[i]->parent == (uint32_t)dir && str_eq(g_nodes[i]->name, name)) return (int)i;
    }
    return -1;
}

int fat32_resolve(int cwd, const char *path) {
    if (!g_ready) return -1;
    if (!path || path[0] == '\0') return cwd;
    int cur = (path[0] == '/') ? 0 : cwd;
    size_t i = (path[0] == '/') ? 1 : 0;
    char part[64];
    size_t p = 0;
    while (1) {
        char c = path[i];
        if (c == '/' || c == '\0') {
            part[p] = '\0';
            if (p > 0) {
                if (str_eq(part, ".")) {
                    /* no-op */
                } else if (str_eq(part, "..")) {
                    if (cur != 0 && g_nodes[cur]) cur = (int)g_nodes[cur]->parent;
                } else {
                    int next = find_child(cur, part);
                    if (next < 0) return -1;
                    cur = next;
                }
            }
            p = 0;
            if (c == '\0') break;
        } else if (p + 1 < sizeof(part)) {
            part[p++] = c;
        }
        i++;
    }
    return cur;
}

int fat32_is_dir(int node) {
    if (node < 0 || (uint32_t)node >= g_node_count) return 0;
    return g_nodes[node] && g_nodes[node]->is_dir != 0;
}

int fat32_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (!data || !size) return 0;
    if (node < 0 || (uint32_t)node >= g_node_count) return 0;
    struct fat32_node *n = g_nodes[node];
    if (!n) return 0;
    if (n->is_dir) return 0;

    uint32_t sector_size = g_bpb.bytes_per_sector;
    uint32_t cluster_bytes = g_bpb.sectors_per_cluster * sector_size;
    uint8_t *buf = (uint8_t *)kmalloc(cluster_bytes);
    if (!buf) return 0;
    uint32_t cluster = n->first_cluster;
    uint64_t remaining = n->size;
    uint8_t *out = (uint8_t *)kmalloc((size_t)remaining);
    if (!out) {
        kfree(buf);
        return 0;
    }
    uint64_t offset = 0;
    while (cluster >= 2 && cluster < 0x0FFFFFF8 && remaining > 0) {
        uint32_t lba = cluster_to_lba(cluster);
        if (fat_read_sectors(lba, g_bpb.sectors_per_cluster, buf) != 0) break;
        uint64_t to_copy = remaining > cluster_bytes ? cluster_bytes : remaining;
        memcpy(out + offset, buf, (size_t)to_copy);
        offset += to_copy;
        remaining -= to_copy;
        cluster = fat_entry(cluster);
    }
    kfree(buf);
    if (offset == 0) {
        kfree(out);
        return 0;
    }
    *data = out;
    *size = offset;
    return 1;
}

static int fat_update_dirent_for_node(int node, uint32_t first_cluster, uint32_t size) {
    if (node <= 0 || (uint32_t)node >= g_node_count || !g_nodes[node]) return -1;
    struct fat32_node *n = g_nodes[node];
    uint8_t name83[11];
    if (!name_to_83(n->name, name83)) return -1;
    uint32_t dir_cluster = g_bpb.root_cluster;
    if (n->parent != 0xFFFFFFFFu && n->parent < g_node_count && g_nodes[n->parent]) {
        dir_cluster = g_nodes[n->parent]->first_cluster;
    }
    struct fat32_dirent de;
    uint32_t de_cluster = 0, de_off = 0;
    int rc = fat_find_dirent(dir_cluster, name83, &de_cluster, &de_off, &de, 0);
    if (rc <= 0) return -1;
    de.fst_clus_lo = (uint16_t)(first_cluster & 0xFFFFu);
    de.fst_clus_hi = (uint16_t)(first_cluster >> 16);
    de.file_size = size;
    return fat_write_dirent(de_cluster, de_off, &de);
}

int fat32_truncate(int node, uint64_t new_size) {
    if (!g_ready) return -1;
    if (node <= 0 || (uint32_t)node >= g_node_count || !g_nodes[node]) return -1;
    struct fat32_node *n = g_nodes[node];
    if (n->is_dir) return -1;

    if (new_size == 0) {
        if (n->first_cluster >= 2) {
            fat_free_chain(n->first_cluster);
        }
        n->first_cluster = 0;
        n->size = 0;
        return fat_update_dirent_for_node(node, n->first_cluster, n->size);
    }
    n->size = (uint32_t)new_size;
    return fat_update_dirent_for_node(node, n->first_cluster, n->size);
}

int fat32_write_file(int node, const uint8_t *data, uint64_t size, uint64_t offset) {
    if (!g_ready) return -1;
    if (!data && size > 0) return -1;
    if (node <= 0 || (uint32_t)node >= g_node_count || !g_nodes[node]) return -1;
    struct fat32_node *n = g_nodes[node];
    if (n->is_dir) return -1;

    uint32_t sector_size = g_bpb.bytes_per_sector;
    uint32_t cluster_bytes = g_bpb.sectors_per_cluster * sector_size;
    uint8_t *buf = (uint8_t *)kmalloc(cluster_bytes);
    if (!buf) return -1;

    uint64_t end = offset + size;
    uint64_t pos = 0;
    while (pos < size) {
        uint64_t file_pos = offset + pos;
        uint32_t cluster_index = (uint32_t)(file_pos / cluster_bytes);
        uint32_t within = (uint32_t)(file_pos % cluster_bytes);
        uint32_t cluster = fat_get_cluster_at(n->first_cluster, cluster_index, 1);
        if (cluster < 2) { kfree(buf); return -1; }
        if (n->first_cluster < 2) n->first_cluster = cluster;
        if (within != 0 || (size - pos) < cluster_bytes) {
            if (fat_read_cluster(cluster, buf, cluster_bytes) != 0) {
                kfree(buf);
                return -1;
            }
        } else {
            memset(buf, 0, cluster_bytes);
        }
        uint64_t to_copy = size - pos;
        if (to_copy > (uint64_t)(cluster_bytes - within)) {
            to_copy = (uint64_t)(cluster_bytes - within);
        }
        memcpy(buf + within, data + pos, (size_t)to_copy);
        if (fat_write_cluster(cluster, buf, cluster_bytes) != 0) {
            kfree(buf);
            return -1;
        }
        pos += to_copy;
    }
    kfree(buf);
    if (end > n->size) n->size = (uint32_t)end;
    return fat_update_dirent_for_node(node, n->first_cluster, n->size);
}

int fat32_create(int cwd, const char *name, int is_dir) {
    if (!g_ready || !name) return -1;
    uint8_t name83[11];
    if (!name_to_83(name, name83)) return -1;
    uint32_t dir_cluster = g_bpb.root_cluster;
    if (cwd >= 0 && (uint32_t)cwd < g_node_count && g_nodes[cwd]) {
        if (!g_nodes[cwd]->is_dir) return -1;
        dir_cluster = g_nodes[cwd]->first_cluster;
    }
    struct fat32_dirent de;
    uint32_t de_cluster = 0, de_off = 0;
    int rc = fat_find_dirent(dir_cluster, name83, &de_cluster, &de_off, &de, 0);
    if (rc == 2) return -1;
    rc = fat_find_dirent(dir_cluster, name83, &de_cluster, &de_off, &de, 1);
    if (rc <= 0) {
        uint32_t last = dir_cluster;
        while (1) {
            uint32_t next = fat_entry(last);
            if (next < 2 || next >= 0x0FFFFFF8) break;
            last = next;
        }
        uint32_t newc = fat_alloc_cluster();
        if (newc < 2) return -1;
        (void)fat_set_entry(last, newc);
        de_cluster = newc;
        de_off = 0;
    }
    struct fat32_dirent nde;
    memset(&nde, 0, sizeof(nde));
    memcpy(nde.name, name83, 11);
    nde.attr = is_dir ? 0x10 : 0x20;
    uint32_t first_cluster = 0;
    if (is_dir) {
        first_cluster = fat_alloc_cluster();
        if (first_cluster < 2) return -1;
        uint32_t cluster_bytes = g_bpb.bytes_per_sector * g_bpb.sectors_per_cluster;
        uint8_t *buf = (uint8_t *)kmalloc(cluster_bytes);
        if (buf) {
            memset(buf, 0, cluster_bytes);
            struct fat32_dirent *dot = (struct fat32_dirent *)buf;
            memcpy(dot->name, name83, 11);
            dot->attr = 0x10;
            dot->fst_clus_lo = (uint16_t)(first_cluster & 0xFFFFu);
            dot->fst_clus_hi = (uint16_t)(first_cluster >> 16);
            struct fat32_dirent *dotdot = (struct fat32_dirent *)(buf + sizeof(struct fat32_dirent));
            memcpy(dotdot->name, "..       ", 11);
            dotdot->attr = 0x10;
            dotdot->fst_clus_lo = (uint16_t)(dir_cluster & 0xFFFFu);
            dotdot->fst_clus_hi = (uint16_t)(dir_cluster >> 16);
            fat_write_cluster(first_cluster, buf, cluster_bytes);
            kfree(buf);
        }
    }
    nde.fst_clus_lo = (uint16_t)(first_cluster & 0xFFFFu);
    nde.fst_clus_hi = (uint16_t)(first_cluster >> 16);
    nde.file_size = 0;
    if (fat_write_dirent(de_cluster, de_off, &nde) != 0) return -1;

    int idx = node_new((cwd < 0) ? 0 : (uint32_t)cwd, first_cluster, 0, is_dir, name);
    return idx;
}

uint64_t fat32_get_size(int node) {
    if (node < 0 || (uint32_t)node >= g_node_count || !g_nodes[node]) return 0;
    return g_nodes[node]->size;
}

void fat32_pwd(int cwd) {
    if (!g_ready) return;
    if (cwd < 0 || (uint32_t)cwd >= g_node_count) return;
    if (cwd == 0) {
        log_printf("/\n");
        return;
    }
    char buf[256];
    size_t len = 0;
    int cur = cwd;
    while (cur > 0 && len + 2 < sizeof(buf)) {
        if (!g_nodes[cur]) break;
        const char *name = g_nodes[cur]->name;
        size_t nlen = str_len(name);
        if (len + nlen + 1 >= sizeof(buf)) break;
        for (size_t i = 0; i < nlen; ++i) buf[len++] = name[i];
        buf[len++] = '/';
        cur = (int)g_nodes[cur]->parent;
    }
    for (size_t i = 0; i < len / 2; ++i) {
        char tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }
    buf[len - 1] = '\0';
    log_printf("/%s\n", buf);
}

void fat32_ls(int node) {
    if (!g_ready) return;
    if (node < 0 || (uint32_t)node >= g_node_count) return;
    struct fat32_node *n = g_nodes[node];
    if (!n) return;
    if (!n->is_dir) {
        log_printf("%s\n", n->name);
        return;
    }
    for (uint32_t i = 0; i < g_node_count; ++i) {
        if (!g_nodes[i]) continue;
        if (g_nodes[i]->parent == (uint32_t)node) {
            log_printf("%s%s ", g_nodes[i]->name, g_nodes[i]->is_dir ? "/" : "");
        }
    }
    log_printf("\n");
}
