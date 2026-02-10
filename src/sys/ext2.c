#include "sys/ext2.h"

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

#define EXT2_MAX_NODES 512
#define EXT2_MAX_NAME  64

struct ext2_superblock {
    uint32_t s_inodes_count;
    uint32_t s_blocks_count;
    uint32_t s_r_blocks_count;
    uint32_t s_free_blocks_count;
    uint32_t s_free_inodes_count;
    uint32_t s_first_data_block;
    uint32_t s_log_block_size;
    uint32_t s_log_frag_size;
    uint32_t s_blocks_per_group;
    uint32_t s_frags_per_group;
    uint32_t s_inodes_per_group;
    uint32_t s_mtime;
    uint32_t s_wtime;
    uint16_t s_mnt_count;
    uint16_t s_max_mnt_count;
    uint16_t s_magic;
    uint16_t s_state;
    uint16_t s_errors;
    uint16_t s_minor_rev_level;
    uint32_t s_lastcheck;
    uint32_t s_checkinterval;
    uint32_t s_creator_os;
    uint32_t s_rev_level;
    uint16_t s_def_resuid;
    uint16_t s_def_resgid;
    uint32_t s_first_ino;
    uint16_t s_inode_size;
    uint16_t s_block_group_nr;
    uint32_t s_feature_compat;
    uint32_t s_feature_incompat;
    uint32_t s_feature_ro_compat;
    uint8_t  s_uuid[16];
    uint8_t  s_volume_name[16];
    uint8_t  s_last_mounted[64];
    uint32_t s_algorithm_usage_bitmap;
} __attribute__((packed));

struct ext2_group_desc {
    uint32_t bg_block_bitmap;
    uint32_t bg_inode_bitmap;
    uint32_t bg_inode_table;
    uint16_t bg_free_blocks_count;
    uint16_t bg_free_inodes_count;
    uint16_t bg_used_dirs_count;
    uint16_t bg_pad;
    uint32_t bg_reserved[3];
} __attribute__((packed));

struct ext2_inode {
    uint16_t i_mode;
    uint16_t i_uid;
    uint32_t i_size;
    uint32_t i_atime;
    uint32_t i_ctime;
    uint32_t i_mtime;
    uint32_t i_dtime;
    uint16_t i_gid;
    uint16_t i_links_count;
    uint32_t i_blocks;
    uint32_t i_flags;
    uint32_t i_osd1;
    uint32_t i_block[15];
    uint32_t i_generation;
    uint32_t i_file_acl;
    uint32_t i_dir_acl;
    uint32_t i_faddr;
    uint8_t  i_osd2[12];
} __attribute__((packed));

struct ext2_dirent {
    uint32_t inode;
    uint16_t rec_len;
    uint8_t name_len;
    uint8_t file_type;
    char name[0];
} __attribute__((packed));

struct ext2_node {
    uint32_t parent;
    uint32_t inode;
    uint32_t size;
    uint8_t is_dir;
    uint8_t scanned;
    char name[EXT2_MAX_NAME];
};

static int g_ready = 0;
static struct ext2_superblock g_sb;
static struct ext2_group_desc *g_gdt = NULL;
static uint32_t g_group_count = 0;
static uint32_t g_block_size = 0;
static uint32_t g_inode_size = 0;
static uint32_t g_gdt_block_start = 0;
static uint32_t g_gdt_block_count = 0;
static const struct block_device *g_dev = NULL;
static struct partition_info g_part;

static struct ext2_node *g_nodes[EXT2_MAX_NODES];
static uint32_t g_node_count = 0;
static uint8_t *g_block_buf = NULL;
static uint8_t *g_inode_buf = NULL;

static uint64_t part_lba(uint64_t lba) {
    return (uint64_t)g_part.first_lba + lba;
}

static int read_sectors(uint64_t lba, uint32_t count, void *buf) {
    if (!g_dev) return -1;
    return block_read_cached(g_dev, part_lba(lba), count, buf);
}

static int write_sectors(uint64_t lba, uint32_t count, const void *buf) {
    if (!g_dev) return -1;
    return block_write_cached(g_dev, part_lba(lba), count, buf);
}

static int read_block(uint32_t block, void *buf) {
    if (!g_dev || g_block_size == 0) return -1;
    uint32_t sector_size = g_dev->sector_size;
    if (sector_size == 0) return -1;
    if ((g_block_size % sector_size) != 0) return -1;
    uint32_t sectors = g_block_size / sector_size;
    uint64_t lba = (uint64_t)block * sectors;
    return read_sectors(lba, sectors, buf);
}

static int write_block(uint32_t block, const void *buf) {
    if (!g_dev || g_block_size == 0) return -1;
    uint32_t sector_size = g_dev->sector_size;
    if (sector_size == 0) return -1;
    if ((g_block_size % sector_size) != 0) return -1;
    uint32_t sectors = g_block_size / sector_size;
    uint64_t lba = (uint64_t)block * sectors;
    return write_sectors(lba, sectors, buf);
}

static void nodes_reset(void) {
    for (uint32_t i = 0; i < g_node_count; ++i) {
        if (g_nodes[i]) {
            slab_free(g_nodes[i]);
            g_nodes[i] = NULL;
        }
    }
    g_node_count = 0;
}

static int node_new(uint32_t parent, uint32_t inode, uint32_t size, int is_dir, const char *name) {
    if (g_node_count >= EXT2_MAX_NODES) return -1;
    struct ext2_node *n = slab_alloc(sizeof(*n));
    if (!n) return -1;
    uint32_t idx = g_node_count++;
    g_nodes[idx] = n;
    n->parent = parent;
    n->inode = inode;
    n->size = size;
    n->is_dir = (uint8_t)(is_dir != 0);
    n->scanned = 0;
    memset(n->name, 0, sizeof(n->name));
    if (name) {
        size_t i = 0;
        for (; i + 1 < sizeof(n->name) && name[i]; ++i) n->name[i] = name[i];
        n->name[i] = '\0';
    }
    return (int)idx;
}

static int read_inode(uint32_t inode_no, struct ext2_inode *out) {
    if (!out || inode_no == 0) return -1;
    uint32_t inodes_per_group = g_sb.s_inodes_per_group;
    uint32_t group = (inode_no - 1) / inodes_per_group;
    uint32_t index = (inode_no - 1) % inodes_per_group;
    if (group >= g_group_count) return -1;
    uint32_t table_block = g_gdt[group].bg_inode_table;
    uint32_t offset = index * g_inode_size;
    uint32_t block = table_block + (offset / g_block_size);
    uint32_t block_off = offset % g_block_size;
    if (!g_inode_buf) g_inode_buf = (uint8_t *)kmalloc(g_block_size);
    if (!g_inode_buf) return -1;
    if (read_block(block, g_inode_buf) != 0) return -1;
    memcpy(out, g_inode_buf + block_off, sizeof(*out));
    return 0;
}

static int is_dir_inode(const struct ext2_inode *ino) {
    return (ino->i_mode & 0xF000) == 0x4000;
}

static void scan_dir(uint32_t parent_node, uint32_t inode_no) {
    if (parent_node >= g_node_count) return;
    struct ext2_node *parent = g_nodes[parent_node];
    if (!parent || parent->scanned) return;
    parent->scanned = 1;

    struct ext2_inode ino;
    if (read_inode(inode_no, &ino) != 0) return;
    if (!is_dir_inode(&ino)) return;

    if (!g_block_buf) g_block_buf = (uint8_t *)kmalloc(g_block_size);
    if (!g_block_buf) return;

    uint32_t total = ino.i_size;
    uint32_t consumed = 0;
    for (uint32_t i = 0; i < 12 && consumed < total; ++i) {
        uint32_t blk = ino.i_block[i];
        if (blk == 0) continue;
        if (read_block(blk, g_block_buf) != 0) return;
        uint32_t off = 0;
        while (off + sizeof(struct ext2_dirent) <= g_block_size && consumed < total) {
            struct ext2_dirent *de = (struct ext2_dirent *)(g_block_buf + off);
            if (de->rec_len == 0) break;
            if (de->inode != 0 && de->name_len > 0) {
                char nm[EXT2_MAX_NAME];
                uint32_t nlen = de->name_len;
                if (nlen >= sizeof(nm)) nlen = sizeof(nm) - 1;
                memcpy(nm, de->name, nlen);
                nm[nlen] = '\0';
                if (!str_eq(nm, ".") && !str_eq(nm, "..")) {
                    struct ext2_inode child;
                    int is_dir = 0;
                    uint32_t size = 0;
                    if (read_inode(de->inode, &child) == 0) {
                        is_dir = is_dir_inode(&child);
                        size = child.i_size;
                    }
                    int child_idx = node_new(parent_node, de->inode, size, is_dir, nm);
                    if (child_idx >= 0 && is_dir) {
                        if (g_node_count < EXT2_MAX_NODES) {
                            scan_dir((uint32_t)child_idx, de->inode);
                        }
                    }
                }
            }
            off += de->rec_len;
            consumed += de->rec_len;
        }
    }
}

static int write_superblock(void) {
    if (!g_dev) return -1;
    uint32_t sector_size = g_dev->sector_size;
    if (sector_size == 0) return -1;
    uint32_t sb_lba = (uint32_t)(1024 / sector_size);
    uint32_t sb_off = 1024 % sector_size;
    uint8_t *sector = (uint8_t *)kmalloc(sector_size);
    if (!sector) return -1;
    if (read_sectors(sb_lba, 1, sector) != 0) {
        kfree(sector);
        return -1;
    }
    memcpy(sector + sb_off, &g_sb, sizeof(g_sb));
    int rc = write_sectors(sb_lba, 1, sector);
    kfree(sector);
    return rc;
}

static int write_gdt(void) {
    if (!g_gdt || g_gdt_block_count == 0) return -1;
    for (uint32_t i = 0; i < g_gdt_block_count; ++i) {
        uint8_t *src = (uint8_t *)g_gdt + (i * g_block_size);
        if (write_block(g_gdt_block_start + i, src) != 0) return -1;
    }
    return 0;
}

static int bitmap_find_and_set(uint32_t bitmap_block, uint32_t max_bits, uint32_t *out_bit) {
    if (!g_block_buf) g_block_buf = (uint8_t *)kmalloc(g_block_size);
    if (!g_block_buf) return -1;
    if (read_block(bitmap_block, g_block_buf) != 0) return -1;
    for (uint32_t i = 0; i < max_bits; ++i) {
        uint32_t byte = i / 8;
        uint32_t bit = i % 8;
        if ((g_block_buf[byte] & (1u << bit)) == 0) {
            g_block_buf[byte] |= (uint8_t)(1u << bit);
            if (write_block(bitmap_block, g_block_buf) != 0) return -1;
            if (out_bit) *out_bit = i;
            return 0;
        }
    }
    return -1;
}

static int bitmap_clear(uint32_t bitmap_block, uint32_t bit_index) {
    if (!g_block_buf) g_block_buf = (uint8_t *)kmalloc(g_block_size);
    if (!g_block_buf) return -1;
    if (read_block(bitmap_block, g_block_buf) != 0) return -1;
    uint32_t byte = bit_index / 8;
    uint32_t bit = bit_index % 8;
    g_block_buf[byte] &= (uint8_t)~(1u << bit);
    return write_block(bitmap_block, g_block_buf);
}

static int find_child(uint32_t parent, const char *name) {
    for (uint32_t i = 0; i < g_node_count; ++i) {
        if (!g_nodes[i]) continue;
        if (g_nodes[i]->parent == parent && str_eq(g_nodes[i]->name, name)) return (int)i;
    }
    return -1;
}

int ext2_init_from_partition(uint32_t part_index) {
    memset(&g_sb, 0, sizeof(g_sb));
    g_ready = 0;
    g_dev = NULL;
    if (g_gdt) {
        kfree(g_gdt);
        g_gdt = NULL;
    }
    g_group_count = 0;
    g_block_size = 0;
    g_inode_size = 0;
    g_gdt_block_start = 0;
    g_gdt_block_count = 0;
    memset(&g_part, 0, sizeof(g_part));
    nodes_reset();
    if (g_block_buf) {
        kfree(g_block_buf);
        g_block_buf = NULL;
    }
    if (g_inode_buf) {
        kfree(g_inode_buf);
        g_inode_buf = NULL;
    }

    const struct partition_info *p = partition_get(part_index);
    if (!p) return -1;
    const struct block_device *dev = block_get(p->device_index);
    if (!dev || dev->sector_size == 0) return -1;
    g_part = *p;
    g_dev = dev;

    uint32_t sector_size = dev->sector_size;
    uint32_t sb_lba = (uint32_t)(1024 / sector_size);
    uint32_t sb_off = 1024 % sector_size;
    uint8_t *sector = (uint8_t *)kmalloc(sector_size);
    if (!sector) return -1;
    if (read_sectors(sb_lba, 1, sector) != 0) {
        kfree(sector);
        return -1;
    }
    memcpy(&g_sb, sector + sb_off, sizeof(g_sb));
    kfree(sector);
    if (g_sb.s_magic != 0xEF53) return -1;

    g_block_size = 1024u << g_sb.s_log_block_size;
    if (g_block_size == 0) return -1;
    g_inode_size = g_sb.s_inode_size ? g_sb.s_inode_size : 128;
    if (g_inode_size < sizeof(struct ext2_inode)) g_inode_size = sizeof(struct ext2_inode);

    uint32_t blocks_per_group = g_sb.s_blocks_per_group;
    if (blocks_per_group == 0) return -1;
    g_group_count = (g_sb.s_blocks_count + blocks_per_group - 1) / blocks_per_group;
    if (g_group_count == 0) return -1;

    uint32_t gdt_block = (g_block_size == 1024) ? 2 : 1;
    uint32_t gdt_bytes = g_group_count * sizeof(struct ext2_group_desc);
    uint32_t gdt_blocks = (gdt_bytes + g_block_size - 1) / g_block_size;
    g_gdt_block_start = gdt_block;
    g_gdt_block_count = gdt_blocks;
    g_gdt = (struct ext2_group_desc *)kmalloc(gdt_blocks * g_block_size);
    if (!g_gdt) return -1;
    for (uint32_t i = 0; i < gdt_blocks; ++i) {
        uint8_t *dst = (uint8_t *)g_gdt + (i * g_block_size);
        if (read_block(gdt_block + i, dst) != 0) return -1;
    }

    int root = node_new(0xFFFFFFFFu, 2, 0, 1, "/");
    if (root < 0) return -1;
    scan_dir((uint32_t)root, 2);
    g_ready = 1;
    log_printf("ext2: ready (block=%u, groups=%u)\n", (unsigned)g_block_size, (unsigned)g_group_count);
    return 0;
}

int ext2_is_ready(void) {
    return g_ready != 0;
}

int ext2_root(void) {
    return 0;
}

int ext2_resolve(int cwd, const char *path) {
    if (!g_ready) return -1;
    if (!path || path[0] == '\0') return cwd;
    if (str_eq(path, "/")) return 0;
    int cur = (path[0] == '/') ? 0 : cwd;
    if (cur < 0 || (uint32_t)cur >= g_node_count) cur = 0;

    char part[EXT2_MAX_NAME];
    size_t p = 0;
    size_t i = 0;
    while (1) {
        char c = path[i];
        if (c == '/' || c == '\0') {
            part[p] = '\0';
            if (p > 0) {
                if (str_eq(part, ".")) {
                } else if (str_eq(part, "..")) {
                    if (cur != 0 && g_nodes[cur]) cur = (int)g_nodes[cur]->parent;
                } else {
                    if (g_nodes[cur] && g_nodes[cur]->is_dir && !g_nodes[cur]->scanned) {
                        scan_dir((uint32_t)cur, g_nodes[cur]->inode);
                    }
                    int next = find_child((uint32_t)cur, part);
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

int ext2_is_dir(int node) {
    if (!g_ready) return 0;
    if (node < 0 || (uint32_t)node >= g_node_count) return 0;
    return g_nodes[node] && g_nodes[node]->is_dir != 0;
}

int ext2_read_file(int node, const uint8_t **data, uint64_t *size) {
    if (!g_ready || !data || !size) return 0;
    if (node < 0 || (uint32_t)node >= g_node_count) return 0;
    struct ext2_node *n = g_nodes[node];
    if (!n || n->is_dir) return 0;
    struct ext2_inode ino;
    if (read_inode(n->inode, &ino) != 0) return 0;
    uint64_t file_size = ino.i_size;
    if (file_size == 0) return 0;

    uint8_t *out = (uint8_t *)kmalloc((size_t)file_size);
    if (!out) return 0;
    if (!g_block_buf) g_block_buf = (uint8_t *)kmalloc(g_block_size);
    if (!g_block_buf) {
        kfree(out);
        return 0;
    }

    uint64_t offset = 0;
    for (uint32_t i = 0; i < 12 && offset < file_size; ++i) {
        uint32_t blk = ino.i_block[i];
        if (blk == 0) continue;
        if (read_block(blk, g_block_buf) != 0) break;
        uint64_t to_copy = file_size - offset;
        if (to_copy > g_block_size) to_copy = g_block_size;
        memcpy(out + offset, g_block_buf, (size_t)to_copy);
        offset += to_copy;
    }

    if (offset < file_size && ino.i_block[12] != 0) {
        uint32_t ind_blk = ino.i_block[12];
        if (read_block(ind_blk, g_block_buf) == 0) {
            uint32_t *entries = (uint32_t *)g_block_buf;
            uint32_t count = g_block_size / sizeof(uint32_t);
            for (uint32_t i = 0; i < count && offset < file_size; ++i) {
                uint32_t blk = entries[i];
                if (blk == 0) continue;
                if (read_block(blk, g_block_buf) != 0) break;
                uint64_t to_copy = file_size - offset;
                if (to_copy > g_block_size) to_copy = g_block_size;
                memcpy(out + offset, g_block_buf, (size_t)to_copy);
                offset += to_copy;
            }
        }
    }

    if (offset == 0) {
        kfree(out);
        return 0;
    }
    *data = out;
    *size = offset;
    return 1;
}

int ext2_alloc_block(uint32_t *out_block) {
    if (!g_ready || !out_block) return -1;
    if (g_sb.s_free_blocks_count == 0) return -1;
    uint32_t blocks_per_group = g_sb.s_blocks_per_group;
    if (blocks_per_group == 0) return -1;

    for (uint32_t g = 0; g < g_group_count; ++g) {
        if (g_gdt[g].bg_free_blocks_count == 0) continue;
        uint32_t bit = 0;
        if (bitmap_find_and_set(g_gdt[g].bg_block_bitmap, blocks_per_group, &bit) == 0) {
            uint32_t block_no = g * blocks_per_group + bit;
            if (block_no < g_sb.s_first_data_block) continue;
            g_gdt[g].bg_free_blocks_count--;
            g_sb.s_free_blocks_count--;
            if (write_gdt() != 0) return -1;
            if (write_superblock() != 0) return -1;
            *out_block = block_no;
            return 0;
        }
    }
    return -1;
}

int ext2_free_block(uint32_t block) {
    if (!g_ready) return -1;
    uint32_t blocks_per_group = g_sb.s_blocks_per_group;
    if (blocks_per_group == 0) return -1;
    uint32_t g = block / blocks_per_group;
    uint32_t bit = block % blocks_per_group;
    if (g >= g_group_count) return -1;
    if (bitmap_clear(g_gdt[g].bg_block_bitmap, bit) != 0) return -1;
    g_gdt[g].bg_free_blocks_count++;
    g_sb.s_free_blocks_count++;
    if (write_gdt() != 0) return -1;
    return write_superblock();
}

int ext2_alloc_inode(uint16_t mode, uint32_t *out_inode) {
    if (!g_ready || !out_inode) return -1;
    if (g_sb.s_free_inodes_count == 0) return -1;
    uint32_t inodes_per_group = g_sb.s_inodes_per_group;
    if (inodes_per_group == 0) return -1;

    for (uint32_t g = 0; g < g_group_count; ++g) {
        if (g_gdt[g].bg_free_inodes_count == 0) continue;
        uint32_t bit = 0;
        if (bitmap_find_and_set(g_gdt[g].bg_inode_bitmap, inodes_per_group, &bit) == 0) {
            uint32_t inode_no = g * inodes_per_group + bit + 1;
            if (inode_no < g_sb.s_first_ino) continue;
            g_gdt[g].bg_free_inodes_count--;
            g_sb.s_free_inodes_count--;
            if (write_gdt() != 0) return -1;
            if (write_superblock() != 0) return -1;

            struct ext2_inode ino;
            memset(&ino, 0, sizeof(ino));
            ino.i_mode = mode;
            if (read_inode(inode_no, &ino) == 0) {
                ino.i_mode = mode;
            }
            *out_inode = inode_no;
            return 0;
        }
    }
    return -1;
}

int ext2_free_inode(uint32_t inode) {
    if (!g_ready) return -1;
    if (inode == 0) return -1;
    uint32_t inodes_per_group = g_sb.s_inodes_per_group;
    if (inodes_per_group == 0) return -1;
    uint32_t g = (inode - 1) / inodes_per_group;
    uint32_t bit = (inode - 1) % inodes_per_group;
    if (g >= g_group_count) return -1;
    if (bitmap_clear(g_gdt[g].bg_inode_bitmap, bit) != 0) return -1;
    g_gdt[g].bg_free_inodes_count++;
    g_sb.s_free_inodes_count++;
    if (write_gdt() != 0) return -1;
    return write_superblock();
}

void ext2_pwd(int cwd) {
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

void ext2_ls(int node) {
    if (!g_ready) return;
    if (node < 0 || (uint32_t)node >= g_node_count) return;
    struct ext2_node *n = g_nodes[node];
    if (!n) return;
    if (!n->is_dir) {
        log_printf("%s\n", n->name);
        return;
    }
    if (!n->scanned) scan_dir((uint32_t)node, n->inode);
    for (uint32_t i = 0; i < g_node_count; ++i) {
        if (!g_nodes[i]) continue;
        if (g_nodes[i]->parent == (uint32_t)node) {
            log_printf("%s%s ", g_nodes[i]->name, g_nodes[i]->is_dir ? "/" : "");
        }
    }
    log_printf("\n");
}
