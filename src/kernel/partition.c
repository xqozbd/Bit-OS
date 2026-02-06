#include "kernel/partition.h"

#include "lib/compat.h"
#include "kernel/block.h"
#include "kernel/heap.h"
#include "lib/log.h"

extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);
extern void *memset(void *s, int c, size_t n);

#define MAX_PARTITIONS 64

static struct partition_info g_parts[MAX_PARTITIONS];
static size_t g_part_count = 0;

struct mbr_entry {
    uint8_t status;
    uint8_t chs_first[3];
    uint8_t type;
    uint8_t chs_last[3];
    uint32_t lba_first;
    uint32_t sectors;
} __attribute__((packed));

struct gpt_header {
    uint8_t signature[8];
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_crc32;
    uint32_t reserved;
    uint64_t current_lba;
    uint64_t backup_lba;
    uint64_t first_usable_lba;
    uint64_t last_usable_lba;
    uint8_t disk_guid[16];
    uint64_t part_entry_lba;
    uint32_t part_entry_count;
    uint32_t part_entry_size;
    uint32_t part_entry_crc32;
} __attribute__((packed));

struct gpt_entry {
    uint8_t type_guid[16];
    uint8_t unique_guid[16];
    uint64_t first_lba;
    uint64_t last_lba;
    uint64_t attrs;
    uint16_t name[36];
} __attribute__((packed));

static void add_partition(enum partition_scheme scheme, uint32_t dev_idx, uint32_t part_idx,
                          uint64_t first_lba, uint64_t last_lba, uint32_t type, const char *name) {
    if (g_part_count >= MAX_PARTITIONS) return;
    struct partition_info *p = &g_parts[g_part_count++];
    p->scheme = scheme;
    p->device_index = dev_idx;
    p->part_index = part_idx;
    p->first_lba = first_lba;
    p->last_lba = last_lba;
    p->lba_count = (last_lba >= first_lba) ? (last_lba - first_lba + 1) : 0;
    p->type = type;
    memset(p->name, 0, sizeof(p->name));
    if (name) {
        size_t i = 0;
        for (; i + 1 < sizeof(p->name) && name[i]; ++i) {
            p->name[i] = name[i];
        }
        p->name[i] = '\0';
    }
}

static int is_gpt_signature(const uint8_t sig[8]) {
    return sig[0] == 'E' && sig[1] == 'F' && sig[2] == 'I' && sig[3] == ' ' &&
           sig[4] == 'P' && sig[5] == 'A' && sig[6] == 'R' && sig[7] == 'T';
}

static void parse_mbr(const uint8_t *buf, uint32_t dev_idx) {
    const struct mbr_entry *ents = (const struct mbr_entry *)(buf + 446);
    for (uint32_t i = 0; i < 4; ++i) {
        const struct mbr_entry *e = &ents[i];
        if (e->type == 0 || e->sectors == 0) continue;
        uint64_t first = e->lba_first;
        uint64_t last = (uint64_t)e->lba_first + (uint64_t)e->sectors - 1;
        add_partition(PART_SCHEME_MBR, dev_idx, i, first, last, e->type, "mbr");
    }
}

static void parse_gpt(const struct block_device *dev, uint32_t dev_idx) {
    uint8_t sector[BLOCK_CACHE_MAX_SECTOR_SIZE];
    if (block_read_cached(dev, 1, 1, sector) != 0) return;
    const struct gpt_header *hdr = (const struct gpt_header *)sector;
    if (!is_gpt_signature(hdr->signature)) return;
    if (hdr->part_entry_size < sizeof(struct gpt_entry)) return;

    uint64_t entry_lba = hdr->part_entry_lba;
    uint32_t entry_count = hdr->part_entry_count;
    uint32_t entry_size = hdr->part_entry_size;
    uint64_t total_bytes = (uint64_t)entry_count * (uint64_t)entry_size;
    if (total_bytes == 0) return;

    uint64_t sector_size = dev->sector_size;
    uint64_t sectors = (total_bytes + sector_size - 1) / sector_size;
    if (sectors > 1024) return;

    uint8_t *entries = (uint8_t *)kmalloc((size_t)(sectors * sector_size));
    if (!entries) return;
    if (block_read_cached(dev, entry_lba, (uint32_t)sectors, entries) != 0) {
        kfree(entries);
        return;
    }

    for (uint32_t i = 0; i < entry_count && g_part_count < MAX_PARTITIONS; ++i) {
        const uint8_t *ent_base = entries + (uint64_t)i * entry_size;
        const struct gpt_entry *ent = (const struct gpt_entry *)ent_base;
        if (ent->first_lba == 0 && ent->last_lba == 0) continue;
        char name[36];
        memset(name, 0, sizeof(name));
        for (uint32_t n = 0; n < 35; ++n) {
            uint16_t ch = ent->name[n];
            if (ch == 0) break;
            name[n] = (ch < 0x80) ? (char)ch : '?';
        }
        add_partition(PART_SCHEME_GPT, dev_idx, i, ent->first_lba, ent->last_lba, 0, name);
    }

    kfree(entries);
}

void partition_init(void) {
    memset(g_parts, 0, sizeof(g_parts));
    g_part_count = 0;

    size_t dev_count = block_device_count();
    for (uint32_t d = 0; d < dev_count; ++d) {
        const struct block_device *dev = block_get(d);
        if (!dev) continue;
        if (dev->sector_size < 512 || dev->sector_size > BLOCK_CACHE_MAX_SECTOR_SIZE) continue;
        uint8_t sector[BLOCK_CACHE_MAX_SECTOR_SIZE];
        if (block_read_cached(dev, 0, 1, sector) != 0) continue;
        uint16_t sig = (uint16_t)sector[510] | ((uint16_t)sector[511] << 8);
        if (sig != 0xAA55) continue;

        const struct mbr_entry *ents = (const struct mbr_entry *)(sector + 446);
        int has_gpt = 0;
        for (uint32_t i = 0; i < 4; ++i) {
            if (ents[i].type == 0xEE) {
                has_gpt = 1;
                break;
            }
        }
        if (has_gpt) {
            parse_gpt(dev, d);
        } else {
            parse_mbr(sector, d);
        }
    }

    if (g_part_count == 0) {
        log_printf("Boot: no partitions found\n");
    } else {
        log_printf("Boot: partitions=%u\n", (unsigned)g_part_count);
        for (size_t i = 0; i < g_part_count; ++i) {
            const struct partition_info *p = &g_parts[i];
            const char *scheme = p->scheme == PART_SCHEME_GPT ? "gpt" : "mbr";
            log_printf("  %s%u: dev=%u lba=%llu..%llu (%llu)\n",
                       scheme, (unsigned)p->part_index, (unsigned)p->device_index,
                       (unsigned long long)p->first_lba,
                       (unsigned long long)p->last_lba,
                       (unsigned long long)p->lba_count);
        }
    }
}

size_t partition_count(void) {
    return g_part_count;
}

const struct partition_info *partition_get(size_t index) {
    if (index >= g_part_count) return NULL;
    return &g_parts[index];
}
