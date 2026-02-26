#include "sys/journal.h"

#include <stddef.h>
#include <stdint.h>

#include "kernel/heap.h"
#include "lib/compat.h"
#include "lib/strutil.h"
#include "lib/log.h"
#include "lib/crc32.h"
#include "sys/vfs.h"

enum {
    JOURNAL_MAGIC = 0xB17A4E01u,
    JOURNAL_TYPE_WRITE = 1,
    JOURNAL_TYPE_TRUNC = 2
};

struct journal_header {
    uint32_t magic;
    uint32_t type;
    uint32_t path_len;
    uint32_t data_len;
    uint64_t offset_or_size;
    uint32_t crc;
} __attribute__((packed));

static int g_enabled = 0;
static int g_journal_node = -1;

static int ensure_journal_file(void) {
    g_journal_node = vfs_resolve(0, "/.journal");
    if (g_journal_node < 0) {
        g_journal_node = vfs_create(0, "/.journal", 0);
    }
    return g_journal_node;
}

int journal_enabled(void) {
    return g_enabled && g_journal_node >= 0;
}

int journal_can_log(int node) {
    return journal_enabled() && node != g_journal_node;
}

static int skip_if_journal_node(int node) {
    return journal_enabled() && node == g_journal_node;
}

static int append_record(uint32_t type, int node, uint64_t offs, const uint8_t *data, uint32_t len) {
    if (!journal_enabled() || skip_if_journal_node(node)) return 0;

    char path[256];
    if (vfs_build_path(node, path, sizeof(path)) != 0) return -1;
    uint32_t path_len = (uint32_t)str_len(path);
    if (path_len == 0 || path_len + len + sizeof(struct journal_header) > 4096) return -1;

    size_t total = sizeof(struct journal_header) + path_len + len;
    uint8_t *buf = (uint8_t *)kmalloc(total);
    if (!buf) return -1;

    struct journal_header *hdr = (struct journal_header *)buf;
    hdr->magic = JOURNAL_MAGIC;
    hdr->type = type;
    hdr->path_len = path_len;
    hdr->data_len = len;
    hdr->offset_or_size = offs;
    hdr->crc = 0;
    uint8_t *p = buf + sizeof(*hdr);
    for (uint32_t i = 0; i < path_len; ++i) p[i] = (uint8_t)path[i];
    if (len > 0 && data) {
        uint8_t *d = p + path_len;
        for (uint32_t i = 0; i < len; ++i) d[i] = data[i];
    }
    hdr->crc = crc32(buf + offsetof(struct journal_header, type),
                     total - offsetof(struct journal_header, type));

    int rc = vfs_write_file(g_journal_node, buf, (uint64_t)total, vfs_get_size(g_journal_node));
    kfree(buf);
    return rc < 0 ? -1 : 0;
}

int journal_log_write(int vfs_node, uint64_t offset, const uint8_t *data, uint32_t len) {
    return append_record(JOURNAL_TYPE_WRITE, vfs_node, offset, data, len);
}

int journal_log_truncate(int vfs_node, uint64_t new_size) {
    return append_record(JOURNAL_TYPE_TRUNC, vfs_node, new_size, NULL, 0);
}

void journal_clear(void) {
    if (!journal_enabled()) return;
    (void)vfs_truncate(g_journal_node, 0);
}

static void replay_entry(const struct journal_header *hdr, const char *path, const uint8_t *payload) {
    if (!hdr || !path) return;
    int node = vfs_resolve(0, path);
    if (node < 0) return;
    if (hdr->type == JOURNAL_TYPE_WRITE) {
        (void)vfs_write_file(node, payload, hdr->data_len, hdr->offset_or_size);
    } else if (hdr->type == JOURNAL_TYPE_TRUNC) {
        (void)vfs_truncate(node, hdr->offset_or_size);
    }
}

void journal_replay(void) {
    if (!journal_enabled()) return;
    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!vfs_read_file(g_journal_node, &data, &size) || !data || size < sizeof(struct journal_header)) {
        return;
    }
    uint64_t off = 0;
    while (off + sizeof(struct journal_header) <= size) {
        const struct journal_header *hdr = (const struct journal_header *)(data + off);
        if (hdr->magic != JOURNAL_MAGIC) break;
        uint64_t rec_len = sizeof(*hdr) + hdr->path_len + hdr->data_len;
        if (rec_len == 0 || off + rec_len > size) break;
        uint32_t crc = crc32((const uint8_t *)hdr + offsetof(struct journal_header, type),
                             rec_len - offsetof(struct journal_header, type));
        if (crc == hdr->crc) {
            const char *path = (const char *)(data + off + sizeof(*hdr));
            const uint8_t *payload = (const uint8_t *)(data + off + sizeof(*hdr) + hdr->path_len);
            replay_entry(hdr, path, payload);
        }
        off += rec_len;
    }
    journal_clear();
}

void journal_init(void) {
    g_enabled = 0;
    g_journal_node = -1;
    /* Only ext2 root currently supported. */
    if (vfs_root_backend() != VFS_BACKEND_EXT2) {
        return;
    }
    if (ensure_journal_file() < 0) {
        log_printf("journal: failed to create log file\n");
        return;
    }
    g_enabled = 1;
    journal_replay();
}
