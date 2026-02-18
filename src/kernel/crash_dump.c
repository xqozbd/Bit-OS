#include "kernel/crash_dump.h"

#include <stddef.h>
#include <stdint.h>

#include "lib/log.h"
#include "kernel/watchdog.h"
#include "sys/vfs.h"

#define CRASH_DUMP_MAGIC 0x43525348u /* 'CRSH' */
#define CRASH_DUMP_VERSION 1u
#define CRASH_DUMP_MAX (64 * 1024u)

struct crash_dump_header {
    uint32_t magic;
    uint16_t version;
    uint16_t reserved;
    uint32_t length;
    uint32_t reason;
};

struct crash_dump_store {
    struct crash_dump_header hdr;
    char data[CRASH_DUMP_MAX];
};

__attribute__((section(".noinit")))
static struct crash_dump_store g_crash_dump;

static void utoa_hex(uint64_t val, char *out, size_t out_len) {
    static const char hex[] = "0123456789abcdef";
    if (!out || out_len < 3) return;
    out[0] = '0';
    out[1] = 'x';
    size_t idx = 2;
    int started = 0;
    for (int i = 15; i >= 0 && idx + 1 < out_len; --i) {
        uint8_t nib = (val >> (i * 4)) & 0xF;
        if (!started && nib == 0 && i != 0) continue;
        started = 1;
        out[idx++] = hex[nib];
    }
    if (!started && idx + 1 < out_len) out[idx++] = '0';
    out[idx] = '\0';
}

static size_t append_str(char *dst, size_t cap, const char *s) {
    size_t n = 0;
    if (!dst || !s) return 0;
    while (n + 1 < cap && s[n]) {
        dst[n] = s[n];
        n++;
    }
    if (n < cap) dst[n] = '\0';
    return n;
}

static size_t append_line(char *dst, size_t cap, const char *label, uint64_t val) {
    if (!dst || cap == 0) return 0;
    size_t n = 0;
    if (label) n += append_str(dst + n, cap - n, label);
    char tmp[32];
    utoa_hex(val, tmp, sizeof(tmp));
    n += append_str(dst + n, cap - n, tmp);
    if (n + 2 < cap) {
        dst[n++] = '\n';
        dst[n] = '\0';
    }
    return n;
}

static void crash_dump_write_header(uint32_t reason, const char *msg) {
    g_crash_dump.hdr.magic = CRASH_DUMP_MAGIC;
    g_crash_dump.hdr.version = (uint16_t)CRASH_DUMP_VERSION;
    g_crash_dump.hdr.reserved = 0;
    g_crash_dump.hdr.reason = reason;

    size_t n = 0;
    n += append_str(g_crash_dump.data + n, CRASH_DUMP_MAX - n, "BitOS crash dump\n");
    n += append_line(g_crash_dump.data + n, CRASH_DUMP_MAX - n, "reason=", reason);
    const char *stage = watchdog_last_stage();
    if (stage && n + 1 < CRASH_DUMP_MAX) {
        n += append_str(g_crash_dump.data + n, CRASH_DUMP_MAX - n, "stage=");
        n += append_str(g_crash_dump.data + n, CRASH_DUMP_MAX - n, stage);
        if (n + 2 < CRASH_DUMP_MAX) {
            g_crash_dump.data[n++] = '\n';
            g_crash_dump.data[n] = '\0';
        }
    }
    if (msg && msg[0] && n + 1 < CRASH_DUMP_MAX) {
        n += append_str(g_crash_dump.data + n, CRASH_DUMP_MAX - n, "msg=");
        n += append_str(g_crash_dump.data + n, CRASH_DUMP_MAX - n, msg);
        if (n + 2 < CRASH_DUMP_MAX) {
            g_crash_dump.data[n++] = '\n';
            g_crash_dump.data[n] = '\0';
        }
    }
    if (n + 1 < CRASH_DUMP_MAX) {
        g_crash_dump.data[n++] = '\n';
        g_crash_dump.data[n] = '\0';
    }
    size_t remain = CRASH_DUMP_MAX - n;
    if (remain > 0) {
        size_t ring_len = log_ring_snapshot(g_crash_dump.data + n, remain - 1);
        n += ring_len;
        if (n < CRASH_DUMP_MAX) g_crash_dump.data[n] = '\0';
    }
    g_crash_dump.hdr.length = (uint32_t)n;
}

void crash_dump_capture(uint32_t code, const char *msg) {
    log_ring_freeze(1);
    crash_dump_write_header(code, msg);
}

void crash_dump_capture_exception(uint8_t vec, uint64_t err, int has_err) {
    uint32_t reason = 0x45584300u | (uint32_t)vec; /* 'EXC' + vec */
    char msg[64];
    msg[0] = '\0';
    if (has_err) {
        size_t n = 0;
        n += append_str(msg + n, sizeof(msg) - n, "err=");
        char tmp[32];
        utoa_hex(err, tmp, sizeof(tmp));
        append_str(msg + n, sizeof(msg) - n, tmp);
    }
    crash_dump_capture(reason, msg[0] ? msg : NULL);
}

static int crash_dump_write_path(const char *path) {
    if (!path || !path[0]) return -1;
    int node = vfs_resolve(0, path);
    if (node < 0) {
        node = vfs_create(0, path, 0);
        if (node < 0) return -1;
    }
    int rc = vfs_truncate(node, 0);
    if (rc != 0) return -1;
    return vfs_write_file(node, (const uint8_t *)&g_crash_dump, sizeof(g_crash_dump.hdr) + g_crash_dump.hdr.length, 0);
}

void crash_dump_flush_to_disk(void) {
    if (g_crash_dump.hdr.magic != CRASH_DUMP_MAGIC) return;
    if (g_crash_dump.hdr.length == 0) return;
    if (crash_dump_write_path("/crashdump.log") < 0) {
        (void)crash_dump_write_path("/var/log/crashdump.log");
    }
    g_crash_dump.hdr.magic = 0;
}
