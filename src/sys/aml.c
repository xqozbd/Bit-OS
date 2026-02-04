#include "sys/aml.h"

#include <stddef.h>
#include <stdint.h>

#include "kernel/heap.h"
#include "lib/log.h"

enum {
    AML_MAX_NAMES = 512,
    AML_MAX_METHODS = 256,
    AML_MAX_PATH = 128
};

struct aml_name_obj {
    char *path;
    const uint8_t *obj;
    uint32_t obj_len;
};

struct aml_method_obj {
    char *path;
    const uint8_t *body;
    uint32_t body_len;
};

static const uint8_t *g_aml = NULL;
static uint32_t g_aml_len = 0;
static struct aml_name_obj g_names[AML_MAX_NAMES];
static struct aml_method_obj g_methods[AML_MAX_METHODS];
static uint32_t g_name_count = 0;
static uint32_t g_method_count = 0;

static int is_nameseg_char(char c) {
    return (c >= 'A' && c <= 'Z') || (c == '_') || (c >= '0' && c <= '9');
}

static int append_seg(char *dst, size_t dstsz, const char seg[5]) {
    size_t len = 0;
    while (dst[len]) len++;
    if (len + 1 + 4 + 1 >= dstsz) return 0;
    if (len > 1) dst[len++] = '.';
    for (int i = 0; i < 4; ++i) dst[len++] = seg[i];
    dst[len] = '\0';
    return 1;
}

static void strip_one_segment(char *path) {
    size_t len = 0;
    while (path[len]) len++;
    if (len <= 1) return;
    for (size_t i = len; i-- > 1;) {
        if (path[i] == '.') {
            path[i] = '\0';
            return;
        }
    }
    path[1] = '\0';
}

static int parse_nameseg(const uint8_t *p, char out[5]) {
    for (int i = 0; i < 4; ++i) {
        char c = (char)p[i];
        if (!is_nameseg_char(c)) return 0;
        out[i] = c;
    }
    out[4] = '\0';
    return 1;
}

static int aml_read_pkg_length(const uint8_t *p, uint32_t *out_len, uint32_t *out_consumed) {
    if (!p || !out_len || !out_consumed) return 0;
    uint8_t lead = p[0];
    uint8_t byte_count = (uint8_t)((lead >> 6) & 0x3);
    uint32_t len = (uint32_t)(lead & 0x0F);
    for (uint8_t i = 0; i < byte_count; ++i) {
        len |= (uint32_t)p[1 + i] << (4 + 8 * i);
    }
    *out_len = len;
    *out_consumed = (uint32_t)(1 + byte_count);
    return 1;
}

static int aml_parse_namepath(const uint8_t *p, uint32_t len, const char *cur_scope,
                              char *out, size_t outsz, uint32_t *consumed) {
    if (!p || !out || !consumed || outsz < 2) return 0;
    out[0] = '\\';
    out[1] = '\0';

    uint32_t off = 0;
    int absolute = 0;
    if (off < len && p[off] == '\\') { absolute = 1; off++; }
    while (off < len && p[off] == '^') {
        off++;
        if (!absolute && cur_scope) {
            char tmp[AML_MAX_PATH];
            tmp[0] = '\0';
            for (size_t i = 0; i < AML_MAX_PATH - 1 && cur_scope[i]; ++i) tmp[i] = cur_scope[i], tmp[i + 1] = '\0';
            strip_one_segment(tmp);
            for (size_t i = 0; i < outsz - 1 && tmp[i]; ++i) out[i] = tmp[i], out[i + 1] = '\0';
        }
    }
    if (!absolute && out[1] == '\0' && cur_scope) {
        for (size_t i = 0; i < outsz - 1 && cur_scope[i]; ++i) out[i] = cur_scope[i], out[i + 1] = '\0';
    }

    if (off >= len) { *consumed = off; return 1; }
    if (p[off] == 0x00) { *consumed = off + 1; return 1; } /* NullName */

    if (p[off] == 0x2E) { /* DualNamePrefix */
        off++;
        char seg[5];
        if (!parse_nameseg(&p[off], seg)) return 0;
        if (!append_seg(out, outsz, seg)) return 0;
        off += 4;
        if (!parse_nameseg(&p[off], seg)) return 0;
        if (!append_seg(out, outsz, seg)) return 0;
        off += 4;
        *consumed = off;
        return 1;
    }
    if (p[off] == 0x2F) { /* MultiNamePrefix */
        off++;
        if (off >= len) return 0;
        uint8_t count = p[off++];
        for (uint8_t i = 0; i < count; ++i) {
            char seg[5];
            if (off + 4 > len || !parse_nameseg(&p[off], seg)) return 0;
            if (!append_seg(out, outsz, seg)) return 0;
            off += 4;
        }
        *consumed = off;
        return 1;
    }
    /* Single NameSeg */
    char seg[5];
    if (!parse_nameseg(&p[off], seg)) return 0;
    if (!append_seg(out, outsz, seg)) return 0;
    off += 4;
    *consumed = off;
    return 1;
}

static char *dup_path(const char *path) {
    if (!path) return NULL;
    size_t len = 0;
    while (path[len]) len++;
    char *p = (char *)kmalloc(len + 1);
    if (!p) return NULL;
    for (size_t i = 0; i <= len; ++i) p[i] = path[i];
    return p;
}

static void add_name(const char *path, const uint8_t *obj, uint32_t obj_len) {
    if (g_name_count >= AML_MAX_NAMES) return;
    g_names[g_name_count].path = dup_path(path);
    g_names[g_name_count].obj = obj;
    g_names[g_name_count].obj_len = obj_len;
    g_name_count++;
}

static void add_method(const char *path, const uint8_t *body, uint32_t body_len) {
    if (g_method_count >= AML_MAX_METHODS) return;
    g_methods[g_method_count].path = dup_path(path);
    g_methods[g_method_count].body = body;
    g_methods[g_method_count].body_len = body_len;
    g_method_count++;
}

static uint32_t parse_block(const uint8_t *p, uint32_t len, const char *scope);

static uint32_t parse_named_block(const uint8_t *p, uint32_t len, const char *scope, uint32_t name_off, uint32_t body_off) {
    char path[AML_MAX_PATH];
    uint32_t name_len = 0;
    if (!aml_parse_namepath(&p[name_off], len - name_off, scope, path, sizeof(path), &name_len)) return 0;
    uint32_t body = body_off + name_len;
    if (body > len) return 0;
    parse_block(&p[body], len - body, path);
    return body;
}

static uint32_t parse_block(const uint8_t *p, uint32_t len, const char *scope) {
    uint32_t off = 0;
    while (off < len) {
        uint8_t op = p[off];
        if (op == 0x08) { /* NameOp */
            char path[AML_MAX_PATH];
            uint32_t name_len = 0;
            if (!aml_parse_namepath(&p[off + 1], len - off - 1, scope, path, sizeof(path), &name_len)) return len;
            uint32_t obj = off + 1 + name_len;
            add_name(path, &p[obj], len - obj);
            off = obj + 1;
            continue;
        }
        if (op == 0x14) { /* MethodOp */
            uint32_t pkg_len = 0, pkg_consumed = 0;
            if (!aml_read_pkg_length(&p[off + 1], &pkg_len, &pkg_consumed)) return len;
            char path[AML_MAX_PATH];
            uint32_t name_len = 0;
            uint32_t name_off = off + 1 + pkg_consumed;
            if (!aml_parse_namepath(&p[name_off], len - name_off, scope, path, sizeof(path), &name_len)) return len;
            uint32_t flags_off = name_off + name_len;
            uint32_t body = flags_off + 1;
            uint32_t body_len = 0;
            if (pkg_len > (pkg_consumed + name_len + 1)) {
                body_len = pkg_len - (pkg_consumed + name_len + 1);
            }
            add_method(path, &p[body], body_len);
            off = off + 1 + pkg_consumed + pkg_len;
            continue;
        }
        if (op == 0x10) { /* ScopeOp */
            uint32_t pkg_len = 0, pkg_consumed = 0;
            if (!aml_read_pkg_length(&p[off + 1], &pkg_len, &pkg_consumed)) return len;
            uint32_t name_off = off + 1 + pkg_consumed;
            parse_named_block(p, off + 1 + pkg_consumed + pkg_len, scope, name_off, name_off);
            off = off + 1 + pkg_consumed + pkg_len;
            continue;
        }
        if (op == 0x5B && off + 1 < len && p[off + 1] == 0x82) { /* DeviceOp */
            uint32_t pkg_len = 0, pkg_consumed = 0;
            if (!aml_read_pkg_length(&p[off + 2], &pkg_len, &pkg_consumed)) return len;
            uint32_t name_off = off + 2 + pkg_consumed;
            parse_named_block(p, off + 2 + pkg_consumed + pkg_len, scope, name_off, name_off);
            off = off + 2 + pkg_consumed + pkg_len;
            continue;
        }
        if (op == 0x5B && off + 1 < len && p[off + 1] == 0x83) { /* ProcessorOp */
            uint32_t pkg_len = 0, pkg_consumed = 0;
            if (!aml_read_pkg_length(&p[off + 2], &pkg_len, &pkg_consumed)) return len;
            uint32_t name_off = off + 2 + pkg_consumed;
            char path[AML_MAX_PATH];
            uint32_t name_len = 0;
            if (!aml_parse_namepath(&p[name_off], len - name_off, scope, path, sizeof(path), &name_len)) return len;
            uint32_t body = name_off + name_len + 6;
            parse_block(&p[body], len - body, path);
            off = off + 2 + pkg_consumed + pkg_len;
            continue;
        }
        if (op == 0x5B && off + 1 < len && p[off + 1] == 0x84) { /* PowerResOp */
            uint32_t pkg_len = 0, pkg_consumed = 0;
            if (!aml_read_pkg_length(&p[off + 2], &pkg_len, &pkg_consumed)) return len;
            uint32_t name_off = off + 2 + pkg_consumed;
            parse_named_block(p, off + 2 + pkg_consumed + pkg_len, scope, name_off, name_off);
            off = off + 2 + pkg_consumed + pkg_len;
            continue;
        }
        off++;
    }
    return off;
}

void aml_init(const uint8_t *aml, uint32_t len) {
    g_aml = aml;
    g_aml_len = len;
    g_name_count = 0;
    g_method_count = 0;
    if (!g_aml || g_aml_len == 0) return;
    parse_block(g_aml, g_aml_len, "\\");
    log_printf("AML: names=%u methods=%u\n", (unsigned)g_name_count, (unsigned)g_method_count);
}

const uint8_t *aml_find_name_object(const char *full_path, uint32_t *out_len) {
    if (out_len) *out_len = 0;
    if (!full_path) return NULL;
    for (uint32_t i = 0; i < g_name_count; ++i) {
        if (!g_names[i].path) continue;
        const char *a = g_names[i].path;
        const char *b = full_path;
        int eq = 1;
        for (; *a || *b; ++a, ++b) {
            if (*a != *b) { eq = 0; break; }
            if (!*a && !*b) break;
        }
        if (eq) {
            if (out_len) *out_len = g_names[i].obj_len;
            return g_names[i].obj;
        }
    }
    return NULL;
}

static const uint8_t *method_find(const char *full_path, uint32_t *out_len) {
    if (out_len) *out_len = 0;
    if (!full_path) return NULL;
    for (uint32_t i = 0; i < g_method_count; ++i) {
        if (!g_methods[i].path) continue;
        const char *a = g_methods[i].path;
        const char *b = full_path;
        int eq = 1;
        for (; *a || *b; ++a, ++b) {
            if (*a != *b) { eq = 0; break; }
            if (!*a && !*b) break;
        }
        if (eq) {
            if (out_len) *out_len = g_methods[i].body_len;
            return g_methods[i].body;
        }
    }
    return NULL;
}

const uint8_t *aml_eval_method_return(const char *full_path, uint32_t *out_len) {
    if (out_len) *out_len = 0;
    uint32_t body_len = 0;
    const uint8_t *body = method_find(full_path, &body_len);
    if (!body || body_len == 0) return NULL;
    for (uint32_t i = 0; i + 2 < body_len; ++i) {
        if (body[i] == 0xA4) { /* ReturnOp */
            const uint8_t *obj = &body[i + 1];
            if (out_len) *out_len = body_len - (i + 1);
            return obj;
        }
    }
    return NULL;
}

const uint8_t *aml_eval_method_return_suffix(const char *suffix, uint32_t *out_len) {
    if (out_len) *out_len = 0;
    if (!suffix) return NULL;
    size_t slen = 0;
    while (suffix[slen]) slen++;
    for (uint32_t i = 0; i < g_method_count; ++i) {
        const char *path = g_methods[i].path;
        if (!path) continue;
        size_t plen = 0;
        while (path[plen]) plen++;
        if (plen >= slen) {
            const char *tail = &path[plen - slen];
            int eq = 1;
            for (size_t j = 0; j < slen; ++j) {
                if (tail[j] != suffix[j]) { eq = 0; break; }
            }
            if (eq) {
                return aml_eval_method_return(path, out_len);
            }
        }
    }
    return NULL;
}
