#include "kernel/sandbox.h"

#include <stddef.h>
#include <stdint.h>

#include "kernel/heap.h"
#include "kernel/task.h"
#include "lib/log.h"
#include "sys/fcntl.h"
#include "sys/mman.h"
#include "sys/syscall.h"
#include "sys/vfs.h"

void *memset(void *s, int c, size_t n);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);

static int streq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int starts_with(const char *s, const char *prefix) {
    if (!s || !prefix) return 0;
    while (*prefix) {
        if (*s != *prefix) return 0;
        s++;
        prefix++;
    }
    return 1;
}

static int path_prefix(const char *path, const char *prefix) {
    if (!path || !prefix || !prefix[0]) return 0;
    while (*path && *prefix) {
        if (*path != *prefix) return 0;
        path++;
        prefix++;
    }
    if (*prefix != '\0') return 0;
    return *path == '\0' || *path == '/';
}

static uint32_t str_len(const char *s) {
    uint32_t n = 0;
    while (s && s[n]) n++;
    return n;
}

static void str_copy(char *dst, uint32_t cap, const char *src) {
    uint32_t i = 0;
    if (!dst || cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    while (src[i] && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
}

static void append(char *dst, uint32_t cap, const char *src) {
    uint32_t d = str_len(dst);
    uint32_t i = 0;
    if (!dst || !src || d >= cap) return;
    while (src[i] && d + 1 < cap) {
        dst[d++] = src[i++];
    }
    dst[d] = '\0';
}

static void append_u32(char *dst, uint32_t cap, uint32_t v) {
    char tmp[12];
    uint32_t n = 0;
    if (v == 0) {
        append(dst, cap, "0");
        return;
    }
    while (v && n < sizeof(tmp)) {
        tmp[n++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (n > 0) {
        char c[2];
        c[0] = tmp[--n];
        c[1] = '\0';
        append(dst, cap, c);
    }
}

static void trim(char *s) {
    uint32_t start = 0;
    uint32_t end;
    uint32_t i;
    if (!s) return;
    while (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') start++;
    if (start) {
        for (i = 0; s[start + i]; ++i) s[i] = s[start + i];
        s[i] = '\0';
    }
    end = str_len(s);
    while (end > 0 && (s[end - 1] == ' ' || s[end - 1] == '\t' ||
                       s[end - 1] == '\r' || s[end - 1] == '\n')) {
        s[--end] = '\0';
    }
}

static void basename_of(const char *path, char *out, uint32_t cap) {
    const char *base = path;
    if (!path) {
        str_copy(out, cap, "unknown");
        return;
    }
    for (const char *p = path; *p; ++p) {
        if (*p == '/') base = p + 1;
    }
    str_copy(out, cap, base);
}

static void add_rule(char rules[SANDBOX_MAX_PATH_RULES][SANDBOX_PATH_LEN],
                     uint8_t *count, const char *path) {
    if (!rules || !count || !path || !path[0]) return;
    if (*count >= SANDBOX_MAX_PATH_RULES) return;
    str_copy(rules[*count], SANDBOX_PATH_LEN, path);
    (*count)++;
}

static int read_profile_file(const char *path, const uint8_t **data, uint64_t *size) {
    int node = vfs_resolve(0, path);
    if (node < 0) return 0;
    if (!vfs_read_file(node, data, size)) return 0;
    return *data && *size > 0;
}

static void parse_caps(struct task *t, char *value) {
    char tok[24];
    uint32_t ti = 0;
    if (!t || !value) return;
    t->sandbox_caps = 0;
    for (uint32_t i = 0;; ++i) {
        char c = value[i];
        if (c == ',' || c == ' ' || c == '\t' || c == '\0') {
            tok[ti] = '\0';
            trim(tok);
            if (streq(tok, "net")) t->sandbox_caps |= SANDBOX_CAP_NET;
            else if (streq(tok, "fs")) t->sandbox_caps |= SANDBOX_CAP_FS;
            else if (streq(tok, "input")) t->sandbox_caps |= SANDBOX_CAP_INPUT;
            else if (streq(tok, "audio")) t->sandbox_caps |= SANDBOX_CAP_AUDIO;
            else if (streq(tok, "broker")) t->sandbox_caps |= SANDBOX_CAP_BROKER;
            ti = 0;
            if (c == '\0') break;
        } else if (ti + 1 < sizeof(tok)) {
            tok[ti++] = c;
        }
    }
}

static void parse_class(struct task *t, const char *value) {
    if (!t || !value) return;
    if (streq(value, "desktop")) t->sandbox_class = SANDBOX_CLASS_DESKTOP;
    else if (streq(value, "utility")) t->sandbox_class = SANDBOX_CLASS_UTILITY;
    else if (streq(value, "broker")) t->sandbox_class = SANDBOX_CLASS_BROKER;
    else if (streq(value, "compositor")) t->sandbox_class = SANDBOX_CLASS_COMPOSITOR;
    else t->sandbox_class = SANDBOX_CLASS_SYSTEM;
}

static void ensure_temp_root(struct task *t) {
    char pid[16];
    if (!t) return;
    if (vfs_resolve(0, "/tmp/app") < 0) (void)vfs_create(0, "/tmp/app", 1);
    t->sandbox_temp_root[0] = '\0';
    append(t->sandbox_temp_root, SANDBOX_PATH_LEN, "/tmp/app/");
    pid[0] = '\0';
    append_u32(pid, sizeof(pid), t->pid);
    append(t->sandbox_temp_root, SANDBOX_PATH_LEN, pid);
    if (vfs_resolve(0, t->sandbox_temp_root) < 0) {
        (void)vfs_create(0, t->sandbox_temp_root, 1);
    }
}

void sandbox_task_init(struct task *t) {
    if (!t) return;
    t->sandbox_flags = 0;
    t->sandbox_caps = SANDBOX_CAP_NET | SANDBOX_CAP_FS | SANDBOX_CAP_INPUT | SANDBOX_CAP_AUDIO;
    t->sandbox_class = SANDBOX_CLASS_SYSTEM;
    t->sandbox_loaded = 0;
    t->sandbox_need_consent = 0;
    t->sandbox_broker = 0;
    t->sandbox_reserved = 0;
    t->sandbox_profile[0] = '\0';
    t->sandbox_temp_root[0] = '\0';
    t->sandbox_allow_count = 0;
    t->sandbox_deny_count = 0;
    for (uint32_t i = 0; i < SANDBOX_MAX_PATH_RULES; ++i) {
        t->sandbox_allow[i][0] = '\0';
        t->sandbox_deny[i][0] = '\0';
    }
}

void sandbox_task_clone(struct task *dst, const struct task *src) {
    if (!dst || !src) return;
    dst->sandbox_flags = src->sandbox_flags;
    dst->sandbox_caps = src->sandbox_caps;
    dst->sandbox_class = src->sandbox_class;
    dst->sandbox_loaded = src->sandbox_loaded;
    dst->sandbox_need_consent = src->sandbox_need_consent;
    dst->sandbox_broker = src->sandbox_broker;
    str_copy(dst->sandbox_profile, sizeof(dst->sandbox_profile), src->sandbox_profile);
    str_copy(dst->sandbox_temp_root, sizeof(dst->sandbox_temp_root), src->sandbox_temp_root);
    dst->sandbox_allow_count = src->sandbox_allow_count;
    dst->sandbox_deny_count = src->sandbox_deny_count;
    for (uint32_t i = 0; i < SANDBOX_MAX_PATH_RULES; ++i) {
        str_copy(dst->sandbox_allow[i], SANDBOX_PATH_LEN, src->sandbox_allow[i]);
        str_copy(dst->sandbox_deny[i], SANDBOX_PATH_LEN, src->sandbox_deny[i]);
    }
}

void sandbox_enable_legacy(struct task *t, uint32_t flags) {
    if (!t) return;
    t->sandbox_flags |= (flags & SANDBOX_ALL);
    t->sandbox_loaded = 1;
    t->sandbox_class = SANDBOX_CLASS_UTILITY;
    if (flags & SANDBOX_NET) t->sandbox_caps &= ~SANDBOX_CAP_NET;
    if (flags & SANDBOX_DEV) t->sandbox_caps &= ~(SANDBOX_CAP_INPUT | SANDBOX_CAP_AUDIO);
    if (flags & SANDBOX_FS_WRITE) {
        add_rule(t->sandbox_allow, &t->sandbox_allow_count, "/tmp");
    }
    ensure_temp_root(t);
}

static void parse_profile(struct task *t, const uint8_t *data, uint64_t size) {
    char line[160];
    uint32_t pos = 0;
    if (!t || !data) return;
    for (uint64_t i = 0; i <= size; ++i) {
        char c = (i < size) ? (char)data[i] : '\n';
        if (c == '\n' || c == '\0') {
            line[pos] = '\0';
            pos = 0;
            trim(line);
            if (line[0] == '\0' || line[0] == '#') continue;
            char *eq = NULL;
            for (uint32_t j = 0; line[j]; ++j) {
                if (line[j] == '=') {
                    eq = &line[j];
                    break;
                }
            }
            if (!eq) continue;
            *eq = '\0';
            char *key = line;
            char *value = eq + 1;
            trim(key);
            trim(value);
            if (streq(key, "caps")) parse_caps(t, value);
            else if (streq(key, "class")) parse_class(t, value);
            else if (streq(key, "allow")) add_rule(t->sandbox_allow, &t->sandbox_allow_count, value);
            else if (streq(key, "deny")) add_rule(t->sandbox_deny, &t->sandbox_deny_count, value);
            else if (streq(key, "consent")) t->sandbox_need_consent = streq(value, "prompt") ? 1u : 0u;
            continue;
        }
        if (pos + 1 < sizeof(line)) line[pos++] = c;
    }
}

int sandbox_load_for_exec(struct task *t, const char *exec_path) {
    char base[32];
    char profile_path[80];
    const uint8_t *data = NULL;
    uint64_t size = 0;
    if (!t || !exec_path) return -1;
    sandbox_task_init(t);
    basename_of(exec_path, base, sizeof(base));
    profile_path[0] = '\0';
    append(profile_path, sizeof(profile_path), "/etc/sandbox/");
    append(profile_path, sizeof(profile_path), base);
    append(profile_path, sizeof(profile_path), ".profile");
    if (!read_profile_file(profile_path, &data, &size)) {
        if (!starts_with(exec_path, "/bin/")) return 0;
        if (!read_profile_file("/etc/sandbox/default.profile", &data, &size)) return 0;
        str_copy(t->sandbox_profile, sizeof(t->sandbox_profile), "default");
    } else {
        str_copy(t->sandbox_profile, sizeof(t->sandbox_profile), base);
    }
    t->sandbox_loaded = 1;
    t->sandbox_caps = 0;
    t->sandbox_class = SANDBOX_CLASS_DESKTOP;
    parse_profile(t, data, size);
    if ((t->sandbox_caps & SANDBOX_CAP_NET) == 0) t->sandbox_flags |= SANDBOX_NET;
    if ((t->sandbox_caps & SANDBOX_CAP_FS) == 0) t->sandbox_flags |= SANDBOX_FS_WRITE;
    if (t->sandbox_class == SANDBOX_CLASS_BROKER || (t->sandbox_caps & SANDBOX_CAP_BROKER)) {
        t->sandbox_broker = 1;
    }
    ensure_temp_root(t);
    log_printf("sandbox: pid=%u exec=%s profile=%s class=%u caps=0x%x temp=%s\n",
               (unsigned)t->pid, exec_path, t->sandbox_profile,
               (unsigned)t->sandbox_class, (unsigned)t->sandbox_caps,
               t->sandbox_temp_root);
    return 0;
}

int sandbox_check_exec_isolation(struct task *t, uint64_t old_pml4, uint64_t new_pml4) {
    if (!t || !t->is_user) return 1;
    if (new_pml4 == 0 || new_pml4 == old_pml4) {
        sandbox_audit_deny(t, "exec", t->name ? t->name : "(unknown)", "page-table-isolation");
        return 0;
    }
    return 1;
}

int sandbox_check_wx(struct task *t, const char *op, uint32_t prot) {
    if ((prot & (PROT_WRITE | PROT_EXEC)) == (PROT_WRITE | PROT_EXEC)) {
        sandbox_audit_deny(t, op ? op : "mmap", "memory", "wx-mapping");
        return 0;
    }
    return 1;
}

int sandbox_check_path(struct task *t, const char *op, const char *path, uint32_t access) {
    int writing = (access & SANDBOX_ACCESS_WRITE) != 0;
    if (!t || !path) return 1;
    if (t->sandbox_flags & SANDBOX_DEV) {
        if (path_prefix(path, "/dev") && !streq(path, "/dev/null")) {
            sandbox_audit_deny(t, op, path, "device-denied");
            return 0;
        }
    }
    if (path_prefix(path, "/dev/input") && (t->sandbox_caps & SANDBOX_CAP_INPUT) == 0) {
        sandbox_audit_deny(t, op, path, "input-capability");
        return 0;
    }
    if (path_prefix(path, "/dev/audio") && (t->sandbox_caps & SANDBOX_CAP_AUDIO) == 0) {
        sandbox_audit_deny(t, op, path, "audio-capability");
        return 0;
    }
    for (uint32_t i = 0; i < t->sandbox_deny_count; ++i) {
        if (path_prefix(path, t->sandbox_deny[i])) {
            sandbox_audit_deny(t, op, path, "path-deny");
            return 0;
        }
    }
    if (!writing) return 1;
    if ((t->sandbox_caps & SANDBOX_CAP_FS) == 0) {
        sandbox_audit_deny(t, op, path, "fs-capability");
        return 0;
    }
    if (t->sandbox_temp_root[0] && path_prefix(path, t->sandbox_temp_root)) return 1;
    if ((t->sandbox_flags & SANDBOX_FS_WRITE) == 0 && !t->sandbox_loaded) return 1;
    for (uint32_t i = 0; i < t->sandbox_allow_count; ++i) {
        if (path_prefix(path, t->sandbox_allow[i])) return 1;
    }
    if (path_prefix(path, "/tmp") && !t->sandbox_loaded) return 1;
    sandbox_audit_deny(t, op, path, "path-write-not-allowed");
    return 0;
}

int sandbox_check_syscall(struct task *t, uint64_t num) {
    if (!t || !t->is_user) return 1;
    if (!t->sandbox_loaded && t->sandbox_flags == 0) return 1;
    if (num == SYS_MOUNT || num == SYS_UMOUNT) {
        if ((t->sandbox_flags & SANDBOX_MOUNT) || t->sandbox_class != SANDBOX_CLASS_SYSTEM) {
            sandbox_audit_deny(t, "syscall", "mount", "syscall-filter");
            return 0;
        }
    }
    if (num == SYS_POWEROFF || num == SYS_REBOOT || num == SYS_HID_KBD_REPORT) {
        if (t->sandbox_class != SANDBOX_CLASS_SYSTEM && t->sandbox_class != SANDBOX_CLASS_BROKER) {
            sandbox_audit_deny(t, "syscall", "privileged", "syscall-filter");
            return 0;
        }
    }
    if ((num == SYS_SETUID || num == SYS_SETGID || num == SYS_CHOWN || num == SYS_CHMOD) &&
        t->sandbox_class != SANDBOX_CLASS_SYSTEM && t->sandbox_class != SANDBOX_CLASS_BROKER) {
        sandbox_audit_deny(t, "syscall", "identity-or-mode", "syscall-filter");
        return 0;
    }
    return 1;
}

int sandbox_broker_call(struct task *t, struct sandbox_broker_request *req) {
    if (!t || !req) return -1;
    if (req->op == SANDBOX_BROKER_REGISTER) {
        if (t->sandbox_class != SANDBOX_CLASS_BROKER && (t->sandbox_caps & SANDBOX_CAP_BROKER) == 0) {
            sandbox_audit_deny(t, "broker", "register", "broker-capability");
            return -1;
        }
        t->sandbox_broker = 1;
        log_printf("sandbox: broker registered pid=%u\n", (unsigned)t->pid);
        return 0;
    }
    if (req->op == SANDBOX_BROKER_REQUEST_PATH) {
        if (!sandbox_check_path(t, "broker-path", req->target, req->access)) return -1;
        if (t->sandbox_need_consent) {
            sandbox_audit_deny(t, "consent", req->target, "user-prompt-required");
            return -1;
        }
        return 0;
    }
    if (req->op == SANDBOX_BROKER_CONSENT) {
        if (!t->sandbox_broker) {
            sandbox_audit_deny(t, "consent", "record", "not-broker");
            return -1;
        }
        log_printf("sandbox: consent recorded by broker pid=%u target=%s reason=%s\n",
                   (unsigned)t->pid, req->target, req->reason);
        return 0;
    }
    return -1;
}

void sandbox_audit_deny(struct task *t, const char *op, const char *target, const char *reason) {
    char line[256];
    int node;
    uint64_t off;
    if (!op) op = "op";
    if (!target) target = "";
    if (!reason) reason = "denied";
    line[0] = '\0';
    append(line, sizeof(line), "deny pid=");
    append_u32(line, sizeof(line), t ? t->pid : 0);
    append(line, sizeof(line), " class=");
    append_u32(line, sizeof(line), t ? t->sandbox_class : 0);
    append(line, sizeof(line), " op=");
    append(line, sizeof(line), op);
    append(line, sizeof(line), " target=");
    append(line, sizeof(line), target);
    append(line, sizeof(line), " reason=");
    append(line, sizeof(line), reason);
    append(line, sizeof(line), "\n");
    log_printf("sandbox-audit: %s", line);
    node = vfs_resolve(0, "/var/log/sandbox.log");
    if (node < 0) {
        if (vfs_resolve(0, "/var/log") < 0) (void)vfs_create(0, "/var/log", 1);
        node = vfs_create(0, "/var/log/sandbox.log", 0);
    }
    if (node >= 0) {
        off = vfs_get_size(node);
        (void)vfs_write_file(node, (const uint8_t *)line, str_len(line), off);
    }
}
