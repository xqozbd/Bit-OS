#include "sys.h"

enum { MAX_USERS = 32 };
enum { SALT_LEN = 16, HASH_LEN = 32, PASS_ITER = 4096, EMAIL_LEN = 96 };

enum {
    USER_FLAG_ADMIN = 1u << 0
};

#define ACCOUNTS_DB "/var/accounts/users.db"
#define PASSWD_FALLBACK "/etc/passwd"

struct user_entry {
    char name[32];
    char email[EMAIL_LEN];
    uint32_t uid;
    uint32_t gid;
    uint32_t flags;
    uint8_t salt[SALT_LEN];
    uint8_t hash[HASH_LEN];
    int has_pass;
};

static int create_user_flow(char *buf, int buf_len, struct user_entry *users, int max_users);
static int read_line(char *out, int max);

static void u32_to_text_local(uint32_t v, char *out, uint32_t cap) {
    char tmp[16];
    uint32_t i = 0;
    uint32_t j = 0;
    if (!out || cap == 0) return;
    if (v == 0) {
        if (cap > 1) {
            out[0] = '0';
            out[1] = '\0';
        } else {
            out[0] = '\0';
        }
        return;
    }
    while (v && i + 1 < (uint32_t)sizeof(tmp)) {
        tmp[i++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (i > 0 && j + 1 < cap) out[j++] = tmp[--i];
    out[j] = '\0';
}

static int is_digit_local(char c) {
    return (c >= '0' && c <= '9');
}

static int secure_accounts_storage(void) {
    int ok = 1;
    if (sys_chown("/var/accounts", 0, 0) != 0) ok = 0;
    if (sys_chmod("/var/accounts", 0700) != 0) ok = 0;
    if (sys_chown(ACCOUNTS_DB, 0, 0) != 0) ok = 0;
    if (sys_chmod(ACCOUNTS_DB, 0600) != 0) ok = 0;
    return ok;
}

static int validate_username(const char *name) {
    if (!name || !name[0]) return 0;
    for (int i = 0; name[i]; ++i) {
        char c = name[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-' || c == '.') {
            continue;
        }
        return 0;
    }
    return 1;
}

static int validate_email(const char *email) {
    int at = -1;
    int dot = -1;
    if (!email || !email[0]) return 0;
    for (int i = 0; email[i]; ++i) {
        char c = email[i];
        if (c == ' ' || c == ':' || c == '\n' || c == '\r' || c == '\t') return 0;
        if (c == '@') {
            if (at >= 0) return 0;
            at = i;
        } else if (c == '.') {
            dot = i;
        }
    }
    if (at <= 0) return 0;
    if (dot <= at + 1) return 0;
    if (!email[dot + 1]) return 0;
    return 1;
}

static void prompt_username(char *name, int name_len, const char *label) {
    for (;;) {
        uputs(label ? label : "username");
        uputs(": ");
        read_line(name, name_len);
        if (!validate_username(name)) {
            uputs("username must use letters, numbers, '.', '_' or '-'\n");
            continue;
        }
        return;
    }
}

static void prompt_email(char *email, int email_len, const char *label) {
    for (;;) {
        uputs(label ? label : "email");
        uputs(": ");
        read_line(email, email_len);
        if (!validate_email(email)) {
            uputs("enter a valid email address\n");
            continue;
        }
        return;
    }
}

static void ustrncpy_local(char *dst, const char *src, size_t n) {
    if (!dst || n == 0) return;
    size_t i = 0;
    if (src) {
        for (; i + 1 < n && src[i]; ++i) dst[i] = src[i];
    }
    if (n > 0) dst[i++] = '\0';
    for (; i < n; ++i) dst[i] = '\0';
}

static int umemcmp_local(const void *a, const void *b, size_t n) {
    const uint8_t *p1 = (const uint8_t *)a;
    const uint8_t *p2 = (const uint8_t *)b;
    for (size_t i = 0; i < n; ++i) {
        if (p1[i] != p2[i]) return (p1[i] < p2[i]) ? -1 : 1;
    }
    return 0;
}

struct sha256_ctx {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    uint32_t buf_len;
};

static uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_init(struct sha256_ctx *c) {
    c->h[0] = 0x6a09e667u;
    c->h[1] = 0xbb67ae85u;
    c->h[2] = 0x3c6ef372u;
    c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu;
    c->h[5] = 0x9b05688cu;
    c->h[6] = 0x1f83d9abu;
    c->h[7] = 0x5be0cd19u;
    c->len = 0;
    c->buf_len = 0;
}

static void sha256_block(struct sha256_ctx *c, const uint8_t *p) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,
        0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,
        0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,
        0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,
        0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,
        0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,
        0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,
        0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,
        0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (int i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], d = c->h[3], e = c->h[4];
    uint32_t f = c->h[5], g = c->h[6], h = c->h[7], t1, t2, c2 = c->h[2];
    for (int i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        t1 = h + S1 + ch + k[i] + w[i];
        uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c2) ^ (b & c2);
        t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c2; c2 = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += c2; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_update(struct sha256_ctx *c, const uint8_t *p, size_t n) {
    if (!c || !p || n == 0) return;
    c->len += (uint64_t)n * 8ull;
    while (n > 0) {
        uint32_t space = 64 - c->buf_len;
        uint32_t take = (n < space) ? (uint32_t)n : space;
        for (uint32_t i = 0; i < take; ++i) c->buf[c->buf_len + i] = p[i];
        c->buf_len += take;
        p += take;
        n -= take;
        if (c->buf_len == 64) {
            sha256_block(c, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final(struct sha256_ctx *c, uint8_t out[32]) {
    uint8_t pad[64];
    uint32_t pad_len = 0;
    pad[pad_len++] = 0x80;
    while ((c->buf_len + pad_len) % 64 != 56) {
        pad[pad_len++] = 0x00;
    }
    uint8_t lenb[8];
    for (int i = 0; i < 8; ++i) {
        lenb[7 - i] = (uint8_t)((c->len >> (i * 8)) & 0xffu);
    }
    sha256_update(c, pad, pad_len);
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

static void hash_password(const uint8_t salt[SALT_LEN], const char *pass, uint8_t out[HASH_LEN]) {
    struct sha256_ctx ctx;
    size_t plen = ustrlen(pass);
    sha256_init(&ctx);
    sha256_update(&ctx, salt, SALT_LEN);
    sha256_update(&ctx, (const uint8_t *)pass, plen);
    sha256_final(&ctx, out);
    for (int i = 0; i < PASS_ITER; ++i) {
        sha256_init(&ctx);
        sha256_update(&ctx, out, HASH_LEN);
        sha256_update(&ctx, (const uint8_t *)pass, plen);
        sha256_final(&ctx, out);
    }
}

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static void hex_encode(const uint8_t *src, int len, char *dst, int dst_len) {
    static const char *hex = "0123456789abcdef";
    if (!src || !dst || dst_len < len * 2 + 1) return;
    for (int i = 0; i < len; ++i) {
        dst[i * 2] = hex[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hex[src[i] & 0xF];
    }
    dst[len * 2] = '\0';
}

static int hex_decode(const char *src, uint8_t *dst, int len) {
    if (!src || !dst) return 0;
    for (int i = 0; i < len; ++i) {
        int hi = hex_val(src[i * 2]);
        int lo = hex_val(src[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static int read_urandom(uint8_t *buf, int len) {
    int fd = (int)sys_open("/dev/urandom", O_RDONLY);
    if (fd < 0) return 0;
    int got = 0;
    while (got < len) {
        long n = sys_read(fd, buf + got, (size_t)(len - got));
        if (n <= 0) break;
        got += (int)n;
    }
    sys_close(fd);
    return got == len;
}

static int read_line(char *out, int max) {
    int len = 0;
    while (len + 1 < max) {
        char c = 0;
        long n = sys_read(0, &c, 1);
        if (n <= 0) continue;
        if (c == '\r') continue;
        if (c == '\n') {
            out[len] = '\0';
            return len;
        }
        out[len++] = c;
    }
    out[len] = '\0';
    return len;
}

static int load_passwd(char *buf, int buf_len, struct user_entry *users, int max_users) {
    if (!buf || buf_len <= 1 || !users || max_users <= 0) return 0;
    int fd = (int)sys_open(PASSWD_FALLBACK, O_RDONLY);
    if (fd < 0) {
        buf[0] = '\0';
        return 0;
    }
    long n = sys_read(fd, buf, (size_t)(buf_len - 1));
    sys_close(fd);
    if (n <= 0) {
        buf[0] = '\0';
        return 0;
    }
    buf[n] = '\0';

    int count = 0;
    char *p = buf;
    while (*p && count < max_users) {
        char *line = p;
        while (*p && *p != '\n') p++;
        if (*p == '\n') *p++ = '\0';
        if (!line[0] || line[0] == '#') continue;

        char *u = line;
        char *c1 = u;
        while (*c1 && *c1 != ':') c1++;
        if (*c1 != ':') continue;
        *c1++ = '\0';
        char *u_id = c1;
        char *c2 = u_id;
        while (*c2 && *c2 != ':') c2++;
        if (*c2 != ':') continue;
        *c2++ = '\0';
        char *g_id = c2;
        char *c3 = g_id;
        while (*c3 && *c3 != ':') c3++;
        *c3 = '\0';

        struct user_entry *e = &users[count++];
        int i = 0;
        for (; i + 1 < (int)sizeof(e->name) && u[i]; ++i) e->name[i] = u[i];
        e->name[i] = '\0';
        e->email[0] = '\0';
        e->uid = (uint32_t)uatoi(u_id);
        e->gid = (uint32_t)uatoi(g_id);
        e->flags = (e->uid == 0) ? USER_FLAG_ADMIN : 0;
        e->has_pass = 0;
    }
    return count;
}

static int parse_user(const char *user, uint32_t *uid, uint32_t *gid, struct user_entry *users, int count) {
    if (!user || !users || count <= 0) return 0;
    for (int i = 0; i < count; ++i) {
        if (ustrcmp(users[i].name, user) == 0) {
            if (uid) *uid = users[i].uid;
            if (gid) *gid = users[i].gid;
            return 1;
        }
    }
    return 0;
}

static uint32_t next_uid(struct user_entry *users, int count) {
    uint32_t max = 999;
    for (int i = 0; i < count; ++i) {
        if (users[i].uid >= 1000 && users[i].uid > max) max = users[i].uid;
    }
    return max + 1;
}

static int has_user(struct user_entry *users, int count, const char *name) {
    for (int i = 0; i < count; ++i) {
        if (ustrcmp(users[i].name, name) == 0) return 1;
    }
    return 0;
}

static int has_email(struct user_entry *users, int count, const char *email) {
    for (int i = 0; i < count; ++i) {
        if (users[i].email[0] && ustrcmp(users[i].email, email) == 0) return 1;
    }
    return 0;
}

static int find_user_index(struct user_entry *users, int count, const char *name) {
    if (!users || !name) return -1;
    for (int i = 0; i < count; ++i) {
        if (ustrcmp(users[i].name, name) == 0) return i;
    }
    return -1;
}

static int count_users(struct user_entry *users, int max) {
    int c = 0;
    for (int i = 0; i < max; ++i) {
        if (users[i].name[0]) c++;
    }
    return c;
}

static int configured_password_count(struct user_entry *users, int count) {
    int configured = 0;
    for (int i = 0; i < count; ++i) {
        if (users[i].name[0] && users[i].has_pass) configured++;
    }
    return configured;
}

static int write_passwd(const char *data, int len) {
    int fd = (int)sys_open(PASSWD_FALLBACK, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) return 0;
    int written = 0;
    while (written < len) {
        long n = sys_write(fd, data + written, (size_t)(len - written));
        if (n <= 0) break;
        written += (int)n;
    }
    sys_close(fd);
    return (written == len);
}

static int load_accounts(char *buf, int buf_len, struct user_entry *users, int max_users) {
    int fd = (int)sys_open(ACCOUNTS_DB, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    long n = sys_read(fd, buf, (size_t)(buf_len - 1));
    sys_close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    int count = 0;
    char *p = buf;
    while (*p && count < max_users) {
        char *line = p;
        char *fields[7];
        int field_count = 0;
        while (*p && *p != '\n') p++;
        if (*p == '\n') *p++ = '\0';
        if (!line[0] || line[0] == '#') continue;
        fields[field_count++] = line;
        for (char *it = line; *it && field_count < 7; ++it) {
            if (*it == ':') {
                *it = '\0';
                fields[field_count++] = it + 1;
            }
        }
        if (field_count != 5 && field_count != 7) continue;

        struct user_entry *e = &users[count++];
        int i = 0;
        for (; i + 1 < (int)sizeof(e->name) && fields[0][i]; ++i) e->name[i] = fields[0][i];
        e->name[i] = '\0';
        e->uid = (uint32_t)uatoi(fields[1]);
        e->gid = (uint32_t)uatoi(fields[2]);
        e->email[0] = '\0';
        e->flags = (e->uid == 0) ? USER_FLAG_ADMIN : 0;
        e->has_pass = 0;

        if (field_count == 7) {
            e->flags = (uint32_t)uatoi(fields[3]);
            ustrncpy_local(e->email, fields[4], sizeof(e->email));
            if ((int)ustrlen(fields[5]) == SALT_LEN * 2 &&
                (int)ustrlen(fields[6]) == HASH_LEN * 2 &&
                hex_decode(fields[5], e->salt, SALT_LEN) &&
                hex_decode(fields[6], e->hash, HASH_LEN)) {
                e->has_pass = 1;
            }
        } else if ((int)ustrlen(fields[3]) == SALT_LEN * 2 &&
                   (int)ustrlen(fields[4]) == HASH_LEN * 2 &&
                   hex_decode(fields[3], e->salt, SALT_LEN) &&
                   hex_decode(fields[4], e->hash, HASH_LEN)) {
            e->has_pass = 1;
        }
    }
    return count;
}

static int reload_users(char *buf, int buf_len, struct user_entry *users, int max_users) {
    for (int i = 0; i < max_users; ++i) {
        users[i].name[0] = '\0';
        users[i].email[0] = '\0';
        users[i].uid = 0;
        users[i].gid = 0;
        users[i].flags = 0;
        users[i].has_pass = 0;
    }
    int count = load_accounts(buf, buf_len, users, max_users);
    if (count == 0) count = load_passwd(buf, buf_len, users, max_users);
    return count;
}

static int write_accounts(struct user_entry *users, int count) {
    char buf[2048];
    int len = 0;
    const char *hdr = "# BitOS accounts v2\n";
    for (int i = 0; hdr[i] && len + 1 < (int)sizeof(buf); ++i) buf[len++] = hdr[i];
    for (int i = 0; i < count && len + 1 < (int)sizeof(buf); ++i) {
        char line[256];
        int l = 0;
        const char *name = users[i].name;
        for (int j = 0; name[j] && l + 1 < (int)sizeof(line); ++j) line[l++] = name[j];
        line[l++] = ':';
        char tmp[16];
        int t = 0;
        uint32_t v = users[i].uid;
        if (v == 0) tmp[t++] = '0';
        while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
        for (int j = t - 1; j >= 0 && l + 1 < (int)sizeof(line); --j) line[l++] = tmp[j];
        line[l++] = ':';
        v = users[i].gid; t = 0;
        if (v == 0) tmp[t++] = '0';
        while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
        for (int j = t - 1; j >= 0 && l + 1 < (int)sizeof(line); --j) line[l++] = tmp[j];
        line[l++] = ':';
        v = users[i].flags; t = 0;
        if (v == 0) tmp[t++] = '0';
        while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
        for (int j = t - 1; j >= 0 && l + 1 < (int)sizeof(line); --j) line[l++] = tmp[j];
        line[l++] = ':';
        for (int j = 0; users[i].email[j] && l + 1 < (int)sizeof(line); ++j) line[l++] = users[i].email[j];
        line[l++] = ':';
        if (users[i].has_pass) {
            char salt_hex[SALT_LEN * 2 + 1];
            char hash_hex[HASH_LEN * 2 + 1];
            hex_encode(users[i].salt, SALT_LEN, salt_hex, (int)sizeof(salt_hex));
            hex_encode(users[i].hash, HASH_LEN, hash_hex, (int)sizeof(hash_hex));
            for (int j = 0; salt_hex[j] && l + 1 < (int)sizeof(line); ++j) line[l++] = salt_hex[j];
            line[l++] = ':';
            for (int j = 0; hash_hex[j] && l + 1 < (int)sizeof(line); ++j) line[l++] = hash_hex[j];
        } else {
            line[l++] = '-';
            line[l++] = ':';
            line[l++] = '-';
        }
        line[l++] = '\n';
        if (len + l >= (int)sizeof(buf)) break;
        for (int j = 0; j < l; ++j) buf[len++] = line[j];
    }
    int fd = (int)sys_open(ACCOUNTS_DB, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) return 0;
    int written = 0;
    while (written < len) {
        long n = sys_write(fd, buf + written, (size_t)(len - written));
        if (n <= 0) break;
        written += (int)n;
    }
    sys_close(fd);
    if (written != len) return 0;
    return secure_accounts_storage();
}

static int prompt_and_set_password(struct user_entry *e, const char *label) {
    char pass1[64], pass2[64];
    if (!e) return 0;
    for (;;) {
        uputs(label ? label : "password");
        uputs(": ");
        read_line(pass1, (int)sizeof(pass1));
        uputs("confirm password: ");
        read_line(pass2, (int)sizeof(pass2));
        if (pass1[0] == '\0') {
            uputs("password cannot be empty\n");
            continue;
        }
        if (ustrcmp(pass1, pass2) != 0) {
            uputs("passwords do not match\n");
            continue;
        }
        break;
    }
    if (!read_urandom(e->salt, SALT_LEN)) {
        uint64_t t = (uint64_t)sys_uptime_ticks();
        for (int i = 0; i < SALT_LEN; ++i) e->salt[i] = (uint8_t)(t >> (i * 3));
    }
    hash_password(e->salt, pass1, e->hash);
    e->has_pass = 1;
    return 1;
}

static int configure_admin_flow(struct user_entry *users, int max_users) {
    int total = count_users(users, max_users);
    int idx = -1;
    struct user_entry *e;

    for (int i = 0; i < total; ++i) {
        if (users[i].flags & USER_FLAG_ADMIN) {
            idx = i;
            break;
        }
    }

    if (idx < 0) idx = find_user_index(users, total, "root");

    if (idx < 0) {
        for (int i = 0; i < max_users; ++i) {
            if (users[i].name[0] == '\0') {
                idx = i;
                ustrncpy_local(users[i].name, "root", sizeof(users[i].name));
                users[i].uid = 0;
                users[i].gid = 0;
                users[i].has_pass = 0;
                break;
            }
        }
    }
    if (idx < 0) {
        uputs("no free slot for admin account\n");
        return 0;
    }

    e = &users[idx];
    if (!e->name[0]) {
        prompt_username(e->name, (int)sizeof(e->name), "administrator username");
    } else {
        char ans[8];
        uputs("administrator username [");
        uputs(e->name);
        uputs("] change? (y/n): ");
        read_line(ans, (int)sizeof(ans));
        if (ans[0] == 'y' || ans[0] == 'Y') {
            char name[32];
            for (;;) {
                prompt_username(name, (int)sizeof(name), "administrator username");
                if (has_user(users, total, name) && ustrcmp(name, e->name) != 0) {
                    uputs("user already exists\n");
                    continue;
                }
                ustrncpy_local(e->name, name, sizeof(e->name));
                break;
            }
        }
    }
    prompt_email(e->email, (int)sizeof(e->email), "administrator email");
    e->uid = 0;
    e->gid = 0;
    e->flags = USER_FLAG_ADMIN;
    if (!prompt_and_set_password(e, "administrator password")) return 0;

    total = count_users(users, max_users);
    if (!write_accounts(users, total)) {
        uputs("failed to write admin account database\n");
        return 0;
    }
    uputs("administrator account configured\n");
    return 1;
}

static int run_first_boot_setup(char *buf, int buf_len, struct user_entry *users, int max_users) {
    char ans[8];
    uputs("First boot setup\n");
    uputs("Configure administrator account now? (y/n): ");
    read_line(ans, (int)sizeof(ans));
    if (ans[0] == 'y' || ans[0] == 'Y') {
        if (!configure_admin_flow(users, max_users)) return 0;
    }
    uputs("Create a standard desktop user now? (y/n): ");
    read_line(ans, (int)sizeof(ans));
    if (ans[0] == 'y' || ans[0] == 'Y') {
        if (!create_user_flow(buf, buf_len, users, max_users)) return 0;
    }
    return 1;
}

static int create_user_flow(char *buf, int buf_len, struct user_entry *users, int max_users) {
    char name[32];
    char email[EMAIL_LEN];
    for (;;) {
        prompt_username(name, (int)sizeof(name), "new username");
        if (has_user(users, count_users(users, max_users), name)) {
            uputs("user already exists\n");
            continue;
        }
        break;
    }
    for (;;) {
        prompt_email(email, (int)sizeof(email), "email");
        if (has_email(users, count_users(users, max_users), email)) {
            uputs("email already exists\n");
            continue;
        }
        break;
    }

    uint32_t uid = next_uid(users, max_users);
    uint32_t gid = uid;

    int len = 0;
    if (buf[0]) {
        while (buf[len] && len + 1 < buf_len) len++;
        if (len > 0 && buf[len - 1] != '\n' && len + 1 < buf_len) buf[len++] = '\n';
    } else {
        const char *root = "root:0:0\n";
        for (int i = 0; root[i] && len + 1 < buf_len; ++i) buf[len++] = root[i];
    }

    char line[64];
    int l = 0;
    for (int i = 0; name[i] && l + 1 < (int)sizeof(line); ++i) line[l++] = name[i];
    if (l + 1 < (int)sizeof(line)) line[l++] = ':';
    char tmp[16];
    int t = 0;
    uint32_t v = uid;
    if (v == 0) tmp[t++] = '0';
    while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = t - 1; i >= 0 && l + 1 < (int)sizeof(line); --i) line[l++] = tmp[i];
    if (l + 1 < (int)sizeof(line)) line[l++] = ':';
    v = gid; t = 0;
    if (v == 0) tmp[t++] = '0';
    while (v && t < (int)sizeof(tmp)) { tmp[t++] = (char)('0' + (v % 10)); v /= 10; }
    for (int i = t - 1; i >= 0 && l + 1 < (int)sizeof(line); --i) line[l++] = tmp[i];
    if (l + 1 < (int)sizeof(line)) line[l++] = '\n';

    if (len + l >= buf_len) {
        uputs("passwd file too large\n");
        return 0;
    }
    for (int i = 0; i < l; ++i) buf[len++] = line[i];
    buf[len] = '\0';

    struct user_entry *e = NULL;
    for (int i = 0; i < max_users; ++i) {
        if (users[i].name[0] == '\0') { e = &users[i]; break; }
    }
    if (!e) e = &users[max_users - 1];
    ustrncpy_local(e->name, name, sizeof(e->name));
    ustrncpy_local(e->email, email, sizeof(e->email));
    e->uid = uid;
    e->gid = gid;
    e->flags = 0;
    if (!prompt_and_set_password(e, "new password")) return 0;

    int total = count_users(users, max_users);
    if (!write_accounts(users, total)) {
        if (!write_passwd(buf, len)) {
            uputs("failed to update accounts\n");
            return 0;
        }
        uputs("accounts db unavailable, wrote /etc/passwd\n");
    } else {
        uputs("user added\n");
    }
    return 1;
}

static void print_user_list(struct user_entry *users, int count) {
    char num[16];
    for (int i = 0; i < count; ++i) {
        if (!users[i].name[0]) continue;
        uputs("  ");
        u32_to_text_local((uint32_t)(i + 1), num, (uint32_t)sizeof(num));
        uputs(num);
        uputs(") ");
        uputs(users[i].name);
        if (users[i].email[0]) {
            uputs(" <");
            uputs(users[i].email);
            uputs(">");
        }
        if (users[i].flags & USER_FLAG_ADMIN) uputs(" [admin]");
        uputs("\n");
    }
}

static int parse_selection_index(const char *s, int count) {
    int v = 0;
    if (!s || !s[0]) return -1;
    for (int i = 0; s[i]; ++i) {
        if (!is_digit_local(s[i])) return -1;
        v = v * 10 + (s[i] - '0');
    }
    if (v <= 0 || v > count) return -1;
    return v - 1;
}

void _start(void) {
    char passwd[1024];
    struct user_entry users[MAX_USERS];
    int count = reload_users(passwd, (int)sizeof(passwd), users, MAX_USERS);

    if (count == 0) {
        uputs("No users found. Create one now? (y/n): ");
        char ans[8];
        read_line(ans, (int)sizeof(ans));
        if (ans[0] != 'y' && ans[0] != 'Y') sys_exit(1);
        if (!create_user_flow(passwd, (int)sizeof(passwd), users, MAX_USERS)) sys_exit(1);
        count = reload_users(passwd, (int)sizeof(passwd), users, MAX_USERS);
        if (count == 0) sys_exit(1);
    } else if (configured_password_count(users, count) == 0) {
        if (!run_first_boot_setup(passwd, (int)sizeof(passwd), users, MAX_USERS)) sys_exit(1);
        count = reload_users(passwd, (int)sizeof(passwd), users, MAX_USERS);
        if (count == 0) sys_exit(1);
    }

    for (;;) {
        char choice[32];
        char user[32];
        uint32_t uid = 0, gid = 0;
        int idx = -1;

        uputs("\nBitOS Login\n");
        print_user_list(users, count);
        uputs("  c) create standard user\n");
        uputs("  a) configure administrator\n");
        uputs("Select user number or type username: ");
        read_line(choice, (int)sizeof(choice));

        if (choice[0] == 'c' || choice[0] == 'C') {
            if (create_user_flow(passwd, (int)sizeof(passwd), users, MAX_USERS)) {
                count = reload_users(passwd, (int)sizeof(passwd), users, MAX_USERS);
            }
            continue;
        }
        if (choice[0] == 'a' || choice[0] == 'A') {
            if (configure_admin_flow(users, MAX_USERS)) {
                count = reload_users(passwd, (int)sizeof(passwd), users, MAX_USERS);
            }
            continue;
        }

        idx = parse_selection_index(choice, count);
        if (idx >= 0) {
            ustrncpy_local(user, users[idx].name, sizeof(user));
        } else {
            ustrncpy_local(user, choice, sizeof(user));
            for (int i = 0; i < count; ++i) {
                if (ustrcmp(users[i].name, user) == 0) { idx = i; break; }
            }
        }
        if (idx < 0 || !parse_user(user, &uid, &gid, users, count)) {
            uputs("login: unknown user\n");
            continue;
        }
        if (users[idx].has_pass) {
            char pass[64];
            uputs("password: ");
            read_line(pass, (int)sizeof(pass));
            uint8_t hash[HASH_LEN];
            hash_password(users[idx].salt, pass, hash);
            if (umemcmp_local(hash, users[idx].hash, HASH_LEN) != 0) {
                uputs("login: invalid password\n");
                continue;
            }
        }
        sys_setgid(gid);
        sys_setuid(uid);

        char *argv[2] = { "/bin/sh", 0 };
        sys_execve("/bin/sh", 1, argv, 0);
        sys_exit(1);
    }
}
