#include "sys.h"

enum { MAX_USERS = 32 };
enum { SALT_LEN = 16, HASH_LEN = 32, PASS_ITER = 4096 };

#define ACCOUNTS_DB "/var/accounts/users.db"
#define PASSWD_FALLBACK "/etc/passwd"

struct user_entry {
    char name[32];
    uint32_t uid;
    uint32_t gid;
    uint8_t salt[SALT_LEN];
    uint8_t hash[HASH_LEN];
    int has_pass;
};

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
        e->uid = (uint32_t)uatoi(u_id);
        e->gid = (uint32_t)uatoi(g_id);
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

static int count_users(struct user_entry *users, int max) {
    int c = 0;
    for (int i = 0; i < max; ++i) {
        if (users[i].name[0]) c++;
    }
    return c;
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
        if (*c3 != ':') continue;
        *c3++ = '\0';
        char *salt_hex = c3;
        char *c4 = salt_hex;
        while (*c4 && *c4 != ':') c4++;
        if (*c4 != ':') continue;
        *c4++ = '\0';
        char *hash_hex = c4;
        struct user_entry *e = &users[count++];
        int i = 0;
        for (; i + 1 < (int)sizeof(e->name) && u[i]; ++i) e->name[i] = u[i];
        e->name[i] = '\0';
        e->uid = (uint32_t)uatoi(u_id);
        e->gid = (uint32_t)uatoi(g_id);
        e->has_pass = 0;
        if ((int)ustrlen(salt_hex) == SALT_LEN * 2 &&
            (int)ustrlen(hash_hex) == HASH_LEN * 2 &&
            hex_decode(salt_hex, e->salt, SALT_LEN) &&
            hex_decode(hash_hex, e->hash, HASH_LEN)) {
            e->has_pass = 1;
        }
    }
    return count;
}

static int write_accounts(struct user_entry *users, int count) {
    char buf[2048];
    int len = 0;
    const char *hdr = "# BitOS accounts v1\n";
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
    return (written == len);
}

static int create_user_flow(char *buf, int buf_len, struct user_entry *users, int max_users) {
    char name[32];
    for (;;) {
        uputs("new username: ");
        read_line(name, (int)sizeof(name));
        if (name[0] == '\0') {
            uputs("name cannot be empty\n");
            continue;
        }
        int bad = 0;
        for (int i = 0; name[i]; ++i) {
            if (name[i] == ':' || name[i] == '\n' || name[i] == '\r' || name[i] == ' ') {
                bad = 1;
                break;
            }
        }
        if (bad) {
            uputs("invalid characters in name\n");
            continue;
        }
        if (has_user(users, count_users(users, max_users), name)) {
            uputs("user already exists\n");
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
    e->uid = uid;
    e->gid = gid;
    char pass1[64], pass2[64];
    for (;;) {
        uputs("new password: ");
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

void _start(void) {
    char passwd[1024];
    struct user_entry users[MAX_USERS];
    for (int i = 0; i < MAX_USERS; ++i) users[i].name[0] = '\0';
    int count = load_accounts(passwd, (int)sizeof(passwd), users, MAX_USERS);
    if (count == 0) {
        count = load_passwd(passwd, (int)sizeof(passwd), users, MAX_USERS);
    }

    if (count == 0) {
        uputs("No users found. Create one now? (y/n): ");
        char ans[8];
        read_line(ans, (int)sizeof(ans));
        if (ans[0] != 'y' && ans[0] != 'Y') sys_exit(1);
        if (!create_user_flow(passwd, (int)sizeof(passwd), users, MAX_USERS)) sys_exit(1);
        count = load_passwd(passwd, (int)sizeof(passwd), users, MAX_USERS);
        if (count == 0) sys_exit(1);
    }

    for (;;) {
        if (count >= 1) {
            uputs("1) login\n2) add user\nchoice: ");
            char choice[8];
            read_line(choice, (int)sizeof(choice));
            if (choice[0] == '2') {
                if (create_user_flow(passwd, (int)sizeof(passwd), users, MAX_USERS)) {
                    count = load_passwd(passwd, (int)sizeof(passwd), users, MAX_USERS);
                }
                continue;
            }
        }

        uputs("login: ");
        char user[32];
        read_line(user, (int)sizeof(user));

        uint32_t uid = 0, gid = 0;
        int idx = -1;
        for (int i = 0; i < count; ++i) {
            if (ustrcmp(users[i].name, user) == 0) { idx = i; break; }
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
