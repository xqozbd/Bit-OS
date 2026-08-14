#include "sys.h"
#include "desktop.h"
#include "uitk.h"

#if defined(BITOS_USE_GNU_ATTRS)
#define BITOS_USER_NORETURN __attribute__((noreturn))
#define BITOS_USER_NAKED __attribute__((naked))
#else
#define BITOS_USER_NORETURN
#define BITOS_USER_NAKED
#endif

extern char font8x8_basic[128][8];

#define WM_IPC_PATH "/tmp/wm.ipc"
#define APP_BUF_MAX 8192
#define APP_TEXT_MAX 8192
#define APP_ITEMS_MAX 64
#define APP_MIME_MAX 32
#define APP_DESKTOP_MAX 32
#define APP_PATH_MAX 128
#define APP_BUTTON_MAX 8

#define UI_BG 0x15202Bu
#define UI_PANEL 0x1C2A38u
#define UI_PANEL_ALT 0x223244u
#define UI_ACCENT 0x4F7AA3u
#define UI_ACCENT_ALT 0x6A94BFu
#define UI_TEXT 0xF3F7FBu
#define UI_TEXT_DIM 0xB4C1CFu
#define UI_WARN 0xA35D4Fu
#define UI_OK 0x4F8A66u

#define GUI_MAX_USERS 32
#define GUI_SALT_LEN 16
#define GUI_HASH_LEN 32
#define GUI_PASS_ITER 4096
#define GUI_EMAIL_LEN 96
#define GUI_PASS_MAX 64
#define GUI_ACCOUNTS_DB "/var/accounts/users.db"
#define GUI_PASSWD_FALLBACK "/etc/passwd"
#define GUI_SESSION_FILE "/tmp/desktop-session"

enum {
    GUI_USER_FLAG_ADMIN = 1u << 0
};

struct rect { int32_t x; int32_t y; uint32_t w; uint32_t h; };
struct button { struct rect r; char label[24]; };

struct app_window {
    struct desktop_runtime *rt;
    struct desktop_shm_window *shm;
    int rt_fd;
    int shm_fd;
    uint32_t win_id;
    uint32_t slot;
    uint32_t last_buttons;
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
    char title[DESKTOP_TITLE_MAX];
    char buffer_path[DESKTOP_PATH_MAX];
    int focused;
};

struct file_item {
    char name[64];
    char path[APP_PATH_MAX];
    int is_dir;
};

struct desktop_entry {
    char name[64];
    char exec[96];
    char mime[96];
};

struct mime_assoc {
    char key[32];
    char exec[96];
};

struct editor_state {
    char path[APP_PATH_MAX];
    char data[APP_TEXT_MAX];
    uint32_t len;
    uint32_t cursor;
    int dirty;
    char status[96];
};

struct pty_state {
    int master_fd;
    int child_pid;
    char lines[48][96];
    uint32_t line_count;
    char status[96];
};

struct gui_user_entry {
    char name[32];
    char email[GUI_EMAIL_LEN];
    uint32_t uid;
    uint32_t gid;
    uint32_t flags;
    uint8_t salt[GUI_SALT_LEN];
    uint8_t hash[GUI_HASH_LEN];
    int has_pass;
};

struct login_state {
    struct gui_user_entry users[GUI_MAX_USERS];
    int user_count;
    int mode_create;
    int focus_field;
    int secure_fd;
    char username[32];
    char email[GUI_EMAIL_LEN];
    char password[GUI_PASS_MAX];
    char confirm[GUI_PASS_MAX];
    char status[128];
};

static long spawn_exec_line(const char *exec_line, const char *path_arg);

static uint32_t str_len(const char *s) { uint32_t n = 0; while (s && s[n]) ++n; return n; }
static int str_eq(const char *a, const char *b) { uint32_t i = 0; if (!a || !b) return 0; while (a[i] && b[i]) { if (a[i] != b[i]) return 0; ++i; } return a[i] == b[i]; }
static int starts_with(const char *s, const char *p) { uint32_t i = 0; if (!s || !p) return 0; while (p[i]) { if (s[i] != p[i]) return 0; ++i; } return 1; }
static int ends_with(const char *s, const char *suffix) {
    uint32_t ls = str_len(s), le = str_len(suffix), i;
    if (le > ls) return 0;
    for (i = 0; i < le; ++i) if (s[ls - le + i] != suffix[i]) return 0;
    return 1;
}
static int is_space(char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; }
static int bytes_eq(const uint8_t *a, const uint8_t *b, uint32_t n) { uint32_t i; if (!a || !b) return 0; for (i = 0; i < n; ++i) if (a[i] != b[i]) return 0; return 1; }
static void str_copy(char *dst, uint32_t cap, const char *src) { uint32_t i = 0; if (!dst || cap == 0) return; if (!src) { dst[0] = '\0'; return; } while (src[i] && i + 1 < cap) { dst[i] = src[i]; ++i; } dst[i] = '\0'; }
static void str_append(char *dst, uint32_t cap, const char *src) { uint32_t i = str_len(dst), j = 0; if (!dst || cap == 0 || !src) return; while (src[j] && i + 1 < cap) dst[i++] = src[j++]; dst[i] = '\0'; }
static void trim(char *s) {
    uint32_t start = 0, end = str_len(s), i;
    while (s[start] && is_space(s[start])) ++start;
    while (end > start && is_space(s[end - 1])) --end;
    if (start == 0 && s[end] == '\0') { s[end] = '\0'; return; }
    for (i = 0; start + i < end; ++i) s[i] = s[start + i];
    s[i] = '\0';
}
static const char *base_name(const char *path) { const char *last = path ? path : ""; uint32_t i = 0; while (path && path[i]) { if (path[i] == '/') last = path + i + 1; ++i; } return last; }
static const char *path_ext(const char *path) { const char *b = base_name(path), *dot = 0; uint32_t i = 0; while (b[i]) { if (b[i] == '.') dot = b + i + 1; ++i; } return dot ? dot : ""; }
static uint64_t monotonic_ms(void) { uint64_t hz = (uint64_t)sys_timer_hz(), ticks = (uint64_t)sys_uptime_ticks(); if (!hz) hz = 100; return (ticks * 1000ull) / hz; }
static void u32_to_text(uint32_t v, char *out, uint32_t cap) { char tmp[16]; uint32_t i = 0, j = 0; if (!out || cap == 0) return; if (v == 0) { if (cap > 1) { out[0] = '0'; out[1] = '\0'; } return; } while (v && i + 1 < (uint32_t)sizeof(tmp)) { tmp[i++] = (char)('0' + (v % 10u)); v /= 10u; } while (i && j + 1 < cap) out[j++] = tmp[--i]; out[j] = '\0'; }
static void u64_to_text(uint64_t v, char *out, uint32_t cap) { char tmp[32]; uint32_t i = 0, j = 0; if (!out || cap == 0) return; if (v == 0) { if (cap > 1) { out[0] = '0'; out[1] = '\0'; } return; } while (v && i + 1 < (uint32_t)sizeof(tmp)) { tmp[i++] = (char)('0' + (v % 10ull)); v /= 10ull; } while (i && j + 1 < cap) out[j++] = tmp[--i]; out[j] = '\0'; }

static int validate_username_local(const char *name) {
    uint32_t i = 0;
    if (!name || !name[0]) return 0;
    while (name[i]) {
        char c = name[i];
        if (!((c >= 'a' && c <= 'z') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') ||
              c == '_' || c == '-' || c == '.')) {
            return 0;
        }
        ++i;
    }
    return 1;
}

static int validate_email_local(const char *email) {
    int at = -1;
    int dot = -1;
    uint32_t i = 0;
    if (!email || !email[0]) return 0;
    while (email[i]) {
        char c = email[i];
        if (c == ' ' || c == ':' || c == '\t' || c == '\r' || c == '\n') return 0;
        if (c == '@') {
            if (at >= 0) return 0;
            at = (int)i;
        } else if (c == '.') {
            dot = (int)i;
        }
        ++i;
    }
    if (at <= 0) return 0;
    if (dot <= at + 1) return 0;
    if (!email[dot + 1]) return 0;
    return 1;
}

static int hex_val_local(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static void hex_encode_local(const uint8_t *src, int len, char *dst, int dst_len) {
    static const char *hex = "0123456789abcdef";
    int i;
    if (!src || !dst || dst_len < len * 2 + 1) return;
    for (i = 0; i < len; ++i) {
        dst[i * 2] = hex[(src[i] >> 4) & 0xF];
        dst[i * 2 + 1] = hex[src[i] & 0xF];
    }
    dst[len * 2] = '\0';
}

static int hex_decode_local(const char *src, uint8_t *dst, int len) {
    int i;
    if (!src || !dst) return 0;
    for (i = 0; i < len; ++i) {
        int hi = hex_val_local(src[i * 2]);
        int lo = hex_val_local(src[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        dst[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

struct sha256_ctx_local {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    uint32_t buf_len;
};

static uint32_t rotr32_local(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init_local(struct sha256_ctx_local *c) {
    c->h[0] = 0x6a09e667u; c->h[1] = 0xbb67ae85u; c->h[2] = 0x3c6ef372u; c->h[3] = 0xa54ff53au;
    c->h[4] = 0x510e527fu; c->h[5] = 0x9b05688cu; c->h[6] = 0x1f83d9abu; c->h[7] = 0x5be0cd19u;
    c->len = 0;
    c->buf_len = 0;
}

static void sha256_block_local(struct sha256_ctx_local *c, const uint8_t *p) {
    static const uint32_t k[64] = {
        0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
        0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
        0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
        0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
        0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
        0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
        0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
        0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
    };
    uint32_t w[64];
    uint32_t a, b, c2, d, e, f, g, h;
    int i;
    for (i = 0; i < 16; ++i) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
    }
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32_local(w[i - 15], 7) ^ rotr32_local(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = rotr32_local(w[i - 2], 17) ^ rotr32_local(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    a = c->h[0]; b = c->h[1]; c2 = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
    for (i = 0; i < 64; ++i) {
        uint32_t s1 = rotr32_local(e, 6) ^ rotr32_local(e, 11) ^ rotr32_local(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + s1 + ch + k[i] + w[i];
        uint32_t s0 = rotr32_local(a, 2) ^ rotr32_local(a, 13) ^ rotr32_local(a, 22);
        uint32_t maj = (a & b) ^ (a & c2) ^ (b & c2);
        uint32_t t2 = s0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c2; c2 = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += c2; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_update_local(struct sha256_ctx_local *c, const uint8_t *p, uint32_t n) {
    if (!c || !p || n == 0) return;
    c->len += (uint64_t)n * 8ull;
    while (n > 0) {
        uint32_t space = 64 - c->buf_len;
        uint32_t take = (n < space) ? n : space;
        uint32_t i;
        for (i = 0; i < take; ++i) c->buf[c->buf_len + i] = p[i];
        c->buf_len += take;
        p += take;
        n -= take;
        if (c->buf_len == 64) {
            sha256_block_local(c, c->buf);
            c->buf_len = 0;
        }
    }
}

static void sha256_final_local(struct sha256_ctx_local *c, uint8_t out[32]) {
    uint8_t pad[64];
    uint8_t lenb[8];
    uint32_t pad_len = 0;
    int i;
    pad[pad_len++] = 0x80;
    while ((c->buf_len + pad_len) % 64 != 56) pad[pad_len++] = 0x00;
    for (i = 0; i < 8; ++i) lenb[7 - i] = (uint8_t)((c->len >> (i * 8)) & 0xFFu);
    sha256_update_local(c, pad, pad_len);
    sha256_update_local(c, lenb, 8);
    for (i = 0; i < 8; ++i) {
        out[i * 4 + 0] = (uint8_t)(c->h[i] >> 24);
        out[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        out[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        out[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

static void hash_password_local(const uint8_t salt[GUI_SALT_LEN], const char *pass, uint8_t out[GUI_HASH_LEN]) {
    struct sha256_ctx_local ctx;
    uint32_t plen = str_len(pass);
    int i;
    sha256_init_local(&ctx);
    sha256_update_local(&ctx, salt, GUI_SALT_LEN);
    sha256_update_local(&ctx, (const uint8_t *)pass, plen);
    sha256_final_local(&ctx, out);
    for (i = 0; i < GUI_PASS_ITER; ++i) {
        sha256_init_local(&ctx);
        sha256_update_local(&ctx, out, GUI_HASH_LEN);
        sha256_update_local(&ctx, (const uint8_t *)pass, plen);
        sha256_final_local(&ctx, out);
    }
}

static int read_urandom_local(uint8_t *buf, int len) {
    int fd = (int)sys_open("/dev/urandom", O_RDONLY);
    int got = 0;
    if (fd < 0) return 0;
    while (got < len) {
        long n = sys_read(fd, buf + got, (uint32_t)(len - got));
        if (n <= 0) break;
        got += (int)n;
    }
    sys_close(fd);
    return got == len;
}

static int secure_accounts_storage_local(void) {
    int ok = 1;
    if (sys_chown("/var/accounts", 0, 0) != 0) ok = 0;
    if (sys_chmod("/var/accounts", 0700) != 0) ok = 0;
    if (sys_chown(GUI_ACCOUNTS_DB, 0, 0) != 0) ok = 0;
    if (sys_chmod(GUI_ACCOUNTS_DB, 0600) != 0) ok = 0;
    return ok;
}

static void pixel(struct desktop_shm_window *shm, int32_t x, int32_t y, uint32_t rgb) {
    if (!shm || x < 0 || y < 0) return;
    if ((uint32_t)x >= shm->width || (uint32_t)y >= shm->height) return;
    shm->pixels[(uint64_t)y * shm->stride + (uint64_t)x] = rgb;
}

static void fill_rect(struct desktop_shm_window *shm, int32_t x, int32_t y, uint32_t w, uint32_t h, uint32_t rgb) {
    uint32_t yy, xx;
    for (yy = 0; yy < h; ++yy) for (xx = 0; xx < w; ++xx) pixel(shm, x + (int32_t)xx, y + (int32_t)yy, rgb);
}

static void draw_char(struct desktop_shm_window *shm, int32_t x, int32_t y, char c, uint32_t fg, uint32_t bg) {
    uint32_t row, col; uint8_t ch = (uint8_t)c;
    for (row = 0; row < 8; ++row) {
        uint8_t bits = (uint8_t)font8x8_basic[ch][row];
        for (col = 0; col < 8; ++col) pixel(shm, x + (int32_t)col, y + (int32_t)row, (bits & (1u << col)) ? fg : bg);
    }
}

static void draw_text(struct desktop_shm_window *shm, int32_t x, int32_t y, const char *s, uint32_t fg, uint32_t bg) {
    uint32_t i = 0; int32_t cx = x, cy = y;
    while (s && s[i]) {
        if (s[i] == '\n') { cy += 10; cx = x; ++i; continue; }
        draw_char(shm, cx, cy, s[i], fg, bg);
        cx += 8;
        ++i;
    }
}

static void draw_button(struct desktop_shm_window *shm, const struct button *b, int hot) {
    uint32_t bg = hot ? UI_ACCENT_ALT : UI_ACCENT;
    fill_rect(shm, b->r.x, b->r.y, b->r.w, b->r.h, bg);
    fill_rect(shm, b->r.x, b->r.y, b->r.w, 1, UI_TEXT);
    fill_rect(shm, b->r.x, b->r.y + (int32_t)b->r.h - 1, b->r.w, 1, UI_TEXT);
    fill_rect(shm, b->r.x, b->r.y, 1, b->r.h, UI_TEXT);
    fill_rect(shm, b->r.x + (int32_t)b->r.w - 1, b->r.y, 1, b->r.h, UI_TEXT);
    draw_text(shm, b->r.x + 8, b->r.y + (int32_t)(b->r.h / 2u) - 4, b->label, UI_TEXT, bg);
}

static void clear_window(struct app_window *app, uint32_t bg) {
    if (!app || !app->shm) return;
    fill_rect(app->shm, 0, 0, app->shm->width, app->shm->height, bg);
}

static int rect_hit(const struct rect *r, int32_t x, int32_t y) {
    if (!r) return 0;
    if (x < r->x || y < r->y) return 0;
    return (uint32_t)(x - r->x) < r->w && (uint32_t)(y - r->y) < r->h;
}

static int queue_pop_local(struct desktop_queue *q, struct desktop_msg *out) {
    uint32_t tail;
    if (!q || !out) return 0;
    if (q->tail == q->head) return 0;
    tail = q->tail % DESKTOP_QUEUE_CAP;
    *out = q->msgs[tail];
    q->tail = (q->tail + 1u) % DESKTOP_QUEUE_CAP;
    return 1;
}

static void request_lock(struct desktop_runtime *rt) { while (__sync_lock_test_and_set(&rt->request_lock, 1u)) sys_sleep_ms(1); }
static void request_unlock(struct desktop_runtime *rt) { __sync_lock_release(&rt->request_lock); }

static int request_push(struct desktop_runtime *rt, const struct desktop_msg *m) {
    uint32_t head, next;
    if (!rt || !m) return 0;
    request_lock(rt);
    head = rt->requests.head % DESKTOP_QUEUE_CAP;
    next = (rt->requests.head + 1u) % DESKTOP_QUEUE_CAP;
    if (next == rt->requests.tail) { rt->requests.dropped++; request_unlock(rt); return 0; }
    rt->requests.msgs[head] = *m;
    rt->requests.head = next;
    request_unlock(rt);
    return 1;
}

static uint64_t shm_size(uint32_t w, uint32_t h) { return sizeof(struct desktop_shm_window) + (uint64_t)w * (uint64_t)h * sizeof(uint32_t); }

static int app_sync_slot(struct app_window *app) {
    uint32_t i;
    if (!app || !app->rt) return -1;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) {
        struct desktop_window_slot *s = &app->rt->windows[i];
        if (s->win_id == app->win_id) {
            app->slot = i;
            app->x = s->x;
            app->y = s->y;
            app->w = s->w;
            app->h = s->h;
            str_copy(app->buffer_path, DESKTOP_PATH_MAX, s->buffer_path);
            return 0;
        }
    }
    return -1;
}

static int app_remap(struct app_window *app) {
    uint64_t size;
    if (!app || !app->buffer_path[0]) return -1;
    if (app->shm && app->w && app->h) (void)sys_munmap(app->shm, (size_t)shm_size(app->w, app->h));
    if (app->shm_fd >= 0) sys_close(app->shm_fd);
    app->shm_fd = (int)sys_open(app->buffer_path, O_RDWR);
    if (app->shm_fd < 0) return -1;
    size = shm_size(app->w, app->h);
    app->shm = (struct desktop_shm_window *)sys_mmap(0, (size_t)size, PROT_READ | PROT_WRITE, MAP_FILE, app->shm_fd, 0);
    if (!app->shm || app->shm == (void *)-1) return -1;
    str_copy(app->shm->title, DESKTOP_TITLE_MAX, app->title);
    return 0;
}

static int app_open(struct app_window *app, const char *title, uint32_t w, uint32_t h) {
    struct desktop_msg m;
    uint64_t deadline = monotonic_ms() + 3000ull;
    uint32_t pid = (uint32_t)sys_getpid(), i;
    if (!app) return -1;
    app->rt_fd = (int)sys_open(WM_IPC_PATH, O_RDWR);
    if (app->rt_fd < 0) return -1;
    app->rt = (struct desktop_runtime *)sys_mmap(0, sizeof(struct desktop_runtime), PROT_READ | PROT_WRITE, MAP_FILE, app->rt_fd, 0);
    if (!app->rt || app->rt == (void *)-1) return -1;
    app->shm = 0; app->shm_fd = -1; app->win_id = 0; app->focused = 0; app->last_buttons = 0;
    str_copy(app->title, DESKTOP_TITLE_MAX, title);
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) if (app->rt->windows[i].owner_pid == pid && app->rt->windows[i].win_id) app->rt->windows[i].owner_pid = 0;
    m.cmd = DESKTOP_CMD_CREATE; m.win_id = 0; m.serial = 0; m.flags = 0;
    m.x = 48; m.y = 48; m.w = w; m.h = h; m.arg0 = pid; m.arg1 = 0; m.timestamp_ns = 0;
    if (!request_push(app->rt, &m)) return -1;
    while (monotonic_ms() < deadline) {
        for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) {
            struct desktop_window_slot *s = &app->rt->windows[i];
            if (s->owner_pid == pid && s->win_id != 0 && s->buffer_path[0]) {
                app->win_id = s->win_id;
                app->slot = i;
                app->x = s->x; app->y = s->y; app->w = s->w; app->h = s->h;
                str_copy(app->buffer_path, DESKTOP_PATH_MAX, s->buffer_path);
                if (app_remap(app) == 0) return 0;
            }
        }
        sys_sleep_ms(10);
    }
    return -1;
}

static void app_close(struct app_window *app) {
    struct desktop_msg m;
    if (!app || !app->rt || !app->win_id) return;
    m.cmd = DESKTOP_CMD_DESTROY; m.win_id = app->win_id; m.serial = 0; m.flags = 0;
    m.x = 0; m.y = 0; m.w = 0; m.h = 0; m.arg0 = 0; m.arg1 = 0; m.timestamp_ns = 0;
    (void)request_push(app->rt, &m);
}

static void app_damage(struct app_window *app, int32_t x, int32_t y, uint32_t w, uint32_t h) {
    struct desktop_msg m;
    if (!app || !app->rt || !app->win_id) return;
    m.cmd = DESKTOP_CMD_DAMAGE; m.win_id = app->win_id; m.serial = 0; m.flags = 0;
    m.x = x; m.y = y; m.w = w; m.h = h; m.arg0 = 0; m.arg1 = 0; m.timestamp_ns = 0;
    (void)request_push(app->rt, &m);
}

static int app_local_x(const struct app_window *app, const struct desktop_msg *m) { return m->x - (app->x + 1); }
static int app_local_y(const struct app_window *app, const struct desktop_msg *m) { return m->y - (app->y + 23); }

static int read_file_text(const char *path, char *buf, uint32_t cap) {
    int fd; long n; uint32_t off = 0;
    if (!buf || cap == 0) return -1;
    fd = (int)sys_open(path, O_RDONLY);
    if (fd < 0) { buf[0] = '\0'; return -1; }
    while (off + 1 < cap) {
        n = sys_read(fd, buf + off, cap - off - 1);
        if (n <= 0) break;
        off += (uint32_t)n;
    }
    sys_close(fd);
    buf[off] = '\0';
    return (int)off;
}

static int write_file_text(const char *path, const char *buf) {
    int fd; uint32_t len = str_len(buf), off = 0; long n;
    fd = (int)sys_open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) return -1;
    while (off < len) {
        n = sys_write(fd, buf + off, len - off);
        if (n <= 0) break;
        off += (uint32_t)n;
    }
    sys_close(fd);
    return (off == len) ? 0 : -1;
}

static int copy_file_text(const char *src, const char *dst) {
    char buf[APP_BUF_MAX];
    if (read_file_text(src, buf, (uint32_t)sizeof(buf)) < 0) return -1;
    return write_file_text(dst, buf);
}

static uint32_t parse_u32_local(const char *s) {
    uint32_t v = 0;
    uint32_t i = 0;
    while (s && s[i] >= '0' && s[i] <= '9') {
        v = v * 10u + (uint32_t)(s[i] - '0');
        ++i;
    }
    return v;
}

static int user_name_exists_local(struct gui_user_entry *users, int count, const char *name) {
    int i;
    for (i = 0; i < count; ++i) if (str_eq(users[i].name, name)) return 1;
    return 0;
}

static int user_email_exists_local(struct gui_user_entry *users, int count, const char *email) {
    int i;
    for (i = 0; i < count; ++i) if (users[i].email[0] && str_eq(users[i].email, email)) return 1;
    return 0;
}

static uint32_t next_uid_local(struct gui_user_entry *users, int count) {
    uint32_t uid = 1000;
    int i;
    for (i = 0; i < count; ++i) if (users[i].uid >= uid) uid = users[i].uid + 1u;
    return uid;
}

static int load_accounts_local(struct gui_user_entry *users, int max_users) {
    char buf[4096];
    int count = 0;
    int fd = (int)sys_open(GUI_ACCOUNTS_DB, O_RDONLY);
    uint32_t off = 0;
    long n;
    if (fd >= 0) {
        n = sys_read(fd, buf, sizeof(buf) - 1);
        sys_close(fd);
        if (n > 0) {
            buf[n] = '\0';
            while (buf[off] && count < max_users) {
                char line[256];
                char *fields[8];
                uint32_t li = 0;
                int fi = 0;
                while (buf[off] == '\n' || buf[off] == '\r') ++off;
                while (buf[off] && buf[off] != '\n' && li + 1 < (uint32_t)sizeof(line)) line[li++] = buf[off++];
                while (buf[off] == '\n' || buf[off] == '\r') ++off;
                line[li] = '\0';
                trim(line);
                if (!line[0] || line[0] == '#') continue;
                fields[fi++] = line;
                for (li = 0; line[li] && fi < 8; ++li) {
                    if (line[li] == ':') {
                        line[li] = '\0';
                        fields[fi++] = &line[li + 1];
                    }
                }
                if (fi < 7) continue;
                str_copy(users[count].name, (uint32_t)sizeof(users[count].name), fields[0]);
                users[count].uid = parse_u32_local(fields[1]);
                users[count].gid = parse_u32_local(fields[2]);
                users[count].flags = parse_u32_local(fields[3]);
                str_copy(users[count].email, (uint32_t)sizeof(users[count].email), fields[4]);
                users[count].has_pass = 0;
                if ((int)str_len(fields[5]) == GUI_SALT_LEN * 2 &&
                    (int)str_len(fields[6]) == GUI_HASH_LEN * 2 &&
                    hex_decode_local(fields[5], users[count].salt, GUI_SALT_LEN) &&
                    hex_decode_local(fields[6], users[count].hash, GUI_HASH_LEN)) {
                    users[count].has_pass = 1;
                }
                ++count;
            }
            return count;
        }
    }

    fd = (int)sys_open(GUI_PASSWD_FALLBACK, O_RDONLY);
    if (fd < 0) return 0;
    n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    off = 0;
    while (buf[off] && count < max_users) {
        char line[128];
        char *fields[4];
        uint32_t li = 0;
        int fi = 0;
        while (buf[off] == '\n' || buf[off] == '\r') ++off;
        while (buf[off] && buf[off] != '\n' && li + 1 < (uint32_t)sizeof(line)) line[li++] = buf[off++];
        while (buf[off] == '\n' || buf[off] == '\r') ++off;
        line[li] = '\0';
        trim(line);
        if (!line[0] || line[0] == '#') continue;
        fields[fi++] = line;
        for (li = 0; line[li] && fi < 4; ++li) {
            if (line[li] == ':') {
                line[li] = '\0';
                fields[fi++] = &line[li + 1];
            }
        }
        if (fi < 3) continue;
        str_copy(users[count].name, (uint32_t)sizeof(users[count].name), fields[0]);
        users[count].uid = parse_u32_local(fields[1]);
        users[count].gid = parse_u32_local(fields[2]);
        users[count].flags = (users[count].uid == 0) ? GUI_USER_FLAG_ADMIN : 0;
        users[count].email[0] = '\0';
        users[count].has_pass = 0;
        ++count;
    }
    return count;
}

static int write_accounts_local(struct gui_user_entry *users, int count) {
    int fd;
    int i;
    const char *hdr = "# BitOS accounts v2\n";
    fd = (int)sys_open(GUI_ACCOUNTS_DB, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) return 0;
    (void)sys_write(fd, hdr, str_len(hdr));
    for (i = 0; i < count; ++i) {
        char line[320];
        char salt_hex[GUI_SALT_LEN * 2 + 1];
        char hash_hex[GUI_HASH_LEN * 2 + 1];
        char num[16];
        line[0] = '\0';
        str_append(line, (uint32_t)sizeof(line), users[i].name);
        str_append(line, (uint32_t)sizeof(line), ":");
        u32_to_text(users[i].uid, num, (uint32_t)sizeof(num));
        str_append(line, (uint32_t)sizeof(line), num);
        str_append(line, (uint32_t)sizeof(line), ":");
        u32_to_text(users[i].gid, num, (uint32_t)sizeof(num));
        str_append(line, (uint32_t)sizeof(line), num);
        str_append(line, (uint32_t)sizeof(line), ":");
        u32_to_text(users[i].flags, num, (uint32_t)sizeof(num));
        str_append(line, (uint32_t)sizeof(line), num);
        str_append(line, (uint32_t)sizeof(line), ":");
        str_append(line, (uint32_t)sizeof(line), users[i].email);
        str_append(line, (uint32_t)sizeof(line), ":");
        if (users[i].has_pass) {
            hex_encode_local(users[i].salt, GUI_SALT_LEN, salt_hex, (int)sizeof(salt_hex));
            hex_encode_local(users[i].hash, GUI_HASH_LEN, hash_hex, (int)sizeof(hash_hex));
            str_append(line, (uint32_t)sizeof(line), salt_hex);
            str_append(line, (uint32_t)sizeof(line), ":");
            str_append(line, (uint32_t)sizeof(line), hash_hex);
        }
        str_append(line, (uint32_t)sizeof(line), "\n");
        (void)sys_write(fd, line, str_len(line));
    }
    sys_close(fd);
    return secure_accounts_storage_local();
}

static int write_session_local(const struct gui_user_entry *user) {
    char buf[256];
    buf[0] = '\0';
    if (!user) return -1;
    str_append(buf, (uint32_t)sizeof(buf), "user=");
    str_append(buf, (uint32_t)sizeof(buf), user->name);
    str_append(buf, (uint32_t)sizeof(buf), "\nemail=");
    str_append(buf, (uint32_t)sizeof(buf), user->email);
    str_append(buf, (uint32_t)sizeof(buf), "\n");
    return write_file_text(GUI_SESSION_FILE, buf);
}

static int parse_dir(const char *path, struct file_item *items, uint32_t *count) {
    char buf[APP_BUF_MAX];
    long n; uint32_t off = 0, out = 0;
    if (!items || !count) return -1;
    n = sys_listdir(path, buf, sizeof(buf) - 1);
    if (n < 0) { *count = 0; return -1; }
    buf[n] = '\0';
    while (buf[off] && out < APP_ITEMS_MAX) {
        char tok[64]; uint32_t ti = 0;
        while (buf[off] && is_space(buf[off])) ++off;
        while (buf[off] && !is_space(buf[off]) && ti + 1 < (uint32_t)sizeof(tok)) tok[ti++] = buf[off++];
        tok[ti] = '\0';
        if (!tok[0] || str_eq(tok, ".")) continue;
        str_copy(items[out].name, (uint32_t)sizeof(items[out].name), tok);
        if (str_eq(path, "/")) { str_copy(items[out].path, (uint32_t)sizeof(items[out].path), "/"); str_append(items[out].path, (uint32_t)sizeof(items[out].path), tok); }
        else { str_copy(items[out].path, (uint32_t)sizeof(items[out].path), path); str_append(items[out].path, (uint32_t)sizeof(items[out].path), "/"); str_append(items[out].path, (uint32_t)sizeof(items[out].path), tok); }
        items[out].is_dir = (sys_listdir(items[out].path, buf, 16) >= 0);
        ++out;
    }
    *count = out;
    return 0;
}

static int split_exec(char *line, char **argv, int max_argv, const char *path_arg) {
    int argc = 0;
    while (*line && argc + 1 < max_argv) {
        while (*line && is_space(*line)) ++line;
        if (!*line) break;
        argv[argc++] = line;
        while (*line && !is_space(*line)) ++line;
        if (*line) *line++ = '\0';
    }
    argv[argc] = 0;
    for (int i = 0; i < argc; ++i) if (str_eq(argv[i], "%f")) argv[i] = (char *)(path_arg ? path_arg : "");
    return argc;
}

static long spawn_exec_line(const char *exec_line, const char *path_arg) {
    char line[128];
    char *argv[8];
    int argc;
    long pid;
    str_copy(line, (uint32_t)sizeof(line), exec_line);
    argc = split_exec(line, argv, 8, path_arg);
    if (argc <= 0) return -1;
    pid = sys_fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        (void)sys_execve(argv[0], argc, argv, 0);
        sys_exit(127);
    }
    return pid;
}

static int load_desktop_entries(struct desktop_entry *entries, uint32_t *count) {
    char names[APP_BUF_MAX];
    long n; uint32_t off = 0, out = 0;
    n = sys_listdir("/usr/share/applications", names, sizeof(names) - 1);
    if (n < 0) { *count = 0; return -1; }
    names[n] = '\0';
    while (names[off] && out < APP_DESKTOP_MAX) {
        char name[64], path[APP_PATH_MAX], buf[1024];
        uint32_t ni = 0, i = 0;
        while (names[off] && is_space(names[off])) ++off;
        while (names[off] && !is_space(names[off]) && ni + 1 < (uint32_t)sizeof(name)) name[ni++] = names[off++];
        name[ni] = '\0';
        if (!ends_with(name, ".desktop")) continue;
        str_copy(path, (uint32_t)sizeof(path), "/usr/share/applications/");
        str_append(path, (uint32_t)sizeof(path), name);
        if (read_file_text(path, buf, (uint32_t)sizeof(buf)) < 0) continue;
        entries[out].name[0] = '\0';
        entries[out].exec[0] = '\0';
        entries[out].mime[0] = '\0';
        while (buf[i]) {
            char line[128]; uint32_t li = 0;
            while (buf[i] && buf[i] != '\n' && li + 1 < (uint32_t)sizeof(line)) line[li++] = buf[i++];
            if (buf[i] == '\n') ++i;
            line[li] = '\0'; trim(line);
            if (starts_with(line, "Name=")) str_copy(entries[out].name, (uint32_t)sizeof(entries[out].name), line + 5);
            else if (starts_with(line, "Exec=")) str_copy(entries[out].exec, (uint32_t)sizeof(entries[out].exec), line + 5);
            else if (starts_with(line, "MimeType=")) str_copy(entries[out].mime, (uint32_t)sizeof(entries[out].mime), line + 9);
        }
        if (!entries[out].name[0]) str_copy(entries[out].name, (uint32_t)sizeof(entries[out].name), base_name(name));
        if (entries[out].exec[0]) ++out;
    }
    *count = out;
    return 0;
}

static int resolve_mime_app(const char *path, char *out, uint32_t cap) {
    char buf[1024];
    uint32_t i = 0;
    const char *ext = path_ext(path);
    if (read_file_text("/etc/mimeapps.list", buf, (uint32_t)sizeof(buf)) < 0) return -1;
    while (buf[i]) {
        char line[128], key[32], val[96];
        uint32_t li = 0, j = 0, k = 0;
        while (buf[i] && buf[i] != '\n' && li + 1 < (uint32_t)sizeof(line)) line[li++] = buf[i++];
        if (buf[i] == '\n') ++i;
        line[li] = '\0'; trim(line);
        if (!line[0] || line[0] == '#') continue;
        while (line[j] && line[j] != '=' && k + 1 < (uint32_t)sizeof(key)) key[k++] = line[j++];
        key[k] = '\0';
        if (line[j] != '=') continue;
        str_copy(val, (uint32_t)sizeof(val), line + j + 1);
        trim(key); trim(val);
        if ((ext[0] && str_eq(key, ext)) || (!ext[0] && str_eq(key, "default"))) { str_copy(out, cap, val); return 0; }
    }
    return -1;
}

static void render_frame(struct app_window *app, const char *header, const char *status, const struct button *buttons, uint32_t button_count, uint32_t hot, uint32_t bg) {
    uint32_t i;
    clear_window(app, bg);
    fill_rect(app->shm, 0, 0, app->shm->width, 18, UI_PANEL_ALT);
    draw_text(app->shm, 8, 5, header, UI_TEXT, UI_PANEL_ALT);
    if (status && status[0]) draw_text(app->shm, 8, (int32_t)app->shm->height - 14, status, UI_TEXT_DIM, bg);
    for (i = 0; i < button_count; ++i) draw_button(app->shm, &buttons[i], i == hot);
}

static int common_event(struct app_window *app, const struct desktop_msg *m) {
    struct desktop_msg ack;
    if (!app || !m) return 0;
    if (m->cmd == DESKTOP_EVT_PING) {
        ack.cmd = DESKTOP_CMD_PONG; ack.win_id = app->win_id; ack.serial = m->serial; ack.flags = 0;
        ack.x = 0; ack.y = 0; ack.w = 0; ack.h = 0; ack.arg0 = 0; ack.arg1 = 0; ack.timestamp_ns = 0;
        (void)request_push(app->rt, &ack);
        return 1;
    }
    if (m->cmd == DESKTOP_EVT_CONFIGURE) {
        ack.cmd = DESKTOP_CMD_CONFIGURE_ACK; ack.win_id = app->win_id; ack.serial = m->serial; ack.flags = 0;
        ack.x = 0; ack.y = 0; ack.w = 0; ack.h = 0; ack.arg0 = 0; ack.arg1 = 0; ack.timestamp_ns = 0;
        (void)app_sync_slot(app);
        (void)app_remap(app);
        (void)request_push(app->rt, &ack);
        return 1;
    }
    if (m->cmd == DESKTOP_EVT_FOCUS) { app->focused = m->arg0 ? 1 : 0; return 1; }
    if (m->cmd == DESKTOP_EVT_DESTROYED) return -1;
    return 0;
}

static void editor_load(struct editor_state *ed, const char *path) {
    str_copy(ed->path, (uint32_t)sizeof(ed->path), path);
    if (read_file_text(path, ed->data, (uint32_t)sizeof(ed->data)) < 0) ed->data[0] = '\0';
    ed->len = str_len(ed->data);
    ed->cursor = ed->len;
    ed->dirty = 0;
    str_copy(ed->status, (uint32_t)sizeof(ed->status), "Ready");
}

static void editor_save(struct editor_state *ed) {
    if (write_file_text(ed->path, ed->data) == 0) { ed->dirty = 0; str_copy(ed->status, (uint32_t)sizeof(ed->status), "Saved"); }
    else str_copy(ed->status, (uint32_t)sizeof(ed->status), "Save failed");
}

static void editor_insert(struct editor_state *ed, char c) {
    uint32_t i;
    if (ed->len + 1 >= APP_TEXT_MAX) return;
    for (i = ed->len + 1; i > ed->cursor; --i) ed->data[i] = ed->data[i - 1];
    ed->data[ed->cursor++] = c;
    ed->len++;
    ed->dirty = 1;
}

static void editor_backspace(struct editor_state *ed) {
    uint32_t i;
    if (ed->cursor == 0 || ed->len == 0) return;
    for (i = ed->cursor - 1; i < ed->len; ++i) ed->data[i] = ed->data[i + 1];
    ed->cursor--;
    ed->len--;
    ed->dirty = 1;
}

static void render_editor(struct app_window *app, struct editor_state *ed, const char *header, const struct button *buttons, uint32_t hot) {
    uint32_t i = 0, row = 0; int32_t y = 30;
    char status[128];
    str_copy(status, (uint32_t)sizeof(status), ed->path);
    if (ed->dirty) str_append(status, (uint32_t)sizeof(status), " [modified]");
    if (ed->status[0]) { str_append(status, (uint32_t)sizeof(status), " - "); str_append(status, (uint32_t)sizeof(status), ed->status); }
    render_frame(app, header, status, buttons, 2, hot, UI_BG);
    fill_rect(app->shm, 8, 28, app->shm->width - 16, app->shm->height - 50, UI_PANEL);
    while (ed->data[i] && y + 10 < (int32_t)app->shm->height - 18) {
        char line[96]; uint32_t li = 0;
        while (ed->data[i] && ed->data[i] != '\n' && li + 1 < (uint32_t)sizeof(line)) line[li++] = ed->data[i++];
        if (ed->data[i] == '\n') ++i;
        line[li] = '\0';
        draw_text(app->shm, 12, y, line, UI_TEXT, UI_PANEL);
        y += 10; ++row;
    }
}

static void term_reset(struct pty_state *pt) {
    uint32_t y, x;
    pt->line_count = 1;
    for (y = 0; y < 48; ++y) for (x = 0; x < 96; ++x) pt->lines[y][x] = '\0';
    str_copy(pt->status, (uint32_t)sizeof(pt->status), "PTY running");
}

static void term_add_char(struct pty_state *pt, char c) {
    uint32_t line = pt->line_count ? pt->line_count - 1 : 0, len;
    if (c == '\r') return;
    if (c == '\n') {
        if (pt->line_count < 48) pt->line_count++;
        else {
            for (line = 1; line < 48; ++line) str_copy(pt->lines[line - 1], 96, pt->lines[line]);
            pt->line_count = 48;
        }
        pt->lines[pt->line_count - 1][0] = '\0';
        return;
    }
    if (c == '\b' || c == 127) {
        len = str_len(pt->lines[line]);
        if (len) pt->lines[line][len - 1] = '\0';
        return;
    }
    len = str_len(pt->lines[line]);
    if (len + 1 < 96 && c >= 32) { pt->lines[line][len] = c; pt->lines[line][len + 1] = '\0'; }
}

static void term_pump(struct pty_state *pt) {
    char buf[256]; long n; uint32_t i;
    struct pollfd pfd;
    if (pt->master_fd < 0) return;
    pfd.fd = pt->master_fd; pfd.events = POLLIN; pfd.revents = 0;
    if (sys_poll(&pfd, 1, 0) <= 0 || !(pfd.revents & POLLIN)) return;
    n = sys_read(pt->master_fd, buf, sizeof(buf));
    if (n <= 0) { str_copy(pt->status, (uint32_t)sizeof(pt->status), "Process exited"); return; }
    for (i = 0; i < (uint32_t)n; ++i) term_add_char(pt, buf[i]);
}

static void render_term(struct app_window *app, struct pty_state *pt, const char *header) {
    uint32_t i; int32_t y = 30;
    render_frame(app, header, pt->status, 0, 0, 0, 0x10161Du);
    fill_rect(app->shm, 8, 28, app->shm->width - 16, app->shm->height - 44, 0x0D1117u);
    for (i = 0; i < pt->line_count && y + 10 < (int32_t)app->shm->height - 20; ++i, y += 10) draw_text(app->shm, 12, y, pt->lines[i], UI_TEXT, 0x0D1117u);
}

static int start_pty_child(struct pty_state *pt, const char *path) {
    int slave_fd = -1;
    long pid;
    if (sys_pty_open(&pt->master_fd, &slave_fd) < 0) return -1;
    pid = sys_fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        char *argv[2];
        (void)sys_dup2(slave_fd, 0); (void)sys_dup2(slave_fd, 1); (void)sys_dup2(slave_fd, 2);
        argv[0] = (char *)path; argv[1] = 0;
        (void)sys_execve(path, 1, argv, 0);
        sys_exit(127);
    }
    pt->child_pid = (int)pid;
    return 0;
}

static int button_hot(const struct button *buttons, uint32_t count, int32_t x, int32_t y) {
    uint32_t i;
    for (i = 0; i < count; ++i) if (rect_hit(&buttons[i].r, x, y)) return (int)i;
    return -1;
}

static int run_pty_app(const char *title, const char *path) {
    struct app_window app;
    struct pty_state pt;
    struct desktop_msg m;
    if (app_open(&app, title, 760, 460) < 0) return 1;
    term_reset(&pt);
    pt.master_fd = -1; pt.child_pid = -1;
    if (start_pty_child(&pt, path) < 0) str_copy(pt.status, (uint32_t)sizeof(pt.status), "PTY spawn failed");
    for (;;) {
        term_pump(&pt);
        render_term(&app, &pt, title);
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) {
            int rc = common_event(&app, &m);
            if (rc < 0) { app_close(&app); sys_exit(0); }
            if (m.cmd == DESKTOP_EVT_KEY && !(m.arg1 & INPUT_FLAG_RELEASE) && pt.master_fd >= 0) {
                char c = (char)m.arg0;
                if (c == '\r') c = '\n';
                if (m.arg0 == 8u) c = '\b';
                if ((c >= 32 && c < 127) || c == '\n' || c == '\b' || c == '\t') (void)sys_write(pt.master_fd, &c, 1);
            }
        }
        sys_sleep_ms(16);
    }
    return 0;
}

static int run_editor_app(const char *title, const char *path) {
    struct app_window app;
    struct editor_state ed;
    struct desktop_msg m;
    struct button buttons[2] = { { { 8, 4, 64, 18 }, "Save" }, { { 78, 4, 64, 18 }, "Reload" } };
    if (app_open(&app, title, 700, 420) < 0) return 1;
    editor_load(&ed, path);
    for (;;) {
        int hot = -1;
        render_editor(&app, &ed, title, buttons, (uint32_t)-1);
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) {
            int rc = common_event(&app, &m), lx = app_local_x(&app, &m), ly = app_local_y(&app, &m);
            if (rc < 0) { app_close(&app); sys_exit(0); }
            if (m.cmd == DESKTOP_EVT_POINTER) {
                hot = button_hot(buttons, 2, lx, ly);
                if ((m.arg0 & 1u) && !(app.last_buttons & 1u)) {
                    if (hot == 0) editor_save(&ed);
                    else if (hot == 1) editor_load(&ed, ed.path);
                }
                app.last_buttons = m.arg0;
            } else if (m.cmd == DESKTOP_EVT_KEY && !(m.arg1 & INPUT_FLAG_RELEASE)) {
                char c = (char)m.arg0;
                if (c == '\b' || m.arg0 == 8u || m.arg0 == 127u) editor_backspace(&ed);
                else if (c == '\r' || c == '\n') editor_insert(&ed, '\n');
                else if (c == 19 || c == 'S') editor_save(&ed);
                else if (c >= 32 && c < 127) editor_insert(&ed, c);
            }
        }
        render_editor(&app, &ed, title, buttons, hot >= 0 ? (uint32_t)hot : (uint32_t)-1);
        app_damage(&app, 0, 0, app.w, app.h);
        sys_sleep_ms(16);
    }
}

static int run_clipboard_app(void) { return run_editor_app("Clipboard", "/tmp/clipboard.txt"); }
static int run_text_editor_main(int argc, char **argv) { return run_editor_app("Editor", (argc > 1 && argv[1]) ? argv[1] : "/tmp/note.txt"); }

static void login_clear_secret(char *buf, uint32_t cap) {
    uint32_t i;
    if (!buf || cap == 0) return;
    for (i = 0; i < cap; ++i) buf[i] = '\0';
}

static void login_mask_text(const char *src, char *dst, uint32_t cap) {
    uint32_t i = 0;
    if (!dst || cap == 0) return;
    while (src && src[i] && i + 1 < cap) {
        dst[i] = '*';
        ++i;
    }
    dst[i] = '\0';
}

static void draw_input_box(struct desktop_shm_window *shm, const struct rect *r, const char *label,
                           const char *value, const char *placeholder, int focused, int secret) {
    char shown[GUI_PASS_MAX];
    const char *text = value;
    fill_rect(shm, r->x, r->y, r->w, r->h, UI_PANEL_ALT);
    fill_rect(shm, r->x, r->y, r->w, 1, focused ? UI_ACCENT_ALT : UI_TEXT_DIM);
    fill_rect(shm, r->x, r->y + (int32_t)r->h - 1, r->w, 1, focused ? UI_ACCENT_ALT : UI_TEXT_DIM);
    fill_rect(shm, r->x, r->y, 1, r->h, focused ? UI_ACCENT_ALT : UI_TEXT_DIM);
    fill_rect(shm, r->x + (int32_t)r->w - 1, r->y, 1, r->h, focused ? UI_ACCENT_ALT : UI_TEXT_DIM);
    draw_text(shm, r->x, r->y - 12, label, UI_TEXT_DIM, UI_BG);
    if (secret && value && value[0]) {
        login_mask_text(value, shown, (uint32_t)sizeof(shown));
        text = shown;
    }
    if (text && text[0]) draw_text(shm, r->x + 8, r->y + 10, text, UI_TEXT, UI_PANEL_ALT);
    else draw_text(shm, r->x + 8, r->y + 10, placeholder, UI_TEXT_DIM, UI_PANEL_ALT);
}

static char *login_field_ptr(struct login_state *st) {
    if (!st) return 0;
    if (st->mode_create) {
        if (st->focus_field == 0) return st->username;
        if (st->focus_field == 1) return st->email;
        if (st->focus_field == 2) return st->password;
        if (st->focus_field == 3) return st->confirm;
    } else {
        if (st->focus_field == 0) return st->username;
        if (st->focus_field == 1) return st->password;
    }
    return 0;
}

static uint32_t login_field_cap(const struct login_state *st) {
    if (!st) return 0;
    if (st->mode_create) {
        if (st->focus_field == 0) return (uint32_t)sizeof(st->username);
        if (st->focus_field == 1) return (uint32_t)sizeof(st->email);
        if (st->focus_field == 2) return (uint32_t)sizeof(st->password);
        if (st->focus_field == 3) return (uint32_t)sizeof(st->confirm);
    } else {
        if (st->focus_field == 0) return (uint32_t)sizeof(st->username);
        if (st->focus_field == 1) return (uint32_t)sizeof(st->password);
    }
    return 0;
}

static void login_focus_next(struct login_state *st) {
    int limit;
    if (!st) return;
    limit = st->mode_create ? 4 : 2;
    st->focus_field = (st->focus_field + 1) % limit;
}

static int login_lookup_user(struct login_state *st, const char *name_or_email) {
    int i;
    if (!st || !name_or_email || !name_or_email[0]) return -1;
    for (i = 0; i < st->user_count; ++i) {
        if (str_eq(st->users[i].name, name_or_email) ||
            (st->users[i].email[0] && str_eq(st->users[i].email, name_or_email))) {
            return i;
        }
    }
    return -1;
}

static int login_finish_session(const struct gui_user_entry *user) {
    if (!user) return -1;
    (void)write_session_local(user);
    (void)sys_setgid(user->gid);
    (void)sys_setuid(user->uid);
    (void)spawn_exec_line("/bin/launcher", 0);
    (void)spawn_exec_line("/bin/terminal", 0);
    (void)spawn_exec_line("/bin/files", 0);
    return 0;
}

static int login_submit(struct login_state *st) {
    if (!st) return 0;
    if (st->mode_create) {
        struct gui_user_entry *u;
        uint32_t uid;
        if (st->user_count >= GUI_MAX_USERS) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Account limit reached");
            return 0;
        }
        if (!validate_username_local(st->username)) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Invalid username");
            return 0;
        }
        if (!validate_email_local(st->email)) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Invalid email");
            return 0;
        }
        if (user_name_exists_local(st->users, st->user_count, st->username)) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Username already exists");
            return 0;
        }
        if (user_email_exists_local(st->users, st->user_count, st->email)) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Email already exists");
            return 0;
        }
        if (str_len(st->password) < 6) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Password must be at least 6 chars");
            return 0;
        }
        if (!str_eq(st->password, st->confirm)) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Passwords do not match");
            return 0;
        }
        u = &st->users[st->user_count];
        str_copy(u->name, (uint32_t)sizeof(u->name), st->username);
        str_copy(u->email, (uint32_t)sizeof(u->email), st->email);
        uid = (st->user_count == 0) ? 0u : next_uid_local(st->users, st->user_count);
        u->uid = uid;
        u->gid = uid;
        u->flags = (st->user_count == 0) ? GUI_USER_FLAG_ADMIN : 0u;
        if (!read_urandom_local(u->salt, GUI_SALT_LEN)) {
            uint64_t t = monotonic_ms();
            uint32_t i;
            for (i = 0; i < GUI_SALT_LEN; ++i) u->salt[i] = (uint8_t)(t >> ((i * 3u) & 31u));
        }
        hash_password_local(u->salt, st->password, u->hash);
        u->has_pass = 1;
        if (!write_accounts_local(st->users, st->user_count + 1)) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Failed to write account database");
            return 0;
        }
        st->user_count++;
        st->mode_create = 0;
        st->focus_field = 1;
        login_clear_secret(st->password, (uint32_t)sizeof(st->password));
        login_clear_secret(st->confirm, (uint32_t)sizeof(st->confirm));
        str_copy(st->status, (uint32_t)sizeof(st->status), "Account created. Sign in.");
        return 0;
    }

    {
        int idx = login_lookup_user(st, st->username);
        uint8_t hash[GUI_HASH_LEN];
        if (idx < 0) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Unknown user");
            return 0;
        }
        if (!st->users[idx].has_pass) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Account has no password");
            return 0;
        }
        hash_password_local(st->users[idx].salt, st->password, hash);
        if (!bytes_eq(hash, st->users[idx].hash, GUI_HASH_LEN)) {
            str_copy(st->status, (uint32_t)sizeof(st->status), "Incorrect password");
            return 0;
        }
        str_copy(st->status, (uint32_t)sizeof(st->status), "Login successful");
        return login_finish_session(&st->users[idx]) == 0;
    }
}

static void login_set_secure(struct login_state *st, int enabled) {
    struct input_secure_request req;
    if (!st || st->secure_fd < 0) return;
    req.enabled = enabled ? 1u : 0u;
    req.reserved = 0u;
    (void)sys_ioctl(st->secure_fd, INPUT_IOCTL_SET_SECURE, &req);
}

static void render_dlogin(struct app_window *app, struct login_state *st, const struct rect *fields, const struct button *buttons, uint32_t hot) {
    char subtitle[128];
    render_frame(app,
                 st->mode_create ? "BitOS Login - Create Account" : "BitOS Login",
                 st->status,
                 buttons,
                 2,
                 hot,
                 UI_BG);
    fill_rect(app->shm, 22, 38, app->shm->width - 44, app->shm->height - 92, UI_PANEL);
    draw_text(app->shm, 38, 56, st->mode_create ? "Create a local BitOS account" : "Sign in to BitOS", UI_TEXT, UI_PANEL);
    subtitle[0] = '\0';
    if (st->user_count == 0) str_copy(subtitle, (uint32_t)sizeof(subtitle), "First account becomes administrator. Passwords are salted and hashed.");
    else str_copy(subtitle, (uint32_t)sizeof(subtitle), "Use mouse or Tab. Account storage is root-owned.");
    draw_text(app->shm, 38, 70, subtitle, UI_TEXT_DIM, UI_PANEL);
    draw_input_box(app->shm, &fields[0], "Username", st->username, "username or email", st->focus_field == 0, 0);
    if (st->mode_create) {
        draw_input_box(app->shm, &fields[1], "Email", st->email, "name@example.com", st->focus_field == 1, 0);
        draw_input_box(app->shm, &fields[2], "Password", st->password, "minimum 6 characters", st->focus_field == 2, 1);
        draw_input_box(app->shm, &fields[3], "Confirm Password", st->confirm, "repeat password", st->focus_field == 3, 1);
        draw_text(app->shm, 38, 312, "Stored in /var/accounts/users.db with root-only permissions.", UI_TEXT_DIM, UI_PANEL);
    } else {
        draw_input_box(app->shm, &fields[2], "Password", st->password, "password", st->focus_field == 1, 1);
        draw_text(app->shm, 38, 278, "Successful sign-in starts launcher, terminal, and files.", UI_TEXT_DIM, UI_PANEL);
    }
}

static int run_dlogin_app(void) {
    struct app_window app;
    struct login_state st;
    struct desktop_msg m;
    struct rect fields[4] = {
        { 38, 112, 280, 34 },
        { 334, 112, 250, 34 },
        { 38, 182, 280, 34 },
        { 334, 182, 250, 34 }
    };
    struct button buttons[2] = {
        { { 38, 346, 140, 26 }, "Sign In" },
        { { 190, 346, 170, 26 }, "Create Account" }
    };
    if (app_open(&app, "Login", 640, 420) < 0) return 1;
    __builtin_memset(&st, 0, sizeof(st));
    st.secure_fd = (int)sys_open("/dev/input", O_RDONLY | O_NONBLOCK);
    st.user_count = load_accounts_local(st.users, GUI_MAX_USERS);
    st.mode_create = (st.user_count == 0) ? 1 : 0;
    st.focus_field = 0;
    str_copy(st.status, (uint32_t)sizeof(st.status), st.mode_create ? "Create the first account to unlock the desktop" : "Enter your username and password");
    login_set_secure(&st, 1);
    for (;;) {
        int hot = -1;
        if (st.mode_create) {
            str_copy(buttons[0].label, (uint32_t)sizeof(buttons[0].label), "Create");
            str_copy(buttons[1].label, (uint32_t)sizeof(buttons[1].label), (st.user_count > 0) ? "Back To Login" : "Create First Account");
        } else {
            str_copy(buttons[0].label, (uint32_t)sizeof(buttons[0].label), "Sign In");
            str_copy(buttons[1].label, (uint32_t)sizeof(buttons[1].label), "Create Account");
        }
        render_dlogin(&app, &st, fields, buttons, hot);
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) {
            int rc = common_event(&app, &m);
            int lx = app_local_x(&app, &m);
            int ly = app_local_y(&app, &m);
            if (rc < 0) {
                login_set_secure(&st, 0);
                if (st.secure_fd >= 0) sys_close(st.secure_fd);
                app_close(&app);
                sys_exit(0);
            }
            if (m.cmd == DESKTOP_EVT_POINTER) {
                hot = button_hot(buttons, 2, lx, ly);
                if ((m.arg0 & 1u) && !(app.last_buttons & 1u)) {
                    if (rect_hit(&fields[0], lx, ly)) st.focus_field = 0;
                    else if (st.mode_create && rect_hit(&fields[1], lx, ly)) st.focus_field = 1;
                    else if (rect_hit(&fields[2], lx, ly)) st.focus_field = st.mode_create ? 2 : 1;
                    else if (st.mode_create && rect_hit(&fields[3], lx, ly)) st.focus_field = 3;
                    else if (hot == 0) {
                        if (login_submit(&st)) {
                            login_set_secure(&st, 0);
                            if (st.secure_fd >= 0) sys_close(st.secure_fd);
                            login_clear_secret(st.password, (uint32_t)sizeof(st.password));
                            login_clear_secret(st.confirm, (uint32_t)sizeof(st.confirm));
                            app_close(&app);
                            sys_exit(0);
                        }
                    } else if (hot == 1 && st.user_count > 0) {
                        st.mode_create = !st.mode_create;
                        st.focus_field = 0;
                        login_clear_secret(st.password, (uint32_t)sizeof(st.password));
                        login_clear_secret(st.confirm, (uint32_t)sizeof(st.confirm));
                        str_copy(st.status, (uint32_t)sizeof(st.status), st.mode_create ? "Create a new account" : "Enter your username and password");
                    }
                }
                app.last_buttons = m.arg0;
            } else if (m.cmd == DESKTOP_EVT_KEY && !(m.arg1 & INPUT_FLAG_RELEASE)) {
                char *field = login_field_ptr(&st);
                uint32_t cap = login_field_cap(&st);
                uint32_t len = field ? str_len(field) : 0;
                if (m.arg0 == '\t') {
                    login_focus_next(&st);
                } else if (m.arg0 == '\r' || m.arg0 == '\n') {
                    if (login_submit(&st)) {
                        login_set_secure(&st, 0);
                        if (st.secure_fd >= 0) sys_close(st.secure_fd);
                        login_clear_secret(st.password, (uint32_t)sizeof(st.password));
                        login_clear_secret(st.confirm, (uint32_t)sizeof(st.confirm));
                        app_close(&app);
                        sys_exit(0);
                    }
                } else if ((m.arg0 == 8u || m.arg0 == 127u) && field && len > 0) {
                    field[len - 1] = '\0';
                } else if (field && cap > 1 && m.arg0 >= 32u && m.arg0 < 127u && len + 1 < cap) {
                    field[len] = (char)m.arg0;
                    field[len + 1] = '\0';
                }
            }
        }
        sys_sleep_ms(16);
    }
}

static void uitk_present(struct app_window *app, struct uitk_tree *ui) {
    if (!app || !app->shm || !ui) return;
    ui->width = app->shm->width;
    ui->height = app->shm->height;
    uitk_layout(ui);
    uitk_render(ui, app->shm);
    app_damage(app, 0, 0, app->w, app->h);
}

static void append_line(char *buf, uint32_t cap, const char *line) {
    str_append(buf, cap, line);
    str_append(buf, cap, "\n");
}

static void launcher_entries_text(const struct desktop_entry *entries, uint32_t count, const char *filter, char *out, uint32_t cap, uint32_t *map, uint32_t *mapped) {
    uint32_t i;
    uint32_t out_count = 0;
    out[0] = '\0';
    for (i = 0; i < count; ++i) {
        int include = 1;
        uint32_t j;
        if (filter && filter[0]) {
            include = 0;
            for (j = 0; entries[i].name[j]; ++j) {
                uint32_t k = 0;
                while (filter[k] && entries[i].name[j + k] == filter[k]) ++k;
                if (!filter[k]) { include = 1; break; }
            }
        }
        if (!include) continue;
        if (out_count < APP_DESKTOP_MAX) map[out_count] = i;
        ++out_count;
        append_line(out, cap, entries[i].name);
    }
    if (!out[0]) append_line(out, cap, "No matches");
    *mapped = out_count;
}

static int run_settings_app(void) {
    struct app_window app;
    struct desktop_msg m;
    struct fb_info fb;
    struct input_stats st;
    struct uitk_tree ui;
    char metrics[512];
    char notes[192];
    char num[32];
    char saved_theme[24] = "classic";
    int main_col, bar, body, left_col, right_scroll;
    int icon_id, title_id, save_id, classic_id, slate_id, amber_id;
    int theme_label_id, theme_list_id, name_label_id, name_input_id;
    int table_id, notes_label_id, notes_id, dialog_id, dialog_msg_id, dialog_ok_id;
    int show_dialog = 0;
    if (app_open(&app, "Settings", 720, 440) < 0) return 1;
    uitk_init(&ui, app.w, app.h, 0);
    main_col = uitk_add_column(&ui, ui.root, "settings.main");
    uitk_set_padding(&ui, main_col, 8, 8);
    bar = uitk_add_row(&ui, main_col, "settings.bar");
    uitk_set_flags(&ui, bar, UITK_FLAG_VISIBLE | UITK_FLAG_HEADER);
    icon_id = uitk_add_icon(&ui, bar, "gear");
    title_id = uitk_add_label(&ui, bar, "Desktop Settings");
    uitk_set_flags(&ui, title_id, UITK_FLAG_VISIBLE | UITK_FLAG_ELLIPSIS);
    save_id = uitk_add_button(&ui, bar, "Save");
    classic_id = uitk_add_button(&ui, bar, "Classic");
    slate_id = uitk_add_button(&ui, bar, "Slate");
    amber_id = uitk_add_button(&ui, bar, "Amber");
    body = uitk_add_row(&ui, main_col, "settings.body");
    left_col = uitk_add_column(&ui, body, "settings.left");
    theme_label_id = uitk_add_label(&ui, left_col, "Theme presets and desktop identity");
    uitk_set_flags(&ui, theme_label_id, UITK_FLAG_VISIBLE | UITK_FLAG_WRAP);
    theme_list_id = uitk_add_list(&ui, left_col, "Classic\nSlate\nAmber");
    name_label_id = uitk_add_label(&ui, left_col, "Theme name");
    name_input_id = uitk_add_input(&ui, left_col, "theme name", saved_theme);
    notes_label_id = uitk_add_label(&ui, left_col, "Session notes");
    right_scroll = uitk_add_scroll(&ui, body, "settings.scroll");
    table_id = uitk_add_table(&ui, right_scroll, "Metric|Value");
    notes_id = uitk_add_textarea(&ui, right_scroll, "notes", "BitOS desktop preferences\n- framebuffer active\n- toolkit wired into desktop apps");
    dialog_id = uitk_add_dialog(&ui, ui.root, "Saved");
    dialog_msg_id = uitk_add_label(&ui, dialog_id, "Theme configuration written to /tmp/bitos-theme.conf");
    dialog_ok_id = uitk_add_button(&ui, dialog_id, "OK");
    uitk_set_flags(&ui, dialog_id, 0);
    uitk_set_a11y(&ui, save_id, UITK_ROLE_BUTTON, "Save theme", 0);
    uitk_set_a11y(&ui, theme_list_id, UITK_ROLE_LIST, "Theme preset list", 0);
    for (;;) {
        int action;
        metrics[0] = '\0';
        notes[0] = '\0';
        (void)sys_fb_info(&fb);
        {
            int fd = (int)sys_open("/dev/input", O_RDONLY | O_NONBLOCK);
            if (fd >= 0) {
                if (sys_ioctl(fd, INPUT_IOCTL_GET_STATS, &st) != 0) st.total_events = 0;
                sys_close(fd);
            } else {
                st.total_events = 0;
                st.reader_dropped_events = 0;
                st.secure_mode = 0;
                st.accel_profile = 0;
            }
        }
        str_append(metrics, (uint32_t)sizeof(metrics), "Display|"); u32_to_text(fb.width, num, (uint32_t)sizeof(num)); str_append(metrics, (uint32_t)sizeof(metrics), num); str_append(metrics, (uint32_t)sizeof(metrics), "x"); u32_to_text(fb.height, num, (uint32_t)sizeof(num)); append_line(metrics, (uint32_t)sizeof(metrics), num);
        str_append(metrics, (uint32_t)sizeof(metrics), "Pitch / BPP|"); u32_to_text(fb.pitch, num, (uint32_t)sizeof(num)); str_append(metrics, (uint32_t)sizeof(metrics), num); str_append(metrics, (uint32_t)sizeof(metrics), " / "); u32_to_text(fb.bpp, num, (uint32_t)sizeof(num)); append_line(metrics, (uint32_t)sizeof(metrics), num);
        str_append(metrics, (uint32_t)sizeof(metrics), "Input events|"); u64_to_text(st.total_events, num, (uint32_t)sizeof(num)); append_line(metrics, (uint32_t)sizeof(metrics), num);
        str_append(metrics, (uint32_t)sizeof(metrics), "Dropped|"); u64_to_text(st.reader_dropped_events, num, (uint32_t)sizeof(num)); append_line(metrics, (uint32_t)sizeof(metrics), num);
        str_append(metrics, (uint32_t)sizeof(metrics), "Secure mode|"); append_line(metrics, (uint32_t)sizeof(metrics), st.secure_mode ? "on" : "off");
        str_append(notes, (uint32_t)sizeof(notes), "Current preset: "); str_append(notes, (uint32_t)sizeof(notes), saved_theme); str_append(notes, (uint32_t)sizeof(notes), "\nPointer accel profile: "); u32_to_text(st.accel_profile, num, (uint32_t)sizeof(num)); str_append(notes, (uint32_t)sizeof(notes), num);
        uitk_set_text(&ui, table_id, metrics);
        uitk_set_value(&ui, notes_id, notes);
        uitk_set_value(&ui, name_input_id, saved_theme);
        if (show_dialog) uitk_set_flags(&ui, dialog_id, UITK_FLAG_VISIBLE | UITK_FLAG_MODAL);
        else uitk_set_flags(&ui, dialog_id, 0);
        clear_window(&app, UI_BG);
        uitk_present(&app, &ui);
        if (show_dialog) {
            ui.nodes[dialog_id].rect.x = (int32_t)(app.w / 2u) - 180;
            ui.nodes[dialog_id].rect.y = (int32_t)(app.h / 2u) - 70;
            ui.nodes[dialog_id].rect.w = 360;
            ui.nodes[dialog_id].rect.h = 140;
            ui.nodes[dialog_msg_id].rect.x = ui.nodes[dialog_id].rect.x + 10;
            ui.nodes[dialog_msg_id].rect.y = ui.nodes[dialog_id].rect.y + 34;
            ui.nodes[dialog_msg_id].rect.w = ui.nodes[dialog_id].rect.w - 20;
            ui.nodes[dialog_msg_id].rect.h = 40;
            ui.nodes[dialog_ok_id].rect.x = ui.nodes[dialog_id].rect.x + (int32_t)(ui.nodes[dialog_id].rect.w / 2u) - 40;
            ui.nodes[dialog_ok_id].rect.y = ui.nodes[dialog_id].rect.y + 92;
            ui.nodes[dialog_ok_id].rect.w = 80;
            ui.nodes[dialog_ok_id].rect.h = 24;
            clear_window(&app, UI_BG);
            uitk_render(&ui, app.shm);
            app_damage(&app, 0, 0, app.w, app.h);
        }
        while (queue_pop_local(&app.shm->events, &m)) {
            int rc = common_event(&app, &m);
            if (rc < 0) { app_close(&app); sys_exit(0); }
            if (m.cmd == DESKTOP_EVT_POINTER) {
                uitk_pointer(&ui, app_local_x(&app, &m), app_local_y(&app, &m), m.arg0, 0);
            } else if (m.cmd == DESKTOP_EVT_KEY) {
                uitk_key(&ui, m.arg0, m.arg1, 0);
            }
        }
        while ((action = uitk_take_action(&ui)) >= 0) {
            if (action == classic_id) str_copy(saved_theme, (uint32_t)sizeof(saved_theme), "classic");
            else if (action == slate_id) str_copy(saved_theme, (uint32_t)sizeof(saved_theme), "slate");
            else if (action == amber_id) str_copy(saved_theme, (uint32_t)sizeof(saved_theme), "amber");
            else if (action == theme_list_id) {
                int sel = ui.nodes[theme_list_id].selection;
                if (sel == 0) str_copy(saved_theme, (uint32_t)sizeof(saved_theme), "classic");
                else if (sel == 1) str_copy(saved_theme, (uint32_t)sizeof(saved_theme), "slate");
                else if (sel == 2) str_copy(saved_theme, (uint32_t)sizeof(saved_theme), "amber");
            } else if (action == save_id) {
                char conf[64];
                str_copy(conf, (uint32_t)sizeof(conf), "theme=");
                str_append(conf, (uint32_t)sizeof(conf), saved_theme);
                str_append(conf, (uint32_t)sizeof(conf), "\n");
                (void)write_file_text("/tmp/bitos-theme.conf", conf);
                show_dialog = 1;
            } else if (action == dialog_ok_id) {
                show_dialog = 0;
            }
        }
        sys_sleep_ms(16);
    }
}

static int run_launcher_app(void) {
    struct app_window app;
    struct desktop_msg m;
    struct desktop_entry entries[APP_DESKTOP_MAX];
    struct uitk_tree ui;
    char list_text[APP_BUF_MAX];
    char detail_text[APP_BUF_MAX];
    uint32_t map[APP_DESKTOP_MAX];
    uint32_t count = 0;
    uint32_t mapped = 0;
    int main_col, bar, toolbar, title_icon_id, title_id, launch_id, menu_toggle_id;
    int filter_id, list_id, detail_table_id, hint_id, menu_id;
    int show_menu = 0;
    if (app_open(&app, "Launcher", 620, 420) < 0) return 1;
    (void)load_desktop_entries(entries, &count);
    uitk_init(&ui, app.w, app.h, 0);
    main_col = uitk_add_column(&ui, ui.root, "launcher.main");
    uitk_set_padding(&ui, main_col, 8, 8);
    bar = uitk_add_menubar(&ui, main_col, "launcher.bar");
    toolbar = uitk_add_row(&ui, bar, "launcher.toolbar");
    title_icon_id = uitk_add_icon(&ui, toolbar, "app");
    title_id = uitk_add_label(&ui, toolbar, "Application Launcher");
    launch_id = uitk_add_button(&ui, toolbar, "Launch");
    menu_toggle_id = uitk_add_button(&ui, toolbar, "Menu");
    filter_id = uitk_add_input(&ui, main_col, "filter apps", "");
    hint_id = uitk_add_label(&ui, main_col, "Use Tab to move focus, type to filter, Enter to launch.");
    uitk_set_flags(&ui, hint_id, UITK_FLAG_VISIBLE | UITK_FLAG_WRAP | UITK_FLAG_ELLIPSIS);
    list_id = uitk_add_list(&ui, main_col, "");
    detail_table_id = uitk_add_table(&ui, main_col, "Field|Value");
    menu_id = uitk_add_context_menu(&ui, ui.root, "Launch selected\nOpen Terminal\nOpen Files");
    uitk_set_flags(&ui, menu_id, 0);
    uitk_set_a11y(&ui, list_id, UITK_ROLE_LIST, "Launcher app list", 0);
    for (;;) {
        int action;
        uint32_t sel;
        launcher_entries_text(entries, count, ui.nodes[filter_id].value, list_text, (uint32_t)sizeof(list_text), map, &mapped);
        uitk_set_text(&ui, list_id, list_text);
        sel = (ui.nodes[list_id].selection >= 0) ? (uint32_t)ui.nodes[list_id].selection : 0;
        if (sel >= mapped && mapped) sel = mapped - 1u;
        if (mapped && sel < mapped) {
            uint32_t entry_idx = map[sel];
            detail_text[0] = '\0';
            str_append(detail_text, (uint32_t)sizeof(detail_text), "Name|"); append_line(detail_text, (uint32_t)sizeof(detail_text), entries[entry_idx].name);
            str_append(detail_text, (uint32_t)sizeof(detail_text), "Exec|"); append_line(detail_text, (uint32_t)sizeof(detail_text), entries[entry_idx].exec);
            str_append(detail_text, (uint32_t)sizeof(detail_text), "Mime|"); append_line(detail_text, (uint32_t)sizeof(detail_text), entries[entry_idx].mime[0] ? entries[entry_idx].mime : "-");
        } else {
            str_copy(detail_text, (uint32_t)sizeof(detail_text), "Field|Value\nState|No desktop entries");
        }
        uitk_set_text(&ui, detail_table_id, detail_text);
        if (show_menu) uitk_set_flags(&ui, menu_id, UITK_FLAG_VISIBLE | UITK_FLAG_CONTEXT | UITK_FLAG_FOCUSABLE);
        else uitk_set_flags(&ui, menu_id, 0);
        clear_window(&app, UI_BG);
        uitk_present(&app, &ui);
        if (show_menu) {
            ui.nodes[menu_id].rect.x = (int32_t)app.w - 172;
            ui.nodes[menu_id].rect.y = 34;
            ui.nodes[menu_id].rect.w = 160;
            ui.nodes[menu_id].rect.h = 76;
            clear_window(&app, UI_BG);
            uitk_render(&ui, app.shm);
            app_damage(&app, 0, 0, app.w, app.h);
        }
        while (queue_pop_local(&app.shm->events, &m)) {
            int rc = common_event(&app, &m);
            if (rc < 0) { app_close(&app); sys_exit(0); }
            if (m.cmd == DESKTOP_EVT_POINTER) {
                uitk_pointer(&ui, app_local_x(&app, &m), app_local_y(&app, &m), m.arg0, 0);
            } else if (m.cmd == DESKTOP_EVT_KEY) {
                uitk_key(&ui, m.arg0, m.arg1, 0);
            }
        }
        while ((action = uitk_take_action(&ui)) >= 0) {
            sel = (ui.nodes[list_id].selection >= 0) ? (uint32_t)ui.nodes[list_id].selection : 0u;
            if (sel >= mapped && mapped) sel = mapped - 1u;
            if (action == menu_toggle_id) {
                show_menu = !show_menu;
            } else if (action == launch_id || action == list_id) {
                if (mapped && sel < mapped) (void)spawn_exec_line(entries[map[sel]].exec, 0);
            } else if (action == menu_id) {
                int menu_sel = ui.nodes[menu_id].selection;
                if (menu_sel == 0 && mapped && sel < mapped) (void)spawn_exec_line(entries[map[sel]].exec, 0);
                else if (menu_sel == 1) (void)spawn_exec_line("/bin/terminal", 0);
                else if (menu_sel == 2) (void)spawn_exec_line("/bin/files", 0);
                show_menu = 0;
            }
        }
        sys_sleep_ms(16);
    }
}

static int run_files_app(void) {
    struct app_window app; struct desktop_msg m; struct file_item items[APP_ITEMS_MAX];
    struct button buttons[5] = { { { 8, 4, 56, 18 }, "Up" }, { { 68, 4, 64, 18 }, "Open" }, { { 136, 4, 64, 18 }, "Copy" }, { { 204, 4, 64, 18 }, "Delete" }, { { 272, 4, 72, 18 }, "Refresh" } };
    char cwd[APP_PATH_MAX] = "/home/guest", status[96] = "Browser ready", dst[APP_PATH_MAX];
    uint32_t count = 0, sel = 0;
    if (app_open(&app, "Files", 540, 380) < 0) return 1;
    (void)parse_dir(cwd, items, &count);
    for (;;) {
        uint32_t i; int hot = -1;
        render_frame(&app, cwd, status, buttons, 5, (uint32_t)-1, UI_BG);
        fill_rect(app.shm, 8, 28, app.shm->width - 16, app.shm->height - 44, UI_PANEL);
        for (i = 0; i < count && i < 24; ++i) {
            uint32_t bg = (i == sel) ? UI_ACCENT : UI_PANEL;
            fill_rect(app.shm, 12, 34 + (int32_t)(i * 12), app.shm->width - 24, 10, bg);
            draw_text(app.shm, 16, 35 + (int32_t)(i * 12), items[i].name, items[i].is_dir ? UI_OK : UI_TEXT, bg);
        }
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) {
            int rc = common_event(&app, &m), lx = app_local_x(&app, &m), ly = app_local_y(&app, &m);
            if (rc < 0) { app_close(&app); sys_exit(0); }
            if (m.cmd == DESKTOP_EVT_POINTER) {
                hot = button_hot(buttons, 5, lx, ly);
                if (lx >= 12 && lx < (int32_t)app.w - 12 && ly >= 34) { int row = (ly - 34) / 12; if (row >= 0 && (uint32_t)row < count) sel = (uint32_t)row; }
                if ((m.arg0 & 1u) && !(app.last_buttons & 1u)) {
                    if (hot == 0) {
                        const char *b = base_name(cwd);
                        if (!str_eq(cwd, "/")) { cwd[str_len(cwd) - str_len(b)] = '\0'; if (cwd[str_len(cwd) - 1] == '/') cwd[str_len(cwd) - 1] = '\0'; if (!cwd[0]) str_copy(cwd, (uint32_t)sizeof(cwd), "/"); }
                        (void)parse_dir(cwd, items, &count); sel = 0;
                    } else if (hot == 1 && sel < count) {
                        if (items[sel].is_dir) { str_copy(cwd, (uint32_t)sizeof(cwd), items[sel].path); (void)parse_dir(cwd, items, &count); sel = 0; }
                        else {
                            char exec[96];
                            if (resolve_mime_app(items[sel].path, exec, (uint32_t)sizeof(exec)) == 0) (void)spawn_exec_line(exec, items[sel].path);
                            else (void)spawn_exec_line("/bin/editor %f", items[sel].path);
                        }
                    } else if (hot == 2 && sel < count && !items[sel].is_dir) {
                        str_copy(dst, (uint32_t)sizeof(dst), "/tmp/");
                        str_append(dst, (uint32_t)sizeof(dst), items[sel].name);
                        str_append(dst, (uint32_t)sizeof(dst), ".copy");
                        str_copy(status, (uint32_t)sizeof(status), copy_file_text(items[sel].path, dst) == 0 ? "Copied to /tmp" : "Copy failed");
                    } else if (hot == 3 && sel < count && !items[sel].is_dir) {
                        str_copy(status, (uint32_t)sizeof(status), write_file_text(items[sel].path, "") == 0 ? "Deleted (truncated)" : "Delete failed");
                        (void)parse_dir(cwd, items, &count);
                    } else if (hot == 4) {
                        (void)parse_dir(cwd, items, &count);
                    }
                }
                app.last_buttons = m.arg0;
            }
        }
        sys_sleep_ms(16);
    }
}

static int write_ppm(const char *path, const uint32_t *pix, uint32_t w, uint32_t h) {
    int fd; char hdr[64]; uint32_t n = 0, i;
    fd = (int)sys_open(path, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd < 0) return -1;
    str_copy(hdr, (uint32_t)sizeof(hdr), "P6\n"); u32_to_text(w, hdr + str_len(hdr), (uint32_t)(sizeof(hdr) - str_len(hdr))); str_append(hdr, (uint32_t)sizeof(hdr), " "); u32_to_text(h, hdr + str_len(hdr), (uint32_t)(sizeof(hdr) - str_len(hdr))); str_append(hdr, (uint32_t)sizeof(hdr), "\n255\n");
    n = str_len(hdr); (void)sys_write(fd, hdr, n);
    for (i = 0; i < w * h; ++i) { uint8_t rgb[3] = { (uint8_t)((pix[i] >> 16) & 0xFFu), (uint8_t)((pix[i] >> 8) & 0xFFu), (uint8_t)(pix[i] & 0xFFu) }; (void)sys_write(fd, rgb, 3); }
    sys_close(fd); return 0;
}

static int run_screenshot_app(int argc, char **argv) {
    struct app_window app; struct desktop_msg m; struct fb_mode_info mode; void *fb; char path[96], num[32], status[96];
    struct button buttons[2] = { { { 8, 4, 72, 18 }, "Whole" }, { { 86, 4, 72, 18 }, "Window" } };
    if (app_open(&app, "Screenshot", 380, 180) < 0) return 1;
    str_copy(status, (uint32_t)sizeof(status), "Choose Whole or Window");
    for (;;) {
        int hot = -1;
        render_frame(&app, "Screenshot Utility", status, buttons, 2, (uint32_t)-1, UI_BG);
        draw_text(app.shm, 12, 40, "Writes a PPM file to /tmp.", UI_TEXT, UI_BG);
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) {
            int rc = common_event(&app, &m), lx = app_local_x(&app, &m), ly = app_local_y(&app, &m);
            if (rc < 0) { app_close(&app); sys_exit(0); }
            if (m.cmd == DESKTOP_EVT_POINTER) {
                hot = button_hot(buttons, 2, lx, ly);
                if ((m.arg0 & 1u) && !(app.last_buttons & 1u) && hot >= 0) {
                    str_copy(path, (uint32_t)sizeof(path), "/tmp/screenshot-"); u64_to_text(monotonic_ms(), num, (uint32_t)sizeof(num)); str_append(path, (uint32_t)sizeof(path), num); str_append(path, (uint32_t)sizeof(path), ".ppm");
                    if (hot == 0 && sys_ioctl((int)sys_open("/dev/fb0", O_RDONLY), FB_IOCTL_GET_MODE, &mode) == 0) {
                        int fd = (int)sys_open("/dev/fb0", O_RDWR); fb = sys_mmap(0, (size_t)mode.size_bytes, PROT_READ | PROT_WRITE, MAP_FILE, fd, 0); if (fb && fb != (void *)-1) (void)write_ppm(path, (const uint32_t *)fb, mode.width, mode.height); if (fd >= 0) sys_close(fd);
                    } else if (hot == 1 && app.shm) (void)write_ppm(path, app.shm->pixels, app.shm->width, app.shm->height);
                    str_copy(status, (uint32_t)sizeof(status), path);
                }
                app.last_buttons = m.arg0;
            }
        }
        if (argc > 1 && argv[1] && str_eq(argv[1], "whole")) { argc = 1; buttons[0].r.x = buttons[0].r.x; }
        sys_sleep_ms(32);
    }
}

static int run_procmon_app(void) {
    struct app_window app; struct desktop_msg m; char statb[1024], memb[1024], taskb[2048], body[4096];
    if (app_open(&app, "Process Monitor", 620, 360) < 0) return 1;
    for (;;) {
        body[0] = '\0';
        (void)read_file_text("/proc/stat", statb, (uint32_t)sizeof(statb));
        (void)read_file_text("/proc/meminfo", memb, (uint32_t)sizeof(memb));
        (void)read_file_text("/proc/tasks", taskb, (uint32_t)sizeof(taskb));
        str_append(body, (uint32_t)sizeof(body), statb); str_append(body, (uint32_t)sizeof(body), "\n"); str_append(body, (uint32_t)sizeof(body), memb); str_append(body, (uint32_t)sizeof(body), "\n"); str_append(body, (uint32_t)sizeof(body), taskb);
        render_frame(&app, "Process Monitor", "Auto refresh", 0, 0, 0, UI_BG);
        fill_rect(app.shm, 8, 28, app.shm->width - 16, app.shm->height - 44, UI_PANEL);
        draw_text(app.shm, 12, 34, body, UI_TEXT, UI_PANEL);
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) { int rc = common_event(&app, &m); if (rc < 0) { app_close(&app); sys_exit(0); } }
        sys_sleep_ms(1000);
    }
}

static int run_crashreport_app(void) {
    struct app_window app; struct desktop_msg m; char buf[4096], status[96];
    const char *paths[] = { "/var/log/kpanic.log", "/var/log/boot-desktop.log", "/crashdump.log" };
    if (app_open(&app, "Crash Reporter", 640, 360) < 0) return 1;
    for (;;) {
        int found = -1; uint32_t i;
        for (i = 0; i < 3; ++i) if (read_file_text(paths[i], buf, (uint32_t)sizeof(buf)) >= 0) { found = (int)i; break; }
        str_copy(status, (uint32_t)sizeof(status), found >= 0 ? paths[found] : "No crash log found");
        if (found < 0) str_copy(buf, (uint32_t)sizeof(buf), "No crash or boot log was found.");
        render_frame(&app, "Crash Reporter", status, 0, 0, 0, UI_BG);
        fill_rect(app.shm, 8, 28, app.shm->width - 16, app.shm->height - 44, UI_PANEL);
        draw_text(app.shm, 12, 34, buf, UI_TEXT, UI_PANEL);
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) { int rc = common_event(&app, &m); if (rc < 0) { app_close(&app); sys_exit(0); } }
        sys_sleep_ms(1000);
    }
}

static int run_update_app(void) {
    struct app_window app; struct desktop_msg m; char buf[2048];
    if (app_open(&app, "Software Update", 460, 220) < 0) return 1;
    for (;;) {
        if (read_file_text("/etc/update-feed.txt", buf, (uint32_t)sizeof(buf)) < 0) str_copy(buf, (uint32_t)sizeof(buf), "No update feed configured.\nThis is a notifier stub.");
        render_frame(&app, "Software Update", "Notifier stub", 0, 0, 0, UI_BG);
        fill_rect(app.shm, 8, 28, app.shm->width - 16, app.shm->height - 44, UI_PANEL);
        draw_text(app.shm, 12, 34, buf, UI_TEXT, UI_PANEL);
        app_damage(&app, 0, 0, app.w, app.h);
        while (queue_pop_local(&app.shm->events, &m)) { int rc = common_event(&app, &m); if (rc < 0) { app_close(&app); sys_exit(0); } }
        sys_sleep_ms(1500);
    }
}

static int run_open_helper(int argc, char **argv) {
    char exec[96];
    if (argc < 2 || !argv[1]) return 1;
    if (resolve_mime_app(argv[1], exec, (uint32_t)sizeof(exec)) == 0) return spawn_exec_line(exec, argv[1]) < 0;
    return spawn_exec_line("/bin/editor %f", argv[1]) < 0;
}

typedef int (*app_entry_fn)(int argc, char **argv);

struct app_route {
    const char *name;
    const char *title;
    const char *exec_path;
    app_entry_fn run;
};

static int app_terminal(int argc, char **argv) { (void)argc; (void)argv; return run_pty_app("Terminal", "/bin/sh"); }
static int app_dlogin(int argc, char **argv) { (void)argc; (void)argv; return run_dlogin_app(); }
static int app_files(int argc, char **argv) { (void)argc; (void)argv; return run_files_app(); }
static int app_settings(int argc, char **argv) { (void)argc; (void)argv; return run_settings_app(); }
static int app_editor(int argc, char **argv) { return run_text_editor_main(argc, argv); }
static int app_launcher(int argc, char **argv) { (void)argc; (void)argv; return run_launcher_app(); }
static int app_clipboard(int argc, char **argv) { (void)argc; (void)argv; return run_clipboard_app(); }
static int app_screenshot(int argc, char **argv) { return run_screenshot_app(argc, argv); }
static int app_procmon(int argc, char **argv) { (void)argc; (void)argv; return run_procmon_app(); }
static int app_crashreport(int argc, char **argv) { (void)argc; (void)argv; return run_crashreport_app(); }
static int app_updatenotify(int argc, char **argv) { (void)argc; (void)argv; return run_update_app(); }
static int app_open_route(int argc, char **argv) { return run_open_helper(argc, argv); }

static const struct app_route app_routes[] = {
    { "terminal", "Terminal", "/bin/sh", app_terminal },
    { "dlogin", "Login", "/bin/login", app_dlogin },
    { "files", "Files", "/bin/files", app_files },
    { "settings", "Settings", "/bin/settings", app_settings },
    { "editor", "Editor", "/bin/editor", app_editor },
    { "launcher", "Launcher", "/bin/launcher", app_launcher },
    { "clipboard", "Clipboard", "/bin/clipboard", app_clipboard },
    { "screenshot", "Screenshot", "/bin/screenshot", app_screenshot },
    { "procmon", "Process Monitor", "/bin/procmon", app_procmon },
    { "crashreport", "Crash Reporter", "/bin/crashreport", app_crashreport },
    { "updatenotify", "Software Update", "/bin/updatenotify", app_updatenotify },
    { "open", "Open", "/bin/open", app_open_route }
};

static const struct app_route *find_app_route(const char *name) {
    uint32_t i;
    for (i = 0; i < (uint32_t)(sizeof(app_routes) / sizeof(app_routes[0])); ++i) {
        if (str_eq(name, app_routes[i].name)) return &app_routes[i];
    }
    return 0;
}

static int run_registered_app(const char *name, int argc, char **argv) {
    const struct app_route *route = find_app_route(name);
    if (route && route->run) return route->run(argc, argv);
    return run_pty_app("Terminal", "/bin/sh");
}

void BITOS_USER_NORETURN bitos_deskapp_start(uint64_t *sp) {
    int argc = 0;
    char **argv = 0;
    const char *app;
    if (sp) { argc = (int)sp[0]; argv = (char **)&sp[1]; }
    app = (argc > 0 && argv && argv[0]) ? base_name(argv[0]) : "terminal";
    sys_exit(run_registered_app(app, argc, argv));
    for (;;) { }
}

#if defined(__GNUC__) || defined(__clang__)
void BITOS_USER_NAKED BITOS_USER_NORETURN _start(void) {
    __asm__ volatile(
        "mov %rsp, %rdi\n"
        "andq $-16, %rsp\n"
        "call bitos_deskapp_start\n"
    );
}
#else
void _start(void) { bitos_deskapp_start(0); }
#endif
