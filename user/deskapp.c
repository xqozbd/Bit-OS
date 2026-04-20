#include "sys.h"
#include "desktop.h"
#include "uitk.h"

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

void _start(void) {
    uint64_t *sp = 0;
    int argc = 0;
    char **argv = 0;
    const char *app;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));
#endif
    if (sp) { argc = (int)sp[0]; argv = (char **)&sp[1]; }
    app = (argc > 0 && argv && argv[0]) ? base_name(argv[0]) : "terminal";
    if (str_eq(app, "terminal")) sys_exit(run_pty_app("Terminal", "/bin/sh"));
    if (str_eq(app, "dlogin")) sys_exit(run_pty_app("Login", "/bin/login"));
    if (str_eq(app, "files")) sys_exit(run_files_app());
    if (str_eq(app, "settings")) sys_exit(run_settings_app());
    if (str_eq(app, "editor")) sys_exit(run_text_editor_main(argc, argv));
    if (str_eq(app, "launcher")) sys_exit(run_launcher_app());
    if (str_eq(app, "clipboard")) sys_exit(run_clipboard_app());
    if (str_eq(app, "screenshot")) sys_exit(run_screenshot_app(argc, argv));
    if (str_eq(app, "procmon")) sys_exit(run_procmon_app());
    if (str_eq(app, "crashreport")) sys_exit(run_crashreport_app());
    if (str_eq(app, "updatenotify")) sys_exit(run_update_app());
    if (str_eq(app, "open")) sys_exit(run_open_helper(argc, argv));
    sys_exit(run_pty_app("Terminal", "/bin/sh"));
}
