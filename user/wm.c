#include "sys.h"
#include "desktop.h"
#include "../src/drivers/video/font8x8_basic.h"

#define WM_READY_PATH "/tmp/wm.ready"
#define WM_IPC_PATH "/tmp/wm.ipc"
#define WM_WINDOW_PREFIX "/tmp/wm.win"

#define WM_COLOR_BG 0x101820u
#define WM_COLOR_BG_ALT 0x162131u
#define WM_COLOR_FRAME_ACTIVE 0x2E4261u
#define WM_COLOR_FRAME_INACTIVE 0x203244u
#define WM_COLOR_FRAME_HUNG 0x603030u
#define WM_COLOR_FRAME_THROTTLED 0x5B4B18u

#define WM_RATE_LIMIT_PER_SEC 48u
#define WM_THROTTLE_MS 1000u
#define WM_PING_INTERVAL_MS 1000u
#define WM_HUNG_TIMEOUT_MS 5000u
#define WM_FRAME_MS 16u
#define WM_WORKSPACES 4u
#define WM_MAX_PINNED 8u
#define WM_MAX_TASK_BUTTONS DESKTOP_MAX_WINDOWS
#define WM_MAX_LAUNCHER_ITEMS 20u
#define WM_RUNBUF_MAX 96u
#define WM_PINNED_CONFIG "/etc/wm_pinned.conf"

#define WM_COLOR_TASKBAR 0x141C28u
#define WM_COLOR_TASKBAR_BORDER 0x4D5F7Au
#define WM_COLOR_TASK_ACTIVE 0x496B92u
#define WM_COLOR_TASK_IDLE 0x243446u
#define WM_COLOR_TASK_HOVER 0x334A62u
#define WM_COLOR_PANEL 0x1A2230u
#define WM_COLOR_PANEL_BORDER 0x5A6A80u
#define WM_COLOR_NOTIFICATION 0x1B2838u
#define WM_COLOR_RUN_DIALOG 0x0F1722u
#define WM_COLOR_RUN_ACCENT 0x5678A0u

struct ui_rect { int32_t x; int32_t y; uint32_t w; uint32_t h; };
struct ui_panel { struct ui_rect rect; uint32_t bg; uint32_t border; };
struct ui_button {
    struct ui_rect rect; const char *label; uint32_t fg; uint32_t bg; uint32_t bg_hover;
    uint32_t bg_pressed; uint32_t border; int hovered; int pressed;
};
struct ui_menu_item { const char *label; const char *command; };
struct ui_menu {
    struct ui_rect rect; const struct ui_menu_item *items; uint32_t item_count; uint32_t item_h;
    int visible; int hovered_idx;
};
struct run_dialog {
    int visible;
    char text[WM_RUNBUF_MAX];
    uint32_t len;
    struct ui_rect rect;
};
struct desktop_shell {
    struct ui_panel taskbar;
    struct ui_panel notification_area;
    struct ui_button start_button;
    struct ui_button session_button;
    struct ui_button workspace_buttons[WM_WORKSPACES];
    struct ui_button pinned_buttons[WM_MAX_PINNED];
    struct ui_button task_buttons[WM_MAX_TASK_BUTTONS];
    struct ui_menu launcher;
    struct ui_menu session_menu;
    struct run_dialog run_dialog;
    struct ui_menu_item launcher_items[WM_MAX_LAUNCHER_ITEMS];
    struct ui_menu_item pinned_items[WM_MAX_PINNED];
    struct ui_menu_item session_items[3];
    char pinned_labels[WM_MAX_PINNED][DESKTOP_TITLE_MAX];
    char pinned_cmds[WM_MAX_PINNED][64];
    char task_labels[WM_MAX_TASK_BUTTONS][DESKTOP_TITLE_MAX];
    int task_slots[WM_MAX_TASK_BUTTONS];
    uint32_t task_count;
    uint32_t pinned_count;
    uint32_t active_workspace;
    uint32_t bar_h;
};
struct dirty_rect { int valid; int32_t x; int32_t y; uint32_t w; uint32_t h; };
struct wm_window {
    int used; uint32_t win_id; uint32_t owner_pid; int32_t x; int32_t y; uint32_t w; uint32_t h;
    int32_t restore_x; int32_t restore_y; uint32_t restore_w; uint32_t restore_h; uint32_t state;
    uint32_t frame_color; uint32_t configure_serial; uint64_t last_seen_ms; uint64_t throttle_until_ms;
    uint64_t rate_window_start_ms; uint32_t rate_window_count; uint32_t workspace; char title[DESKTOP_TITLE_MAX];
    char buffer_path[DESKTOP_PATH_MAX]; struct desktop_shm_window *shm;
};

static void mark_dirty(struct dirty_rect *dirty, int32_t x, int32_t y, uint32_t w, uint32_t h);
static void bring_to_front(uint32_t *order, uint32_t slot);

static int str_eq(const char *a, const char *b) { if (!a || !b) return 0; while (*a && *b) { if (*a != *b) return 0; a++; b++; } return (*a == '\0' && *b == '\0'); }
static uint32_t str_len(const char *s) { uint32_t n = 0; while (s && s[n]) n++; return n; }
static void str_copy(char *dst, uint32_t cap, const char *src) { uint32_t i = 0; if (!dst || cap == 0) return; if (!src) { dst[0] = '\0'; return; } while (src[i] && i + 1 < cap) { dst[i] = src[i]; i++; } dst[i] = '\0'; }
static void str_append(char *dst, uint32_t cap, const char *src) { uint32_t n = str_len(dst), i = 0; if (!dst || cap == 0 || n >= cap - 1 || !src) return; while (src[i] && n + 1 < cap) dst[n++] = src[i++]; dst[n] = '\0'; }
static void u32_to_text(uint32_t v, char *out, uint32_t cap) { char tmp[16]; uint32_t i = 0, j = 0; if (!out || cap == 0) return; if (v == 0) { if (cap > 1) { out[0] = '0'; out[1] = '\0'; } else out[0] = '\0'; return; } while (v && i + 1 < (uint32_t)sizeof(tmp)) { tmp[i++] = (char)('0' + (v % 10u)); v /= 10u; } while (i > 0 && j + 1 < cap) out[j++] = tmp[--i]; out[j] = '\0'; }
static int is_space(char c) { return (c == ' ' || c == '\t' || c == '\n' || c == '\r'); }
static int starts_with(const char *s, const char *prefix) { uint32_t i = 0; if (!s || !prefix) return 0; while (prefix[i]) { if (s[i] != prefix[i]) return 0; ++i; } return 1; }
static const char *base_name(const char *path) { const char *last = path; uint32_t i = 0; if (!path) return ""; while (path[i]) { if (path[i] == '/') last = path + i + 1; ++i; } return last ? last : path; }
static void str_trim(char *s) { char *start = s; char *end; if (!s) return; while (*start && is_space(*start)) ++start; end = start; while (*end) ++end; while (end > start && is_space(*(end - 1))) --end; if (start != s) { while (start < end) *s++ = *start++; *s = '\0'; } else { *end = '\0'; } }
static int str_chr(const char *s, char c) { uint32_t i = 0; if (!s) return -1; while (s[i]) { if (s[i] == c) return (int)i; ++i; } return -1; }
static void copy_label_from_path(char *dst, uint32_t cap, const char *path) { const char *base = base_name(path); uint32_t i = 0; if (!dst || cap == 0) return; while (base[i] && i + 1 < cap) { char ch = base[i]; if (ch == '.') break; dst[i] = ch; ++i; } dst[i] = '\0'; if (i == 0) str_copy(dst, cap, "App"); }
static void resolve_command_path(const char *cmd, char *out, uint32_t cap) { if (!out || cap == 0) return; out[0] = '\0'; if (!cmd || !cmd[0]) return; if (cmd[0] == '/' || starts_with(cmd, "./")) str_copy(out, cap, cmd); else { str_copy(out, cap, "/bin/"); str_append(out, cap, cmd); } }
static int env_bool(char **envp, const char *key) { uint32_t klen = str_len(key); int i = 0; if (!envp || !key) return 0; while (envp[i]) { const char *e = envp[i]; uint32_t j = 0; while (j < klen && e[j] == key[j]) j++; if (j == klen && e[j] == '=') { const char *v = e + j + 1; return str_eq(v, "1") || str_eq(v, "on") || str_eq(v, "true") || str_eq(v, "yes"); } i++; } return 0; }
static uint64_t uptime_ms(void) { uint64_t ticks = (uint64_t)sys_uptime_ticks(), hz = (uint64_t)sys_timer_hz(); if (hz == 0) hz = 100; return (ticks * 1000ull) / hz; }
static int32_t clamp_i32(int32_t v, int32_t lo, int32_t hi) { if (v < lo) return lo; if (v > hi) return hi; return v; }
static uint32_t clamp_u32(uint32_t v, uint32_t hi) { return v > hi ? hi : v; }
static int urect_contains(const struct ui_rect *r, int32_t x, int32_t y) { if (!r) return 0; if (x < r->x || y < r->y) return 0; if ((uint32_t)(x - r->x) >= r->w) return 0; if ((uint32_t)(y - r->y) >= r->h) return 0; return 1; }
static uint32_t color_darken(uint32_t rgb24, uint32_t sub) { uint32_t r = (rgb24 >> 16) & 0xFFu, g = (rgb24 >> 8) & 0xFFu, b = rgb24 & 0xFFu; if (r > sub) r -= sub; else r = 0; if (g > sub) g -= sub; else g = 0; if (b > sub) b -= sub; else b = 0; return (r << 16) | (g << 8) | b; }
static uint32_t pack_rgb(const struct fb_mode_info *m, uint32_t rgb24) {
    uint32_t r = (rgb24 >> 16) & 0xFFu, g = (rgb24 >> 8) & 0xFFu, b = rgb24 & 0xFFu;
    uint32_t rp = (m->red_mask_size == 0) ? 0 : ((r >> (8u - m->red_mask_size)) & ((1u << m->red_mask_size) - 1u));
    uint32_t gp = (m->green_mask_size == 0) ? 0 : ((g >> (8u - m->green_mask_size)) & ((1u << m->green_mask_size) - 1u));
    uint32_t bp = (m->blue_mask_size == 0) ? 0 : ((b >> (8u - m->blue_mask_size)) & ((1u << m->blue_mask_size) - 1u));
    return (rp << m->red_mask_shift) | (gp << m->green_mask_shift) | (bp << m->blue_mask_shift);
}
static void fb_put(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, uint32_t rgb24) {
    uint32_t bpp, px; uint8_t *p; if (!fb || !m) return; if (x < 0 || y < 0) return; if ((uint32_t)x >= m->width || (uint32_t)y >= m->height) return;
    bpp = (m->bpp + 7u) / 8u; if (bpp == 0) return; p = (uint8_t *)fb + (uint64_t)y * m->pitch + (uint64_t)x * bpp; px = pack_rgb(m, rgb24);
    if (bpp == 4) { p[0] = (uint8_t)(px & 0xFFu); p[1] = (uint8_t)((px >> 8) & 0xFFu); p[2] = (uint8_t)((px >> 16) & 0xFFu); p[3] = (uint8_t)((px >> 24) & 0xFFu); }
    else if (bpp == 3) { p[0] = (uint8_t)(px & 0xFFu); p[1] = (uint8_t)((px >> 8) & 0xFFu); p[2] = (uint8_t)((px >> 16) & 0xFFu); }
    else if (bpp == 2) { p[0] = (uint8_t)(px & 0xFFu); p[1] = (uint8_t)((px >> 8) & 0xFFu); } else p[0] = (uint8_t)(px & 0xFFu);
}
static void fb_rect(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, uint32_t w, uint32_t h, uint32_t rgb24) { uint32_t yy, xx; for (yy = 0; yy < h; ++yy) for (xx = 0; xx < w; ++xx) fb_put(fb, m, x + (int32_t)xx, y + (int32_t)yy, rgb24); }
static void fb_char(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, char c, uint32_t fg, uint32_t bg) { uint8_t ch = (uint8_t)c; uint32_t row, col; for (row = 0; row < 8; ++row) { uint8_t bits = (uint8_t)font8x8_basic[ch][row]; for (col = 0; col < 8; ++col) fb_put(fb, m, x + (int32_t)col, y + (int32_t)row, (bits & (1u << col)) ? fg : bg); } }
static void fb_text(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, const char *s, uint32_t fg, uint32_t bg) { int32_t cx = x; uint32_t i = 0; while (s && s[i]) { fb_char(fb, m, cx, y, s[i], fg, bg); cx += 8; i++; } }
static void ui_draw_panel(void *fb, const struct fb_mode_info *m, const struct ui_panel *p) { if (!fb || !m || !p) return; fb_rect(fb, m, p->rect.x, p->rect.y, p->rect.w, p->rect.h, p->bg); if (p->rect.w > 1 && p->rect.h > 1) { fb_rect(fb, m, p->rect.x, p->rect.y, p->rect.w, 1, p->border); fb_rect(fb, m, p->rect.x, p->rect.y + (int32_t)p->rect.h - 1, p->rect.w, 1, p->border); fb_rect(fb, m, p->rect.x, p->rect.y, 1, p->rect.h, p->border); fb_rect(fb, m, p->rect.x + (int32_t)p->rect.w - 1, p->rect.y, 1, p->rect.h, p->border); } }
static void ui_draw_button(void *fb, const struct fb_mode_info *m, const struct ui_button *b) { struct ui_panel panel; uint32_t bg; if (!fb || !m || !b) return; bg = b->bg; if (b->pressed) bg = b->bg_pressed; else if (b->hovered) bg = b->bg_hover; panel.rect = b->rect; panel.bg = bg; panel.border = b->border; ui_draw_panel(fb, m, &panel); fb_text(fb, m, b->rect.x + 8, b->rect.y + (int32_t)(b->rect.h / 2u) - 4, b->label, b->fg, bg); }
static int ui_menu_item_at(const struct ui_menu *menu, int32_t x, int32_t y) { int32_t rel; int idx; if (!menu || !menu->visible) return -1; if (!urect_contains(&menu->rect, x, y)) return -1; if (y < menu->rect.y + 3) return -1; rel = y - menu->rect.y - 3; if (rel < 0) return -1; idx = rel / (int32_t)menu->item_h; if (idx < 0 || (uint32_t)idx >= menu->item_count) return -1; return idx; }
static void ui_draw_menu(void *fb, const struct fb_mode_info *m, const struct ui_menu *menu) { struct ui_panel panel; uint32_t i; if (!fb || !m || !menu || !menu->visible) return; panel.rect = menu->rect; panel.bg = 0x1A2230u; panel.border = 0x5A6A80u; ui_draw_panel(fb, m, &panel); for (i = 0; i < menu->item_count; ++i) { int32_t y = menu->rect.y + 3 + (int32_t)(i * menu->item_h); uint32_t row_bg = ((int)i == menu->hovered_idx) ? 0x2C3D59u : 0x1A2230u; fb_rect(fb, m, menu->rect.x + 3, y, menu->rect.w - 6, menu->item_h, row_bg); fb_text(fb, m, menu->rect.x + 10, y + (int32_t)(menu->item_h / 2u) - 4, menu->items[i].label, 0xFFFFFFu, row_bg); } }
static void shell_format_clock(char *out, uint32_t out_len) { struct timespec ts; uint64_t sec = 0; uint32_t h, m, s; if (!out || out_len < 9) return; if (sys_clock_gettime(CLOCK_REALTIME, &ts) == 0) sec = ts.tv_sec; h = (uint32_t)((sec / 3600ull) % 24ull); m = (uint32_t)((sec / 60ull) % 60ull); s = (uint32_t)(sec % 60ull); out[0] = (char)('0' + (h / 10u)); out[1] = (char)('0' + (h % 10u)); out[2] = ':'; out[3] = (char)('0' + (m / 10u)); out[4] = (char)('0' + (m % 10u)); out[5] = ':'; out[6] = (char)('0' + (s / 10u)); out[7] = (char)('0' + (s % 10u)); out[8] = '\0'; }
static void add_menu_item(struct desktop_shell *shell, const char *label, const char *cmd) {
    uint32_t idx;
    if (!shell || shell->launcher.item_count >= WM_MAX_LAUNCHER_ITEMS) return;
    idx = shell->launcher.item_count++;
    shell->launcher_items[idx].label = label;
    shell->launcher_items[idx].command = cmd;
}
static void shell_set_default_pins(struct desktop_shell *shell) {
    static const struct ui_menu_item defaults[] = {
        { "Terminal", "/bin/terminal" },
        { "Files", "/bin/files" },
        { "Editor", "/bin/editor" },
        { "Launcher", "/bin/launcher" }
    };
    uint32_t i;
    if (!shell) return;
    shell->pinned_count = 0;
    for (i = 0; i < (uint32_t)(sizeof(defaults) / sizeof(defaults[0])) && i < WM_MAX_PINNED; ++i) {
        str_copy(shell->pinned_labels[i], DESKTOP_TITLE_MAX, defaults[i].label);
        str_copy(shell->pinned_cmds[i], (uint32_t)sizeof(shell->pinned_cmds[i]), defaults[i].command);
        shell->pinned_items[i].label = shell->pinned_labels[i];
        shell->pinned_items[i].command = shell->pinned_cmds[i];
        shell->pinned_count++;
    }
}
static void shell_load_pinned(struct desktop_shell *shell) {
    int fd;
    char buf[512];
    long n;
    uint32_t off = 0;
    if (!shell) return;
    shell_set_default_pins(shell);
    fd = (int)sys_open(WM_PINNED_CONFIG, O_RDONLY);
    if (fd < 0) return;
    n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return;
    buf[n] = '\0';
    shell->pinned_count = 0;
    while (buf[off] && shell->pinned_count < WM_MAX_PINNED) {
        char line[96];
        char label[DESKTOP_TITLE_MAX];
        char cmd[64];
        uint32_t li = 0;
        int sep;
        while (buf[off] && (buf[off] == '\n' || buf[off] == '\r')) ++off;
        while (buf[off] && buf[off] != '\n' && li + 1 < (uint32_t)sizeof(line)) line[li++] = buf[off++];
        while (buf[off] == '\n' || buf[off] == '\r') ++off;
        line[li] = '\0';
        str_trim(line);
        if (!line[0] || line[0] == '#') continue;
        sep = str_chr(line, '=');
        if (sep < 0) sep = str_chr(line, ':');
        if (sep >= 0) {
            line[sep] = '\0';
            str_copy(label, (uint32_t)sizeof(label), line);
            str_trim(label);
            str_copy(cmd, (uint32_t)sizeof(cmd), line + sep + 1);
            str_trim(cmd);
        } else {
            str_copy(cmd, (uint32_t)sizeof(cmd), line);
            str_trim(cmd);
            copy_label_from_path(label, (uint32_t)sizeof(label), cmd);
        }
        if (!cmd[0]) continue;
        str_copy(shell->pinned_labels[shell->pinned_count], DESKTOP_TITLE_MAX, label[0] ? label : "App");
        resolve_command_path(cmd, shell->pinned_cmds[shell->pinned_count], (uint32_t)sizeof(shell->pinned_cmds[shell->pinned_count]));
        shell->pinned_items[shell->pinned_count].label = shell->pinned_labels[shell->pinned_count];
        shell->pinned_items[shell->pinned_count].command = shell->pinned_cmds[shell->pinned_count];
        shell->pinned_count++;
    }
    if (shell->pinned_count == 0) shell_set_default_pins(shell);
}
static int window_on_workspace(const struct wm_window *w, uint32_t workspace) {
    if (!w || !w->used) return 0;
    if (!(w->state & DESKTOP_WIN_STATE_MAPPED) || (w->state & DESKTOP_WIN_STATE_MINIMIZED)) return 0;
    return w->workspace == workspace;
}
static void launch_program(const char *path) {
    long pid;
    char resolved[64];
    char *argv[2];
    resolve_command_path(path, resolved, (uint32_t)sizeof(resolved));
    if (!resolved[0]) return;
    pid = sys_fork();
    if (pid < 0) return;
    if (pid == 0) {
        argv[0] = resolved;
        argv[1] = 0;
        if (sys_execve(resolved, 1, argv, 0) < 0) sys_exit(1);
        sys_exit(0);
    }
}
static void shell_session_action(const char *cmd) {
    if (!cmd || !cmd[0]) return;
    if (str_eq(cmd, "@logout")) sys_exit(0);
    if (str_eq(cmd, "@reboot")) { (void)sys_reboot(); return; }
    if (str_eq(cmd, "@shutdown")) { (void)sys_poweroff(); return; }
    launch_program(cmd);
}
static void shell_build_launcher(struct desktop_shell *shell) {
    static const struct ui_menu_item defaults[] = {
        { "Terminal", "/bin/terminal" }, { "Files", "/bin/files" }, { "Editor", "/bin/editor" }, { "Settings", "/bin/settings" },
        { "Launcher", "/bin/launcher" }, { "Clipboard", "/bin/clipboard" }, { "Screenshot", "/bin/screenshot" }, { "Processes", "/bin/procmon" },
        { "Crash Reporter", "/bin/crashreport" }, { "Update", "/bin/updatenotify" }, { "Shell", "/bin/sh" }, { "Login", "/bin/dlogin" }
    };
    uint32_t i;
    if (!shell) return;
    shell->launcher.item_count = 0;
    for (i = 0; i < shell->pinned_count; ++i) add_menu_item(shell, shell->pinned_items[i].label, shell->pinned_items[i].command);
    for (i = 0; i < (uint32_t)(sizeof(defaults) / sizeof(defaults[0])); ++i) add_menu_item(shell, defaults[i].label, defaults[i].command);
    shell->launcher.items = shell->launcher_items;
}
static void shell_sync_tasks(struct desktop_shell *shell, struct wm_window *wins, uint32_t *order, uint32_t active_slot) {
    uint32_t i;
    int32_t x = 250;
    if (!shell || !wins || !order) return;
    shell->task_count = 0;
    for (i = 0; i < DESKTOP_MAX_WINDOWS && shell->task_count < WM_MAX_TASK_BUTTONS; ++i) {
        uint32_t slot = order[i];
        if (slot == 0xFFFFFFFFu || slot >= DESKTOP_MAX_WINDOWS || !wins[slot].used) continue;
        if (wins[slot].workspace != shell->active_workspace) continue;
        str_copy(shell->task_labels[shell->task_count], DESKTOP_TITLE_MAX, wins[slot].title);
        shell->task_buttons[shell->task_count].label = shell->task_labels[shell->task_count];
        shell->task_buttons[shell->task_count].fg = 0xF6FBFFu;
        shell->task_buttons[shell->task_count].bg = (slot == active_slot) ? WM_COLOR_TASK_ACTIVE : WM_COLOR_TASK_IDLE;
        shell->task_buttons[shell->task_count].bg_hover = WM_COLOR_TASK_HOVER;
        shell->task_buttons[shell->task_count].bg_pressed = color_darken(shell->task_buttons[shell->task_count].bg, 25);
        shell->task_buttons[shell->task_count].border = (slot == active_slot) ? 0xB8D7FFu : 0x60748Cu;
        shell->task_buttons[shell->task_count].rect.x = x;
        shell->task_buttons[shell->task_count].rect.y = shell->taskbar.rect.y + 4;
        shell->task_buttons[shell->task_count].rect.w = 92;
        shell->task_buttons[shell->task_count].rect.h = 22;
        shell->task_buttons[shell->task_count].hovered = 0;
        shell->task_buttons[shell->task_count].pressed = 0;
        shell->task_slots[shell->task_count] = (int)slot;
        x += 96;
        shell->task_count++;
    }
}
static void shell_layout(struct desktop_shell *shell, const struct fb_mode_info *m) {
    uint32_t i;
    int32_t x;
    if (!shell || !m) return;
    shell->bar_h = 30;
    shell->taskbar.rect.x = 0;
    shell->taskbar.rect.y = (int32_t)m->height - (int32_t)shell->bar_h;
    shell->taskbar.rect.w = m->width;
    shell->taskbar.rect.h = shell->bar_h;
    shell->taskbar.bg = WM_COLOR_TASKBAR;
    shell->taskbar.border = WM_COLOR_TASKBAR_BORDER;
    shell->start_button.rect.x = 6;
    shell->start_button.rect.y = shell->taskbar.rect.y + 4;
    shell->start_button.rect.w = 68;
    shell->start_button.rect.h = 22;
    x = 80;
    for (i = 0; i < WM_WORKSPACES; ++i) {
        shell->workspace_buttons[i].rect.x = x;
        shell->workspace_buttons[i].rect.y = shell->taskbar.rect.y + 4;
        shell->workspace_buttons[i].rect.w = 22;
        shell->workspace_buttons[i].rect.h = 22;
        shell->workspace_buttons[i].label = (i == 0) ? "1" : (i == 1) ? "2" : (i == 2) ? "3" : "4";
        shell->workspace_buttons[i].fg = 0xF7FBFFu;
        shell->workspace_buttons[i].bg = (i == shell->active_workspace) ? 0x45698Fu : 0x223244u;
        shell->workspace_buttons[i].bg_hover = 0x35506Cu;
        shell->workspace_buttons[i].bg_pressed = 0x1A2836u;
        shell->workspace_buttons[i].border = 0x7D92AAu;
        x += 26;
    }
    for (i = 0; i < shell->pinned_count && i < WM_MAX_PINNED; ++i) {
        shell->pinned_buttons[i].rect.x = x;
        shell->pinned_buttons[i].rect.y = shell->taskbar.rect.y + 4;
        shell->pinned_buttons[i].rect.w = 56;
        shell->pinned_buttons[i].rect.h = 22;
        shell->pinned_buttons[i].label = shell->pinned_items[i].label;
        shell->pinned_buttons[i].fg = 0xF7FBFFu;
        shell->pinned_buttons[i].bg = 0x2A3B50u;
        shell->pinned_buttons[i].bg_hover = 0x3D5876u;
        shell->pinned_buttons[i].bg_pressed = 0x1A2837u;
        shell->pinned_buttons[i].border = 0x69819Bu;
        x += 60;
    }
    shell->session_button.rect.w = 58;
    shell->session_button.rect.h = 22;
    shell->session_button.rect.x = (int32_t)m->width - 192;
    shell->session_button.rect.y = shell->taskbar.rect.y + 4;
    shell->session_button.fg = 0xF7FBFFu;
    shell->session_button.bg = 0x324760u;
    shell->session_button.bg_hover = 0x476685u;
    shell->session_button.bg_pressed = 0x243446u;
    shell->session_button.border = 0x8AA5C2u;
    shell->notification_area.rect.x = (int32_t)m->width - 128;
    shell->notification_area.rect.y = shell->taskbar.rect.y + 4;
    shell->notification_area.rect.w = 124;
    shell->notification_area.rect.h = 22;
    shell->notification_area.bg = WM_COLOR_NOTIFICATION;
    shell->notification_area.border = 0x4A617A;
    shell->launcher.item_h = 22;
    shell->launcher.rect.x = 6;
    shell->launcher.rect.w = 220;
    shell->launcher.rect.h = shell->launcher.item_count * shell->launcher.item_h + 6;
    shell->launcher.rect.y = shell->taskbar.rect.y - (int32_t)shell->launcher.rect.h - 4;
    shell->session_menu.item_h = 22;
    shell->session_menu.rect.w = 160;
    shell->session_menu.rect.h = shell->session_menu.item_count * shell->session_menu.item_h + 6;
    shell->session_menu.rect.x = shell->session_button.rect.x;
    shell->session_menu.rect.y = shell->taskbar.rect.y - (int32_t)shell->session_menu.rect.h - 4;
    shell->run_dialog.rect.w = 360;
    shell->run_dialog.rect.h = 68;
    shell->run_dialog.rect.x = ((int32_t)m->width - (int32_t)shell->run_dialog.rect.w) / 2;
    shell->run_dialog.rect.y = ((int32_t)m->height - (int32_t)shell->run_dialog.rect.h) / 2 - 30;
}
static void shell_update_hover(struct desktop_shell *shell, int32_t mx, int32_t my, int left_down) {
    uint32_t i;
    if (!shell) return;
    shell->start_button.hovered = urect_contains(&shell->start_button.rect, mx, my);
    shell->start_button.pressed = left_down && shell->start_button.hovered;
    shell->session_button.hovered = urect_contains(&shell->session_button.rect, mx, my);
    shell->session_button.pressed = left_down && shell->session_button.hovered;
    for (i = 0; i < WM_WORKSPACES; ++i) {
        shell->workspace_buttons[i].hovered = urect_contains(&shell->workspace_buttons[i].rect, mx, my);
        shell->workspace_buttons[i].pressed = left_down && shell->workspace_buttons[i].hovered;
    }
    for (i = 0; i < shell->pinned_count && i < WM_MAX_PINNED; ++i) {
        shell->pinned_buttons[i].hovered = urect_contains(&shell->pinned_buttons[i].rect, mx, my);
        shell->pinned_buttons[i].pressed = left_down && shell->pinned_buttons[i].hovered;
    }
    for (i = 0; i < shell->task_count && i < WM_MAX_TASK_BUTTONS; ++i) {
        shell->task_buttons[i].hovered = urect_contains(&shell->task_buttons[i].rect, mx, my);
        shell->task_buttons[i].pressed = left_down && shell->task_buttons[i].hovered;
    }
    shell->launcher.hovered_idx = ui_menu_item_at(&shell->launcher, mx, my);
    shell->session_menu.hovered_idx = ui_menu_item_at(&shell->session_menu, mx, my);
}
static int shell_handle_press(struct desktop_shell *shell, int32_t mx, int32_t my, uint32_t *active_workspace, uint32_t *active_slot, struct wm_window *wins, uint32_t *order, struct dirty_rect *dirty) {
    uint32_t i;
    int idx;
    if (!shell) return 0;
    if (urect_contains(&shell->start_button.rect, mx, my)) { shell->launcher.visible = !shell->launcher.visible; shell->session_menu.visible = 0; return 1; }
    if (urect_contains(&shell->session_button.rect, mx, my)) { shell->session_menu.visible = !shell->session_menu.visible; shell->launcher.visible = 0; return 1; }
    for (i = 0; i < WM_WORKSPACES; ++i) if (urect_contains(&shell->workspace_buttons[i].rect, mx, my)) { *active_workspace = i; shell->active_workspace = i; shell->launcher.visible = 0; shell->session_menu.visible = 0; dirty->valid = 1; return 1; }
    for (i = 0; i < shell->pinned_count && i < WM_MAX_PINNED; ++i) if (urect_contains(&shell->pinned_buttons[i].rect, mx, my)) { launch_program(shell->pinned_items[i].command); shell->launcher.visible = 0; shell->session_menu.visible = 0; return 1; }
    for (i = 0; i < shell->task_count && i < WM_MAX_TASK_BUTTONS; ++i) {
        if (!urect_contains(&shell->task_buttons[i].rect, mx, my)) continue;
        if (shell->task_slots[i] >= 0 && (uint32_t)shell->task_slots[i] < DESKTOP_MAX_WINDOWS && wins[shell->task_slots[i]].used) {
            if (*active_slot == (uint32_t)shell->task_slots[i]) wins[shell->task_slots[i]].state ^= DESKTOP_WIN_STATE_MINIMIZED;
            if (*active_slot < DESKTOP_MAX_WINDOWS && wins[*active_slot].used) wins[*active_slot].state &= ~DESKTOP_WIN_STATE_ACTIVE;
            *active_slot = (uint32_t)shell->task_slots[i];
            wins[*active_slot].state &= ~DESKTOP_WIN_STATE_MINIMIZED;
            wins[*active_slot].state |= DESKTOP_WIN_STATE_ACTIVE;
            bring_to_front(order, *active_slot);
            mark_dirty(dirty, wins[*active_slot].x, wins[*active_slot].y, wins[*active_slot].w + 2, wins[*active_slot].h + 24);
        }
        shell->launcher.visible = 0;
        shell->session_menu.visible = 0;
        return 1;
    }
    if (shell->launcher.visible) {
        idx = ui_menu_item_at(&shell->launcher, mx, my);
        if (idx >= 0) { launch_program(shell->launcher.items[idx].command); shell->launcher.visible = 0; return 1; }
        if (!urect_contains(&shell->launcher.rect, mx, my)) shell->launcher.visible = 0;
    }
    if (shell->session_menu.visible) {
        idx = ui_menu_item_at(&shell->session_menu, mx, my);
        if (idx >= 0) { shell_session_action(shell->session_menu.items[idx].command); shell->session_menu.visible = 0; return 1; }
        if (!urect_contains(&shell->session_menu.rect, mx, my)) shell->session_menu.visible = 0;
    }
    if (shell->run_dialog.visible) {
        if (!urect_contains(&shell->run_dialog.rect, mx, my)) shell->run_dialog.visible = 0;
        return 1;
    }
    if (urect_contains(&shell->taskbar.rect, mx, my) || urect_contains(&shell->notification_area.rect, mx, my)) return 1;
    return 0;
}
static void shell_draw_notification_area(void *fb, const struct fb_mode_info *m, struct desktop_shell *shell, const struct input_stats *stats) {
    char text[48];
    uint32_t idx = 0;
    if (!fb || !m || !shell) return;
    ui_draw_panel(fb, m, &shell->notification_area);
    idx = 0;
    text[idx++] = 'W'; text[idx++] = 'S'; text[idx++] = (char)('1' + shell->active_workspace); text[idx++] = ' ';
    if (stats && stats->secure_mode) { text[idx++] = 'S'; text[idx++] = 'E'; text[idx++] = 'C'; text[idx++] = ' '; }
    text[idx++] = 'D'; text[idx++] = 'R'; text[idx++] = 'P'; text[idx++] = ':';
    if (stats) {
        uint32_t d = (uint32_t)(stats->reader_dropped_events % 10u);
        text[idx++] = (char)('0' + d);
    } else {
        text[idx++] = '0';
    }
    text[idx] = '\0';
    fb_text(fb, m, shell->notification_area.rect.x + 6, shell->notification_area.rect.y + 7, text, 0xE6EEF9u, shell->notification_area.bg);
}
static void shell_draw_run_dialog(void *fb, const struct fb_mode_info *m, struct desktop_shell *shell) {
    struct ui_panel panel;
    if (!fb || !m || !shell || !shell->run_dialog.visible) return;
    panel.rect = shell->run_dialog.rect;
    panel.bg = WM_COLOR_RUN_DIALOG;
    panel.border = WM_COLOR_RUN_ACCENT;
    ui_draw_panel(fb, m, &panel);
    fb_text(fb, m, shell->run_dialog.rect.x + 10, shell->run_dialog.rect.y + 10, "Run Command", 0xFFFFFFu, panel.bg);
    fb_rect(fb, m, shell->run_dialog.rect.x + 10, shell->run_dialog.rect.y + 30, shell->run_dialog.rect.w - 20, 22, 0x1A2432u);
    fb_text(fb, m, shell->run_dialog.rect.x + 16, shell->run_dialog.rect.y + 37, shell->run_dialog.text[0] ? shell->run_dialog.text : "/bin/", 0xF7FBFFu, 0x1A2432u);
}
static void shell_draw(void *fb, const struct fb_mode_info *m, struct desktop_shell *shell, const struct input_stats *stats) {
    char clock[16];
    int32_t tx, ty;
    uint32_t i;
    if (!fb || !m || !shell) return;
    ui_draw_panel(fb, m, &shell->taskbar);
    ui_draw_button(fb, m, &shell->start_button);
    for (i = 0; i < WM_WORKSPACES; ++i) ui_draw_button(fb, m, &shell->workspace_buttons[i]);
    for (i = 0; i < shell->pinned_count && i < WM_MAX_PINNED; ++i) ui_draw_button(fb, m, &shell->pinned_buttons[i]);
    for (i = 0; i < shell->task_count && i < WM_MAX_TASK_BUTTONS; ++i) ui_draw_button(fb, m, &shell->task_buttons[i]);
    ui_draw_button(fb, m, &shell->session_button);
    ui_draw_menu(fb, m, &shell->launcher);
    ui_draw_menu(fb, m, &shell->session_menu);
    shell_draw_notification_area(fb, m, shell, stats);
    shell_format_clock(clock, (uint32_t)sizeof(clock));
    tx = shell->session_button.rect.x - 8 - (int32_t)(8 * str_len(clock));
    ty = shell->taskbar.rect.y + 11;
    fb_text(fb, m, tx, ty, clock, 0xEAF2FFu, shell->taskbar.bg);
    shell_draw_run_dialog(fb, m, shell);
}
static void shell_open_run_dialog(struct desktop_shell *shell, const char *seed) {
    if (!shell) return;
    shell->run_dialog.visible = 1;
    shell->run_dialog.len = 0;
    shell->run_dialog.text[0] = '\0';
    if (seed) {
        str_copy(shell->run_dialog.text, WM_RUNBUF_MAX, seed);
        shell->run_dialog.len = str_len(shell->run_dialog.text);
    }
    shell->launcher.visible = 0;
    shell->session_menu.visible = 0;
}
static int shell_run_dialog_key(struct desktop_shell *shell, const struct input_event *ev) {
    if (!shell || !ev || !shell->run_dialog.visible) return 0;
    if (ev->keycode == 27) { shell->run_dialog.visible = 0; return 1; }
    if (ev->keycode == '\n' || ev->keycode == '\r') {
        if (shell->run_dialog.text[0]) launch_program(shell->run_dialog.text);
        shell->run_dialog.visible = 0;
        return 1;
    }
    if (ev->keycode == '\b') {
        if (shell->run_dialog.len > 0) shell->run_dialog.text[--shell->run_dialog.len] = '\0';
        return 1;
    }
    if (ev->keycode >= 32 && ev->keycode < 127 && shell->run_dialog.len + 1 < WM_RUNBUF_MAX) {
        shell->run_dialog.text[shell->run_dialog.len++] = (char)ev->keycode;
        shell->run_dialog.text[shell->run_dialog.len] = '\0';
        return 1;
    }
    return 1;
}
static void mark_dirty(struct dirty_rect *dirty, int32_t x, int32_t y, uint32_t w, uint32_t h) { int32_t x2, y2, dx2, dy2; if (!dirty || w == 0 || h == 0) return; if (!dirty->valid) { dirty->valid = 1; dirty->x = x; dirty->y = y; dirty->w = w; dirty->h = h; return; } x2 = dirty->x + (int32_t)dirty->w; y2 = dirty->y + (int32_t)dirty->h; dx2 = x + (int32_t)w; dy2 = y + (int32_t)h; if (x < dirty->x) dirty->x = x; if (y < dirty->y) dirty->y = y; if (dx2 > x2) x2 = dx2; if (dy2 > y2) y2 = dy2; dirty->w = (uint32_t)(x2 - dirty->x); dirty->h = (uint32_t)(y2 - dirty->y); }
static void mark_cursor_dirty(struct dirty_rect *dirty, int32_t mx, int32_t my, int safe_mode) { if (safe_mode) mark_dirty(dirty, mx, my, 2, 2); else mark_dirty(dirty, mx - 6, my - 6, 13, 13); }
static void queue_reset(struct desktop_queue *q) { if (!q) return; q->version = DESKTOP_PROTOCOL_VERSION; q->head = 0; q->tail = 0; q->dropped = 0; }
static void queue_push(struct desktop_queue *q, struct desktop_msg msg) { uint32_t head, next; if (!q) return; head = q->head; next = (head + 1u) % DESKTOP_QUEUE_CAP; if (next == q->tail) { q->tail = (q->tail + 1u) % DESKTOP_QUEUE_CAP; q->dropped++; } q->msgs[head] = msg; q->head = next; }
static int queue_pop(struct desktop_queue *q, struct desktop_msg *out) { uint32_t tail; if (!q || !out) return 0; tail = q->tail; if (tail == q->head) return 0; *out = q->msgs[tail]; q->tail = (tail + 1u) % DESKTOP_QUEUE_CAP; return 1; }
static void request_lock(struct desktop_runtime *rt) { if (!rt) return; while (__sync_lock_test_and_set(&rt->request_lock, 1u)) sys_sleep_ms(1); }
static void request_unlock(struct desktop_runtime *rt) { if (!rt) return; __sync_lock_release(&rt->request_lock); }
static void request_push(struct desktop_runtime *rt, struct desktop_msg msg) { if (!rt) return; request_lock(rt); queue_push(&rt->requests, msg); request_unlock(rt); }
static void zero_fill_fd(int fd, uint64_t size) { static uint8_t zeroes[256]; while (size > 0) { uint64_t chunk = size; if (chunk > sizeof(zeroes)) chunk = sizeof(zeroes); (void)sys_write(fd, zeroes, (size_t)chunk); size -= chunk; } }
static int create_backing_file(const char *path, uint64_t size) { int fd = (int)sys_open(path, O_RDWR | O_CREAT | O_TRUNC); if (fd < 0) return -1; zero_fill_fd(fd, size); return fd; }
static void build_window_path(uint32_t idx, char *out, uint32_t cap) { char num[12]; str_copy(out, cap, WM_WINDOW_PREFIX); u32_to_text(idx, num, (uint32_t)sizeof(num)); str_append(out, cap, num); }
static struct desktop_runtime *runtime_open(void) {
    uint64_t size = sizeof(struct desktop_runtime); int fd = create_backing_file(WM_IPC_PATH, size); struct desktop_runtime *rt; uint32_t i;
    if (fd < 0) return 0; rt = (struct desktop_runtime *)sys_mmap(0, (size_t)size, PROT_READ | PROT_WRITE, MAP_FILE, fd, 0); sys_close(fd); if (!rt || rt == (void *)-1) return 0;
    rt->version = DESKTOP_PROTOCOL_VERSION; rt->capabilities = DESKTOP_CAP_SHARED_BUFFERS | DESKTOP_CAP_DAMAGE_TRACKING | DESKTOP_CAP_POINTER_FOCUS | DESKTOP_CAP_KEYBOARD_FOCUS | DESKTOP_CAP_WINDOW_STATES | DESKTOP_CAP_CONFIGURE_ACK | DESKTOP_CAP_HEARTBEAT | DESKTOP_CAP_RATE_LIMIT; rt->max_windows = DESKTOP_MAX_WINDOWS; rt->active_win_id = 0; rt->request_lock = 0; rt->reserved0 = 0; queue_reset(&rt->requests); queue_reset(&rt->events);
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) { rt->windows[i].win_id = 0; rt->windows[i].owner_pid = 0; rt->windows[i].state = 0; rt->windows[i].z_order = 0; rt->windows[i].x = 0; rt->windows[i].y = 0; rt->windows[i].w = 0; rt->windows[i].h = 0; rt->windows[i].configure_serial = 0; rt->windows[i].heartbeat_ms = 0; rt->windows[i].title[0] = '\0'; rt->windows[i].buffer_path[0] = '\0'; }
    return rt;
}
static void write_ready_file(void) { int fd = (int)sys_open(WM_READY_PATH, O_WRONLY | O_CREAT | O_TRUNC); char buf[24]; uint32_t pid = (uint32_t)sys_getpid(), n = 0; if (fd < 0) return; u32_to_text(pid, buf, (uint32_t)sizeof(buf)); while (buf[n]) n++; if (n + 1 < (uint32_t)sizeof(buf)) buf[n++] = '\n'; (void)sys_write(fd, buf, n); sys_close(fd); }
static struct desktop_shm_window *win_alloc_shared(char *path_out, uint32_t idx, uint32_t w, uint32_t h) {
    uint64_t bytes = (uint64_t)w * (uint64_t)h * sizeof(uint32_t), total = sizeof(struct desktop_shm_window) + bytes; int fd; struct desktop_shm_window *shm; uint64_t i;
    build_window_path(idx, path_out, DESKTOP_PATH_MAX); fd = create_backing_file(path_out, total); if (fd < 0) return 0; shm = (struct desktop_shm_window *)sys_mmap(0, (size_t)total, PROT_READ | PROT_WRITE, MAP_FILE, fd, 0); sys_close(fd); if (!shm || shm == (void *)-1) return 0;
    shm->width = w; shm->height = h; shm->stride = w; shm->format = 1; shm->flags = 0; shm->configure_serial = 0; shm->damage_x = 0; shm->damage_y = 0; shm->damage_w = w; shm->damage_h = h; shm->heartbeat_ns = 0; shm->ack_serial = 0; shm->title[0] = '\0'; queue_reset(&shm->events);
    for (i = 0; i < (uint64_t)w * (uint64_t)h; ++i) shm->pixels[i] = 0x202020u; return shm;
}
static void win_put(struct desktop_shm_window *w, int32_t x, int32_t y, uint32_t rgb24) { if (!w) return; if (x < 0 || y < 0) return; if ((uint32_t)x >= w->width || (uint32_t)y >= w->height) return; w->pixels[(uint64_t)y * w->stride + (uint64_t)x] = rgb24; }
static void win_rect(struct desktop_shm_window *w, int32_t x, int32_t y, uint32_t ww, uint32_t hh, uint32_t rgb24) { uint32_t yy, xx; for (yy = 0; yy < hh; ++yy) for (xx = 0; xx < ww; ++xx) win_put(w, x + (int32_t)xx, y + (int32_t)yy, rgb24); }
static void win_char(struct desktop_shm_window *w, int32_t x, int32_t y, char c, uint32_t fg, uint32_t bg) { uint8_t ch = (uint8_t)c; uint32_t row, col; for (row = 0; row < 8; ++row) { uint8_t bits = (uint8_t)font8x8_basic[ch][row]; for (col = 0; col < 8; ++col) win_put(w, x + (int32_t)col, y + (int32_t)row, (bits & (1u << col)) ? fg : bg); } }
static void win_text(struct desktop_shm_window *w, int32_t x, int32_t y, const char *s, uint32_t fg, uint32_t bg) { int32_t cx = x; uint32_t i = 0; while (s && s[i]) { win_char(w, cx, y, s[i], fg, bg); cx += 8; i++; } }
static void win_mark_damage(struct desktop_shm_window *w, int32_t x, int32_t y, uint32_t ww, uint32_t hh) { int32_t x2, y2, dx2, dy2; if (!w || ww == 0 || hh == 0) return; if (w->damage_w == 0 || w->damage_h == 0) { w->damage_x = x; w->damage_y = y; w->damage_w = ww; w->damage_h = hh; return; } x2 = w->damage_x + (int32_t)w->damage_w; y2 = w->damage_y + (int32_t)w->damage_h; dx2 = x + (int32_t)ww; dy2 = y + (int32_t)hh; if (x < w->damage_x) w->damage_x = x; if (y < w->damage_y) w->damage_y = y; if (dx2 > x2) x2 = dx2; if (dy2 > y2) y2 = dy2; w->damage_w = (uint32_t)(x2 - w->damage_x); w->damage_h = (uint32_t)(y2 - w->damage_y); }
static void win_paint_demo(struct desktop_shm_window *shm, uint32_t body, const char *caption, const char *subtitle) { if (!shm) return; win_rect(shm, 0, 0, shm->width, shm->height, body); win_rect(shm, 0, 0, shm->width, 20, color_darken(body, 30)); win_text(shm, 6, 6, caption, 0xFFFFFFu, color_darken(body, 30)); win_rect(shm, 12, 38, shm->width - 24, 2, 0x4D5F7Au); win_text(shm, 12, 50, subtitle, 0xE6EEF9u, body); win_rect(shm, 14, 82, 120, 28, 0x2A3B55u); win_text(shm, 24, 92, "Button", 0xFFFFFFu, 0x2A3B55u); win_mark_damage(shm, 0, 0, shm->width, shm->height); }
static void runtime_emit(struct desktop_runtime *rt, uint32_t cmd, uint32_t win_id, uint32_t serial, int32_t x, int32_t y, uint32_t w, uint32_t h, uint32_t arg0, uint32_t arg1) { struct desktop_msg msg; if (!rt) return; msg.cmd = cmd; msg.win_id = win_id; msg.serial = serial; msg.flags = 0; msg.x = x; msg.y = y; msg.w = w; msg.h = h; msg.arg0 = arg0; msg.arg1 = arg1; msg.timestamp_ns = 0; queue_push(&rt->events, msg); }
static void window_emit(struct wm_window *w, uint32_t cmd, uint32_t serial, int32_t x, int32_t y, uint32_t ww, uint32_t hh, uint32_t arg0, uint32_t arg1) {
    struct desktop_msg msg;
    if (!w || !w->shm) return;
    msg.cmd = cmd;
    msg.win_id = w->win_id;
    msg.serial = serial;
    msg.flags = 0;
    msg.x = x;
    msg.y = y;
    msg.w = ww;
    msg.h = hh;
    msg.arg0 = arg0;
    msg.arg1 = arg1;
    msg.timestamp_ns = 0;
    queue_push(&w->shm->events, msg);
}
static void runtime_clear_window(struct desktop_runtime *rt, uint32_t slot) {
    if (!rt || slot >= DESKTOP_MAX_WINDOWS) return;
    rt->windows[slot].win_id = 0;
    rt->windows[slot].owner_pid = 0;
    rt->windows[slot].state = 0;
    rt->windows[slot].z_order = 0;
    rt->windows[slot].x = 0;
    rt->windows[slot].y = 0;
    rt->windows[slot].w = 0;
    rt->windows[slot].h = 0;
    rt->windows[slot].configure_serial = 0;
    rt->windows[slot].heartbeat_ms = 0;
    rt->windows[slot].title[0] = '\0';
    rt->windows[slot].buffer_path[0] = '\0';
}

static void runtime_publish_window(struct desktop_runtime *rt, uint32_t slot, const struct wm_window *w, uint32_t z) {
    if (!rt || !w || slot >= DESKTOP_MAX_WINDOWS) return;
    rt->windows[slot].win_id = w->win_id;
    rt->windows[slot].owner_pid = w->owner_pid;
    rt->windows[slot].state = w->state;
    rt->windows[slot].z_order = z;
    rt->windows[slot].x = w->x;
    rt->windows[slot].y = w->y;
    rt->windows[slot].w = w->w;
    rt->windows[slot].h = w->h;
    rt->windows[slot].configure_serial = w->configure_serial;
    rt->windows[slot].heartbeat_ms = (uint32_t)clamp_u32((uint32_t)w->last_seen_ms, 0xFFFFFFFFu);
    if (w->shm && w->shm->title[0]) str_copy(rt->windows[slot].title, DESKTOP_TITLE_MAX, w->shm->title);
    else str_copy(rt->windows[slot].title, DESKTOP_TITLE_MAX, w->title);
    str_copy(rt->windows[slot].buffer_path, DESKTOP_PATH_MAX, w->buffer_path);
}

static void runtime_sync_slots(struct desktop_runtime *rt, struct wm_window *wins, uint32_t *order, uint32_t active_slot) {
    uint32_t i;
    if (!rt || !wins || !order) return;
    rt->active_win_id = (active_slot < DESKTOP_MAX_WINDOWS && wins[active_slot].used) ? wins[active_slot].win_id : 0;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) runtime_clear_window(rt, i);
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) {
        uint32_t slot = order[i];
        if (slot == 0xFFFFFFFFu || slot >= DESKTOP_MAX_WINDOWS || !wins[slot].used) continue;
        runtime_publish_window(rt, slot, &wins[slot], i);
    }
}

static void window_outer_rect(const struct wm_window *w, struct ui_rect *r) {
    if (!w || !r) return;
    r->x = w->x;
    r->y = w->y;
    r->w = w->w + 2;
    r->h = w->h + 24;
}

static int window_contains(const struct wm_window *w, int32_t x, int32_t y) {
    struct ui_rect r;
    if (!w) return 0;
    window_outer_rect(w, &r);
    return urect_contains(&r, x, y);
}

static int window_title_hit(const struct wm_window *w, int32_t x, int32_t y) {
    if (!w) return 0;
    if (x < w->x + 1 || y < w->y + 1) return 0;
    if (x >= w->x + 1 + (int32_t)w->w) return 0;
    if (y >= w->y + 23) return 0;
    return 1;
}

static void window_clamp(struct wm_window *w, const struct fb_mode_info *m, uint32_t bar_h) {
    int32_t max_x, max_y;
    if (!w || !m) return;
    max_x = (int32_t)m->width - (int32_t)w->w - 2;
    max_y = (int32_t)m->height - (int32_t)w->h - 24 - (int32_t)bar_h;
    if (max_x < 0) max_x = 0;
    if (max_y < 0) max_y = 0;
    w->x = clamp_i32(w->x, 0, max_x);
    w->y = clamp_i32(w->y, 0, max_y);
}

static int find_window_by_id(struct wm_window *wins, uint32_t win_id) {
    uint32_t i;
    if (!wins || win_id == 0) return -1;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) if (wins[i].used && wins[i].win_id == win_id) return (int)i;
    return -1;
}

static int alloc_window_slot(struct wm_window *wins) {
    uint32_t i;
    if (!wins) return -1;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) if (!wins[i].used) return (int)i;
    return -1;
}

static void clear_order_entry(uint32_t *order, uint32_t slot) {
    uint32_t i;
    if (!order) return;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) if (order[i] == slot) order[i] = 0xFFFFFFFFu;
}

static void bring_to_front(uint32_t *order, uint32_t slot) {
    uint32_t next[DESKTOP_MAX_WINDOWS];
    uint32_t i, out = 0;
    if (!order || slot >= DESKTOP_MAX_WINDOWS) return;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) next[i] = 0xFFFFFFFFu;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) {
        if (order[i] == 0xFFFFFFFFu || order[i] == slot) continue;
        next[out++] = order[i];
    }
    next[out] = slot;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) order[i] = next[i];
}

static int top_window_at(struct wm_window *wins, uint32_t *order, int32_t x, int32_t y, uint32_t workspace) {
    int i;
    if (!wins || !order) return -1;
    for (i = (int)DESKTOP_MAX_WINDOWS - 1; i >= 0; --i) {
        uint32_t slot = order[i];
        if (slot == 0xFFFFFFFFu || slot >= DESKTOP_MAX_WINDOWS || !wins[slot].used) continue;
        if (!window_on_workspace(&wins[slot], workspace)) continue;
        if (window_contains(&wins[slot], x, y)) return (int)slot;
    }
    return -1;
}

static void runtime_focus(struct desktop_runtime *rt, struct wm_window *wins, uint32_t *order, uint32_t *active_slot, int new_slot, struct dirty_rect *dirty) {
    if (new_slot < 0 || (uint32_t)new_slot >= DESKTOP_MAX_WINDOWS || !wins[new_slot].used) return;
    if (*active_slot < DESKTOP_MAX_WINDOWS && wins[*active_slot].used) {
        wins[*active_slot].state &= ~DESKTOP_WIN_STATE_ACTIVE;
        mark_dirty(dirty, wins[*active_slot].x, wins[*active_slot].y, wins[*active_slot].w + 2, wins[*active_slot].h + 24);
        window_emit(&wins[*active_slot], DESKTOP_EVT_FOCUS, wins[*active_slot].configure_serial, wins[*active_slot].x, wins[*active_slot].y, wins[*active_slot].w, wins[*active_slot].h, 0, 0);
    }
    *active_slot = (uint32_t)new_slot;
    wins[*active_slot].state |= DESKTOP_WIN_STATE_ACTIVE;
    bring_to_front(order, *active_slot);
    mark_dirty(dirty, wins[*active_slot].x, wins[*active_slot].y, wins[*active_slot].w + 2, wins[*active_slot].h + 24);
    window_emit(&wins[*active_slot], DESKTOP_EVT_FOCUS, wins[*active_slot].configure_serial, wins[*active_slot].x, wins[*active_slot].y, wins[*active_slot].w, wins[*active_slot].h, 1, 0);
    runtime_emit(rt, DESKTOP_EVT_FOCUS, wins[*active_slot].win_id, wins[*active_slot].configure_serial, wins[*active_slot].x, wins[*active_slot].y, wins[*active_slot].w, wins[*active_slot].h, 0, 0);
}

static int create_window_internal(struct desktop_runtime *rt, struct wm_window *wins, uint32_t *order, const struct fb_mode_info *mode, uint32_t bar_h, int32_t x, int32_t y, uint32_t w, uint32_t h, uint32_t owner_pid, uint32_t frame_color, const char *title, const char *subtitle, uint32_t extra_state, uint32_t workspace, struct dirty_rect *dirty) {
    int slot = alloc_window_slot(wins);
    struct wm_window *win;
    if (slot < 0) return -1;
    win = &wins[slot];
    win->used = 1;
    win->win_id = 1;
    while (find_window_by_id(wins, win->win_id) >= 0) ++win->win_id;
    win->owner_pid = owner_pid;
    win->x = x; win->y = y; win->w = w; win->h = h;
    win->restore_x = x; win->restore_y = y; win->restore_w = w; win->restore_h = h;
    win->state = DESKTOP_WIN_STATE_MAPPED | extra_state;
    win->frame_color = frame_color;
    win->configure_serial = 1;
    win->last_seen_ms = uptime_ms();
    win->throttle_until_ms = 0;
    win->rate_window_start_ms = 0;
    win->rate_window_count = 0;
    win->workspace = workspace % WM_WORKSPACES;
    str_copy(win->title, DESKTOP_TITLE_MAX, title);
    win->buffer_path[0] = '\0';
    win->shm = win_alloc_shared(win->buffer_path, win->win_id, w, h);
    if (!win->shm) { win->used = 0; return -1; }
    win->shm->configure_serial = win->configure_serial;
    win->shm->ack_serial = win->configure_serial;
    str_copy(win->shm->title, DESKTOP_TITLE_MAX, title);
    window_clamp(win, mode, bar_h);
    win_paint_demo(win->shm, color_darken(frame_color, 20), title, subtitle);
    bring_to_front(order, (uint32_t)slot);
    runtime_emit(rt, DESKTOP_EVT_CREATED, win->win_id, win->configure_serial, win->x, win->y, win->w, win->h, owner_pid, 0);
    runtime_emit(rt, DESKTOP_EVT_MAPPED, win->win_id, win->configure_serial, win->x, win->y, win->w, win->h, 0, 0);
    mark_dirty(dirty, win->x, win->y, win->w + 2, win->h + 24);
    return slot;
}

static void destroy_window(struct desktop_runtime *rt, struct wm_window *wins, uint32_t *order, uint32_t *active_slot, uint32_t *pointer_focus, uint32_t slot, struct dirty_rect *dirty) {
    if (!wins || slot >= DESKTOP_MAX_WINDOWS || !wins[slot].used) return;
    mark_dirty(dirty, wins[slot].x, wins[slot].y, wins[slot].w + 2, wins[slot].h + 24);
    window_emit(&wins[slot], DESKTOP_EVT_DESTROYED, wins[slot].configure_serial, wins[slot].x, wins[slot].y, wins[slot].w, wins[slot].h, 0, 0);
    runtime_emit(rt, DESKTOP_EVT_DESTROYED, wins[slot].win_id, wins[slot].configure_serial, wins[slot].x, wins[slot].y, wins[slot].w, wins[slot].h, 0, 0);
    if (*active_slot == slot) *active_slot = 0xFFFFFFFFu;
    if (*pointer_focus == slot) *pointer_focus = 0xFFFFFFFFu;
    clear_order_entry(order, slot);
    wins[slot].used = 0;
    wins[slot].state = 0;
    wins[slot].title[0] = '\0';
    wins[slot].buffer_path[0] = '\0';
    wins[slot].shm = 0;
}
static void draw_window(void *fb, const struct fb_mode_info *m, const struct wm_window *w, int active, uint32_t workspace) {
    uint32_t frame, yy, xx;
    const char *title;
    if (!fb || !m || !w || !w->shm || !w->used) return;
    if (!window_on_workspace(w, workspace)) return;
    title = (w->shm->title[0] != '\0') ? w->shm->title : w->title;
    frame = active ? w->frame_color : color_darken(w->frame_color, 40);
    if (w->state & DESKTOP_WIN_STATE_HUNG) frame = WM_COLOR_FRAME_HUNG;
    if (w->state & DESKTOP_WIN_STATE_THROTTLED) frame = WM_COLOR_FRAME_THROTTLED;
    fb_rect(fb, m, w->x, w->y, w->w + 2, w->h + 24, 0x05070Au);
    fb_rect(fb, m, w->x + 1, w->y + 1, w->w, 22, frame);
    fb_text(fb, m, w->x + 7, w->y + 7, title, 0xFFFFFFu, frame);
    for (yy = 0; yy < w->h; ++yy) for (xx = 0; xx < w->w; ++xx) fb_put(fb, m, w->x + 1 + (int32_t)xx, w->y + 23 + (int32_t)yy, w->shm->pixels[(uint64_t)yy * w->shm->stride + (uint64_t)xx]);
}

static void paint_background(void *fb, const struct fb_mode_info *m, uint32_t bar_h, int safe_mode, uint32_t workspace) {
    uint32_t y, accent;
    if (!fb || !m) return;
    accent = (workspace == 0) ? 0x1C3550u : (workspace == 1) ? 0x2A3F2Au : (workspace == 2) ? 0x50351Cu : 0x3B2450u;
    for (y = 0; y + bar_h < m->height; ++y) {
        uint32_t band = safe_mode ? WM_COLOR_BG : (WM_COLOR_BG + ((y & 0x1Fu) << 8));
        if ((y / 32u) & 1u) band = color_darken(accent, 24);
        fb_rect(fb, m, 0, (int32_t)y, m->width, 1, band);
    }
    if (!safe_mode) {
        fb_rect(fb, m, 18, 24, m->width / 3u, 2, accent);
        fb_rect(fb, m, 40, 54, m->width / 4u, 2, color_darken(accent, 30));
        fb_rect(fb, m, (int32_t)m->width - (int32_t)(m->width / 3u) - 24, 72, m->width / 3u, 2, accent);
        fb_text(fb, m, 22, 12, (workspace == 0) ? "Workspace 1" : (workspace == 1) ? "Workspace 2" : (workspace == 2) ? "Workspace 3" : "Workspace 4", 0xE8F0FFu, WM_COLOR_BG);
    }
}

static void draw_cursor(void *fb, const struct fb_mode_info *m, int32_t mx, int32_t my, int safe_mode) {
    if (safe_mode) { fb_rect(fb, m, mx, my, 2, 2, 0xFFFFFFu); return; }
    fb_rect(fb, m, mx - 1, my - 6, 3, 13, 0xFFFFFFu);
    fb_rect(fb, m, mx - 6, my - 1, 13, 3, 0xFFFFFFu);
}

static void compose(void *fb, const struct fb_mode_info *m, struct wm_window *wins, uint32_t *order, uint32_t active_slot, struct desktop_shell *shell, int32_t mx, int32_t my, int safe_mode, const struct input_stats *stats) {
    uint32_t i;
    if (!fb || !m || !wins || !order || !shell) return;
    paint_background(fb, m, shell->bar_h, safe_mode, shell->active_workspace);
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) {
        uint32_t slot = order[i];
        if (slot == 0xFFFFFFFFu || slot >= DESKTOP_MAX_WINDOWS || !wins[slot].used) continue;
        draw_window(fb, m, &wins[slot], slot == active_slot, shell->active_workspace);
    }
    shell_draw(fb, m, shell, stats);
    draw_cursor(fb, m, mx, my, safe_mode);
}

static void dispatch_key_event(struct desktop_runtime *rt, const struct wm_window *w, const struct input_event *ev) {
    if (!rt || !w || !ev) return;
    window_emit((struct wm_window *)w, DESKTOP_EVT_KEY, w->configure_serial, 0, 0, 0, 0, (uint32_t)ev->keycode, (uint32_t)ev->flags);
    runtime_emit(rt, DESKTOP_EVT_KEY, w->win_id, w->configure_serial, 0, 0, 0, 0, (uint32_t)ev->keycode, (uint32_t)ev->flags);
}

static void dispatch_pointer_event(struct desktop_runtime *rt, const struct wm_window *w, const struct input_event *ev) {
    if (!rt || !w || !ev) return;
    window_emit((struct wm_window *)w, DESKTOP_EVT_POINTER, w->configure_serial, ev->x, ev->y, (uint32_t)((ev->dx < 0) ? -ev->dx : ev->dx), (uint32_t)((ev->dy < 0) ? -ev->dy : ev->dy), ev->buttons, (uint32_t)ev->flags);
    runtime_emit(rt, DESKTOP_EVT_POINTER, w->win_id, w->configure_serial, ev->x, ev->y, (uint32_t)((ev->dx < 0) ? -ev->dx : ev->dx), (uint32_t)((ev->dy < 0) ? -ev->dy : ev->dy), ev->buttons, (uint32_t)ev->flags);
}

static void update_pointer_focus(struct desktop_runtime *rt, struct wm_window *wins, uint32_t *pointer_focus, int new_slot) {
    if (!pointer_focus) return;
    if ((int)*pointer_focus == new_slot) return;
    if (*pointer_focus < DESKTOP_MAX_WINDOWS && wins[*pointer_focus].used) { window_emit(&wins[*pointer_focus], DESKTOP_EVT_POINTER_LEAVE, wins[*pointer_focus].configure_serial, 0, 0, 0, 0, 0, 0); runtime_emit(rt, DESKTOP_EVT_POINTER_LEAVE, wins[*pointer_focus].win_id, wins[*pointer_focus].configure_serial, 0, 0, 0, 0, 0, 0); }
    if (new_slot >= 0 && (uint32_t)new_slot < DESKTOP_MAX_WINDOWS && wins[new_slot].used) {
        *pointer_focus = (uint32_t)new_slot;
        window_emit(&wins[new_slot], DESKTOP_EVT_POINTER_ENTER, wins[new_slot].configure_serial, 0, 0, 0, 0, 0, 0);
        runtime_emit(rt, DESKTOP_EVT_POINTER_ENTER, wins[new_slot].win_id, wins[new_slot].configure_serial, 0, 0, 0, 0, 0, 0);
    } else {
        *pointer_focus = 0xFFFFFFFFu;
    }
}

static int allow_window_request(struct desktop_runtime *rt, struct wm_window *w) {
    uint64_t now = uptime_ms();
    if (!w) return 1;
    if (w->rate_window_start_ms == 0 || now - w->rate_window_start_ms >= 1000u) { w->rate_window_start_ms = now; w->rate_window_count = 0; }
    ++w->rate_window_count;
    if (now < w->throttle_until_ms) return 0;
    if (w->rate_window_count > WM_RATE_LIMIT_PER_SEC) {
        w->throttle_until_ms = now + WM_THROTTLE_MS;
        w->state |= DESKTOP_WIN_STATE_THROTTLED;
        runtime_emit(rt, DESKTOP_EVT_RATE_LIMIT, w->win_id, w->configure_serial, w->x, w->y, w->w, w->h, w->rate_window_count, 0);
        return 0;
    }
    if ((w->state & DESKTOP_WIN_STATE_THROTTLED) && now >= w->throttle_until_ms) w->state &= ~DESKTOP_WIN_STATE_THROTTLED;
    return 1;
}

static void process_requests(struct desktop_runtime *rt, struct wm_window *wins, uint32_t *order, uint32_t *active_slot, uint32_t *pointer_focus, const struct fb_mode_info *mode, struct desktop_shell *shell, struct dirty_rect *dirty) {
    struct desktop_msg msg;
    uint32_t budget = 32;
    while (budget-- && rt && queue_pop(&rt->requests, &msg)) {
        int slot = (msg.win_id != 0) ? find_window_by_id(wins, msg.win_id) : -1;
        struct wm_window *w = (slot >= 0) ? &wins[slot] : 0;
        if (w) {
            w->last_seen_ms = uptime_ms();
            w->state &= ~DESKTOP_WIN_STATE_HUNG;
            if (!allow_window_request(rt, w)) continue;
        }
        switch (msg.cmd) {
        case DESKTOP_CMD_CREATE: {
            char title[DESKTOP_TITLE_MAX];
            char num[16];
            int created;
            str_copy(title, (uint32_t)sizeof(title), "Window ");
            u32_to_text((uint32_t)(rt->events.head + 1u), num, (uint32_t)sizeof(num));
            str_append(title, (uint32_t)sizeof(title), num);
            created = create_window_internal(rt, wins, order, mode, shell->bar_h, msg.x, msg.y, clamp_i32((int32_t)msg.w, 160, (int32_t)(mode->width - 32u)), clamp_i32((int32_t)msg.h, 120, (int32_t)(mode->height - shell->bar_h - 48u)), msg.arg0, 0x35506Du, title, "protocol-created window", 0, shell->active_workspace, dirty);
            if (created >= 0) runtime_focus(rt, wins, order, active_slot, created, dirty);
            break;
        }
        case DESKTOP_CMD_DESTROY:
            if (slot >= 0) destroy_window(rt, wins, order, active_slot, pointer_focus, (uint32_t)slot, dirty);
            break;
        case DESKTOP_CMD_MAP:
            if (w) { w->state |= DESKTOP_WIN_STATE_MAPPED; w->state &= ~DESKTOP_WIN_STATE_MINIMIZED; window_emit(w, DESKTOP_EVT_MAPPED, w->configure_serial, w->x, w->y, w->w, w->h, 0, 0); runtime_emit(rt, DESKTOP_EVT_MAPPED, w->win_id, w->configure_serial, w->x, w->y, w->w, w->h, 0, 0); mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24); }
            break;
        case DESKTOP_CMD_UNMAP:
            if (w) { w->state &= ~DESKTOP_WIN_STATE_MAPPED; window_emit(w, DESKTOP_EVT_UNMAPPED, w->configure_serial, w->x, w->y, w->w, w->h, 0, 0); runtime_emit(rt, DESKTOP_EVT_UNMAPPED, w->win_id, w->configure_serial, w->x, w->y, w->w, w->h, 0, 0); mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24); }
            break;
        case DESKTOP_CMD_MOVE:
            if (w) { mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24); w->x = msg.x; w->y = msg.y; window_clamp(w, mode, shell->bar_h); mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24); }
            break;
        case DESKTOP_CMD_RESIZE:
            if (w) {
                uint32_t nw = (uint32_t)clamp_i32((int32_t)msg.w, 160, (int32_t)(mode->width - 32u));
                uint32_t nh = (uint32_t)clamp_i32((int32_t)msg.h, 120, (int32_t)(mode->height - shell->bar_h - 48u));
                mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24);
                ++w->configure_serial;
                w->w = nw; w->h = nh; if (w->shm) { char title[DESKTOP_TITLE_MAX]; str_copy(title, (uint32_t)sizeof(title), w->shm->title[0] ? w->shm->title : w->title); w->shm = win_alloc_shared(w->buffer_path, w->win_id, nw, nh); if (w->shm) { w->shm->configure_serial = w->configure_serial; w->shm->ack_serial = w->configure_serial; str_copy(w->shm->title, DESKTOP_TITLE_MAX, title); win_paint_demo(w->shm, WM_COLOR_BG_ALT, title, "configure + shared buffer"); } }
                window_emit(w, DESKTOP_EVT_CONFIGURE, w->configure_serial, w->x, w->y, w->w, w->h, 0, 0);
                runtime_emit(rt, DESKTOP_EVT_CONFIGURE, w->win_id, w->configure_serial, w->x, w->y, w->w, w->h, 0, 0);
                mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24);
            }
            break;
        case DESKTOP_CMD_DAMAGE:
            if (w && w->shm) { win_mark_damage(w->shm, msg.x, msg.y, msg.w, msg.h); mark_dirty(dirty, w->x + 1 + msg.x, w->y + 23 + msg.y, msg.w, msg.h); }
            break;
        case DESKTOP_CMD_FOCUS:
            if (slot >= 0) runtime_focus(rt, wins, order, active_slot, slot, dirty);
            break;
        case DESKTOP_CMD_CONFIGURE_ACK:
            if (w && w->shm) w->shm->ack_serial = msg.serial;
            break;
        case DESKTOP_CMD_SET_STATE:
            if (w) {
                mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24);
                if (msg.arg0 & DESKTOP_WIN_STATE_MINIMIZED) w->state |= DESKTOP_WIN_STATE_MINIMIZED; else w->state &= ~DESKTOP_WIN_STATE_MINIMIZED;
                if (msg.arg0 & DESKTOP_WIN_STATE_MAXIMIZED) { w->restore_x = w->x; w->restore_y = w->y; w->restore_w = w->w; w->restore_h = w->h; w->state |= DESKTOP_WIN_STATE_MAXIMIZED; w->state &= ~DESKTOP_WIN_STATE_FULLSCREEN; w->x = 0; w->y = 0; w->w = mode->width - 2u; w->h = mode->height - shell->bar_h - 24u; }
                else if (w->state & DESKTOP_WIN_STATE_MAXIMIZED) { w->state &= ~DESKTOP_WIN_STATE_MAXIMIZED; w->x = w->restore_x; w->y = w->restore_y; w->w = w->restore_w; w->h = w->restore_h; }
                if (msg.arg0 & DESKTOP_WIN_STATE_FULLSCREEN) { w->restore_x = w->x; w->restore_y = w->y; w->restore_w = w->w; w->restore_h = w->h; w->state |= DESKTOP_WIN_STATE_FULLSCREEN; w->state &= ~DESKTOP_WIN_STATE_MAXIMIZED; w->x = 0; w->y = 0; w->w = mode->width - 2u; w->h = mode->height - 24u; }
                else if (w->state & DESKTOP_WIN_STATE_FULLSCREEN) { w->state &= ~DESKTOP_WIN_STATE_FULLSCREEN; w->x = w->restore_x; w->y = w->restore_y; w->w = w->restore_w; w->h = w->restore_h; }
                mark_dirty(dirty, w->x, w->y, w->w + 2, w->h + 24);
            }
            break;
        case DESKTOP_CMD_PONG:
            if (w) w->last_seen_ms = uptime_ms();
            break;
        default:
            break;
        }
    }
}

static void check_window_health(struct desktop_runtime *rt, struct wm_window *wins, struct dirty_rect *dirty) {
    uint32_t i;
    uint64_t now = uptime_ms();
    if (!wins) return;
    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) {
        if (!wins[i].used || (wins[i].state & DESKTOP_WIN_STATE_SERVER_OWNED)) continue;
        if (!(wins[i].state & DESKTOP_WIN_STATE_HUNG) && now - wins[i].last_seen_ms >= WM_HUNG_TIMEOUT_MS) {
            wins[i].state |= DESKTOP_WIN_STATE_HUNG;
            window_emit(&wins[i], DESKTOP_EVT_HUNG, wins[i].configure_serial, wins[i].x, wins[i].y, wins[i].w, wins[i].h, 0, 0);
            mark_dirty(dirty, wins[i].x, wins[i].y, wins[i].w + 2, wins[i].h + 24);
            runtime_emit(rt, DESKTOP_EVT_HUNG, wins[i].win_id, wins[i].configure_serial, wins[i].x, wins[i].y, wins[i].w, wins[i].h, 0, 0);
        }
        if (now - wins[i].last_seen_ms >= WM_PING_INTERVAL_MS) { window_emit(&wins[i], DESKTOP_EVT_PING, wins[i].configure_serial, wins[i].x, wins[i].y, wins[i].w, wins[i].h, 0, 0); runtime_emit(rt, DESKTOP_EVT_PING, wins[i].win_id, wins[i].configure_serial, wins[i].x, wins[i].y, wins[i].w, wins[i].h, 0, 0); }
    }
}
static void shell_fix_active_workspace(struct desktop_shell *shell, struct wm_window *wins, uint32_t *order, uint32_t *active_slot) {
    int i;
    if (!shell || !wins || !order || !active_slot) return;
    if (*active_slot < DESKTOP_MAX_WINDOWS && wins[*active_slot].used && wins[*active_slot].workspace == shell->active_workspace && !(wins[*active_slot].state & DESKTOP_WIN_STATE_MINIMIZED)) return;
    if (*active_slot < DESKTOP_MAX_WINDOWS && wins[*active_slot].used) wins[*active_slot].state &= ~DESKTOP_WIN_STATE_ACTIVE;
    *active_slot = 0xFFFFFFFFu;
    for (i = (int)DESKTOP_MAX_WINDOWS - 1; i >= 0; --i) {
        uint32_t slot = order[i];
        if (slot == 0xFFFFFFFFu || slot >= DESKTOP_MAX_WINDOWS || !wins[slot].used) continue;
        if (wins[slot].workspace != shell->active_workspace || (wins[slot].state & DESKTOP_WIN_STATE_MINIMIZED)) continue;
        *active_slot = slot;
        wins[slot].state |= DESKTOP_WIN_STATE_ACTIVE;
        return;
    }
}
void _start(void) {
    uint64_t *sp = 0;
    int argc = 0;
    char **argv = 0;
    char **envp = 0;
    int safe_mode = 0;
    int fb_fd, input_fd;
    struct fb_mode_info mode;
    void *fb;
    struct desktop_runtime *rt;
    struct desktop_shell shell;
    struct wm_window wins[DESKTOP_MAX_WINDOWS];
    uint32_t order[DESKTOP_MAX_WINDOWS];
    struct dirty_rect dirty;
    uint32_t active_slot = 0xFFFFFFFFu;
    uint32_t pointer_focus = 0xFFFFFFFFu;
    uint32_t startup_frames = 12;
    int32_t mx, my;
    int drag_slot = -1, drag_off_x = 0, drag_off_y = 0, left_down = 0;
    uint32_t i;
    struct input_stats input_stats;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));
#endif
    if (sp) { argc = (int)sp[0]; argv = (char **)&sp[1]; envp = argv + argc + 1; }
    (void)argc; (void)argv;
    safe_mode = env_bool(envp, "BITOS_DESKTOP_SAFE");

    fb_fd = (int)sys_open("/dev/fb0", O_RDWR);
    if (fb_fd < 0) { uputs("wm: /dev/fb0 not available\n"); sys_exit(1); }
    if (sys_ioctl(fb_fd, FB_IOCTL_GET_MODE, &mode) != 0) { uputs("wm: FB ioctl failed\n"); sys_exit(1); }
    fb = sys_mmap(0, (size_t)mode.size_bytes, PROT_READ | PROT_WRITE, MAP_FILE, fb_fd, 0);
    if (!fb || fb == (void *)-1) { uputs("wm: fb mmap failed\n"); sys_exit(1); }
    input_fd = (int)sys_open("/dev/input", O_RDONLY | O_NONBLOCK);
    rt = runtime_open();
    if (!rt) { uputs("wm: runtime open failed\n"); sys_exit(1); }

    shell.active_workspace = 0;
    shell.start_button.label = "Start";
    shell.start_button.fg = 0xF7FBFFu;
    shell.start_button.bg = 0x33475Fu;
    shell.start_button.bg_hover = 0x406080u;
    shell.start_button.bg_pressed = 0x25384Cu;
    shell.start_button.border = 0x91A3BCu;
    shell.start_button.hovered = 0;
    shell.start_button.pressed = 0;
    shell.session_button.label = "Power";
    shell.session_items[0].label = "Logout";
    shell.session_items[0].command = "@logout";
    shell.session_items[1].label = "Reboot";
    shell.session_items[1].command = "@reboot";
    shell.session_items[2].label = "Shutdown";
    shell.session_items[2].command = "@shutdown";
    shell.session_menu.items = shell.session_items;
    shell.session_menu.item_count = 3;
    shell_load_pinned(&shell);
    shell_build_launcher(&shell);
    shell.launcher.visible = 0;
    shell.launcher.hovered_idx = -1;
    shell.session_menu.visible = 0;
    shell.session_menu.hovered_idx = -1;
    shell.run_dialog.visible = 0;
    shell.run_dialog.len = 0;
    shell.run_dialog.text[0] = '\0';
    shell_layout(&shell, &mode);

    for (i = 0; i < DESKTOP_MAX_WINDOWS; ++i) { wins[i].used = 0; wins[i].win_id = 0; wins[i].workspace = 0; order[i] = 0xFFFFFFFFu; }
    dirty.valid = 1; dirty.x = 0; dirty.y = 0; dirty.w = mode.width; dirty.h = mode.height;
    mx = (int32_t)(mode.width / 2u); my = (int32_t)(mode.height / 2u);

    {
        int slot;
        slot = create_window_internal(rt, wins, order, &mode, shell.bar_h, 42, 44, 340, 180, 0, WM_COLOR_FRAME_ACTIVE, "Welcome", "userspace compositor", DESKTOP_WIN_STATE_SERVER_OWNED, 0, &dirty);
        if (slot >= 0) active_slot = (uint32_t)slot;
        (void)create_window_internal(rt, wins, order, &mode, shell.bar_h, 248, 92, 300, 168, 0, 0x5F2E61u, "Files", "shared-memory window buffer", DESKTOP_WIN_STATE_SERVER_OWNED, 0, &dirty);
        (void)create_window_internal(rt, wins, order, &mode, shell.bar_h, 132, 246, 280, 150, 0, 0x315C4Eu, "Status", "damage tracking + focus", DESKTOP_WIN_STATE_SERVER_OWNED, 1, &dirty);
    }
    if (active_slot < DESKTOP_MAX_WINDOWS && wins[active_slot].used) wins[active_slot].state |= DESKTOP_WIN_STATE_ACTIVE;
    shell_sync_tasks(&shell, wins, order, active_slot);
    runtime_sync_slots(rt, wins, order, active_slot);
    input_stats.total_events = 0;
    input_stats.overflow_events = 0;
    input_stats.reader_dropped_events = 0;
    input_stats.reader_seq = 0;
    input_stats.queue_capacity = 0;
    input_stats.queue_depth = 0;
    input_stats.secure_mode = 0;
    input_stats.keymap = 0;
    input_stats.accel_profile = 0;
    input_stats.shortcut_count = 0;
    /*
     * Paint a complete first frame before init launches the login app. This
     * gives the kernel boot text no extra time on screen and makes desktop
     * takeover visible even if no input has happened yet.
     */
    compose(fb, &mode, wins, order, active_slot, &shell, mx, my, safe_mode, &input_stats);
    write_ready_file();
    if (safe_mode) uputs("wm: safe mode enabled\n");
    uputs("wm: compositor running\n");

    for (;;) {
        struct pollfd pfd; long prc;
        pfd.fd = input_fd; pfd.events = POLLIN; pfd.revents = 0;
        prc = (input_fd >= 0) ? sys_poll(&pfd, 1, WM_FRAME_MS) : 0;
        if (input_fd >= 0 && prc > 0 && (pfd.revents & POLLIN)) {
            for (;;) {
                struct input_event evs[8];
                long n = sys_read(input_fd, evs, sizeof(evs));
                uint32_t cnt, j;
                if (n <= 0) break;
                cnt = (uint32_t)n / (uint32_t)sizeof(struct input_event);
                for (j = 0; j < cnt; ++j) {
                    struct input_event *ev = &evs[j];
                    int top_slot;
                    mark_cursor_dirty(&dirty, mx, my, safe_mode);
                    if (ev->type == INPUT_EVENT_MOUSE) {
                        mx = ev->x; my = ev->y;
                        if (mx < 0) mx = 0; if (my < 0) my = 0;
                        mx = (int32_t)clamp_u32((uint32_t)mx, mode.width ? (mode.width - 1u) : 0);
                        my = (int32_t)clamp_u32((uint32_t)my, mode.height ? (mode.height - 1u) : 0);
                        shell_update_hover(&shell, mx, my, (ev->buttons & 1u) ? 1 : 0);
                        top_slot = top_window_at(wins, order, mx, my, shell.active_workspace);
                        if (urect_contains(&shell.taskbar.rect, mx, my) || (shell.launcher.visible && urect_contains(&shell.launcher.rect, mx, my))) update_pointer_focus(rt, wins, &pointer_focus, -1);
                        else update_pointer_focus(rt, wins, &pointer_focus, top_slot);
                        if ((ev->buttons & 1u) && !left_down) {
                            if (!shell_handle_press(&shell, mx, my, &shell.active_workspace, &active_slot, wins, order, &dirty) && top_slot >= 0) {
                                runtime_focus(rt, wins, order, &active_slot, top_slot, &dirty);
                                if (window_title_hit(&wins[top_slot], mx, my)) { drag_slot = top_slot; drag_off_x = mx - wins[top_slot].x; drag_off_y = my - wins[top_slot].y; }
                            }
                        } else if (!(ev->buttons & 1u) && left_down) {
                            drag_slot = -1;
                        }
                        left_down = (ev->buttons & 1u) ? 1 : 0;
                        if (left_down && drag_slot >= 0 && (uint32_t)drag_slot < DESKTOP_MAX_WINDOWS && wins[drag_slot].used && !(wins[drag_slot].state & (DESKTOP_WIN_STATE_MAXIMIZED | DESKTOP_WIN_STATE_FULLSCREEN | DESKTOP_WIN_STATE_MINIMIZED))) {
                            mark_dirty(&dirty, wins[drag_slot].x, wins[drag_slot].y, wins[drag_slot].w + 2, wins[drag_slot].h + 24);
                            wins[drag_slot].x = mx - drag_off_x; wins[drag_slot].y = my - drag_off_y; window_clamp(&wins[drag_slot], &mode, shell.bar_h);
                            mark_dirty(&dirty, wins[drag_slot].x, wins[drag_slot].y, wins[drag_slot].w + 2, wins[drag_slot].h + 24);
                        }
                        if (pointer_focus < DESKTOP_MAX_WINDOWS && wins[pointer_focus].used) dispatch_pointer_event(rt, &wins[pointer_focus], ev);
                    } else if (ev->type == INPUT_EVENT_KEY && !(ev->flags & INPUT_FLAG_RELEASE)) {
                        if (shell.run_dialog.visible && shell_run_dialog_key(&shell, ev)) {
                            mark_dirty(&dirty, shell.run_dialog.rect.x, shell.run_dialog.rect.y, shell.run_dialog.rect.w, shell.run_dialog.rect.h);
                        } else if ((ev->modifiers & INPUT_MOD_ALT) && ev->keycode == '\t') {
                            uint32_t start = 0, k; int found = -1;
                            for (k = 0; k < DESKTOP_MAX_WINDOWS; ++k) if (order[k] == active_slot) { start = k + 1u; break; }
                            for (k = start; k < DESKTOP_MAX_WINDOWS; ++k) if (order[k] != 0xFFFFFFFFu && wins[order[k]].used && !(wins[order[k]].state & DESKTOP_WIN_STATE_MINIMIZED) && wins[order[k]].workspace == shell.active_workspace) { found = (int)order[k]; break; }
                            if (found < 0) for (k = 0; k < start && k < DESKTOP_MAX_WINDOWS; ++k) if (order[k] != 0xFFFFFFFFu && wins[order[k]].used && !(wins[order[k]].state & DESKTOP_WIN_STATE_MINIMIZED) && wins[order[k]].workspace == shell.active_workspace) { found = (int)order[k]; break; }
                            if (found >= 0) runtime_focus(rt, wins, order, &active_slot, found, &dirty);
                        } else if ((ev->modifiers & INPUT_MOD_ALT) && ev->code == 0x06) {
                            shell_open_run_dialog(&shell, "/bin/");
                            mark_dirty(&dirty, shell.run_dialog.rect.x, shell.run_dialog.rect.y, shell.run_dialog.rect.w, shell.run_dialog.rect.h);
                        } else if ((ev->modifiers & INPUT_MOD_CTRL) && (ev->modifiers & INPUT_MOD_ALT) && (ev->keycode == 'q' || ev->keycode == 'Q')) {
                            sys_exit(0);
                        } else if ((ev->modifiers & INPUT_MOD_ALT) && ev->keycode >= '1' && ev->keycode <= '4') {
                            shell.active_workspace = (uint32_t)(ev->keycode - '1');
                            mark_dirty(&dirty, 0, 0, mode.width, mode.height);
                        } else if ((ev->modifiers & INPUT_MOD_ALT) && (ev->keycode == 'r' || ev->keycode == 'R')) {
                            shell_open_run_dialog(&shell, "/bin/");
                            mark_dirty(&dirty, shell.run_dialog.rect.x, shell.run_dialog.rect.y, shell.run_dialog.rect.w, shell.run_dialog.rect.h);
                        } else if (ev->keycode == 's' || ev->keycode == 'S') {
                            shell.launcher.visible = !shell.launcher.visible; mark_dirty(&dirty, shell.launcher.rect.x, shell.launcher.rect.y, shell.launcher.rect.w, shell.launcher.rect.h);
                        } else if (ev->keycode == 27) {
                            shell.launcher.visible = 0;
                            shell.session_menu.visible = 0;
                            shell.run_dialog.visible = 0;
                        } else if (active_slot < DESKTOP_MAX_WINDOWS && wins[active_slot].used) {
                            if (ev->keycode == 'x' || ev->keycode == 'X') {
                                struct desktop_msg m; m.cmd = DESKTOP_CMD_SET_STATE; m.win_id = wins[active_slot].win_id; m.serial = 0; m.flags = 0; m.x = 0; m.y = 0; m.w = 0; m.h = 0; m.arg0 = (wins[active_slot].state & DESKTOP_WIN_STATE_MAXIMIZED) ? 0 : DESKTOP_WIN_STATE_MAXIMIZED; m.arg1 = 0; m.timestamp_ns = 0; request_push(rt, m);
                            } else if (ev->keycode == 'f' || ev->keycode == 'F') {
                                struct desktop_msg m; m.cmd = DESKTOP_CMD_SET_STATE; m.win_id = wins[active_slot].win_id; m.serial = 0; m.flags = 0; m.x = 0; m.y = 0; m.w = 0; m.h = 0; m.arg0 = (wins[active_slot].state & DESKTOP_WIN_STATE_FULLSCREEN) ? 0 : DESKTOP_WIN_STATE_FULLSCREEN; m.arg1 = 0; m.timestamp_ns = 0; request_push(rt, m);
                            } else if (ev->keycode == 'n' || ev->keycode == 'N') {
                                struct desktop_msg m; m.cmd = DESKTOP_CMD_SET_STATE; m.win_id = wins[active_slot].win_id; m.serial = 0; m.flags = 0; m.x = 0; m.y = 0; m.w = 0; m.h = 0; m.arg0 = (wins[active_slot].state & DESKTOP_WIN_STATE_MINIMIZED) ? 0 : DESKTOP_WIN_STATE_MINIMIZED; m.arg1 = 0; m.timestamp_ns = 0; request_push(rt, m);
                            }
                            dispatch_key_event(rt, &wins[active_slot], ev);
                        }
                    }
                    mark_cursor_dirty(&dirty, mx, my, safe_mode);
                }
            }
        }
        process_requests(rt, wins, order, &active_slot, &pointer_focus, &mode, &shell, &dirty);
        check_window_health(rt, wins, &dirty);
        shell_fix_active_workspace(&shell, wins, order, &active_slot);
        if (input_fd >= 0) {
            if (sys_ioctl(input_fd, INPUT_IOCTL_GET_STATS, &input_stats) != 0) {
                input_stats.total_events = 0;
                input_stats.reader_dropped_events = 0;
                input_stats.secure_mode = 0;
            }
        }
        shell_layout(&shell, &mode);
        shell_sync_tasks(&shell, wins, order, active_slot);
        runtime_sync_slots(rt, wins, order, active_slot);
        if (!dirty.valid && startup_frames == 0) continue;
        /*
         * /dev/fb0 is currently mmap'ed as the live framebuffer. Swapping the
         * kernel backbuffer here replays the old boot console frame over the
         * compositor output, which is why the screen appears stuck on kernel
         * text even though userspace init/wm started correctly.
         */
        compose(fb, &mode, wins, order, active_slot, &shell, mx, my, safe_mode, &input_stats);
        if (startup_frames > 0) --startup_frames;
        dirty.valid = 0; dirty.x = 0; dirty.y = 0; dirty.w = 0; dirty.h = 0;
    }
}
