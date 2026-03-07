#include "sys.h"
#include "desktop.h"
#include "../src/drivers/video/font8x8_basic.h"

struct wm_window {
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
    uint32_t frame_color;
    const char *title;
    struct desktop_shm_window *shm;
};

struct ui_rect {
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
};

struct ui_panel {
    struct ui_rect rect;
    uint32_t bg;
    uint32_t border;
};

struct ui_button {
    struct ui_rect rect;
    const char *label;
    uint32_t fg;
    uint32_t bg;
    uint32_t bg_hover;
    uint32_t bg_pressed;
    uint32_t border;
    int hovered;
    int pressed;
};

struct ui_menu_item {
    const char *label;
    const char *command;
};

struct ui_menu {
    struct ui_rect rect;
    const struct ui_menu_item *items;
    uint32_t item_count;
    uint32_t item_h;
    int visible;
    int hovered_idx;
};

struct desktop_shell {
    struct ui_panel taskbar;
    struct ui_button start_button;
    struct ui_menu launcher;
    uint32_t bar_h;
};

static uint32_t clamp_u32(uint32_t v, uint32_t hi) {
    if (v > hi) return hi;
    return v;
}

static int32_t clamp_i32(int32_t v, int32_t lo, int32_t hi) {
    if (v < lo) return lo;
    if (v > hi) return hi;
    return v;
}

static int urect_contains(const struct ui_rect *r, int32_t x, int32_t y) {
    if (!r) return 0;
    if (x < r->x || y < r->y) return 0;
    if ((uint32_t)(x - r->x) >= r->w) return 0;
    if ((uint32_t)(y - r->y) >= r->h) return 0;
    return 1;
}

static uint32_t color_darken(uint32_t rgb24, uint32_t sub) {
    uint32_t r = (rgb24 >> 16) & 0xFFu;
    uint32_t g = (rgb24 >> 8) & 0xFFu;
    uint32_t b = rgb24 & 0xFFu;
    if (r > sub) r -= sub; else r = 0;
    if (g > sub) g -= sub; else g = 0;
    if (b > sub) b -= sub; else b = 0;
    return (r << 16) | (g << 8) | b;
}

static uint32_t pack_rgb(const struct fb_mode_info *m, uint32_t rgb24) {
    uint32_t r = (rgb24 >> 16) & 0xFFu;
    uint32_t g = (rgb24 >> 8) & 0xFFu;
    uint32_t b = rgb24 & 0xFFu;

    uint32_t rp = (m->red_mask_size == 0) ? 0 : ((r >> (8u - m->red_mask_size)) & ((1u << m->red_mask_size) - 1u));
    uint32_t gp = (m->green_mask_size == 0) ? 0 : ((g >> (8u - m->green_mask_size)) & ((1u << m->green_mask_size) - 1u));
    uint32_t bp = (m->blue_mask_size == 0) ? 0 : ((b >> (8u - m->blue_mask_size)) & ((1u << m->blue_mask_size) - 1u));
    return (rp << m->red_mask_shift) | (gp << m->green_mask_shift) | (bp << m->blue_mask_shift);
}

static void fb_put(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, uint32_t rgb24) {
    if (!fb || !m) return;
    if (x < 0 || y < 0) return;
    if ((uint32_t)x >= m->width || (uint32_t)y >= m->height) return;
    uint32_t bpp = (m->bpp + 7u) / 8u;
    if (bpp == 0) return;
    uint8_t *p = (uint8_t *)fb + (uint64_t)y * m->pitch + (uint64_t)x * bpp;
    uint32_t px = pack_rgb(m, rgb24);
    if (bpp == 4) {
        p[0] = (uint8_t)(px & 0xFFu);
        p[1] = (uint8_t)((px >> 8) & 0xFFu);
        p[2] = (uint8_t)((px >> 16) & 0xFFu);
        p[3] = (uint8_t)((px >> 24) & 0xFFu);
    } else if (bpp == 3) {
        p[0] = (uint8_t)(px & 0xFFu);
        p[1] = (uint8_t)((px >> 8) & 0xFFu);
        p[2] = (uint8_t)((px >> 16) & 0xFFu);
    } else if (bpp == 2) {
        p[0] = (uint8_t)(px & 0xFFu);
        p[1] = (uint8_t)((px >> 8) & 0xFFu);
    } else {
        p[0] = (uint8_t)(px & 0xFFu);
    }
}

static void fb_rect(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, uint32_t w, uint32_t h, uint32_t rgb24) {
    for (uint32_t yy = 0; yy < h; ++yy) {
        for (uint32_t xx = 0; xx < w; ++xx) {
            fb_put(fb, m, x + (int32_t)xx, y + (int32_t)yy, rgb24);
        }
    }
}

static void fb_char(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, char c, uint32_t fg, uint32_t bg) {
    uint8_t ch = (uint8_t)c;
    for (uint32_t row = 0; row < 8; ++row) {
        uint8_t bits = (uint8_t)font8x8_basic[ch][row];
        for (uint32_t col = 0; col < 8; ++col) {
            uint32_t color = (bits & (1u << col)) ? fg : bg;
            fb_put(fb, m, x + (int32_t)col, y + (int32_t)row, color);
        }
    }
}

static void fb_text(void *fb, const struct fb_mode_info *m, int32_t x, int32_t y, const char *s, uint32_t fg, uint32_t bg) {
    int32_t cx = x;
    for (uint32_t i = 0; s && s[i]; ++i) {
        fb_char(fb, m, cx, y, s[i], fg, bg);
        cx += 8;
    }
}

static void ui_draw_panel(void *fb, const struct fb_mode_info *m, const struct ui_panel *p) {
    if (!fb || !m || !p) return;
    fb_rect(fb, m, p->rect.x, p->rect.y, p->rect.w, p->rect.h, p->bg);
    if (p->rect.w > 1 && p->rect.h > 1) {
        fb_rect(fb, m, p->rect.x, p->rect.y, p->rect.w, 1, p->border);
        fb_rect(fb, m, p->rect.x, p->rect.y + (int32_t)p->rect.h - 1, p->rect.w, 1, p->border);
        fb_rect(fb, m, p->rect.x, p->rect.y, 1, p->rect.h, p->border);
        fb_rect(fb, m, p->rect.x + (int32_t)p->rect.w - 1, p->rect.y, 1, p->rect.h, p->border);
    }
}

static void ui_draw_button(void *fb, const struct fb_mode_info *m, const struct ui_button *b) {
    if (!fb || !m || !b) return;
    uint32_t bg = b->bg;
    if (b->pressed) bg = b->bg_pressed;
    else if (b->hovered) bg = b->bg_hover;
    struct ui_panel panel;
    panel.rect = b->rect;
    panel.bg = bg;
    panel.border = b->border;
    ui_draw_panel(fb, m, &panel);

    int32_t tx = b->rect.x + 8;
    int32_t ty = b->rect.y + (int32_t)(b->rect.h / 2u) - 4;
    fb_text(fb, m, tx, ty, b->label, b->fg, bg);
}

static int ui_menu_item_at(const struct ui_menu *menu, int32_t x, int32_t y) {
    if (!menu || !menu->visible) return -1;
    if (!urect_contains(&menu->rect, x, y)) return -1;
    if (y < menu->rect.y + 3) return -1;
    int32_t rel = y - menu->rect.y - 3;
    if (rel < 0) return -1;
    int idx = rel / (int32_t)menu->item_h;
    if (idx < 0 || (uint32_t)idx >= menu->item_count) return -1;
    return idx;
}

static void ui_draw_menu(void *fb, const struct fb_mode_info *m, const struct ui_menu *menu) {
    if (!fb || !m || !menu || !menu->visible) return;
    struct ui_panel panel;
    panel.rect = menu->rect;
    panel.bg = 0x1A2230u;
    panel.border = 0x5A6A80u;
    ui_draw_panel(fb, m, &panel);

    for (uint32_t i = 0; i < menu->item_count; ++i) {
        int32_t y = menu->rect.y + 3 + (int32_t)(i * menu->item_h);
        uint32_t row_bg = ((int)i == menu->hovered_idx) ? 0x2C3D59u : 0x1A2230u;
        fb_rect(fb, m, menu->rect.x + 3, y, menu->rect.w - 6, menu->item_h, row_bg);
        fb_text(fb, m, menu->rect.x + 10, y + (int32_t)(menu->item_h / 2u) - 4,
                menu->items[i].label, 0xFFFFFFu, row_bg);
    }
}

static void launch_program(const char *path) {
    if (!path || !path[0]) return;
    long pid = sys_fork();
    if (pid < 0) return;
    if (pid == 0) {
        char *argv[2];
        argv[0] = (char *)path;
        argv[1] = 0;
        if (sys_execve(path, 1, argv, 0) < 0) {
            sys_exit(1);
        }
        sys_exit(0);
    }
}

static void shell_layout(struct desktop_shell *shell, const struct fb_mode_info *m) {
    if (!shell || !m) return;
    shell->bar_h = 30;

    shell->taskbar.rect.x = 0;
    shell->taskbar.rect.y = (int32_t)m->height - (int32_t)shell->bar_h;
    shell->taskbar.rect.w = m->width;
    shell->taskbar.rect.h = shell->bar_h;
    shell->taskbar.bg = 0x141C28u;
    shell->taskbar.border = 0x4D5F7Au;

    shell->start_button.rect.x = 6;
    shell->start_button.rect.y = shell->taskbar.rect.y + 4;
    shell->start_button.rect.w = 76;
    shell->start_button.rect.h = 22;

    shell->launcher.item_h = 22;
    shell->launcher.rect.x = 6;
    shell->launcher.rect.w = 220;
    shell->launcher.rect.h = shell->launcher.item_count * shell->launcher.item_h + 6;
    shell->launcher.rect.y = shell->taskbar.rect.y - (int32_t)shell->launcher.rect.h - 4;
}

static int shell_handle_press(struct desktop_shell *shell, int32_t mx, int32_t my) {
    if (!shell) return 0;

    if (urect_contains(&shell->start_button.rect, mx, my)) {
        shell->launcher.visible = !shell->launcher.visible;
        return 1;
    }

    if (shell->launcher.visible) {
        int idx = ui_menu_item_at(&shell->launcher, mx, my);
        if (idx >= 0) {
            launch_program(shell->launcher.items[idx].command);
            shell->launcher.visible = 0;
            return 1;
        }
        if (!urect_contains(&shell->launcher.rect, mx, my)) {
            shell->launcher.visible = 0;
            return 1;
        }
    }

    if (urect_contains(&shell->taskbar.rect, mx, my)) {
        return 1;
    }
    return 0;
}

static void shell_update_hover(struct desktop_shell *shell, int32_t mx, int32_t my, int left_down) {
    if (!shell) return;
    shell->start_button.hovered = urect_contains(&shell->start_button.rect, mx, my);
    shell->start_button.pressed = left_down && shell->start_button.hovered;
    shell->launcher.hovered_idx = ui_menu_item_at(&shell->launcher, mx, my);
}

static void shell_format_clock(char *out, uint32_t out_len) {
    if (!out || out_len < 9) return;
    struct timespec ts;
    uint64_t sec = 0;
    if (sys_clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        sec = ts.tv_sec;
    }
    uint32_t h = (uint32_t)((sec / 3600ull) % 24ull);
    uint32_t m = (uint32_t)((sec / 60ull) % 60ull);
    uint32_t s = (uint32_t)(sec % 60ull);

    out[0] = (char)('0' + (h / 10u));
    out[1] = (char)('0' + (h % 10u));
    out[2] = ':';
    out[3] = (char)('0' + (m / 10u));
    out[4] = (char)('0' + (m % 10u));
    out[5] = ':';
    out[6] = (char)('0' + (s / 10u));
    out[7] = (char)('0' + (s % 10u));
    out[8] = '\0';
}

static void shell_draw(void *fb, const struct fb_mode_info *m, struct desktop_shell *shell) {
    if (!fb || !m || !shell) return;
    ui_draw_panel(fb, m, &shell->taskbar);
    ui_draw_button(fb, m, &shell->start_button);
    ui_draw_menu(fb, m, &shell->launcher);

    char clock[16];
    shell_format_clock(clock, (uint32_t)sizeof(clock));
    int32_t tx = (int32_t)m->width - 8 - (int32_t)(8 * ustrlen(clock));
    int32_t ty = shell->taskbar.rect.y + 11;
    fb_text(fb, m, tx, ty, clock, 0xEAF2FFu, shell->taskbar.bg);
}

static struct desktop_shm_window *win_alloc(uint32_t w, uint32_t h) {
    uint64_t bytes = (uint64_t)w * (uint64_t)h * sizeof(uint32_t);
    uint64_t total = sizeof(struct desktop_shm_window) + bytes;
    struct desktop_shm_window *shm = (struct desktop_shm_window *)sys_mmap(0, (size_t)total, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    if (!shm || shm == (void *)-1) return 0;
    shm->width = w;
    shm->height = h;
    shm->stride = w;
    shm->format = 1;
    for (uint64_t i = 0; i < (uint64_t)w * (uint64_t)h; ++i) {
        shm->pixels[i] = 0x202020u;
    }
    return shm;
}

static void win_put(struct desktop_shm_window *w, int32_t x, int32_t y, uint32_t rgb24) {
    if (!w) return;
    if (x < 0 || y < 0) return;
    if ((uint32_t)x >= w->width || (uint32_t)y >= w->height) return;
    w->pixels[(uint64_t)y * w->stride + (uint64_t)x] = rgb24;
}

static void win_rect(struct desktop_shm_window *w, int32_t x, int32_t y, uint32_t ww, uint32_t hh, uint32_t rgb24) {
    for (uint32_t yy = 0; yy < hh; ++yy) {
        for (uint32_t xx = 0; xx < ww; ++xx) {
            win_put(w, x + (int32_t)xx, y + (int32_t)yy, rgb24);
        }
    }
}

static void win_char(struct desktop_shm_window *w, int32_t x, int32_t y, char c, uint32_t fg, uint32_t bg) {
    uint8_t ch = (uint8_t)c;
    for (uint32_t row = 0; row < 8; ++row) {
        uint8_t bits = (uint8_t)font8x8_basic[ch][row];
        for (uint32_t col = 0; col < 8; ++col) {
            uint32_t color = (bits & (1u << col)) ? fg : bg;
            win_put(w, x + (int32_t)col, y + (int32_t)row, color);
        }
    }
}

static void win_text(struct desktop_shm_window *w, int32_t x, int32_t y, const char *s, uint32_t fg, uint32_t bg) {
    int32_t cx = x;
    for (uint32_t i = 0; s && s[i]; ++i) {
        win_char(w, cx, y, s[i], fg, bg);
        cx += 8;
    }
}

static void win_paint_demo(struct wm_window *win, uint32_t body, const char *caption) {
    if (!win || !win->shm) return;
    win_rect(win->shm, 0, 0, win->shm->width, win->shm->height, body);
    win_rect(win->shm, 0, 0, win->shm->width, 20, color_darken(body, 30));
    win_text(win->shm, 6, 6, caption, 0xFFFFFFu, color_darken(body, 30));
    win_rect(win->shm, 12, 38, win->shm->width - 24, 2, 0x4d5f7au);
    win_text(win->shm, 12, 50, "userspace font + shm buffer", 0xE6EEF9u, body);
    win_rect(win->shm, 14, 82, 120, 28, 0x2A3B55u);
    win_text(win->shm, 24, 92, "Button", 0xFFFFFFu, 0x2A3B55u);
}

static void queue_push(struct desktop_queue *q, struct desktop_msg msg) {
    if (!q) return;
    uint32_t head = q->head;
    uint32_t next = (head + 1u) % DESKTOP_QUEUE_CAP;
    if (next == q->tail) {
        q->tail = (q->tail + 1u) % DESKTOP_QUEUE_CAP;
    }
    q->msgs[head] = msg;
    q->head = next;
}

static int window_title_hit(const struct wm_window *w, int32_t x, int32_t y) {
    if (!w) return 0;
    if (x < w->x + 1 || y < w->y + 1) return 0;
    if (x >= w->x + 1 + (int32_t)w->w) return 0;
    if (y >= w->y + 23) return 0;
    return 1;
}

static void window_clamp(struct wm_window *w, const struct fb_mode_info *m, uint32_t bar_h) {
    if (!w || !m) return;
    int32_t max_x = (int32_t)m->width - (int32_t)w->w - 2;
    int32_t max_y = (int32_t)m->height - (int32_t)w->h - 24 - (int32_t)bar_h;
    if (max_x < 0) max_x = 0;
    if (max_y < 0) max_y = 0;
    w->x = clamp_i32(w->x, 0, max_x);
    w->y = clamp_i32(w->y, 0, max_y);
}

static void draw_window(void *fb, const struct fb_mode_info *m, const struct wm_window *w, int active) {
    if (!fb || !m || !w || !w->shm) return;
    uint32_t frame = active ? w->frame_color : color_darken(w->frame_color, 40);
    fb_rect(fb, m, w->x, w->y, w->w + 2, w->h + 24, 0x05070Au);
    fb_rect(fb, m, w->x + 1, w->y + 1, w->w, 22, frame);
    fb_text(fb, m, w->x + 7, w->y + 7, w->title, 0xFFFFFFu, frame);
    for (uint32_t yy = 0; yy < w->h; ++yy) {
        for (uint32_t xx = 0; xx < w->w; ++xx) {
            uint32_t rgb = w->shm->pixels[(uint64_t)yy * w->shm->stride + (uint64_t)xx];
            fb_put(fb, m, w->x + 1 + (int32_t)xx, w->y + 23 + (int32_t)yy, rgb);
        }
    }
}

static void compose(void *fb, const struct fb_mode_info *m, struct wm_window *wins, uint32_t win_count,
                    uint32_t active, struct desktop_shell *shell, int32_t mx, int32_t my) {
    if (!fb || !m) return;
    for (uint32_t y = 0; y < m->height; ++y) {
        uint32_t shade = 0x111822u + ((y & 0x1Fu) << 8);
        fb_rect(fb, m, 0, (int32_t)y, m->width, 1, shade);
    }

    if (active < win_count) {
        for (uint32_t i = 0; i < win_count; ++i) {
            if (i == active) continue;
            draw_window(fb, m, &wins[i], 0);
        }
        draw_window(fb, m, &wins[active], 1);
    } else {
        for (uint32_t i = 0; i < win_count; ++i) {
            draw_window(fb, m, &wins[i], 0);
        }
    }

    shell_draw(fb, m, shell);

    fb_rect(fb, m, mx - 1, my - 6, 3, 13, 0xFFFFFFu);
    fb_rect(fb, m, mx - 6, my - 1, 13, 3, 0xFFFFFFu);
}

void _start(void) {
    int fb_fd = (int)sys_open("/dev/fb0", O_RDWR);
    if (fb_fd < 0) {
        uputs("wm: /dev/fb0 not available\n");
        sys_exit(1);
    }

    struct fb_mode_info mode;
    if (sys_ioctl(fb_fd, FB_IOCTL_GET_MODE, &mode) != 0) {
        uputs("wm: FB ioctl failed\n");
        sys_exit(1);
    }

    void *fb = sys_mmap(0, (size_t)mode.size_bytes, PROT_READ | PROT_WRITE, MAP_FILE, fb_fd, 0);
    if (!fb || fb == (void *)-1) {
        uputs("wm: fb mmap failed\n");
        sys_exit(1);
    }

    int input_fd = (int)sys_open("/dev/input", O_RDONLY);
    struct desktop_queue *queue = (struct desktop_queue *)sys_mmap(0, sizeof(struct desktop_queue),
        PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    if (queue && queue != (void *)-1) {
        queue->version = DESKTOP_PROTOCOL_VERSION;
        queue->head = 0;
        queue->tail = 0;
    } else {
        queue = 0;
    }

    struct wm_window wins[2];
    wins[0].x = 40;
    wins[0].y = 48;
    wins[0].w = 320;
    wins[0].h = 180;
    wins[0].frame_color = 0x2E4261u;
    wins[0].title = "Window Server";
    wins[0].shm = win_alloc(wins[0].w, wins[0].h);

    wins[1].x = 240;
    wins[1].y = 190;
    wins[1].w = 280;
    wins[1].h = 140;
    wins[1].frame_color = 0x5F2E61u;
    wins[1].title = "Compositor";
    wins[1].shm = win_alloc(wins[1].w, wins[1].h);

    win_paint_demo(&wins[0], 0x243447u, "shared memory window #1");
    win_paint_demo(&wins[1], 0x3B2742u, "shared memory window #2");

    if (queue) {
        struct desktop_msg msg0 = { DESKTOP_CMD_CREATE, 1, wins[0].x, wins[0].y, wins[0].w, wins[0].h, 0, 0 };
        struct desktop_msg msg1 = { DESKTOP_CMD_CREATE, 2, wins[1].x, wins[1].y, wins[1].w, wins[1].h, 0, 0 };
        queue_push(queue, msg0);
        queue_push(queue, msg1);
    }

    static const struct ui_menu_item launcher_items[] = {
        { "Shell", "/bin/sh" },
        { "Top", "/bin/top" },
        { "PS", "/bin/ps" },
        { "Hello", "/bin/hello" }
    };

    struct desktop_shell shell;
    shell.start_button.label = "Start";
    shell.start_button.fg = 0xF7FBFFu;
    shell.start_button.bg = 0x33475Fu;
    shell.start_button.bg_hover = 0x406080u;
    shell.start_button.bg_pressed = 0x25384Cu;
    shell.start_button.border = 0x91A3BCu;
    shell.start_button.hovered = 0;
    shell.start_button.pressed = 0;

    shell.launcher.items = launcher_items;
    shell.launcher.item_count = (uint32_t)(sizeof(launcher_items) / sizeof(launcher_items[0]));
    shell.launcher.visible = 0;
    shell.launcher.hovered_idx = -1;
    shell_layout(&shell, &mode);

    int32_t mx = (int32_t)(mode.width / 2u);
    int32_t my = (int32_t)(mode.height / 2u);
    int drag_id = -1;
    int left_down = 0;
    uint32_t active = 1;

    uputs("wm: running (q exits, tab cycles window, click Start for launcher)\n");

    for (;;) {
        if (input_fd >= 0) {
            struct pollfd pfd;
            pfd.fd = input_fd;
            pfd.events = POLLIN;
            pfd.revents = 0;
            long prc = sys_poll(&pfd, 1, 16);
            if (prc > 0 && (pfd.revents & POLLIN)) {
                struct input_event evs[8];
                long n = sys_read(input_fd, evs, sizeof(evs));
                if (n > 0) {
                    uint32_t cnt = (uint32_t)n / (uint32_t)sizeof(struct input_event);
                    for (uint32_t i = 0; i < cnt; ++i) {
                        struct input_event *ev = &evs[i];
                        if (ev->type == INPUT_EVENT_MOUSE) {
                            mx = ev->x;
                            my = ev->y;
                            if (mx < 0) mx = 0;
                            if (my < 0) my = 0;
                            mx = (int32_t)clamp_u32((uint32_t)mx, mode.width ? (mode.width - 1u) : 0);
                            my = (int32_t)clamp_u32((uint32_t)my, mode.height ? (mode.height - 1u) : 0);

                            int now_left = (ev->buttons & 1u) ? 1 : 0;
                            int pressed_edge = now_left && !left_down;
                            int released_edge = !now_left && left_down;

                            shell_update_hover(&shell, mx, my, now_left);

                            if (pressed_edge) {
                                int consumed = shell_handle_press(&shell, mx, my);
                                if (!consumed) {
                                    drag_id = -1;
                                    for (int idx = 1; idx >= 0; --idx) {
                                        uint32_t wi = (idx == 1) ? active : (active ^ 1u);
                                        if (window_title_hit(&wins[wi], mx, my)) {
                                            drag_id = (int)wi;
                                            active = wi;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (released_edge) {
                                drag_id = -1;
                            }
                            left_down = now_left;

                            if (left_down && drag_id >= 0 && (uint32_t)drag_id < 2u && !shell.launcher.visible) {
                                wins[drag_id].x += ev->dx;
                                wins[drag_id].y += ev->dy;
                                window_clamp(&wins[drag_id], &mode, shell.bar_h);
                                if (queue) {
                                    struct desktop_msg mmsg = {
                                        DESKTOP_CMD_MOVE, (uint32_t)(drag_id + 1), wins[drag_id].x, wins[drag_id].y,
                                        wins[drag_id].w, wins[drag_id].h, 0, 0
                                    };
                                    queue_push(queue, mmsg);
                                }
                            }
                        } else if (ev->type == INPUT_EVENT_KEY && ev->value == 1) {
                            if (ev->x == 'q' || ev->x == 'Q') {
                                sys_exit(0);
                            }
                            if (ev->x == '\t') {
                                active = (active + 1u) % 2u;
                            }
                            if (ev->x == 's' || ev->x == 'S') {
                                shell.launcher.visible = !shell.launcher.visible;
                            }
                        }
                    }
                }
            }
        } else {
            sys_sleep_ms(16);
        }

        shell_layout(&shell, &mode);
        compose(fb, &mode, wins, 2, active, &shell, mx, my);
    }
}
