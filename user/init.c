#include "sys.h"
#include "../src/drivers/video/font8x8_basic.h"

#if defined(BITOS_USE_GNU_ATTRS)
#define BITOS_USER_NORETURN __attribute__((noreturn))
#define BITOS_USER_NAKED __attribute__((naked))
#else
#define BITOS_USER_NORETURN
#define BITOS_USER_NAKED
#endif

#define BOOT_MODE_DESKTOP 1
#define BOOT_MODE_CONSOLE 2

#define INPUT_PATH "/dev/input"
#define FB_PATH "/dev/fb0"
#define COMPOSITOR_PATH "/bin/wm"
#define DESKTOP_LOGIN_PATH "/bin/dlogin"
#define LOGIN_PATH "/bin/login"
#define CRON_PATH "/bin/cron"
#define WM_READY_PATH "/tmp/wm.ready"
#define DESKTOP_LOG_PATH "/var/log/boot-desktop.log"

static int str_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++;
        b++;
    }
    return (*a == '\0' && *b == '\0');
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

static int is_digit(char c) {
    return (c >= '0' && c <= '9');
}

static uint64_t parse_u64(const char *s) {
    uint64_t v = 0;
    if (!s) return 0;
    while (*s && is_digit(*s)) {
        v = v * 10u + (uint64_t)(*s - '0');
        s++;
    }
    return v;
}

static int parse_bool(const char *s) {
    if (!s || !s[0]) return 0;
    if (str_eq(s, "1") || str_eq(s, "on") || str_eq(s, "true") || str_eq(s, "yes")) return 1;
    return 0;
}

static uint64_t uptime_ms(void) {
    uint64_t ticks = (uint64_t)sys_uptime_ticks();
    uint64_t hz = (uint64_t)sys_timer_hz();
    if (hz == 0) hz = 100;
    return (ticks * 1000ull) / hz;
}

static uint64_t now_seconds(void) {
    struct timespec ts;
    if (sys_clock_gettime(CLOCK_REALTIME, &ts) == 0 && ts.tv_sec > 0) {
        return ts.tv_sec;
    }
    return uptime_ms() / 1000ull;
}

static int path_exists(const char *path) {
    int fd = (int)sys_open(path, O_RDONLY);
    if (fd < 0) return 0;
    sys_close(fd);
    return 1;
}

static int argv_count(char **argv) {
    int n = 0;
    while (argv && argv[n]) n++;
    return n;
}

static void u64_to_text(uint64_t v, char *out, uint32_t cap) {
    char tmp[32];
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
        tmp[i++] = (char)('0' + (v % 10ull));
        v /= 10ull;
    }
    while (i > 0 && j + 1 < cap) {
        out[j++] = tmp[--i];
    }
    out[j] = '\0';
}

static uint32_t text_append(char *dst, uint32_t cap, uint32_t idx, const char *src) {
    if (!dst || cap == 0 || !src) return idx;
    while (*src && idx + 1 < cap) {
        dst[idx++] = *src++;
    }
    dst[idx] = '\0';
    return idx;
}

static uint32_t text_append_u64(char *dst, uint32_t cap, uint32_t idx, uint64_t v) {
    char num[32];
    u64_to_text(v, num, (uint32_t)sizeof(num));
    return text_append(dst, cap, idx, num);
}

static int g_boot_ui_visible = 0;
static uint32_t g_boot_ui_width = 0;
static uint32_t g_boot_ui_height = 0;
static uint32_t g_boot_ui_line = 0;
static struct fb_info g_boot_fb_info;
static char g_status_line[256];

static int boot_ui_probe(void) {
    if (sys_fb_info(&g_boot_fb_info) < 0 ||
        g_boot_fb_info.width == 0 ||
        g_boot_fb_info.height == 0) {
        return 0;
    }
    g_boot_ui_width = g_boot_fb_info.width;
    g_boot_ui_height = g_boot_fb_info.height;
    return 1;
}

static void boot_ui_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t rgb) {
    if (!g_boot_ui_width || !g_boot_ui_height) return;
    if (x >= g_boot_ui_width || y >= g_boot_ui_height) return;
    if (w > g_boot_ui_width - x) w = g_boot_ui_width - x;
    if (h > g_boot_ui_height - y) h = g_boot_ui_height - y;
    if (!w || !h) return;
    (void)sys_fb_drawrect(x, y, w, h, rgb);
}

static uint32_t boot_ui_char(uint32_t x, uint32_t y, char c, uint32_t fg, uint32_t scale) {
    unsigned char ch = (unsigned char)c;
    if (ch >= 128) ch = '?';
    for (uint32_t row = 0; row < 8; ++row) {
        unsigned char bits = (unsigned char)font8x8_basic[ch][row];
        for (uint32_t col = 0; col < 8; ++col) {
            if (bits & (1u << col)) {
                boot_ui_rect(x + col * scale, y + row * scale, scale, scale, fg);
            }
        }
    }
    return x + (8u * scale);
}

static uint32_t boot_ui_text(uint32_t x, uint32_t y, const char *text, uint32_t fg, uint32_t scale) {
    while (text && *text) {
        x = boot_ui_char(x, y, *text++, fg, scale);
    }
    return x;
}

static void boot_ui_begin(void) {
    if (!boot_ui_probe()) return;
    g_boot_ui_visible = 1;
    g_boot_ui_line = 0;
    (void)sys_fb_clear(0x0B1018);
    boot_ui_rect(0, 0, g_boot_ui_width, 42, 0x1A2638);
    boot_ui_text(24, 12, "BitOS Desktop Startup", 0xF3F7FB, 2);
    boot_ui_text(24, 58, "Userspace init is running. Starting login and desktop.", 0xA8C7E8, 1);
    boot_ui_text(24, 78, "If this screen stays here, the last line below is the failing stage.", 0x7F95AA, 1);
    (void)sys_fb_swap();
}

static void boot_ui_status(const char *svc, const char *msg) {
    uint32_t y;
    uint32_t x;
    if (!g_boot_ui_visible) return;
    if (g_boot_ui_line >= 12) {
        boot_ui_rect(24, 104, g_boot_ui_width > 48 ? g_boot_ui_width - 48 : g_boot_ui_width, 220, 0x0B1018);
        g_boot_ui_line = 0;
    }
    y = 108 + g_boot_ui_line * 18;
    x = boot_ui_text(24, y, "[", 0xF3F7FB, 1);
    x = boot_ui_text(x, y, svc ? svc : "service", 0x7DD3FC, 1);
    x = boot_ui_text(x, y, "] ", 0xF3F7FB, 1);
    (void)boot_ui_text(x, y, msg ? msg : "", 0xE6EEF8, 1);
    g_boot_ui_line++;
    (void)sys_fb_swap();
}

static void log_boot(const char *msg) {
    char line[320];
    uint32_t idx = 0;
    int fd = (int)sys_open(DESKTOP_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND);
    if (fd < 0) return;
    idx = text_append(line, (uint32_t)sizeof(line), idx, "[");
    idx = text_append_u64(line, (uint32_t)sizeof(line), idx, now_seconds());
    idx = text_append(line, (uint32_t)sizeof(line), idx, "] ");
    idx = text_append(line, (uint32_t)sizeof(line), idx, msg ? msg : "(null)");
    idx = text_append(line, (uint32_t)sizeof(line), idx, "\n");
    (void)sys_write(fd, line, idx);
    sys_close(fd);
}

static void early_text(const char *msg) {
    uint32_t len = 0;
    if (!msg) return;
    while (msg[len]) len++;
    if (len) (void)sys_write(1, msg, len);
}

static void status_line(const char *svc, const char *msg) {
    uint32_t idx = 0;
    g_status_line[0] = '\0';
    idx = text_append(g_status_line, (uint32_t)sizeof(g_status_line), idx, "init: [");
    idx = text_append(g_status_line, (uint32_t)sizeof(g_status_line), idx, svc ? svc : "service");
    idx = text_append(g_status_line, (uint32_t)sizeof(g_status_line), idx, "] ");
    idx = text_append(g_status_line, (uint32_t)sizeof(g_status_line), idx, msg ? msg : "");
    idx = text_append(g_status_line, (uint32_t)sizeof(g_status_line), idx, "\n");
    boot_ui_status(svc, msg);
    (void)sys_write(1, g_status_line, idx);
}

static long spawn_execve(char *path, char **argv, char **envp) {
    long pid = sys_fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int argc = argv_count(argv);
        (void)sys_execve(path, argc, argv, envp);
        sys_exit(127);
    }
    return pid;
}

static void kill_and_wait(long pid) {
    int st = 0;
    if (pid <= 0) return;
    (void)sys_kill((int)pid, SIGKILL);
    (void)sys_waitpid((int)pid, &st);
}

static int wait_for_path(const char *svc, const char *path, uint64_t timeout_ms) {
    uint64_t start = uptime_ms();
    status_line(svc, "waiting");
    while ((uptime_ms() - start) < timeout_ms) {
        if (path_exists(path)) {
            status_line(svc, "ready");
            return 1;
        }
        sys_sleep_ms(50);
    }
    status_line(svc, "timeout");
    return 0;
}

static void clear_ready_file(void) {
    int fd = (int)sys_open(WM_READY_PATH, O_WRONLY | O_CREAT | O_TRUNC);
    if (fd >= 0) sys_close(fd);
}

static uint64_t read_ready_pid(void) {
    int fd = (int)sys_open(WM_READY_PATH, O_RDONLY);
    char buf[32];
    long n;
    uint64_t pid = 0;
    uint32_t i = 0;
    if (fd < 0) return 0;
    n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    while (buf[i] == ' ' || buf[i] == '\t' || buf[i] == '\n' || buf[i] == '\r') i++;
    pid = parse_u64(buf + i);
    return pid;
}

static int wait_for_wm_ready(uint32_t pid, uint64_t timeout_ms) {
    uint64_t start = uptime_ms();
    while ((uptime_ms() - start) < timeout_ms) {
        if (read_ready_pid() == (uint64_t)pid) return 1;
        sys_sleep_ms(50);
    }
    return 0;
}

static uint64_t restart_backoff_ms(int failures) {
    uint64_t ms = 500;
    for (int i = 1; i < failures; ++i) {
        if (ms >= 4000) break;
        ms *= 2;
    }
    if (ms > 4000) ms = 4000;
    return ms;
}

static void run_login_recovery(const char *reason) {
    char *login_argv[2];
    login_argv[0] = (char *)LOGIN_PATH;
    login_argv[1] = 0;
    status_line("shell", "console recovery mode");
    if (reason && reason[0]) {
        status_line("shell", reason);
    }
    for (;;) {
        long pid;
        int st = 0;
        pid = spawn_execve(login_argv[0], login_argv, 0);
        if (pid < 0) {
            status_line("shell", "failed to spawn /bin/login");
            sys_sleep_ms(1000);
            continue;
        }
        (void)sys_waitpid((int)pid, &st);
        status_line("shell", "login exited, restarting");
        sys_sleep_ms(1000);
    }
}

static int launch_desktop_login(void) {
    char *argv[2];
    const char *path = DESKTOP_LOGIN_PATH;
    long pid;

    if (!path_exists(path)) {
        path = LOGIN_PATH;
    }
    if (!path_exists(path)) {
        status_line("session", "no login UI available");
        return 0;
    }

    argv[0] = (char *)path;
    argv[1] = 0;
    pid = spawn_execve(argv[0], argv, 0);
    if (pid < 0) {
        status_line("session", "failed to start login UI");
        return 0;
    }

    if (str_eq(path, DESKTOP_LOGIN_PATH)) {
        status_line("session", "graphical login started");
    } else {
        status_line("session", "text login started");
    }
    return 1;
}

static void start_optional_services(int safe_mode) {
    char *cron_argv[2];
    cron_argv[0] = (char *)CRON_PATH;
    cron_argv[1] = 0;
    if (safe_mode) {
        status_line("services", "safe mode: optional services disabled");
        return;
    }
    if (!path_exists(CRON_PATH)) {
        status_line("services", "cron not found, skipping");
        return;
    }
    if (spawn_execve(cron_argv[0], cron_argv, 0) < 0) {
        status_line("services", "cron spawn failed");
    } else {
        status_line("services", "cron started");
    }
}

static void run_desktop_mode(int safe_mode) {
    char *wm_argv[2];
    char *wm_env_safe[2];
    char *wm_env_normal[2];
    int unstable = 0;
    int first_ready = 0;
    int login_started = 0;

    wm_argv[0] = (char *)COMPOSITOR_PATH;
    wm_argv[1] = 0;
    wm_env_safe[0] = "BITOS_DESKTOP_SAFE=1";
    wm_env_safe[1] = 0;
    wm_env_normal[0] = "BITOS_DESKTOP_SAFE=0";
    wm_env_normal[1] = 0;

    status_line("boot", "desktop target selected");
    if (!path_exists(COMPOSITOR_PATH)) {
        status_line("compositor", "missing /bin/wm");
        run_login_recovery("desktop unavailable, fallback to console");
        return;
    }
    if (!wait_for_path("input", INPUT_PATH, 6000)) {
        run_login_recovery("input unavailable, fallback to console");
        return;
    }
    if (!wait_for_path("fb", FB_PATH, 6000)) {
        run_login_recovery("framebuffer unavailable, fallback to console");
        return;
    }
    if (safe_mode) {
        status_line("safe-mode", "enabled (optional services/effects reduced)");
    }

    for (;;) {
        long pid;
        int st = 0;
        uint64_t stable_start = 0;

        clear_ready_file();
        status_line("compositor", "starting");
        pid = spawn_execve(wm_argv[0], wm_argv, safe_mode ? wm_env_safe : wm_env_normal);
        if (pid < 0) {
            unstable++;
            status_line("compositor", "spawn failed");
        } else if (!wait_for_wm_ready((uint32_t)pid, 5000)) {
            unstable++;
            status_line("compositor", "startup watchdog timeout");
            kill_and_wait(pid);
        } else {
            status_line("compositor", "ready");
            stable_start = uptime_ms();
            if (!login_started) {
                login_started = launch_desktop_login();
            }
            if (!first_ready) {
                status_line("shell", "desktop shell ready");
                log_boot("desktop boot result: success");
                start_optional_services(safe_mode);
                first_ready = 1;
            }
            (void)sys_waitpid((int)pid, &st);
            if ((uptime_ms() - stable_start) >= 30000ull) {
                unstable = 0;
            } else {
                unstable++;
            }
            status_line("compositor", "exited");
        }

        if (unstable >= 4) {
            log_boot("desktop boot result: compositor unstable, fallback console");
            run_login_recovery("compositor unstable, fallback to console");
            return;
        }

        {
            uint64_t backoff = restart_backoff_ms(unstable);
            status_line("compositor", "restarting");
            sys_sleep_ms(backoff);
        }
    }
}

static int parse_boot_mode(int argc, char **argv, int *safe_mode) {
    int mode = BOOT_MODE_DESKTOP;
    if (safe_mode) *safe_mode = 0;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) continue;
        if (starts_with(arg, "--mode=")) {
            const char *v = arg + 7;
            if (str_eq(v, "console")) mode = BOOT_MODE_CONSOLE;
            if (str_eq(v, "desktop")) mode = BOOT_MODE_DESKTOP;
        } else if (str_eq(arg, "--safe-mode")) {
            if (safe_mode) *safe_mode = 1;
        } else if (starts_with(arg, "--safe-mode=")) {
            if (safe_mode) *safe_mode = parse_bool(arg + 12);
        }
    }
    return mode;
}

void BITOS_USER_NORETURN bitos_init_start(uint64_t *sp) {
    int safe_mode = 0;
    int mode = BOOT_MODE_DESKTOP;
    (void)sp;

    early_text("init: raw userspace start\n");
    /*
     * Do not touch framebuffer syscalls until the compositor/login path is
     * proven working. Early fb bootstrap was masking progress and may be
     * stalling before the desktop handoff becomes visible.
     */
    status_line("boot", "init started");
    /*
     * Keep first userspace boot deterministic: the kernel already selected
     * desktop mode from Limine. Avoid depending on argv parsing until the
     * login/desktop handoff is visible and stable.
     */
    if (mode == BOOT_MODE_CONSOLE) {
        status_line("boot", "console mode forced");
        run_login_recovery("boot.mode=console");
    } else {
        run_desktop_mode(safe_mode);
    }
    sys_exit(0);
    for (;;) { }
}

#if defined(__GNUC__) || defined(__clang__)
void BITOS_USER_NAKED BITOS_USER_NORETURN _start(void) {
    __asm__ volatile(
        "mov %rsp, %rdi\n"
        "andq $-16, %rsp\n"
        "call bitos_init_start\n"
    );
}
#else
void _start(void) { bitos_init_start(0); }
#endif
