#include "kernel/console.h"

#include <stddef.h>

#include "sys/commands.h"
#include "sys/fs_mock.h"
#include "drivers/ps2/keyboard.h"
#include "drivers/ps2/mouse.h"
#include "lib/log.h"
#include "kernel/monitor.h"
#include "kernel/sched.h"
#include "arch/x86_64/timer.h"
#include "drivers/video/fb_printf.h"

static inline void cpu_relax(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("pause");
#endif
}

static void console_idle(void) {
    for (int i = 0; i < 50; ++i) cpu_relax();
}

static void console_redraw(const char *line, int len, int cursor, int *last_len, int show_caret);
static int g_last_caret_at_end = 0;

static int split_args(char *buf, char **argv, int max_args) {
    int argc = 0;
    size_t i = 0;
    while (buf[i]) {
        while (buf[i] == ' ') i++;
        if (!buf[i]) break;
        if (argc >= max_args) break;
        argv[argc++] = &buf[i];
        while (buf[i] && buf[i] != ' ') i++;
        if (buf[i]) buf[i++] = '\0';
    }
    return argc;
}

void console_init(void) {
    kb_init();
    log_printf("\nConsole ready. Type:\n> ");
    int last_len = 0;
    console_redraw("", 0, 0, &last_len, 1);
}

static void console_redraw(const char *line, int len, int cursor, int *last_len, int show_caret) {
    if (len < 0) len = 0;
    if (cursor < 0) cursor = 0;
    if (cursor > len) cursor = len;

    log_printf("\r> ");
    for (int i = 0; i < len; ++i) log_printf("%c", line[i]);
    int clear_tail = 0;
    if (*last_len > len) clear_tail = *last_len - len;
    /* Clear the previous caret if it was at end-of-line */
    if (g_last_caret_at_end) clear_tail += 1;
    for (int i = 0; i < clear_tail; ++i) log_printf(" ");
    /* Move cursor back to position */
    int back = (len + clear_tail) - cursor;
    for (int i = 0; i < back; ++i) log_printf("\b");
    /* Draw caret */
    if (show_caret) {
        uint32_t fg = 0, bg = 0;
        fb_get_colors(&fg, &bg);
        ms_cursor_hide();
        fb_set_colors(bg, fg);
        char ch = (cursor < len) ? line[cursor] : ' ';
        fb_putc(ch);
        fb_set_colors(fg, bg);
        fb_putc('\b');
        ms_cursor_show();
    }
    g_last_caret_at_end = (show_caret && cursor == len) ? 1 : 0;
    *last_len = len;
}

void console_run(void) {
    int cwd = fs_root();
    char line[128];
    int len = 0;
    int cursor = 0;
    int last_len = 0;
    uint64_t blink_last = timer_uptime_ticks();
    uint32_t blink_interval = timer_pit_hz() / 2;
    if (blink_interval == 0) blink_interval = 50;
    int caret_visible = 1;
    struct command_ctx ctx = { .cwd = &cwd };

    while (1) {
        int did_work = 0;
        while (1) {
            int ch = kb_poll_char();
            if (ch < 0) break;
            did_work = 1;

            if (ch == '\r') ch = '\n';
            if (ch == '\b') {
                if (cursor > 0 && len > 0) {
                    for (int i = cursor - 1; i < len - 1; ++i) {
                        line[i] = line[i + 1];
                    }
                    len--;
                    cursor--;
                    line[len] = '\0';
                }
                console_redraw(line, len, cursor, &last_len, 1);
                continue;
            }

            if (ch == KB_KEY_LEFT) {
                if (cursor > 0) cursor--;
                console_redraw(line, len, cursor, &last_len, 1);
                continue;
            }
            if (ch == KB_KEY_RIGHT) {
                if (cursor < len) cursor++;
                console_redraw(line, len, cursor, &last_len, 1);
                continue;
            }

            if (ch == '\n') {
                console_redraw(line, len, cursor, &last_len, 0);
                log_printf("\n");
                line[len] = '\0';
                if (len > 0) {
                    char *argv[8];
                    int argc = split_args(line, argv, 8);
                    if (argc > 0) {
                        if (!commands_exec(argc, argv, &ctx)) {
                            log_printf("Unknown command. Type 'help'.\n");
                        }
                    }
                }
                len = 0;
                cursor = 0;
                last_len = 0;
                log_printf("> ");
                console_redraw("", 0, 0, &last_len, 1);
                continue;
            }

            if (len + 1 < (int)sizeof(line)) {
                for (int i = len; i > cursor; --i) {
                    line[i] = line[i - 1];
                }
                line[cursor] = (char)ch;
                len++;
                cursor++;
                line[len] = '\0';
                console_redraw(line, len, cursor, &last_len, 1);
            }
        }
        monitor_tick();
        sched_maybe_preempt();
        if (did_work) {
            caret_visible = 1;
            blink_last = timer_uptime_ticks();
        } else {
            uint64_t now = timer_uptime_ticks();
            if (now - blink_last >= blink_interval) {
                blink_last = now;
                caret_visible = !caret_visible;
                console_redraw(line, len, cursor, &last_len, caret_visible);
            }
            console_idle();
        }
    }
}
