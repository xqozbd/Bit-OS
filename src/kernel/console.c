#include "kernel/console.h"

#include <stddef.h>

#include "sys/commands.h"
#include "sys/vfs.h"
#include "drivers/ps2/keyboard.h"
#include "drivers/ps2/mouse.h"
#include "lib/log.h"
#include "kernel/monitor.h"
#include "kernel/sched.h"
#include "arch/x86_64/timer.h"
#include "drivers/video/fb_printf.h"
#include "lib/strutil.h"

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

enum { CONSOLE_HISTORY_MAX = 16 };
static char g_history[CONSOLE_HISTORY_MAX][128];
static int g_history_count = 0;

static void history_add(const char *line, int len) {
    if (len <= 0) return;
    if (len >= (int)sizeof(g_history[0])) len = (int)sizeof(g_history[0]) - 1;
    if (g_history_count > 0) {
        const char *last = g_history[g_history_count - 1];
        if (str_eqn(last, line, (size_t)len) && last[len] == '\0') {
            return;
        }
    }
    if (g_history_count == CONSOLE_HISTORY_MAX) {
        for (int i = 1; i < CONSOLE_HISTORY_MAX; ++i) {
            for (int j = 0; j < (int)sizeof(g_history[0]); ++j) {
                g_history[i - 1][j] = g_history[i][j];
            }
        }
        g_history_count = CONSOLE_HISTORY_MAX - 1;
    }
    for (int i = 0; i < len; ++i) g_history[g_history_count][i] = line[i];
    g_history[g_history_count][len] = '\0';
    g_history_count++;
}

static void history_load(int index, char *line, int *len, int *cursor) {
    if (index < 0 || index >= g_history_count) return;
    int l = (int)str_len(g_history[index]);
    if (l >= 127) l = 127;
    for (int i = 0; i < l; ++i) line[i] = g_history[index][i];
    line[l] = '\0';
    *len = l;
    *cursor = l;
}

static int complete_command(char *line, int *len, int *cursor) {
    if (*cursor != *len) return 0;
    if (*len == 0) return 0;
    int prefix_len = 0;
    for (int i = 0; i < *len; ++i) {
        if (line[i] == ' ') return 0;
        prefix_len++;
    }
    int match_index = -1;
    int match_count = 0;
    size_t total = commands_count();
    for (size_t i = 0; i < total; ++i) {
        const char *cmd = commands_get(i);
        if (!cmd) continue;
        if (str_eqn(cmd, line, (size_t)prefix_len)) {
            match_index = (int)i;
            match_count++;
        }
    }
    if (match_count == 1 && match_index >= 0) {
        const char *cmd = commands_get((size_t)match_index);
        int cmd_len = (int)str_len(cmd);
        if (cmd_len > prefix_len && cmd_len < (int)sizeof(g_history[0])) {
            int add = cmd_len - prefix_len;
            if (*len + add >= (int)sizeof(g_history[0])) return 0;
            for (int i = *len; i < *len + add; ++i) {
                line[i] = cmd[prefix_len + (i - *len)];
            }
            *len += add;
            *cursor = *len;
            line[*len] = '\0';
        }
        return 1;
    }
    if (match_count > 1) {
        log_printf("\n");
        for (size_t i = 0; i < total; ++i) {
            const char *cmd = commands_get(i);
            if (!cmd) continue;
            if (str_eqn(cmd, line, (size_t)prefix_len)) {
                log_printf("%s ", cmd);
            }
        }
        log_printf("\n> ");
        return -1;
    }
    return 0;
}

static int completion_suffix(const char *line, int len, int cursor, char *out, int out_cap) {
    if (cursor != len) return 0;
    if (len == 0) return 0;
    int prefix_len = 0;
    for (int i = 0; i < len; ++i) {
        if (line[i] == ' ') return 0;
        prefix_len++;
    }
    int match_index = -1;
    int match_count = 0;
    size_t total = commands_count();
    for (size_t i = 0; i < total; ++i) {
        const char *cmd = commands_get(i);
        if (!cmd) continue;
        if (str_eqn(cmd, line, (size_t)prefix_len)) {
            match_index = (int)i;
            match_count++;
        }
    }
    if (match_count != 1 || match_index < 0) return 0;
    const char *cmd = commands_get((size_t)match_index);
    int cmd_len = (int)str_len(cmd);
    if (cmd_len <= prefix_len) return 0;
    int suffix_len = cmd_len - prefix_len;
    if (suffix_len + 1 > out_cap) suffix_len = out_cap - 1;
    for (int i = 0; i < suffix_len; ++i) out[i] = cmd[prefix_len + i];
    out[suffix_len] = '\0';
    return suffix_len;
}

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

    fb_scrollback_suspend(1);
    log_printf("\r> ");
    for (int i = 0; i < len; ++i) log_printf("%c", line[i]);

    char ghost[128];
    int ghost_len = completion_suffix(line, len, cursor, ghost, (int)sizeof(ghost));
    if (ghost_len > 0) {
        uint32_t fg = 0, bg = 0;
        fb_get_colors(&fg, &bg);
        uint32_t ghost_fg = 0x808080;
        fb_set_colors(ghost_fg, bg);
        for (int i = 0; i < ghost_len; ++i) fb_putc(ghost[i]);
        fb_set_colors(fg, bg);
    }
    int clear_tail = 0;
    int drawn_len = len + ghost_len;
    if (*last_len > drawn_len) clear_tail = *last_len - drawn_len;
    /* Clear the previous caret if it was at end-of-line */
    if (g_last_caret_at_end) clear_tail += 1;
    for (int i = 0; i < clear_tail; ++i) log_printf(" ");
    /* Move cursor back to position */
    int back = (drawn_len + clear_tail) - cursor;
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
    *last_len = drawn_len;
    fb_scrollback_suspend(0);
}

void console_run(void) {
    int cwd = vfs_resolve(0, "/");
    char line[128];
    int len = 0;
    int cursor = 0;
    int last_len = 0;
    int hist_pos = -1;
    char scratch[128];
    int scratch_len = 0;
    int scratch_valid = 0;
    char clipboard[128];
    int clipboard_len = 0;
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
            if (ch == 0x03) { /* Ctrl+C */
                console_redraw(line, len, cursor, &last_len, 0);
                log_printf("^C\n");
                if (len > 0 && len < (int)sizeof(clipboard)) {
                    for (int i = 0; i < len; ++i) clipboard[i] = line[i];
                    clipboard[len] = '\0';
                    clipboard_len = len;
                }
                len = 0;
                cursor = 0;
                last_len = 0;
                hist_pos = -1;
                scratch_valid = 0;
                log_printf("> ");
                console_redraw("", 0, 0, &last_len, 1);
                continue;
            }
            if (ch == 0x16) { /* Ctrl+V */
                if (clipboard_len > 0) {
                    int avail = (int)sizeof(line) - 1 - len;
                    int to_copy = clipboard_len < avail ? clipboard_len : avail;
                    for (int i = len; i > cursor; --i) {
                        line[i + to_copy - 1] = line[i - 1];
                    }
                    for (int i = 0; i < to_copy; ++i) {
                        line[cursor + i] = clipboard[i];
                    }
                    len += to_copy;
                    cursor += to_copy;
                    line[len] = '\0';
                    console_redraw(line, len, cursor, &last_len, 1);
                }
                continue;
            }
            if (ch == '\t') {
                int rc = complete_command(line, &len, &cursor);
                if (rc != 0) {
                    console_redraw(line, len, cursor, &last_len, 1);
                }
                continue;
            }
            if (ch == '\b') {
                if (hist_pos != -1) {
                    hist_pos = -1;
                    scratch_valid = 0;
                }
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
            if (ch == KB_KEY_PGUP) {
                fb_scrollback_up(1);
                caret_visible = 0;
                continue;
            }
            if (ch == KB_KEY_PGDN) {
                fb_scrollback_down(1);
                if (fb_scrollback_offset() == 0) {
                    caret_visible = 1;
                    console_redraw(line, len, cursor, &last_len, caret_visible);
                } else {
                    caret_visible = 0;
                }
                continue;
            }

            if (fb_scrollback_offset() > 0) {
                fb_scrollback_reset();
                console_redraw(line, len, cursor, &last_len, caret_visible);
            }
            if (ch == KB_KEY_UP) {
                if (g_history_count > 0) {
                    if (hist_pos == -1) {
                        for (int i = 0; i < len; ++i) scratch[i] = line[i];
                        scratch[len] = '\0';
                        scratch_len = len;
                        scratch_valid = 1;
                        hist_pos = g_history_count - 1;
                    } else if (hist_pos > 0) {
                        hist_pos--;
                    }
                    history_load(hist_pos, line, &len, &cursor);
                    console_redraw(line, len, cursor, &last_len, 1);
                }
                continue;
            }
            if (ch == KB_KEY_DOWN) {
                if (hist_pos != -1) {
                    if (hist_pos < g_history_count - 1) {
                        hist_pos++;
                        history_load(hist_pos, line, &len, &cursor);
                    } else {
                        hist_pos = -1;
                        if (scratch_valid) {
                            for (int i = 0; i < scratch_len; ++i) line[i] = scratch[i];
                            line[scratch_len] = '\0';
                            len = scratch_len;
                            cursor = scratch_len;
                        } else {
                            len = 0;
                            cursor = 0;
                            line[0] = '\0';
                        }
                    }
                    console_redraw(line, len, cursor, &last_len, 1);
                }
                continue;
            }

            if (ch == '\n') {
                console_redraw(line, len, cursor, &last_len, 0);
                log_printf("\n");
                line[len] = '\0';
                history_add(line, len);
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
                hist_pos = -1;
                scratch_valid = 0;
                log_printf("> ");
                console_redraw("", 0, 0, &last_len, 1);
                continue;
            }

            if (len + 1 < (int)sizeof(line)) {
                if (hist_pos != -1) {
                    hist_pos = -1;
                    scratch_valid = 0;
                }
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
            if (fb_scrollback_offset() > 0) {
                console_idle();
                continue;
            }
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
