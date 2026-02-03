#include "kernel/console.h"

#include <stddef.h>

#include "sys/commands.h"
#include "sys/fs_mock.h"
#include "drivers/ps2/keyboard.h"
#include "lib/log.h"
#include "kernel/monitor.h"

static inline void cpu_relax(void) {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile ("pause");
#endif
}

static void console_idle(void) {
    for (int i = 0; i < 50; ++i) cpu_relax();
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
}

static void console_redraw(const char *line, int len, int cursor, int *last_len) {
    if (len < 0) len = 0;
    if (cursor < 0) cursor = 0;
    if (cursor > len) cursor = len;

    log_printf("\r> ");
    for (int i = 0; i < len; ++i) log_printf("%c", line[i]);
    if (*last_len > len) {
        for (int i = 0; i < *last_len - len; ++i) log_printf(" ");
    }
    /* Move cursor back to position */
    int back = len - cursor;
    for (int i = 0; i < back; ++i) log_printf("\b");
    /* Draw caret */
    log_printf("_");
    log_printf("\b");
    *last_len = len;
}

void console_run(void) {
    int cwd = fs_root();
    char line[128];
    int len = 0;
    int cursor = 0;
    int last_len = 0;
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
                console_redraw(line, len, cursor, &last_len);
                continue;
            }

            if (ch == KB_KEY_LEFT) {
                if (cursor > 0) cursor--;
                console_redraw(line, len, cursor, &last_len);
                continue;
            }
            if (ch == KB_KEY_RIGHT) {
                if (cursor < len) cursor++;
                console_redraw(line, len, cursor, &last_len);
                continue;
            }

            if (ch == '\n') {
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
                console_redraw(line, len, cursor, &last_len);
            }
        }
        monitor_tick();
        if (!did_work) console_idle();
    }
}
