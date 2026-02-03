#include "console.h"

#include <stddef.h>

#include "commands.h"
#include "fs_mock.h"
#include "keyboard.h"
#include "log.h"
#include "monitor.h"

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

void console_run(void) {
    int cwd = fs_root();
    char line[128];
    int len = 0;
    struct command_ctx ctx = { .cwd = &cwd };

    while (1) {
        int did_work = 0;
        while (1) {
            int ch = kb_poll_char();
            if (ch < 0) break;
            did_work = 1;

            if (ch == '\r') ch = '\n';
            if (ch == '\b') {
                if (len > 0) {
                    len--;
                    line[len] = '\0';
                    log_printf("\b");
                }
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
                log_printf("> ");
                continue;
            }

            if (len + 1 < (int)sizeof(line)) {
                line[len++] = (char)ch;
                line[len] = '\0';
                log_printf("%c", (char)ch);
            }
        }
        monitor_tick();
        if (!did_work) console_idle();
    }
}
