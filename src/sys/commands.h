#ifndef COMMANDS_H
#define COMMANDS_H

#include <stddef.h>

struct command_ctx {
    int *cwd;
};

int commands_exec(int argc, char **argv, struct command_ctx *ctx);
void commands_help(void);
size_t commands_count(void);
const char *commands_get(size_t idx);

#endif /* COMMANDS_H */
