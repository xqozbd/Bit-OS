#ifndef COMMANDS_H
#define COMMANDS_H

struct command_ctx {
    int *cwd;
};

int commands_exec(int argc, char **argv, struct command_ctx *ctx);
void commands_help(void);

#endif /* COMMANDS_H */
