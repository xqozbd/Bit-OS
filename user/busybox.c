#include "sys.h"

static const char *base_name(const char *path) {
    const char *last = path;
    for (const char *p = path; p && *p; ++p) {
        if (*p == '/') last = p + 1;
    }
    return last ? last : path;
}

enum { MAX_ENV = 16, MAX_ENV_LEN = 64, MAX_JOBS = 8 };

static char g_env[MAX_ENV][MAX_ENV_LEN];
static int g_env_count = 0;

struct job {
    int id;
    int pid;
    int stopped;
    char cmd[64];
};

static struct job g_jobs[MAX_JOBS];
static int g_job_next = 1;
static int g_shell_pgid = 0;

static int is_space(char c) {
    return (c == ' ' || c == '\t' || c == '\n' || c == '\r');
}

static void trim_line(char *s) {
    if (!s) return;
    char *start = s;
    while (*start && is_space(*start)) start++;
    char *end = start;
    while (*end) end++;
    while (end > start && is_space(*(end - 1))) end--;
    if (start != s) {
        while (start < end) *s++ = *start++;
        *s = '\0';
    } else {
        *end = '\0';
    }
}

static void strip_comment(char *s) {
    if (!s) return;
    for (int i = 0; s[i]; ++i) {
        if (s[i] == '#') {
            if (i == 0 || is_space(s[i - 1])) {
                s[i] = '\0';
                return;
            }
        }
    }
}

static int split_line(char *s, char **argv, int max) {
    int argc = 0;
    while (s && *s) {
        while (*s && is_space(*s)) s++;
        if (!*s) break;
        if (argc + 1 >= max) break;
        argv[argc++] = s;
        while (*s && !is_space(*s)) s++;
        if (*s) *s++ = '\0';
    }
    argv[argc] = 0;
    return argc;
}

static int dispatch(const char *name, int argc, char **argv);
static int run_command(char *line, int interactive);

static int env_find(const char *key) {
    if (!key) return -1;
    size_t klen = ustrlen(key);
    for (int i = 0; i < g_env_count; ++i) {
        const char *e = g_env[i];
        int match = 1;
        for (size_t j = 0; j < klen; ++j) {
            if (e[j] != key[j]) { match = 0; break; }
        }
        if (!match) continue;
        if (e[klen] == '=') return i;
    }
    return -1;
}

static const char *env_get(const char *key) {
    int idx = env_find(key);
    if (idx < 0) return "";
    const char *e = g_env[idx];
    const char *p = e;
    while (*p && *p != '=') p++;
    if (*p == '=') p++;
    return p;
}

static int env_set_kv(const char *key, const char *val) {
    if (!key || !*key) return 0;
    if (!val) val = "";
    size_t klen = ustrlen(key);
    size_t vlen = ustrlen(val);
    if (klen + 1 + vlen + 1 > MAX_ENV_LEN) return 0;
    int idx = env_find(key);
    if (idx < 0) {
        if (g_env_count >= MAX_ENV) return 0;
        idx = g_env_count++;
    }
    char *dst = g_env[idx];
    size_t pos = 0;
    for (size_t i = 0; i < klen; ++i) dst[pos++] = key[i];
    dst[pos++] = '=';
    for (size_t i = 0; i < vlen; ++i) dst[pos++] = val[i];
    dst[pos] = '\0';
    return 1;
}

static int env_set_assign(const char *assign) {
    if (!assign) return 0;
    const char *eq = assign;
    while (*eq && *eq != '=') eq++;
    if (*eq != '=') return 0;
    char key[32];
    size_t klen = (size_t)(eq - assign);
    if (klen == 0 || klen >= sizeof(key)) return 0;
    for (size_t i = 0; i < klen; ++i) key[i] = assign[i];
    key[klen] = '\0';
    return env_set_kv(key, eq + 1);
}

static int env_unset(const char *key) {
    int idx = env_find(key);
    if (idx < 0) return 0;
    if (idx != g_env_count - 1) {
        for (int i = idx; i < g_env_count - 1; ++i) {
            for (int j = 0; j < MAX_ENV_LEN; ++j) g_env[i][j] = g_env[i + 1][j];
        }
    }
    g_env_count--;
    return 1;
}

static void env_dump(void) {
    for (int i = 0; i < g_env_count; ++i) {
        uputs(g_env[i]);
        uputc('\n');
    }
}

static void jobs_dump(void) {
    for (int i = 0; i < MAX_JOBS; ++i) {
        if (g_jobs[i].id == 0) continue;
        uputc('[');
        uputc((char)('0' + (g_jobs[i].id % 10)));
        uputc(']');
        uputc(' ');
        if (g_jobs[i].stopped) uputs("stopped ");
        else uputs("running ");
        uputs(g_jobs[i].cmd);
        uputc('\n');
    }
}

static int jobs_add(int pid, const char *cmd, int stopped) {
    for (int i = 0; i < MAX_JOBS; ++i) {
        if (g_jobs[i].id == 0) {
            g_jobs[i].id = g_job_next++;
            g_jobs[i].pid = pid;
            g_jobs[i].stopped = stopped;
            int j = 0;
            while (cmd && cmd[j] && j + 1 < (int)sizeof(g_jobs[i].cmd)) {
                g_jobs[i].cmd[j] = cmd[j];
                j++;
            }
            g_jobs[i].cmd[j] = '\0';
            return g_jobs[i].id;
        }
    }
    return -1;
}

static struct job *jobs_find(int id) {
    for (int i = 0; i < MAX_JOBS; ++i) {
        if (g_jobs[i].id == id) return &g_jobs[i];
    }
    return 0;
}

static void jobs_remove_pid(int pid) {
    for (int i = 0; i < MAX_JOBS; ++i) {
        if (g_jobs[i].id && g_jobs[i].pid == pid) {
            g_jobs[i].id = 0;
            g_jobs[i].pid = 0;
            g_jobs[i].stopped = 0;
            g_jobs[i].cmd[0] = '\0';
        }
    }
}

static int applet_ls(int argc, char **argv) {
    (void)argc;
    const char *path = ".";
    if (argv && argv[1] && argv[1][0]) path = argv[1];
    char buf[1024];
    long rc = sys_listdir(path, buf, sizeof(buf) - 1);
    if (rc < 0) {
        uputs("ls: failed\n");
        return 1;
    }
    buf[rc] = '\0';
    sys_write(1, buf, (size_t)rc);
    return 0;
}

static int applet_ps(int argc, char **argv) {
    (void)argc; (void)argv;
    char buf[2048];
    int fd = (int)sys_open("/proc/tasks", O_RDONLY);
    if (fd < 0) {
        uputs("ps: cannot open /proc/tasks\n");
        return 1;
    }
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n < 0) {
        uputs("ps: read failed\n");
        return 1;
    }
    buf[n] = '\0';
    sys_write(1, buf, (size_t)n);
    return 0;
}

static int applet_top(int argc, char **argv) {
    int iters = 5;
    if (argc > 1 && argv && argv[1]) iters = uatoi(argv[1]);
    if (iters <= 0) iters = 1;
    char buf[2048];
    for (int iter = 0; iter < iters; ++iter) {
        int fd = (int)sys_open("/proc/tasks", O_RDONLY);
        if (fd >= 0) {
            long n = sys_read(fd, buf, sizeof(buf) - 1);
            sys_close(fd);
            if (n > 0) {
                buf[n] = '\0';
                sys_write(1, buf, (size_t)n);
            }
        }
        sys_sleep_ms(1000);
    }
    return 0;
}

static int applet_mount(int argc, char **argv) {
    uint32_t part = 0;
    uint32_t type = 1; /* 1=ext2, 2=fat32 */
    if (argc > 1 && argv && argv[1]) {
        if (ustrcmp(argv[1], "fat32") == 0) type = 2;
        else type = 1;
    }
    if (argc > 2 && argv && argv[2]) part = (uint32_t)uatoi(argv[2]);
    long rc = sys_mount(part, type);
    if (rc == 0) {
        if (type == 1) uputs("mount: mounted ext2 partition as root\n");
        else uputs("mount: mounted fat32 partition as root\n");
        return 0;
    }
    uputs("mount: failed\n");
    return 1;
}

static int applet_umount(int argc, char **argv) {
    (void)argc; (void)argv;
    long rc = sys_umount();
    if (rc == 0) {
        uputs("umount: switched root to initramfs/mock\n");
        return 0;
    }
    uputs("umount: failed\n");
    return 1;
}

static int applet_dd(int argc, char **argv) {
    const char *src = "/mock/README.txt";
    const char *dst = "/mock/dd.copy";
    if (argc > 1 && argv && argv[1]) src = argv[1];
    if (argc > 2 && argv && argv[2]) dst = argv[2];

    int fd_in = (int)sys_open(src, O_RDONLY);
    if (fd_in < 0) {
        uputs("dd: open src failed\n");
        return 1;
    }
    int fd_out = (int)sys_open(dst, O_CREAT | O_TRUNC | O_WRONLY);
    if (fd_out < 0) {
        uputs("dd: open dst failed\n");
        sys_close(fd_in);
        return 1;
    }

    char buf[512];
    while (1) {
        long n = sys_read(fd_in, buf, sizeof(buf));
        if (n <= 0) break;
        long w = sys_write(fd_out, buf, (size_t)n);
        if (w != n) break;
    }
    sys_close(fd_in);
    sys_close(fd_out);
    uputs("dd: copy complete\n");
    return 0;
}

static int tokenize_line(const char *line, char *out, int out_max) {
    int w = 0;
    for (int i = 0; line && line[i] && w + 2 < out_max; ++i) {
        char c = line[i];
        if (c == '|' || c == '<' || c == '>' || c == '&') {
            if (w > 0 && out[w - 1] != ' ') out[w++] = ' ';
            out[w++] = c;
            if (c == '>' && line[i + 1] == '>' && w + 2 < out_max) {
                out[w++] = '>';
                i++;
            }
            out[w++] = ' ';
        } else {
            out[w++] = c;
        }
    }
    out[w] = '\0';
    return w;
}

static void expand_vars(char **argv, int argc) {
    for (int i = 0; i < argc; ++i) {
        if (argv[i] && argv[i][0] == '$' && argv[i][1]) {
            argv[i] = (char *)env_get(argv[i] + 1);
        }
    }
}

struct cmd {
    char *argv[8];
    int argc;
    char *in;
    char *out;
    int append;
};

static int parse_pipeline(char **tokens, int tokc, struct cmd *cmds, int max_cmds, int *out_bg) {
    int cmdc = 0;
    int bg = 0;
    struct cmd *cur = &cmds[0];
    cur->argc = 0;
    cur->in = 0;
    cur->out = 0;
    cur->append = 0;
    for (int i = 0; i < tokc; ++i) {
        char *t = tokens[i];
        if (!t) continue;
        if (ustrcmp(t, "|") == 0) {
            if (cur->argc == 0) return -1;
            cur->argv[cur->argc] = 0;
            cmdc++;
            if (cmdc >= max_cmds) return -1;
            cur = &cmds[cmdc];
            cur->argc = 0;
            cur->in = 0;
            cur->out = 0;
            cur->append = 0;
            continue;
        }
        if (ustrcmp(t, "<") == 0 && i + 1 < tokc) {
            cur->in = tokens[++i];
            continue;
        }
        if ((ustrcmp(t, ">") == 0 || ustrcmp(t, ">>") == 0) && i + 1 < tokc) {
            cur->out = tokens[++i];
            cur->append = (t[1] == '>');
            continue;
        }
        if (ustrcmp(t, "&") == 0 && i == tokc - 1) {
            bg = 1;
            continue;
        }
        if (cur->argc + 1 < (int)(sizeof(cur->argv) / sizeof(cur->argv[0]))) {
            cur->argv[cur->argc++] = t;
        }
    }
    if (cur->argc == 0) return -1;
    cur->argv[cur->argc] = 0;
    cmdc++;
    *out_bg = bg;
    return cmdc;
}

static char **build_envp(void) {
    static char *envp[MAX_ENV + 1];
    for (int i = 0; i < g_env_count; ++i) envp[i] = g_env[i];
    envp[g_env_count] = 0;
    return envp;
}

static int run_command(char *line, int interactive) {
    char norm[256];
    strip_comment(line);
    trim_line(line);
    if (!line[0]) return 0;

    tokenize_line(line, norm, (int)sizeof(norm));
    char *tokens[32];
    int tokc = split_line(norm, tokens, 32);
    if (tokc == 0) return 0;
    expand_vars(tokens, tokc);

    if (ustrcmp(tokens[0], "exit") == 0) return -1;
    if (ustrcmp(tokens[0], "set") == 0) {
        if (tokc == 1) env_dump();
        else env_set_assign(tokens[1]);
        return 0;
    }
    if (ustrcmp(tokens[0], "export") == 0) {
        if (tokc == 1) env_dump();
        else {
            if (!env_set_assign(tokens[1])) {
                const char *v = env_get(tokens[1]);
                env_set_kv(tokens[1], v);
            }
        }
        return 0;
    }
    if (ustrcmp(tokens[0], "unset") == 0) {
        if (tokc > 1) env_unset(tokens[1]);
        return 0;
    }
    if (ustrcmp(tokens[0], "env") == 0) {
        env_dump();
        return 0;
    }
    if (ustrcmp(tokens[0], "jobs") == 0) {
        jobs_dump();
        return 0;
    }
    if (ustrcmp(tokens[0], "fg") == 0) {
        int id = (tokc > 1) ? uatoi(tokens[1]) : -1;
        struct job *j = jobs_find(id);
        if (!j) return 0;
        sys_tcsetpgrp(j->pid);
        sys_kill(j->pid, SIGCONT);
        int st = 0;
        int rc = (int)sys_waitpid(j->pid, &st);
        sys_tcsetpgrp(g_shell_pgid);
        if (rc > 0 && st == 128 + SIGSTOP) {
            j->stopped = 1;
        } else {
            jobs_remove_pid(j->pid);
        }
        return 0;
    }
    if (ustrcmp(tokens[0], "bg") == 0) {
        int id = (tokc > 1) ? uatoi(tokens[1]) : -1;
        struct job *j = jobs_find(id);
        if (!j) return 0;
        sys_kill(j->pid, SIGCONT);
        j->stopped = 0;
        return 0;
    }
    if (ustrcmp(tokens[0], "sleep") == 0) {
        if (tokc > 1) sys_sleep_ms((uint64_t)uatoi(tokens[1]) * 1000u);
        return 0;
    }
    if (ustrcmp(tokens[0], "echo") == 0) {
        for (int i = 1; i < tokc; ++i) {
            uputs(tokens[i]);
            if (i + 1 < tokc) uputc(' ');
        }
        uputc('\n');
        return 0;
    }

    struct cmd cmds[4];
    int bg = 0;
    int cmdc = parse_pipeline(tokens, tokc, cmds, 4, &bg);
    if (cmdc < 0) return 0;

    int pipefds[8];
    for (int i = 0; i < (cmdc - 1); ++i) {
        if (sys_pipe(&pipefds[i * 2]) != 0) return 0;
    }

    int pids[4];
    int group_pgid = 0;
    for (int i = 0; i < cmdc; ++i) {
        long pid = sys_fork();
        if (pid == 0) {
            if (i == 0) {
                sys_setpgid(0, 0);
            } else if (group_pgid) {
                sys_setpgid(0, group_pgid);
            }
            if (cmds[i].in) {
                int fd = (int)sys_open(cmds[i].in, O_RDONLY);
                if (fd >= 0) {
                    sys_dup2(fd, 0);
                    sys_close(fd);
                }
            } else if (i > 0) {
                sys_dup2(pipefds[(i - 1) * 2], 0);
            }
            if (cmds[i].out) {
                uint32_t flags = O_WRONLY | O_CREAT | (cmds[i].append ? O_APPEND : O_TRUNC);
                int fd = (int)sys_open(cmds[i].out, flags);
                if (fd >= 0) {
                    sys_dup2(fd, 1);
                    sys_close(fd);
                }
            } else if (i + 1 < cmdc) {
                sys_dup2(pipefds[i * 2 + 1], 1);
            }
            for (int j = 0; j < (cmdc - 1) * 2; ++j) sys_close(pipefds[j]);

            const char *cmd = base_name(cmds[i].argv[0]);
            int rc = dispatch(cmd, cmds[i].argc, cmds[i].argv);
            if (rc != -1) sys_exit(rc);

            sys_execve(cmds[i].argv[0], cmds[i].argc, cmds[i].argv, build_envp());
            sys_exit(1);
        }
        pids[i] = (int)pid;
        if (group_pgid == 0) group_pgid = (int)pid;
        sys_setpgid((int)pid, group_pgid);
    }
    for (int j = 0; j < (cmdc - 1) * 2; ++j) sys_close(pipefds[j]);

    if (bg) {
        jobs_add(group_pgid, line, 0);
        return 0;
    }
    sys_tcsetpgrp(group_pgid);
    for (int i = 0; i < cmdc; ++i) {
        int st = 0;
        int rc = (int)sys_waitpid(pids[i], &st);
        if (rc > 0 && st == 128 + SIGSTOP) {
            jobs_add(group_pgid, line, 1);
        }
    }
    jobs_remove_pid(group_pgid);
    sys_tcsetpgrp(g_shell_pgid);
    (void)interactive;
    return 0;
}

static int applet_sh(int argc, char **argv) {
    int fd = 0;
    if (argc > 1 && argv && argv[1]) {
        fd = (int)sys_open(argv[1], O_RDONLY);
        if (fd < 0) {
            uputs("sh: cannot open script\n");
            return 1;
        }
    }

    char line[256];
    int line_len = 0;
    char buf[256];
    long n;
    while ((n = sys_read(fd, buf, sizeof(buf))) > 0) {
        for (long i = 0; i < n; ++i) {
            char c = buf[i];
            if (c == '\r') continue;
            if (c == '\n') {
                line[line_len] = '\0';
                int rc = run_command(line, 0);
                line_len = 0;
                if (rc < 0) {
                    if (fd > 0) sys_close(fd);
                    return 0;
                }
                continue;
            }
            if (line_len + 1 < (int)sizeof(line)) {
                line[line_len++] = c;
            }
        }
    }
    if (line_len > 0) {
        line[line_len] = '\0';
        (void)run_command(line, 0);
    }
    if (fd > 0) sys_close(fd);
    return 0;
}

static void applet_help(void) {
    uputs("busybox applets: ls ps top mount umount dd sh help\n");
}

static int dispatch(const char *name, int argc, char **argv) {
    if (!name) return 1;
    if (ustrcmp(name, "ls") == 0) return applet_ls(argc, argv);
    if (ustrcmp(name, "ps") == 0) return applet_ps(argc, argv);
    if (ustrcmp(name, "top") == 0) return applet_top(argc, argv);
    if (ustrcmp(name, "mount") == 0) return applet_mount(argc, argv);
    if (ustrcmp(name, "umount") == 0) return applet_umount(argc, argv);
    if (ustrcmp(name, "dd") == 0) return applet_dd(argc, argv);
    if (ustrcmp(name, "sh") == 0) return applet_sh(argc, argv);
    if (ustrcmp(name, "help") == 0) {
        applet_help();
        return 0;
    }
    return -1;
}

void _start(void) {
    uint64_t *sp;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));
#else
    sp = 0;
#endif
    int argc = (int)sp[0];
    char **argv = (char **)&sp[1];

    const char *app = NULL;
    if (argc > 0 && argv && argv[0]) {
        app = base_name(argv[0]);
    }
    if (app && ustrcmp(app, "busybox") == 0 && argc > 1) {
        app = argv[1];
        argc -= 1;
        argv += 1;
    }
    if (!g_shell_pgid) {
        int pid = (int)sys_getpid();
        sys_setpgid(0, pid);
        g_shell_pgid = pid;
        sys_tcsetpgrp(g_shell_pgid);
    }
    if (!app) {
        applet_help();
        sys_exit(1);
    }

    int rc = dispatch(app, argc, argv);
    if (rc == -1) {
        uputs("busybox: unknown applet: ");
        uputs(app);
        uputc('\n');
        applet_help();
        sys_exit(1);
    }
    sys_exit(rc);
}
