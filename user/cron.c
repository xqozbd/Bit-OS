#include "sys.h"

struct cron_job {
    uint32_t interval_ms;
    char cmd[64];
    char args[128];
    uint64_t next_ms;
};

static int is_space(char c) {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int parse_jobs(struct cron_job *jobs, int max) {
    int fd = (int)sys_open("/etc/cron.conf", O_RDONLY);
    if (fd < 0) return 0;
    char buf[1024];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';

    int count = 0;
    char *p = buf;
    while (*p && count < max) {
        while (*p && (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t')) p++;
        if (!*p) break;
        if (*p == '#') {
            while (*p && *p != '\n') p++;
            continue;
        }
        struct cron_job *j = &jobs[count];
        j->cmd[0] = '\0';
        j->args[0] = '\0';
        j->interval_ms = 0;
        j->next_ms = 0;

        char numbuf[16];
        int ni = 0;
        while (*p && !is_space(*p) && ni + 1 < (int)sizeof(numbuf)) {
            numbuf[ni++] = *p++;
        }
        numbuf[ni] = '\0';
        uint32_t sec = (uint32_t)uatoi(numbuf);
        if (sec == 0) {
            while (*p && *p != '\n') p++;
            continue;
        }
        j->interval_ms = sec * 1000u;

        while (*p && is_space(*p)) p++;
        int ci = 0;
        while (*p && !is_space(*p) && ci + 1 < (int)sizeof(j->cmd)) {
            j->cmd[ci++] = *p++;
        }
        j->cmd[ci] = '\0';
        while (*p && is_space(*p)) p++;
        int ai = 0;
        while (*p && *p != '\n' && ai + 1 < (int)sizeof(j->args)) {
            j->args[ai++] = *p++;
        }
        j->args[ai] = '\0';
        if (j->cmd[0]) {
            j->next_ms = j->interval_ms;
            count++;
        }
        while (*p && *p != '\n') p++;
    }
    return count;
}

static int build_argv(const char *cmd, const char *args, char **argv, int max) {
    int argc = 0;
    if (argc < max) argv[argc++] = (char *)cmd;
    if (args && *args) {
        static char buf[128];
        int i = 0;
        while (args[i] && i + 1 < (int)sizeof(buf)) {
            buf[i] = args[i];
            i++;
        }
        buf[i] = '\0';
        char *p = buf;
        while (*p && argc < max) {
            while (*p && is_space(*p)) p++;
            if (!*p) break;
            argv[argc++] = p;
            while (*p && !is_space(*p)) p++;
            if (*p) *p++ = '\0';
        }
    }
    if (argc < max) argv[argc] = 0;
    return argc;
}

static void run_job(const struct cron_job *j) {
    if (!j || !j->cmd[0]) return;
    char *argv[8];
    int argc = build_argv(j->cmd, j->args, argv, 7);
    if (argc <= 0) return;
    long pid = sys_fork();
    if (pid == 0) {
        sys_exec(j->cmd, argc, argv);
        sys_exit(1);
    }
}

void _start(void) {
    uputs("cron: starting\n");
    struct cron_job jobs[8];
    int count = parse_jobs(jobs, 8);
    if (count == 0) {
        uputs("cron: no jobs\n");
    }
    uint64_t now_ms = 0;
    for (;;) {
        sys_sleep_ms(1000);
        now_ms += 1000;
        for (int i = 0; i < count; ++i) {
            if (jobs[i].interval_ms == 0) continue;
            if (now_ms >= jobs[i].next_ms) {
                run_job(&jobs[i]);
                jobs[i].next_ms = now_ms + jobs[i].interval_ms;
            }
        }
    }
}
