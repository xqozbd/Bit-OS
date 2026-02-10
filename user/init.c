#include "sys.h"

struct service {
    char name[32];
    char path[64];
    char after[32];
    int started;
};

static int starts_with(const char *s, const char *p) {
    size_t i = 0;
    while (s[i] && p[i]) {
        if (s[i] != p[i]) return 0;
        i++;
    }
    return p[i] == '\0';
}

static int read_services(struct service *out, int max) {
    int fd = (int)sys_open("/etc/services.conf", O_RDONLY);
    if (fd < 0) return 0;
    char buf[1024];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    buf[n] = '\0';
    int count = 0;
    char *p = buf;
    while (*p && count < max) {
        while (*p == '\n' || *p == '\r' || *p == ' ' || *p == '\t' || *p == '#') {
            if (*p == '#') {
                while (*p && *p != '\n') p++;
            } else {
                p++;
            }
        }
        if (!*p) break;
        struct service *svc = &out[count];
        int idx = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && idx + 1 < (int)sizeof(svc->name)) {
            svc->name[idx++] = *p++;
        }
        svc->name[idx] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        idx = 0;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && idx + 1 < (int)sizeof(svc->path)) {
            svc->path[idx++] = *p++;
        }
        svc->path[idx] = '\0';
        svc->after[0] = '\0';
        while (*p == ' ' || *p == '\t') p++;
        if (starts_with(p, "after=")) {
            p += 6;
            idx = 0;
            while (*p && *p != ' ' && *p != '\t' && *p != '\n' && idx + 1 < (int)sizeof(svc->after)) {
                svc->after[idx++] = *p++;
            }
            svc->after[idx] = '\0';
        }
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
        svc->started = 0;
        if (svc->name[0] && svc->path[0]) count++;
    }
    return count;
}

static int deps_satisfied(struct service *svc, struct service *all, int count) {
    if (svc->after[0] == '\0') return 1;
    for (int i = 0; i < count; ++i) {
        if (ustrlen(all[i].name) && ustrcmp(all[i].name, svc->after) == 0) {
            return all[i].started;
        }
    }
    return 0;
}

static void start_service(struct service *svc) {
    char *argv[2] = { svc->path, 0 };
    long pid = sys_fork();
    if (pid == 0) {
        sys_exec(svc->path, 1, argv);
        sys_exit(1);
    }
    svc->started = 1;
}

void _start(void) {
    uputs("BitOS init starting\n");

    struct service services[16];
    int svc_count = read_services(services, 16);
    int started = 0;
    int spins = 0;

    while (started < svc_count && spins < 64) {
        for (int i = 0; i < svc_count; ++i) {
            if (services[i].started) continue;
            if (deps_satisfied(&services[i], services, svc_count)) {
                uputs("start ");
                uputs(services[i].name);
                uputc('\n');
                start_service(&services[i]);
                started++;
            }
        }
        sys_sleep_ms(100);
        spins++;
    }

    /* Idle loop */
    for (;;) {
        sys_sleep_ms(1000);
    }
}
