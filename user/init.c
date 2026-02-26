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

static int read_services_file(const char *path, struct service *out, int max) {
    int fd = (int)sys_open(path, O_RDONLY);
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

static int read_services(struct service *out, int max) {
    int count = read_services_file("/etc/services.conf", out, max);
    if (count == 0) {
        count = read_services_file("/initramfs/etc/services.conf", out, max);
    }
    return count;
}

static int path_exists(const char *path) {
    if (!path || !path[0]) return 0;
    int fd = (int)sys_open(path, O_RDONLY);
    if (fd < 0) return 0;
    sys_close(fd);
    return 1;
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
    const char *path = svc->path;
    char alt[96];
    if (!path_exists(path)) {
        size_t n = ustrlen(path);
        if (n + 11 < sizeof(alt)) {
            size_t i = 0;
            const char *prefix = "/initramfs";
            for (; prefix[i] && i + 1 < sizeof(alt); ++i) alt[i] = prefix[i];
            size_t j = 0;
            while (path[j] && i + 1 < sizeof(alt)) {
                alt[i++] = path[j++];
            }
            alt[i] = '\0';
            if (path_exists(alt)) {
                path = alt;
            }
        }
    }
    char *argv[2] = { (char *)path, 0 };
    long pid = sys_fork();
    if (pid == 0) {
        sys_exec(path, 1, argv);
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

    if (svc_count == 0) {
        struct service login;
        login.started = 0;
        login.after[0] = '\0';
        login.name[0] = 'l'; login.name[1] = 'o'; login.name[2] = 'g'; login.name[3] = 'i'; login.name[4] = 'n'; login.name[5] = '\0';
        login.path[0] = '/'; login.path[1] = 'b'; login.path[2] = 'i'; login.path[3] = 'n'; login.path[4] = '/';
        login.path[5] = 'l'; login.path[6] = 'o'; login.path[7] = 'g'; login.path[8] = 'i'; login.path[9] = 'n'; login.path[10] = '\0';
        uputs("init: no services.conf, starting login\n");
        start_service(&login);
        svc_count = 1;
        services[0] = login;
        started = 1;
    }

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
