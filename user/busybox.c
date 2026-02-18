#include "sys.h"

static const char *base_name(const char *path) {
    const char *last = path;
    for (const char *p = path; p && *p; ++p) {
        if (*p == '/') last = p + 1;
    }
    return last ? last : path;
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

static void applet_help(void) {
    uputs("busybox applets: ls ps top mount umount dd help\n");
}

static int dispatch(const char *name, int argc, char **argv) {
    if (!name) return 1;
    if (ustrcmp(name, "ls") == 0) return applet_ls(argc, argv);
    if (ustrcmp(name, "ps") == 0) return applet_ps(argc, argv);
    if (ustrcmp(name, "top") == 0) return applet_top(argc, argv);
    if (ustrcmp(name, "mount") == 0) return applet_mount(argc, argv);
    if (ustrcmp(name, "umount") == 0) return applet_umount(argc, argv);
    if (ustrcmp(name, "dd") == 0) return applet_dd(argc, argv);
    if (ustrcmp(name, "help") == 0) {
        applet_help();
        return 0;
    }
    return -1;
}

void _start(void) {
    uint64_t *sp;
    __asm__ volatile("mov %%rsp, %0" : "=r"(sp));
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
