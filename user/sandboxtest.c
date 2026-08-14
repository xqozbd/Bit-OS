#include "sys.h"

static int expect_denied(long rc, const char *name) {
    if (rc < 0) {
        uputs("ok: ");
        uputs(name);
        uputs(" denied\n");
        return 0;
    }
    uputs("FAIL: ");
    uputs(name);
    uputs(" allowed\n");
    return 1;
}

static int expect_allowed(long rc, const char *name) {
    if (rc >= 0) {
        uputs("ok: ");
        uputs(name);
        uputs(" allowed\n");
        return 0;
    }
    uputs("FAIL: ");
    uputs(name);
    uputs(" denied\n");
    return 1;
}

void _start(void) {
    int fail = 0;
    int fd;
    void *p;
    struct sandbox_broker_request req;

    (void)sys_sandbox(SANDBOX_FS_WRITE | SANDBOX_NET | SANDBOX_MOUNT | SANDBOX_DEV);

    fd = (int)sys_open("/etc/passwd", O_WRONLY | O_TRUNC);
    fail += expect_denied(fd, "write /etc/passwd");
    if (fd >= 0) sys_close(fd);

    fd = (int)sys_open("/tmp/sandbox-regression.txt", O_WRONLY | O_CREAT | O_TRUNC);
    fail += expect_allowed(fd, "write /tmp");
    if (fd >= 0) sys_close(fd);

    fd = (int)sys_open("/dev/input", O_RDONLY);
    fail += expect_denied(fd, "open /dev/input");
    if (fd >= 0) sys_close(fd);

    fail += expect_denied((long)sys_call6(SYS_SOCKET, AF_INET, 1, 0, 0, 0, 0), "socket");
    fail += expect_denied(sys_mount(0, 1), "mount");

    p = sys_mmap(0, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON, -1, 0);
    fail += expect_denied((long)p, "W^X mmap");
    if ((long)p >= 0) (void)sys_munmap(p, 4096);

    for (uint32_t i = 0; i < sizeof(req.target); ++i) req.target[i] = 0;
    for (uint32_t i = 0; i < sizeof(req.reason); ++i) req.reason[i] = 0;
    req.op = SANDBOX_BROKER_REGISTER;
    req.access = 0;
    fail += expect_denied(sys_broker(&req), "broker register without cap");

    uputs(fail ? "sandbox-regression: FAIL\n" : "sandbox-regression: PASS\n");
    sys_exit(fail ? 1 : 0);
}
