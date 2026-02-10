#include "sys.h"

void _start(void) {
    char buf[2048];
    int fd = (int)sys_open("/proc/tasks", O_RDONLY);
    if (fd < 0) {
        uputs("ps: cannot open /proc/tasks\n");
        sys_exit(1);
    }
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n < 0) {
        uputs("ps: read failed\n");
        sys_exit(1);
    }
    buf[n] = '\0';
    sys_write(1, buf, (size_t)n);
    sys_exit(0);
}
