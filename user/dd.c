#include "sys.h"

void _start(void) {
    const char *src = "/mock/README.txt";
    const char *dst = "/mock/dd.copy";

    int fd_in = (int)sys_open(src, O_RDONLY);
    if (fd_in < 0) {
        uputs("dd: open src failed\n");
        sys_exit(1);
    }
    int fd_out = (int)sys_open(dst, O_CREAT | O_TRUNC | O_WRONLY);
    if (fd_out < 0) {
        uputs("dd: open dst failed\n");
        sys_close(fd_in);
        sys_exit(1);
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
    sys_exit(0);
}
