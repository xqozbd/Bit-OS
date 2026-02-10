#include "sys.h"

void _start(void) {
    char buf[2048];
    for (int iter = 0; iter < 5; ++iter) {
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
    sys_exit(0);
}
