#include "sys.h"

void _start(void) {
    char buf[1024];
    const char *path = ".";
    long rc = sys_listdir(path, buf, sizeof(buf) - 1);
    if (rc < 0) {
        uputs("ls: failed\n");
        sys_exit(1);
    }
    buf[rc] = '\0';
    sys_write(1, buf, (size_t)rc);
    sys_exit(0);
}
