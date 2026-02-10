#include "sys.h"

void _start(void) {
    /* Default: mount partition 0 as ext2. */
    long rc = sys_mount(0, 1);
    if (rc == 0) {
        uputs("mount: mounted ext2 partition 0 as root\n");
        sys_exit(0);
    }
    rc = sys_mount(0, 2);
    if (rc == 0) {
        uputs("mount: mounted fat32 partition 0 as root\n");
        sys_exit(0);
    }
    uputs("mount: failed\n");
    sys_exit(1);
}
