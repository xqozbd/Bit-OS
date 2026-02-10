#include "sys.h"

void _start(void) {
    long rc = sys_umount();
    if (rc == 0) {
        uputs("umount: switched root to initramfs/mock\n");
        sys_exit(0);
    }
    uputs("umount: failed\n");
    sys_exit(1);
}
