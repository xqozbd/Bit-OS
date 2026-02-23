#ifndef SYS_MMAN_H
#define SYS_MMAN_H

#include <stdint.h>

enum {
    PROT_READ  = 1,
    PROT_WRITE = 2,
    PROT_EXEC  = 4
};

enum {
    MAP_ANON = 1,
    MAP_FILE = 2
};

#endif /* SYS_MMAN_H */
