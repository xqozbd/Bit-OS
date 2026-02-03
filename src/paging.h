#ifndef PAGING_H
#define PAGING_H

#include <stdint.h>

int paging_init(void);

uint64_t paging_hhdm_offset(void);

#endif /* PAGING_H */
