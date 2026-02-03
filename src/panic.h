#ifndef PANIC_H
#define PANIC_H

#include <stdint.h>

void panic_screen(uint32_t code, const char *msg);

#endif /* PANIC_H */
