#ifndef BANNER_H
#define BANNER_H

#include <stdint.h>

struct limine_framebuffer;

void banner_init(struct limine_framebuffer *fb);
void banner_draw(void);
uint32_t banner_height(void);

#endif /* BANNER_H */
