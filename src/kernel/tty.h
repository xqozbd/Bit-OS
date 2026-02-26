#ifndef KERNEL_TTY_H
#define KERNEL_TTY_H

#include <stddef.h>
#include <stdint.h>

enum { TTY_MAX = 4 };

void tty_init(void);
int tty_active(void);
void tty_switch(int tty_id);
void tty_feed_char(int ch);
size_t tty_read(int tty_id, uint8_t *buf, size_t len);
size_t tty_write(int tty_id, const uint8_t *buf, size_t len);
int tty_can_read(int tty_id);

#endif /* KERNEL_TTY_H */
