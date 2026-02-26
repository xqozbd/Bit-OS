#ifndef KERNEL_PTY_H
#define KERNEL_PTY_H

#include <stdint.h>
#include <stddef.h>

struct pty;

struct pty *pty_create(void);
void pty_close_end(struct pty *p, int is_master);
size_t pty_read(struct pty *p, int is_master, void *buf, size_t len);
size_t pty_write(struct pty *p, int is_master, const void *buf, size_t len);
int pty_can_read(struct pty *p, int is_master);
int pty_can_write(struct pty *p, int is_master);

#endif /* KERNEL_PTY_H */
