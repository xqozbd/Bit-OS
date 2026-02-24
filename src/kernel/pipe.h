#ifndef KERNEL_PIPE_H
#define KERNEL_PIPE_H

#include <stddef.h>
#include <stdint.h>

struct pipe;

struct pipe *pipe_create(void);
void pipe_retain(struct pipe *p);
void pipe_retain_end(struct pipe *p, int write_end);
void pipe_close_end(struct pipe *p, int write_end);
int pipe_has_reader(struct pipe *p);
int pipe_has_writer(struct pipe *p);
size_t pipe_read(struct pipe *p, void *buf, size_t len);
size_t pipe_write(struct pipe *p, const void *buf, size_t len);

#endif /* KERNEL_PIPE_H */
