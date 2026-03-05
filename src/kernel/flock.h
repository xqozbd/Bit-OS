#ifndef KERNEL_FLOCK_H
#define KERNEL_FLOCK_H

#include <stdint.h>

int flock_lock(int node, uint32_t pid, int mode, int nonblock);
int flock_unlock(int node, uint32_t pid, int mode, uint32_t count);
void flock_release_pid(uint32_t pid);

#endif /* KERNEL_FLOCK_H */
