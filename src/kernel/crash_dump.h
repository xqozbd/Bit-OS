#ifndef KERNEL_CRASH_DUMP_H
#define KERNEL_CRASH_DUMP_H

#include <stdint.h>

void crash_dump_capture(uint32_t code, const char *msg);
void crash_dump_capture_exception(uint8_t vec, uint64_t err, int has_err);
void crash_dump_flush_to_disk(void);
void crash_dump_flush_ring(void);

#endif /* KERNEL_CRASH_DUMP_H */
