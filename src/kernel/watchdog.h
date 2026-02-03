#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <stdint.h>

void watchdog_init(uint32_t timeout_seconds);
void watchdog_tick(void);
void watchdog_checkpoint_boot_ok(void);
void watchdog_checkpoint(const char *stage);
void watchdog_log_stage(const char *stage);

#endif /* WATCHDOG_H */
