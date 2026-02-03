#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <stdint.h>

void watchdog_init(uint32_t timeout_seconds);
void watchdog_tick(void);
void watchdog_checkpoint_boot_ok(void);

#endif /* WATCHDOG_H */
