#ifndef POWER_H
#define POWER_H

#include <stdint.h>

void power_init(void);
int power_suspend_s3(void);
int power_suspend_s4(void);
int power_shutdown_acpi(void);
void power_shutdown(void);
void power_restart(void);

#endif /* POWER_H */
