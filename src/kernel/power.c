#include "kernel/power.h"

#include "lib/log.h"
#include "sys/acpi.h"

static void log_state(uint8_t state, const char *name) {
    struct acpi_sleep_state ss;
    if (acpi_get_sleep_state(state, &ss)) {
        log_printf("power: %s supported (typA=0x%x typB=0x%x)\n",
                   name, (unsigned)ss.typ_a, (unsigned)ss.typ_b);
    } else {
        log_printf("power: %s not available\n", name);
    }
}

void power_init(void) {
    log_state(3, "S3");
    log_state(4, "S4");
    log_state(5, "S5");
    acpi_thermal_log();
}

int power_suspend_s3(void) {
    log_printf("power: entering S3\n");
    return acpi_sleep(3);
}

int power_suspend_s4(void) {
    log_printf("power: entering S4\n");
    return acpi_sleep(4);
}

int power_shutdown_acpi(void) {
    log_printf("power: entering S5\n");
    return acpi_sleep(5);
}
