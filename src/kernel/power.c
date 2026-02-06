#include "kernel/power.h"

#include "lib/log.h"
#include "sys/acpi.h"
#include "arch/x86_64/io.h"
#include "arch/x86_64/cpu.h"

static void log_state(uint8_t state, const char *name) {
    struct acpi_sleep_state ss;
    if (acpi_get_sleep_state(state, &ss)) {
        log_printf("power: %s supported (typA=0x%x typB=0x%x)\n",
                   name, (unsigned)ss.typ_a, (unsigned)ss.typ_b);
    } else {
        log_printf("power: %s not available\n", name);
    }
}

static void force_triple_fault(void) {
    struct {
        uint16_t limit;
        uint64_t base;
    } __attribute__((packed)) idt = {0, 0};
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile("lidt %0" : : "m"(idt));
    __asm__ volatile("int $0x3");
#endif
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

void power_shutdown(void) {
    if (power_shutdown_acpi()) {
        halt_forever();
    }
    outw(0x604, 0x2000);
    outw(0xB004, 0x2000);
    outw(0x4004, 0x3400);
    outw(0x4004, 0x2000);
    halt_forever();
}

void power_restart(void) {
    if (acpi_reset()) {
        halt_forever();
    }
    outb(0x64, 0xFE);
    outw(0x604, 0x2000);
    outw(0xB004, 0x2000);
    outw(0x4004, 0x3400);
    outw(0x4004, 0x2000);
    force_triple_fault();
    halt_forever();
}
