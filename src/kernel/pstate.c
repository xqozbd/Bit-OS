#include "kernel/pstate.h"

#include <stdint.h>

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/io.h"
#include "lib/log.h"
#include "sys/acpi.h"

enum {
    ACPI_GAS_SYSTEM_IO = 0x01,
    ACPI_GAS_FIXED_HW  = 0x7F
};

static struct acpi_pstate g_pss[16];
static uint32_t g_pss_count = 0;
static struct acpi_gas g_pct_ctrl;
static struct acpi_gas g_pct_stat;
static int g_pct_ok = 0;

static void write_gas(const struct acpi_gas *gas, uint32_t value) {
    if (!gas) return;
    if (gas->addr_space_id == ACPI_GAS_SYSTEM_IO) {
        uint16_t port = (uint16_t)gas->address;
        if (gas->reg_bit_width <= 8) {
            outb(port, (uint8_t)value);
        } else if (gas->reg_bit_width <= 16) {
            outw(port, (uint16_t)value);
        } else {
            outl(port, value);
        }
        return;
    }
    if (gas->addr_space_id == ACPI_GAS_FIXED_HW) {
        cpu_write_msr((uint32_t)gas->address, (uint64_t)value);
    }
}

int pstate_init(void) {
    g_pss_count = 0;
    g_pct_ok = 0;

    uint32_t count = 0;
    const struct acpi_pstate *pss = acpi_pss_table(&count);
    if (!pss || count == 0) {
        log_printf("PSTATE: _PSS not available\n");
        return -1;
    }
    if (count > 16) count = 16;
    for (uint32_t i = 0; i < count; ++i) g_pss[i] = pss[i];
    g_pss_count = count;

    if (!acpi_get_pct(&g_pct_ctrl, &g_pct_stat)) {
        log_printf("PSTATE: _PCT not available\n");
        return -1;
    }
    g_pct_ok = 1;

    log_printf("PSTATE: %u entries, ctrl space=0x%x addr=0x%p\n",
               (unsigned)g_pss_count, (unsigned)g_pct_ctrl.addr_space_id,
               (void *)(uintptr_t)g_pct_ctrl.address);
    for (uint32_t i = 0; i < g_pss_count; ++i) {
        const struct acpi_pstate *ps = &g_pss[i];
        log_printf("PSTATE: P%u %u MHz power=%u ctrl=0x%x stat=0x%x\n",
                   (unsigned)i,
                   (unsigned)ps->freq_mhz,
                   (unsigned)ps->power_mw,
                   (unsigned)ps->control,
                   (unsigned)ps->status);
    }

    /* Default to highest-performance state (index 0 per ACPI spec). */
    return pstate_set(0);
}

int pstate_set(uint32_t index) {
    if (!g_pct_ok || g_pss_count == 0) return -1;
    if (index >= g_pss_count) return -1;
    const struct acpi_pstate *ps = &g_pss[index];
    write_gas(&g_pct_ctrl, ps->control);
    log_printf("PSTATE: set P%u => %u MHz (control=0x%x)\n",
               (unsigned)index, (unsigned)ps->freq_mhz, (unsigned)ps->control);
    return 0;
}

uint32_t pstate_count(void) {
    return g_pss_count;
}
