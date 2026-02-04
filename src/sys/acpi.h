#ifndef ACPI_H
#define ACPI_H

#include <stdint.h>
#include "lib/compat.h"

struct acpi_gas {
    uint8_t addr_space_id;
    uint8_t reg_bit_width;
    uint8_t reg_bit_offset;
    uint8_t access_size;
    uint64_t address;
} __attribute__((packed));

struct acpi_pstate {
    uint32_t freq_mhz;
    uint32_t power_mw;
    uint32_t trans_lat;
    uint32_t bus_lat;
    uint32_t control;
    uint32_t status;
};

void acpi_init(void);
void acpi_log_status(void);
int acpi_pss_count(void);
int acpi_pct_count(void);
const struct acpi_pstate *acpi_pss_table(uint32_t *count);
int acpi_get_pct(struct acpi_gas *ctrl, struct acpi_gas *stat);

#endif /* ACPI_H */
