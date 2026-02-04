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

struct acpi_sleep_state {
    uint16_t typ_a;
    uint16_t typ_b;
};

struct acpi_thermal_info {
    int has_tz;
    int has_tmp;
    int has_crt;
    int has_psv;
    int has_hot;
    int has_tc1;
    int has_tc2;
    int has_tsp;
};

void acpi_init(void);
void acpi_log_status(void);
int acpi_pss_count(void);
int acpi_pct_count(void);
const struct acpi_pstate *acpi_pss_table(uint32_t *count);
int acpi_get_pct(struct acpi_gas *ctrl, struct acpi_gas *stat);
int acpi_get_sleep_state(uint8_t state, struct acpi_sleep_state *out);
int acpi_sleep(uint8_t state);
void acpi_thermal_init(void);
void acpi_thermal_log(void);
const struct acpi_thermal_info *acpi_thermal_info(void);

#endif /* ACPI_H */
