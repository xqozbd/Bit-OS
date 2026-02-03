#ifndef CPU_INFO_H
#define CPU_INFO_H

#include <stdint.h>

void cpu_get_vendor(char out[13]);
void cpu_get_brand(char out[49]);
void cpu_get_family_model(uint32_t *family, uint32_t *model, uint32_t *stepping);
uint32_t cpu_get_feature_ecx(void);
uint32_t cpu_get_feature_edx(void);
uint32_t cpu_get_ext_feature_ecx(void);
uint32_t cpu_get_ext_feature_edx(void);
int cpu_get_tsc_hz(uint64_t *out_hz);
void cpu_set_tsc_hz(uint64_t hz);
int cpu_calibrate_tsc_hz_pit(uint32_t sample_ms);

#endif /* CPU_INFO_H */
