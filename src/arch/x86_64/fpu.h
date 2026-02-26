#ifndef FPU_H
#define FPU_H

#include <stdint.h>

#define FPU_STATE_SIZE 2048
#define FPU_STATE_ALIGN 64

void fpu_init(void);
void fpu_save(uint8_t *state);
void fpu_restore(const uint8_t *state);
void fpu_state_init(uint8_t *state);
int fpu_using_xsave(void);
uint32_t fpu_state_size(void);

#endif /* FPU_H */
