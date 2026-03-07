#ifndef KERNEL_AUDIO_H
#define KERNEL_AUDIO_H

#include <stdint.h>

int audio_init(void);
int audio_shutdown(void);
int audio_enqueue_tone(uint32_t freq_hz, uint32_t duration_ms, uint8_t volume);
int audio_enqueue_silence(uint32_t duration_ms);
int audio_is_running(void);
uint32_t audio_queue_depth(void);

#endif /* KERNEL_AUDIO_H */
