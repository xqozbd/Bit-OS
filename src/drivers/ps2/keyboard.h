#ifndef KEYBOARD_H
#define KEYBOARD_H

#include <stdint.h>

void kb_init(void);
void kb_irq_handler(void);
void kb_tick(void);
int kb_poll_char(void);

enum kb_layout {
    KB_LAYOUT_US = 0,
    KB_LAYOUT_DE = 1
};

int kb_set_layout(enum kb_layout layout);
int kb_set_layout_name(const char *name);
int kb_get_layout(void);
const char *kb_layout_name(int layout);

void kb_set_repeat(uint32_t delay_ms, uint32_t rate_hz);
void kb_get_repeat(uint32_t *delay_ms, uint32_t *rate_hz);

#define KB_KEY_LEFT  0x80
#define KB_KEY_RIGHT 0x81
#define KB_KEY_UP    0x82
#define KB_KEY_DOWN  0x83
#define KB_KEY_PGUP  0x84
#define KB_KEY_PGDN  0x85

#endif /* KEYBOARD_H */
