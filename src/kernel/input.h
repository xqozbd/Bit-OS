#ifndef KERNEL_INPUT_H
#define KERNEL_INPUT_H

#include <stdint.h>

enum {
    INPUT_EVENT_KEY = 1,
    INPUT_EVENT_MOUSE = 2
};

struct input_event {
    uint16_t type;
    uint16_t code;
    int32_t value;
    int32_t x;
    int32_t y;
    int32_t dx;
    int32_t dy;
    uint32_t buttons;
};

void input_init(void);
void input_push_key(uint16_t code, int pressed, int32_t ch);
void input_push_mouse(int32_t x, int32_t y, int32_t dx, int32_t dy, uint32_t buttons);
int input_pop_event(struct input_event *out);
int input_has_event(void);

#endif /* KERNEL_INPUT_H */
