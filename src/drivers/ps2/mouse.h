#ifndef MOUSE_H
#define MOUSE_H

#include <stdint.h>

struct mouse_event {
    int32_t x;
    int32_t y;
    int32_t dx;
    int32_t dy;
    uint8_t buttons; /* bit0=left, bit1=right, bit2=middle */
};

/* Initialize PS/2 mouse device and enable IRQ12 */
void ms_init(void);

/* Called from IRQ path when PS/2 mouse data is available */
void ms_irq_handler(void);

/* Poll for an available mouse event; returns 1 and fills out when available */
int ms_poll_event(struct mouse_event *out);

/* Update and draw cursor from pending mouse events */
void ms_draw_cursor(void);

/* Temporarily hide/show cursor around framebuffer drawing */
void ms_cursor_hide(void);
void ms_cursor_show(void);

#endif /* MOUSE_H */
