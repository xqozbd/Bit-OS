#ifndef KEYBOARD_H
#define KEYBOARD_H

void kb_init(void);
void kb_irq_handler(void);
void kb_tick(void);
int kb_poll_char(void);

#define KB_KEY_LEFT  0x80
#define KB_KEY_RIGHT 0x81

#endif /* KEYBOARD_H */
