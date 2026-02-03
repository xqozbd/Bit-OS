#ifndef KEYBOARD_H
#define KEYBOARD_H

void kb_init(void);
void kb_irq_handler(void);
void kb_tick(void);
int kb_poll_char(void);

#endif /* KEYBOARD_H */
