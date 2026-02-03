#ifndef KEYBOARD_H
#define KEYBOARD_H

enum {
    KB_KEY_UP = 0x100,
    KB_KEY_DOWN = 0x101,
    KB_KEY_LEFT = 0x102,
    KB_KEY_RIGHT = 0x103,
    KB_KEY_CTRL_C = 0x110,
    KB_KEY_CTRL_V = 0x111
};

void kb_init(void);
int kb_poll_char(void);

#endif /* KEYBOARD_H */
