#include <stdint.h>

#include "compat.h"
#include "keyboard.h"

#define KBD_DATA 0x60
#define KBD_STATUS 0x64

#if defined(__GNUC__) || defined(__clang__)
static inline void outb(uint16_t port, uint8_t val) {
    __asm__ volatile ("outb %0, %1" : : "a"(val), "Nd"(port));
}
static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile ("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}
#else
static inline void outb(uint16_t port, uint8_t val) { (void)port; (void)val; }
static inline uint8_t inb(uint16_t port) { (void)port; return 0; }
#endif

static int shift_down = 0;
static int ctrl_down = 0;
static int extended = 0;

static const char scancode_set1[128] = {
    0,  27, '1','2','3','4','5','6','7','8','9','0','-','=', '\b',
    '\t','q','w','e','r','t','y','u','i','o','p','[',']','\n', 0,
    'a','s','d','f','g','h','j','k','l',';','\'','`', 0,'\\',
    'z','x','c','v','b','n','m',',','.','/', 0, '*', 0, ' ',
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,'-',0,'+',0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static const char scancode_set1_shift[128] = {
    0,  27, '!','@','#','$','%','^','&','*','(',')','_','+', '\b',
    '\t','Q','W','E','R','T','Y','U','I','O','P','{','}','\n', 0,
    'A','S','D','F','G','H','J','K','L',':','"','~', 0,'|',
    'Z','X','C','V','B','N','M','<','>','?', 0, '*', 0, ' ',
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,'-',0,'+',0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

void kb_init(void) {
    /* Nothing to program for basic polling. Flush output buffer. */
    while (inb(KBD_STATUS) & 0x01) {
        (void)inb(KBD_DATA);
    }
}

int kb_poll_char(void) {
    if ((inb(KBD_STATUS) & 0x01) == 0) return -1;
    uint8_t sc = inb(KBD_DATA);

    if (sc == 0xE0) {
        extended = 1;
        return -1;
    }

    if (sc & 0x80) {
        uint8_t rel = sc & 0x7F;
        if (rel == 0x2A || rel == 0x36) shift_down = 0;
        if (rel == 0x1D) ctrl_down = 0;
        return -1;
    }

    if (sc == 0x2A || sc == 0x36) {
        shift_down = 1;
        return -1;
    }
    if (sc == 0x1D) {
        ctrl_down = 1;
        return -1;
    }

    if (extended) {
        extended = 0;
        if (sc == 0x48) return KB_KEY_UP;
        if (sc == 0x50) return KB_KEY_DOWN;
        if (sc == 0x4B) return KB_KEY_LEFT;
        if (sc == 0x4D) return KB_KEY_RIGHT;
        return -1;
    }

    char c = shift_down ? scancode_set1_shift[sc] : scancode_set1[sc];
    if (c == 0) return -1;
    if (ctrl_down) {
        if (c == 'c' || c == 'C') return KB_KEY_CTRL_C;
        if (c == 'v' || c == 'V') return KB_KEY_CTRL_V;
    }
    return (int)c;
}
