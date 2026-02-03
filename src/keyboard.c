#include <stdint.h>

#include "compat.h"
#include "cpu.h"
#include "keyboard.h"
#include "timer.h"
#include "pic.h"

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

enum { KB_BUF_SIZE = 256 };

static volatile uint8_t g_buf[KB_BUF_SIZE];
static volatile uint8_t g_head = 0;
static volatile uint8_t g_tail = 0;

static int shift_down = 0;
static int e0_prefix = 0;

static uint8_t g_repeat_sc = 0;
static uint64_t g_repeat_next = 0;
static uint64_t g_repeat_delay_ticks = 0;
static uint64_t g_repeat_rate_ticks = 0;

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
    g_head = 0;
    g_tail = 0;
    shift_down = 0;
    e0_prefix = 0;
    g_repeat_sc = 0;

    uint32_t hz = timer_pit_hz();
    if (hz == 0) hz = 100;
    g_repeat_delay_ticks = (uint64_t)hz / 2; /* 500ms */
    g_repeat_rate_ticks = (uint64_t)hz / 30; /* ~30 Hz */
    if (g_repeat_rate_ticks == 0) g_repeat_rate_ticks = 1;
    pic_clear_mask(1); /* enable IRQ1 keyboard */
}

static inline void kb_buf_push(uint8_t ch) {
    uint8_t next = (uint8_t)(g_head + 1);
    if (next == g_tail) return; /* full */
    g_buf[g_head] = ch;
    g_head = next;
}

static inline int kb_buf_pop(void) {
    if (g_head == g_tail) return -1;
    uint8_t ch = g_buf[g_tail];
    g_tail = (uint8_t)(g_tail + 1);
    return (int)ch;
}

static inline int scancode_to_char(uint8_t sc) {
    char c = shift_down ? scancode_set1_shift[sc] : scancode_set1[sc];
    if (c == 0) return -1;
    return (int)c;
}

static inline int allow_repeat_char(int ch) {
    if (ch == '\n' || ch == '\r' || ch == '\b' || ch == '\t') return 0;
    return (ch >= 32);
}

void kb_irq_handler(void) {
    while (inb(KBD_STATUS) & 0x01) {
        uint8_t sc = inb(KBD_DATA);

        if (sc == 0xE0) {
            e0_prefix = 1;
            continue;
        }

        if (sc & 0x80) {
            uint8_t rel = sc & 0x7F;
            if (rel == 0x2A || rel == 0x36) shift_down = 0;
            if (rel == g_repeat_sc) g_repeat_sc = 0;
            e0_prefix = 0;
            continue;
        }

        if (sc == 0x2A || sc == 0x36) {
            shift_down = 1;
            e0_prefix = 0;
            continue;
        }
        if (e0_prefix) {
            /* Ignore extended scancodes for now. */
            e0_prefix = 0;
            continue;
        }

        int ch = scancode_to_char(sc);
        if (ch < 0) continue;
        if (g_repeat_sc != sc) {
            kb_buf_push((uint8_t)ch);
            if (allow_repeat_char(ch)) {
                g_repeat_sc = sc;
                g_repeat_next = timer_pit_ticks() + g_repeat_delay_ticks;
            } else {
                g_repeat_sc = 0;
            }
        }
    }
}

void kb_tick(void) {
    if (g_repeat_sc == 0) return;
    uint64_t now = timer_pit_ticks();
    if (now < g_repeat_next) return;

    int ch = scancode_to_char(g_repeat_sc);
    if (ch >= 0 && allow_repeat_char(ch)) {
        kb_buf_push((uint8_t)ch);
    }
    g_repeat_next = now + g_repeat_rate_ticks;
}

int kb_poll_char(void) {
    int ch;
    cpu_disable_interrupts();
    ch = kb_buf_pop();
    cpu_enable_interrupts();
    return ch;
}
