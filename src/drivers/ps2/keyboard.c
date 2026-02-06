#include <stdint.h>

#include "lib/compat.h"
#include "arch/x86_64/cpu.h"
#include "drivers/ps2/keyboard.h"
#include "arch/x86_64/timer.h"
#include "arch/x86_64/pic.h"

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

static inline void wait_input_clear(void) {
    while (inb(KBD_STATUS) & 0x02) {}
}

static inline void wait_output_ready(void) {
    while (!(inb(KBD_STATUS) & 0x01)) {}
}

static uint8_t read_cmd_byte(void) {
    wait_input_clear();
    outb(KBD_STATUS, 0x20);
    wait_output_ready();
    return inb(KBD_DATA);
}

static void write_cmd_byte(uint8_t v) {
    wait_input_clear();
    outb(KBD_STATUS, 0x60);
    wait_input_clear();
    outb(KBD_DATA, v);
}

static void send_kbd(uint8_t b) {
    wait_input_clear();
    outb(KBD_DATA, b);
}

static int read_kbd_ack(uint64_t timeout_ticks) {
    uint64_t start = timer_pit_ticks();
    while (timer_pit_ticks() - start < timeout_ticks) {
        if (inb(KBD_STATUS) & 0x01) {
            uint8_t v = inb(KBD_DATA);
            if (v == 0xFA) return 1;
            if (v == 0xFE) return 0;
        }
    }
    return 0;
}

enum { KB_BUF_SIZE = 256 };

static volatile uint8_t g_buf[KB_BUF_SIZE];
static volatile uint8_t g_head = 0;
static volatile uint8_t g_tail = 0;

static int shift_down = 0;
static int ctrl_down = 0;
static int e0_prefix = 0;
static int break_prefix = 0;

static const char scancode_set2[128] = {
    [0x0E] = '`',
    [0x16] = '1', [0x1E] = '2', [0x26] = '3', [0x25] = '4',
    [0x2E] = '5', [0x36] = '6', [0x3D] = '7', [0x3E] = '8',
    [0x46] = '9', [0x45] = '0', [0x4E] = '-', [0x55] = '=',
    [0x66] = '\b',
    [0x0D] = '\t',
    [0x15] = 'q', [0x1D] = 'w', [0x24] = 'e', [0x2D] = 'r',
    [0x2C] = 't', [0x35] = 'y', [0x3C] = 'u', [0x43] = 'i',
    [0x44] = 'o', [0x4D] = 'p', [0x54] = '[', [0x5B] = ']',
    [0x5A] = '\n',
    [0x1C] = 'a', [0x1B] = 's', [0x23] = 'd', [0x2B] = 'f',
    [0x34] = 'g', [0x33] = 'h', [0x3B] = 'j', [0x42] = 'k',
    [0x4B] = 'l', [0x4C] = ';', [0x52] = '\'',
    [0x5D] = '\\',
    [0x1A] = 'z', [0x22] = 'x', [0x21] = 'c', [0x2A] = 'v',
    [0x32] = 'b', [0x31] = 'n', [0x3A] = 'm', [0x41] = ',',
    [0x49] = '.', [0x4A] = '/', [0x29] = ' '
};

static const char scancode_set2_shift[128] = {
    [0x0E] = '~',
    [0x16] = '!', [0x1E] = '@', [0x26] = '#', [0x25] = '$',
    [0x2E] = '%', [0x36] = '^', [0x3D] = '&', [0x3E] = '*',
    [0x46] = '(', [0x45] = ')', [0x4E] = '_', [0x55] = '+',
    [0x66] = '\b',
    [0x0D] = '\t',
    [0x15] = 'Q', [0x1D] = 'W', [0x24] = 'E', [0x2D] = 'R',
    [0x2C] = 'T', [0x35] = 'Y', [0x3C] = 'U', [0x43] = 'I',
    [0x44] = 'O', [0x4D] = 'P', [0x54] = '{', [0x5B] = '}',
    [0x5A] = '\n',
    [0x1C] = 'A', [0x1B] = 'S', [0x23] = 'D', [0x2B] = 'F',
    [0x34] = 'G', [0x33] = 'H', [0x3B] = 'J', [0x42] = 'K',
    [0x4B] = 'L', [0x4C] = ':', [0x52] = '"',
    [0x5D] = '|',
    [0x1A] = 'Z', [0x22] = 'X', [0x21] = 'C', [0x2A] = 'V',
    [0x32] = 'B', [0x31] = 'N', [0x3A] = 'M', [0x41] = '<',
    [0x49] = '>', [0x4A] = '?', [0x29] = ' '
};

void kb_init(void) {
    /* Ensure IRQ1 enabled and translation disabled (use set 2). */
    uint8_t cmd = read_cmd_byte();
    cmd |= 0x01;   /* IRQ1 enable */
    cmd &= (uint8_t)~0x40;   /* disable translation (use set 2) */
    write_cmd_byte(cmd);

    /* Disable mouse while we reprogram keyboard. */
    wait_input_clear();
    outb(KBD_STATUS, 0xA7);
    wait_input_clear();
    outb(KBD_STATUS, 0xAE); /* enable keyboard interface */

    /* Flush output buffer. */
    uint64_t start = timer_pit_ticks();
    while (inb(KBD_STATUS) & 0x01) {
        (void)inb(KBD_DATA);
        if (timer_pit_ticks() - start > 200) { /* ~2s at 100Hz */
            break;
        }
    }

    /* Force scancode set 2 to avoid host translation quirks. */
    send_kbd(0xF0);
    (void)read_kbd_ack(50);
    send_kbd(0x02);
    (void)read_kbd_ack(50);

    g_head = 0;
    g_tail = 0;
    shift_down = 0;
    e0_prefix = 0;
    break_prefix = 0;

    /* Re-enable mouse. */
    wait_input_clear();
    outb(KBD_STATUS, 0xA8);

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
    if (sc >= 0x80) return -1;
    char c = shift_down ? scancode_set2_shift[sc] : scancode_set2[sc];
    if (c == 0) return -1;
    return (int)c;
}

static inline int allow_repeat_char(int ch) {
    if (ch == '\n' || ch == '\r' || ch == '\b' || ch == '\t') return 0;
    return (ch >= 32);
}

void kb_irq_handler(void) {
    while (1) {
        uint8_t status = inb(KBD_STATUS);
        if ((status & 0x01) == 0) break;
        uint8_t sc = inb(KBD_DATA);
        /* Ignore mouse (aux) bytes on keyboard IRQ */
        if (status & 0x20) {
            continue;
        }
        /* Drop bad bytes (parity/timeout) */
        if (status & 0xC0) {
            continue;
        }

        if (sc == 0xFA || sc == 0xFE || sc == 0xAA || sc == 0x00) {
            /* ACK/resend/self-test or null bytes */
            continue;
        }
        if (sc == 0xE0) {
            e0_prefix = 1;
            continue;
        }
        if (sc == 0xF0) {
            break_prefix = 1;
            continue;
        }

        if (break_prefix) {
            if (sc == 0x12 || sc == 0x59) shift_down = 0;
            if (sc == 0x14) ctrl_down = 0;
            break_prefix = 0;
            e0_prefix = 0;
            continue;
        }

        if (!e0_prefix) {
            if (sc == 0x12 || sc == 0x59) {
                shift_down = 1;
                continue;
            }
            if (sc == 0x14) {
                ctrl_down = 1;
                continue;
            }
        }
        if (e0_prefix) {
            if (sc == 0x6B) { /* left */
                kb_buf_push(KB_KEY_LEFT);
            } else if (sc == 0x74) { /* right */
                kb_buf_push(KB_KEY_RIGHT);
            } else if (sc == 0x75) { /* up */
                kb_buf_push(KB_KEY_UP);
            } else if (sc == 0x72) { /* down */
                kb_buf_push(KB_KEY_DOWN);
            } else if (sc == 0x7D) { /* page up */
                kb_buf_push(KB_KEY_PGUP);
            } else if (sc == 0x7A) { /* page down */
                kb_buf_push(KB_KEY_PGDN);
            }
            e0_prefix = 0;
            continue;
        }

        int ch = scancode_to_char(sc);
        if (ch < 0) continue;
        if (ctrl_down) {
            if (ch == 'c' || ch == 'C') {
                kb_buf_push(0x03);
                continue;
            }
            if (ch == 'v' || ch == 'V') {
                kb_buf_push(0x16);
                continue;
            }
        }
        kb_buf_push((uint8_t)ch);
    }
}

void kb_tick(void) {
}

int kb_poll_char(void) {
    int ch;
    cpu_disable_interrupts();
    ch = kb_buf_pop();
    cpu_enable_interrupts();
    return ch;
}
