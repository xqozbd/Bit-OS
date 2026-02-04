#include <stdint.h>
#include <stdarg.h>

#include "lib/compat.h"
#include "lib/log.h"
#include "drivers/ps2/mouse.h"
#include "drivers/video/fb_printf.h"

/* Serial (COM1) logging */
#define COM1_PORT 0x3F8

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

static int fb_ready = 0;

void log_init_serial(void) {
    outb(COM1_PORT + 1, 0x00); /* Disable interrupts */
    outb(COM1_PORT + 3, 0x80); /* Enable DLAB */
    outb(COM1_PORT + 0, 0x03); /* 38400 baud */
    outb(COM1_PORT + 1, 0x00);
    outb(COM1_PORT + 3, 0x03); /* 8N1 */
    outb(COM1_PORT + 2, 0xC7); /* FIFO */
    outb(COM1_PORT + 4, 0x0B); /* IRQs, RTS/DSR */
}

void log_set_fb_ready(int ready) {
    fb_ready = ready;
}

static int serial_can_tx(void) {
    return inb(COM1_PORT + 5) & 0x20;
}

static void serial_putc(char c) {
    if (c == '\n') {
        while (!serial_can_tx()) {}
        outb(COM1_PORT, '\r');
    }
    while (!serial_can_tx()) {}
    outb(COM1_PORT, (uint8_t)c);
}

static void serial_puts(const char *s) {
    while (*s) serial_putc(*s++);
}

static void utoa_unsigned(uint64_t val, unsigned int base, char *out) {
    char buf[32]; int i = 0;
    if (val == 0) { out[0] = '0'; out[1] = '\0'; return; }
    while (val > 0) {
        int digit = val % base;
        buf[i++] = (digit < 10) ? ('0' + digit) : ('a' + (digit - 10));
        val /= base;
    }
    int j = 0; while (i > 0) out[j++] = buf[--i]; out[j] = '\0';
}

static void itoa_signed(int64_t val, char *out) {
    if (val < 0) { *out++ = '-'; utoa_unsigned((uint64_t)(-val), 10, out); }
    else utoa_unsigned((uint64_t)val, 10, out);
}

static void serial_vprintf(const char *fmt, va_list ap) {
    const char *p = fmt;
    char numbuf[64];
    while (*p) {
        if (*p == '%') {
            ++p; if (!*p) break;
            switch (*p) {
                case '%': serial_putc('%'); break;
                case 's': { const char *s = va_arg(ap,const char*); if(!s)s="(null)"; serial_puts(s); } break;
                case 'c': { int c = va_arg(ap,int); serial_putc((char)c); } break;
                case 'd': { int val = va_arg(ap,int); itoa_signed(val,numbuf); serial_puts(numbuf); } break;
                case 'u': { unsigned int val = va_arg(ap,unsigned int); utoa_unsigned(val,10,numbuf); serial_puts(numbuf); } break;
                case 'x': { unsigned int val = va_arg(ap,unsigned int); utoa_unsigned(val,16,numbuf); serial_puts(numbuf); } break;
                case 'p': { void *ptr = va_arg(ap,void*); utoa_unsigned((uintptr_t)ptr,16,numbuf); serial_puts("0x"); serial_puts(numbuf); } break;
                default: serial_putc('%'); serial_putc(*p); break;
            }
        } else {
            serial_putc(*p);
        }
        ++p;
    }
}

void log_printf(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if (fb_ready) {
        ms_cursor_hide();
        va_list ap2;
        va_copy(ap2, ap);
        fb_vprintf(fmt, ap2);
        va_end(ap2);
        ms_cursor_show();
    }
    serial_vprintf(fmt, ap);
    va_end(ap);
}
