#include "drivers/usb/hid_kbd.h"

#include "kernel/tty.h"

static uint8_t g_prev_keys[6];

static int key_in_prev(uint8_t key) {
    if (!key) return 1;
    for (int i = 0; i < 6; ++i) {
        if (g_prev_keys[i] == key) return 1;
    }
    return 0;
}

static char map_key(uint8_t key, int shift) {
    static const char map[128] = {
        [0x04] = 'a', [0x05] = 'b', [0x06] = 'c', [0x07] = 'd',
        [0x08] = 'e', [0x09] = 'f', [0x0A] = 'g', [0x0B] = 'h',
        [0x0C] = 'i', [0x0D] = 'j', [0x0E] = 'k', [0x0F] = 'l',
        [0x10] = 'm', [0x11] = 'n', [0x12] = 'o', [0x13] = 'p',
        [0x14] = 'q', [0x15] = 'r', [0x16] = 's', [0x17] = 't',
        [0x18] = 'u', [0x19] = 'v', [0x1A] = 'w', [0x1B] = 'x',
        [0x1C] = 'y', [0x1D] = 'z',
        [0x1E] = '1', [0x1F] = '2', [0x20] = '3', [0x21] = '4',
        [0x22] = '5', [0x23] = '6', [0x24] = '7', [0x25] = '8',
        [0x26] = '9', [0x27] = '0',
        [0x28] = '\n',
        [0x2A] = '\b',
        [0x2B] = '\t',
        [0x2C] = ' ',
        [0x2D] = '-',
        [0x2E] = '=',
        [0x2F] = '[',
        [0x30] = ']',
        [0x31] = '\\',
        [0x33] = ';',
        [0x34] = '\'',
        [0x35] = '`',
        [0x36] = ',',
        [0x37] = '.',
        [0x38] = '/'
    };

    static const char map_shift[128] = {
        [0x04] = 'A', [0x05] = 'B', [0x06] = 'C', [0x07] = 'D',
        [0x08] = 'E', [0x09] = 'F', [0x0A] = 'G', [0x0B] = 'H',
        [0x0C] = 'I', [0x0D] = 'J', [0x0E] = 'K', [0x0F] = 'L',
        [0x10] = 'M', [0x11] = 'N', [0x12] = 'O', [0x13] = 'P',
        [0x14] = 'Q', [0x15] = 'R', [0x16] = 'S', [0x17] = 'T',
        [0x18] = 'U', [0x19] = 'V', [0x1A] = 'W', [0x1B] = 'X',
        [0x1C] = 'Y', [0x1D] = 'Z',
        [0x1E] = '!', [0x1F] = '@', [0x20] = '#', [0x21] = '$',
        [0x22] = '%', [0x23] = '^', [0x24] = '&', [0x25] = '*',
        [0x26] = '(', [0x27] = ')',
        [0x28] = '\n',
        [0x2A] = '\b',
        [0x2B] = '\t',
        [0x2C] = ' ',
        [0x2D] = '_',
        [0x2E] = '+',
        [0x2F] = '{',
        [0x30] = '}',
        [0x31] = '|',
        [0x33] = ':',
        [0x34] = '"',
        [0x35] = '~',
        [0x36] = '<',
        [0x37] = '>',
        [0x38] = '?'
    };

    if (key >= 128) return 0;
    return shift ? map_shift[key] : map[key];
}

int hid_kbd_inject_report(const uint8_t *report, size_t len) {
    if (!report || len < 8) return 0;
    uint8_t mod = report[0];
    int shift = (mod & 0x02u) || (mod & 0x20u);
    const uint8_t *keys = report + 2;
    for (int i = 0; i < 6; ++i) {
        uint8_t key = keys[i];
        if (!key) continue;
        if (key_in_prev(key)) continue;
        char out = map_key(key, shift);
        if (out) tty_feed_char(out);
    }
    for (int i = 0; i < 6; ++i) g_prev_keys[i] = keys[i];
    return 1;
}
