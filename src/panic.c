#include "panic.h"

#include "cpu.h"
#include "fb_printf.h"
#include "log.h"

void panic_screen(uint32_t code, const char *msg) {
    fb_clear();
    fb_draw_rect(0, 0, 0x7fffffffu, 0x7fffffffu, 0x2b0000);
    fb_set_colors(0xFFFFFF, 0x2b0000);
    fb_set_cursor_px(fb_margin_x(), fb_margin_y());
    log_printf("BITOS PANIC\n");
    log_printf("Error code: 0x%x\n", (unsigned)code);
    if (msg) log_printf("%s\n", msg);
    halt_forever();
}
