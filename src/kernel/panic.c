#include "kernel/panic.h"

#include "arch/x86_64/cpu.h"
#include "drivers/video/fb_printf.h"
#include "lib/log.h"
#include "kernel/watchdog.h"
#include "kernel/crash.h"
#include <stdint.h>

struct panic_bt_frame {
    struct panic_bt_frame *rbp;
    void *rip;
};

static void panic_backtrace(void) {
    struct panic_bt_frame *frame = (struct panic_bt_frame *)__builtin_frame_address(0);
    log_printf("Backtrace:\n");
    for (uint32_t depth = 0; depth < 16; ++depth) {
        if (!frame) break;
        log_printf("  #%u %p\n", (unsigned)depth, frame->rip);
        struct panic_bt_frame *next = frame->rbp;
        if (!next) break;
        if (next <= frame) break;
        if ((uintptr_t)next - (uintptr_t)frame > 0x10000u) break;
        frame = next;
    }
}

void panic_screen(uint32_t code, const char *msg) {
    fb_clear();
    fb_draw_rect(0, 0, 0x7fffffffu, 0x7fffffffu, 0x2b0000);
    fb_set_colors(0xFFFFFF, 0x2b0000);
    fb_set_cursor_px(fb_margin_x(), fb_margin_y());
    log_printf("BITOS PANIC\n");
    log_printf("Error code: 0x%x\n", (unsigned)code);
    log_printf("Stage: %s\n", watchdog_last_stage());
    if (msg) log_printf("%s\n", msg);
    panic_backtrace();
    crash_panic(code, msg);
    halt_forever();
}
