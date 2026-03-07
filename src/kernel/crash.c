#include "kernel/crash.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/io.h"
#include "kernel/thread.h"
#include "kernel/watchdog.h"
#include "lib/log.h"
#include "kernel/crash_dump.h"
#include "kernel/power.h"

static int g_crash_mode = 0; /* 0=halt, 1=reboot */

static int crash_mode_from_str(const char *mode) {
    if (!mode) return 0;
    if (mode[0] == 'r' && mode[1] == 'e' && mode[2] == 'b' && mode[3] == 'o' &&
        mode[4] == 'o' && mode[5] == 't' && mode[6] == '\0') return 1;
    if (mode[0] == 'h' && mode[1] == 'a' && mode[2] == 'l' && mode[3] == 't' &&
        mode[4] == '\0') return 0;
    return 0;
}

const char *crash_mode_name(void) {
    return g_crash_mode ? "reboot" : "halt";
}

void crash_set_mode(const char *mode) {
    g_crash_mode = crash_mode_from_str(mode);
}

int crash_get_mode(void) {
    return g_crash_mode;
}

static void crash_halt_or_recover(void) {
    if (g_crash_mode == 1) {
        log_printf("CRASH: attempting recovery reboot...\n");
        power_restart();
        log_printf("CRASH: reboot did not complete, halting\n");
    }
    log_printf("CRASH: system halted. Power off or reset to recover.\n");
    halt_forever();
}

static int crash_is_user(const struct interrupt_frame *frame, const struct thread *t) {
    if (frame && ((frame->cs & 0x3u) == 0x3u)) return 1;
    if (t && t->is_user) return 1;
    return 0;
}

enum crash_action crash_handle_exception(uint8_t vec,
                                         uint64_t err,
                                         int has_err,
                                         const struct interrupt_frame *frame) {
    struct thread *t = thread_current();
    int is_user = crash_is_user(frame, t);

    log_printf("\nEXCEPTION %u", (unsigned)vec);
    if (has_err) log_printf(" err=0x%x", (unsigned)err);
    if (frame) {
        log_printf(" rip=%p cs=0x%x rflags=0x%x rsp=%p ss=0x%x",
                   (void *)frame->rip, (unsigned)frame->cs,
                   (unsigned)frame->rflags, (void *)frame->rsp, (unsigned)frame->ss);
    }
    log_printf("\nstage: %s\n", watchdog_last_stage());

    if (is_user && t) {
        log_printf("CRASH: userspace task killed tid=%u name=%s\n",
                   (unsigned)t->id, t->name ? t->name : "(null)");
        return CRASH_KILL_TASK;
    }

    /* Non-fatal kernel exceptions we allow to continue. */
    if (vec == 3 || vec == 4) {
        log_printf("CRASH: non-fatal exception, continuing\n");
        return CRASH_CONTINUE;
    }

    log_ring_freeze(1);
    log_ring_dump();
    crash_dump_capture_exception(vec, err, has_err);
    crash_dump_flush_ring();
    log_printf("CRASH: fatal exception\n");
    crash_halt_or_recover();
    return CRASH_HALT;
}

void crash_panic(uint32_t code, const char *msg) {
    log_printf("PANIC: code=0x%x stage=%s\n", (unsigned)code, watchdog_last_stage());
    if (msg) log_printf("PANIC: %s\n", msg);
    log_ring_freeze(1);
    log_ring_dump();
    crash_dump_capture(code, msg);
    crash_dump_flush_ring();
    log_printf("PANIC: fatal\n");
    crash_halt_or_recover();
}
