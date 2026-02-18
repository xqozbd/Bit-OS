#include "kernel/crash.h"

#include "arch/x86_64/cpu.h"
#include "arch/x86_64/io.h"
#include "kernel/thread.h"
#include "kernel/watchdog.h"
#include "lib/log.h"
#include "kernel/crash_dump.h"

static int g_restart_attempts = 0;

static void crash_try_restart(void) {
    /* Try keyboard controller reset first. */
    outb(0x64, 0xFE);

    /* If it didn't reset quickly, try ACPI/QEMU reset ports. */
    outw(0x604, 0x2000);
    outw(0xB004, 0x2000);
    outw(0x4004, 0x3400);
    outw(0x4004, 0x2000);

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

    if (g_restart_attempts == 0) {
        g_restart_attempts = 1;
        log_ring_freeze(1);
        log_ring_dump();
        crash_dump_capture_exception(vec, err, has_err);
        log_printf("CRASH: fatal exception, restarting...\n");
        crash_try_restart();
        return CRASH_RESTART;
    }

    log_ring_freeze(1);
    log_ring_dump();
    crash_dump_capture_exception(vec, err, has_err);
    log_printf("CRASH: fatal exception, shutdown\n");
    crash_try_restart();
    return CRASH_HALT;
}

void crash_panic(uint32_t code, const char *msg) {
    log_printf("PANIC: code=0x%x stage=%s\n", (unsigned)code, watchdog_last_stage());
    if (msg) log_printf("PANIC: %s\n", msg);
    if (g_restart_attempts == 0) {
        g_restart_attempts = 1;
        log_ring_freeze(1);
        log_ring_dump();
        crash_dump_capture(code, msg);
        log_printf("PANIC: restarting...\n");
        crash_try_restart();
    }
    log_ring_freeze(1);
    log_ring_dump();
    crash_dump_capture(code, msg);
    log_printf("PANIC: shutdown\n");
    crash_try_restart();
}
