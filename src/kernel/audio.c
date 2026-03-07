#include "kernel/audio.h"

#include "arch/x86_64/io.h"
#include "kernel/sleep.h"
#include "kernel/spinlock.h"
#include "kernel/thread.h"
#include "lib/log.h"

#include <stdint.h>

#define AUDIO_QUEUE_CAP 64u
#define AUDIO_SLICE_MS 10u
#define PIT_INPUT_HZ 1193182u

struct audio_event {
    uint32_t freq_hz;
    uint32_t duration_ms;
    uint8_t volume;
    uint8_t is_silence;
};

static spinlock_t g_audio_lock;
static struct audio_event g_audio_queue[AUDIO_QUEUE_CAP];
static uint32_t g_audio_q_head = 0;
static uint32_t g_audio_q_tail = 0;
static uint32_t g_audio_q_count = 0;

static struct audio_event g_current_event;
static uint32_t g_current_remaining_ms = 0;
static int g_current_active = 0;

static volatile int g_audio_running = 0;
static volatile int g_audio_stop = 0;
static int g_hw_tone_active = 0;

static void pcspk_stop_locked(void) {
    if (!g_hw_tone_active) return;
    uint8_t gate = inb(0x61);
    outb(0x61, (uint8_t)(gate & (uint8_t)~0x03u));
    g_hw_tone_active = 0;
}

static void pcspk_start_locked(uint32_t freq_hz) {
    if (freq_hz < 20u) freq_hz = 20u;
    if (freq_hz > 20000u) freq_hz = 20000u;
    uint32_t divisor = PIT_INPUT_HZ / freq_hz;
    if (divisor == 0u) divisor = 1u;
    if (divisor > 0xFFFFu) divisor = 0xFFFFu;

    outb(0x43, 0xB6);
    outb(0x42, (uint8_t)(divisor & 0xFFu));
    outb(0x42, (uint8_t)((divisor >> 8) & 0xFFu));

    uint8_t gate = inb(0x61);
    outb(0x61, (uint8_t)(gate | 0x03u));
    g_hw_tone_active = 1;
}

static void audio_apply_event_locked(const struct audio_event *ev) {
    if (!ev) return;
    if (ev->is_silence || ev->freq_hz == 0u) {
        pcspk_stop_locked();
    } else {
        pcspk_start_locked(ev->freq_hz);
    }
}

static int audio_queue_push_locked(const struct audio_event *ev) {
    if (!ev) return 0;
    if (g_audio_q_count >= AUDIO_QUEUE_CAP) return 0;
    g_audio_queue[g_audio_q_tail] = *ev;
    g_audio_q_tail = (g_audio_q_tail + 1u) % AUDIO_QUEUE_CAP;
    g_audio_q_count++;
    return 1;
}

static int audio_queue_pop_locked(struct audio_event *out) {
    if (!out) return 0;
    if (g_audio_q_count == 0u) return 0;
    *out = g_audio_queue[g_audio_q_head];
    g_audio_q_head = (g_audio_q_head + 1u) % AUDIO_QUEUE_CAP;
    g_audio_q_count--;
    return 1;
}

static void audio_worker(void *arg) {
    (void)arg;
    while (!g_audio_stop) {
        uint32_t step_ms = AUDIO_SLICE_MS;
        int idle = 0;

        spinlock_lock(&g_audio_lock);
        if (!g_current_active) {
            if (audio_queue_pop_locked(&g_current_event)) {
                g_current_active = 1;
                g_current_remaining_ms = g_current_event.duration_ms;
                audio_apply_event_locked(&g_current_event);
            } else {
                idle = 1;
            }
        }
        if (!idle && g_current_remaining_ms < step_ms) {
            step_ms = g_current_remaining_ms;
            if (step_ms == 0u) step_ms = 1u;
        }
        spinlock_unlock(&g_audio_lock);

        if (idle) {
            sleep_ms(20);
            continue;
        }

        sleep_ms(step_ms);

        spinlock_lock(&g_audio_lock);
        if (g_current_active) {
            if (g_current_remaining_ms <= step_ms) {
                g_current_remaining_ms = 0;
                g_current_active = 0;
                pcspk_stop_locked();
            } else {
                g_current_remaining_ms -= step_ms;
            }
        }
        spinlock_unlock(&g_audio_lock);
    }

    spinlock_lock(&g_audio_lock);
    g_current_active = 0;
    g_current_remaining_ms = 0;
    pcspk_stop_locked();
    g_audio_running = 0;
    spinlock_unlock(&g_audio_lock);
    thread_exit();
}

int audio_init(void) {
    if (g_audio_running) return 1;

    spinlock_init(&g_audio_lock);
    g_audio_q_head = 0;
    g_audio_q_tail = 0;
    g_audio_q_count = 0;
    g_current_active = 0;
    g_current_remaining_ms = 0;
    g_audio_stop = 0;
    g_hw_tone_active = 0;

    if (!thread_create(audio_worker, NULL, 4096, "audio")) {
        log_printf("audio: thread spawn failed\n");
        return 0;
    }

    g_audio_running = 1;
    log_printf("audio: pc speaker backend online (slice=%u ms)\n", (unsigned)AUDIO_SLICE_MS);
    return 1;
}

int audio_shutdown(void) {
    if (!g_audio_running) return 1;
    g_audio_stop = 1;
    return 1;
}

int audio_enqueue_tone(uint32_t freq_hz, uint32_t duration_ms, uint8_t volume) {
    if (!g_audio_running || duration_ms == 0u) return 0;
    struct audio_event ev;
    ev.freq_hz = freq_hz;
    ev.duration_ms = duration_ms;
    ev.volume = volume;
    ev.is_silence = (freq_hz == 0u) ? 1u : 0u;

    int ok;
    spinlock_lock(&g_audio_lock);
    ok = audio_queue_push_locked(&ev);
    spinlock_unlock(&g_audio_lock);
    return ok;
}

int audio_enqueue_silence(uint32_t duration_ms) {
    return audio_enqueue_tone(0u, duration_ms, 0u);
}

int audio_is_running(void) {
    return g_audio_running != 0;
}

uint32_t audio_queue_depth(void) {
    uint32_t count;
    spinlock_lock(&g_audio_lock);
    count = g_audio_q_count + (g_current_active ? 1u : 0u);
    spinlock_unlock(&g_audio_lock);
    return count;
}
