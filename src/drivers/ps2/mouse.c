#include "drivers/ps2/mouse.h"

#include "lib/compat.h"
#include "drivers/video/fb_printf.h"
#include "arch/x86_64/pic.h"
#include "arch/x86_64/timer.h"

#define PS2_STATUS 0x64
#define PS2_DATA   0x60

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

static inline int wait_input_clear(void) {
	/* Wait until controller input buffer is clear (bit 1 == 0) */
	uint64_t start = timer_pit_ticks();
	while (inb(PS2_STATUS) & 0x02) {
		if (timer_pit_ticks() - start > 50) return 0; /* ~0.5s */
	}
	return 1;
}

static inline int wait_output_ready(void) {
	/* Wait until there's data in output buffer (bit 0 == 1) */
	uint64_t start = timer_pit_ticks();
	while (!(inb(PS2_STATUS) & 0x01)) {
		if (timer_pit_ticks() - start > 50) return 0; /* ~0.5s */
	}
	return 1;
}

static uint8_t read_cmd_byte(void) {
	if (!wait_input_clear()) return 0;
	outb(PS2_STATUS, 0x20);
	if (!wait_output_ready()) return 0;
	return inb(PS2_DATA);
}

static void write_cmd_byte(uint8_t v) {
	if (!wait_input_clear()) return;
	outb(PS2_STATUS, 0x60);
	if (!wait_input_clear()) return;
	outb(PS2_DATA, v);
}

static void send_to_mouse(uint8_t b) {
	if (!wait_input_clear()) return;
	outb(PS2_STATUS, 0xD4); /* tell controller next byte goes to mouse */
	if (!wait_input_clear()) return;
	outb(PS2_DATA, b);
}

/* packet parsing state */
static volatile uint8_t pkt[3];
static volatile uint8_t pkt_idx = 0;
static volatile int32_t g_x = 0;
static volatile int32_t g_y = 0;
static volatile int32_t g_pending_dx = 0;
static volatile int32_t g_pending_dy = 0;
static volatile uint8_t g_buttons = 0;
static volatile int g_event_ready = 0;
static int g_inited = 0;
static uint64_t g_last_event_tick = 0;
static uint64_t g_min_event_ticks = 1;
static int g_cursor_drawn = 0;
static int g_cursor_hidden = 0;
static int32_t g_cur_x = 0;
static int32_t g_cur_y = 0;
#define CURSOR_W 8
#define CURSOR_H 12
static const uint8_t g_cursor_mask[CURSOR_H] = {
	0x01, 0x03, 0x07, 0x0F,
	0x1F, 0x3F, 0x7F, 0xFF,
	0xF8, 0xE0, 0xC0, 0x80
};
static uint32_t g_cursor_w = CURSOR_W;
static uint32_t g_cursor_h = CURSOR_H;
static uint32_t g_saved[CURSOR_W * CURSOR_H];

int ms_poll_event(struct mouse_event *out) {
	if (!out) return 0;
	/* simple single-event model: return last accumulated delta when ready */
	if (!g_event_ready) return 0;
	out->dx = g_pending_dx;
	out->dy = g_pending_dy;
	g_pending_dx = 0;
	g_pending_dy = 0;
	out->buttons = g_buttons;
	out->x = g_x;
	out->y = g_y;
	g_event_ready = 0;
	return 1;
}

static void clamp_cursor(int32_t *x, int32_t *y) {
	uint32_t w = 0, h = 0;
	fb_get_dimensions(&w, &h);
	if (w == 0 || h == 0) return;
	if (*x < 0) *x = 0;
	if (*y < 0) *y = 0;
	if ((uint32_t)*x + g_cursor_w > w) *x = (int32_t)(w - g_cursor_w);
	if ((uint32_t)*y + g_cursor_h > h) *y = (int32_t)(h - g_cursor_h);
}

static void save_under_cursor(int32_t x, int32_t y) {
	for (uint32_t dy = 0; dy < g_cursor_h; ++dy) {
		for (uint32_t dx = 0; dx < g_cursor_w; ++dx) {
			g_saved[dy * g_cursor_w + dx] = fb_read_pixel((uint32_t)(x + (int32_t)dx),
			                                              (uint32_t)(y + (int32_t)dy));
		}
	}
}

static void restore_under_cursor(int32_t x, int32_t y) {
	for (uint32_t dy = 0; dy < g_cursor_h; ++dy) {
		for (uint32_t dx = 0; dx < g_cursor_w; ++dx) {
			fb_write_pixel((uint32_t)(x + (int32_t)dx),
			               (uint32_t)(y + (int32_t)dy),
			               g_saved[dy * g_cursor_w + dx]);
		}
	}
}

static void draw_cursor_at(int32_t x, int32_t y, uint32_t color) {
	for (uint32_t dy = 0; dy < g_cursor_h; ++dy) {
		uint8_t mask = g_cursor_mask[dy];
		for (uint32_t dx = 0; dx < g_cursor_w; ++dx) {
			if ((mask & (1u << dx)) == 0) continue;
			fb_write_pixel((uint32_t)(x + (int32_t)dx),
			               (uint32_t)(y + (int32_t)dy),
			               color);
		}
	}
}

void ms_draw_cursor(void) {
	if (!g_inited) return;
	struct mouse_event ev;
	if (!ms_poll_event(&ev)) return;

	int32_t nx = g_cur_x + ev.dx;
	int32_t ny = g_cur_y + ev.dy;
	clamp_cursor(&nx, &ny);

	if (g_cursor_hidden) {
		g_cur_x = nx;
		g_cur_y = ny;
		return;
	}

	if (g_cursor_drawn) {
		restore_under_cursor(g_cur_x, g_cur_y);
	}
	g_cur_x = nx;
	g_cur_y = ny;
	save_under_cursor(g_cur_x, g_cur_y);
	draw_cursor_at(g_cur_x, g_cur_y, 0xFFFFFF);
	g_cursor_drawn = 1;
	g_cursor_hidden = 0;
}

void ms_cursor_hide(void) {
	if (!g_inited || !g_cursor_drawn || g_cursor_hidden) return;
	restore_under_cursor(g_cur_x, g_cur_y);
	g_cursor_drawn = 0;
	g_cursor_hidden = 1;
}

void ms_cursor_show(void) {
	if (!g_inited || !g_cursor_hidden) return;
	save_under_cursor(g_cur_x, g_cur_y);
	draw_cursor_at(g_cur_x, g_cur_y, 0xFFFFFF);
	g_cursor_drawn = 1;
	g_cursor_hidden = 0;
}

void ms_irq_handler(void) {
	/* Read available bytes */
	while (1) {
		uint8_t status = inb(PS2_STATUS);
		if ((status & 0x01) == 0) break;
		uint8_t b = inb(PS2_DATA);
		/* Only process mouse (aux) bytes */
		if ((status & 0x20) == 0) {
			continue;
		}
		/* Drop bad bytes (parity/timeout) */
		if (status & 0xC0) {
			continue;
		}
		/* If we are out of sync, discard until we find a byte with bit3 set */
		if (pkt_idx == 0) {
			if ((b & 0x08) == 0) continue; /* sync lost */
		}
		pkt[pkt_idx++] = b;
		if (pkt_idx >= 3) {
			pkt_idx = 0;
			/* Validate packet: bit3 must be set, overflow bits must be clear. */
			if ((pkt[0] & 0x08) == 0 || (pkt[0] & 0xC0)) {
				continue;
			}
			uint8_t buttons = pkt[0] & 0x07; /* left/middle/right */
			int8_t dx = (int8_t)pkt[1];
			int8_t dy = (int8_t)pkt[2];
			/* Validate sign bits (bit4/5 in first byte). */
			if (((pkt[0] & 0x10) != 0) != (dx < 0)) continue;
			if (((pkt[0] & 0x20) != 0) != (dy < 0)) continue;
			g_buttons = buttons;
			g_x += (int32_t)dx;
			g_y += -(int32_t)dy; /* invert Y to screen coords */
			g_pending_dx += (int32_t)dx;
			g_pending_dy += -(int32_t)dy;
			uint64_t now = timer_uptime_ticks();
			if (now - g_last_event_tick >= g_min_event_ticks) {
				g_last_event_tick = now;
				g_event_ready = 1;
			}
		}
	}
}

void ms_init(void) {
	g_inited = 1;
	uint32_t hz = timer_pit_hz();
	if (hz == 0) hz = 100;
	/* Rate limit mouse events to ~120 Hz (or 1 tick minimum). */
	g_min_event_ticks = hz / 120u;
	if (g_min_event_ticks == 0) g_min_event_ticks = 1;
	g_last_event_tick = timer_uptime_ticks();
	/* Enable IRQ12 + IRQ1 in controller command byte */
	uint8_t cmd = read_cmd_byte();
	cmd |= 0x03; /* bit0=IRQ1, bit1=IRQ12 */
	cmd &= (uint8_t)~0x20; /* clear "disable mouse" if set */
	write_cmd_byte(cmd);

	/* Enable auxiliary device (mouse) */
	if (!wait_input_clear()) {
		return;
	}
	outb(PS2_STATUS, 0xA8);

	/* Flush any pending output */
	while (inb(PS2_STATUS) & 0x01) (void)inb(PS2_DATA);

	/* Enable IRQ12 through PIC */
	pic_clear_mask(2);
	pic_clear_mask(12);

	/* Set defaults and enable data reporting */
	send_to_mouse(0xF6); /* set defaults */
	if (wait_output_ready()) (void)inb(PS2_DATA); /* ack */
	send_to_mouse(0xF4); /* enable data reporting */
	if (wait_output_ready()) (void)inb(PS2_DATA); /* ack */

	/* Draw initial cursor in center */
	uint32_t w = 0, h = 0;
	fb_get_dimensions(&w, &h);
	if (w && h) {
		g_cur_x = (int32_t)(w / 2);
		g_cur_y = (int32_t)(h / 2);
		clamp_cursor(&g_cur_x, &g_cur_y);
		g_x = g_cur_x;
		g_y = g_cur_y;
		save_under_cursor(g_cur_x, g_cur_y);
		draw_cursor_at(g_cur_x, g_cur_y, 0xFFFFFF);
		g_cursor_drawn = 1;
		g_cursor_hidden = 0;
	}
}
