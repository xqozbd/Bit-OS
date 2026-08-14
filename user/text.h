#ifndef USER_TEXT_H
#define USER_TEXT_H

#include <stddef.h>
#include <stdint.h>

#include "desktop.h"

#define BTEXT_MAX_FONTS 8u
#define BTEXT_FONT_NAME 24u
#define BTEXT_GLYPH_ROWS 8u
#define BTEXT_GLYPH_CACHE 96u
#define BTEXT_MAX_SHAPED 256u

enum btext_font_flags {
    BTEXT_FONT_MONO = 1u << 0,
    BTEXT_FONT_EMOJI = 1u << 1,
    BTEXT_FONT_SYMBOL = 1u << 2
};

enum btext_aa_mode {
    BTEXT_AA_GRAYSCALE = 0,
    BTEXT_AA_SUBPIXEL = 1
};

enum btext_hinting {
    BTEXT_HINT_NONE = 0,
    BTEXT_HINT_LIGHT = 1,
    BTEXT_HINT_FULL = 2
};

enum btext_direction {
    BTEXT_DIR_LTR = 0,
    BTEXT_DIR_RTL = 1,
    BTEXT_DIR_AUTO = 2
};

struct btext_font {
    char name[BTEXT_FONT_NAME];
    uint32_t first_cp;
    uint32_t last_cp;
    uint8_t width;
    uint8_t height;
    uint32_t flags;
};

struct btext_glyph {
    uint32_t codepoint;
    uint8_t font_index;
    uint8_t width;
    uint8_t height;
    uint8_t rows[BTEXT_GLYPH_ROWS];
    uint32_t last_used;
};

struct btext_manager {
    struct btext_font fonts[BTEXT_MAX_FONTS];
    struct btext_glyph cache[BTEXT_GLYPH_CACHE];
    uint32_t font_count;
    uint32_t tick;
    uint32_t hits;
    uint32_t misses;
    uint32_t evictions;
    uint32_t aa_mode;
    uint32_t hinting;
};

struct btext_render_options {
    uint32_t aa_mode;
    uint32_t hinting;
    uint32_t fg;
    uint32_t bg;
};

struct btext_shaped_glyph {
    uint32_t codepoint;
    uint32_t cluster;
    int16_t advance_x;
    int16_t offset_x;
    int16_t offset_y;
    uint8_t direction;
};

struct btext_shape_plan {
    uint32_t script;
    uint32_t language;
    uint32_t direction;
    uint32_t features;
};

struct btext_selection {
    uint32_t anchor;
    uint32_t caret;
    uint32_t length;
};

struct btext_benchmark_result {
    uint32_t glyphs;
    uint32_t cache_hits;
    uint32_t cache_misses;
    uint32_t cache_evictions;
    uint64_t checksum;
};

void btext_manager_init(struct btext_manager *mgr);
int btext_font_add(struct btext_manager *mgr, const char *name, uint32_t first_cp, uint32_t last_cp, uint8_t width, uint8_t height, uint32_t flags);
const struct btext_font *btext_font_for_codepoint(struct btext_manager *mgr, uint32_t cp, uint8_t *font_index);
const struct btext_glyph *btext_glyph_get(struct btext_manager *mgr, uint32_t cp);

int btext_utf8_decode(const char *s, uint32_t len, uint32_t *cp, uint32_t *consumed);
uint32_t btext_utf8_encode(uint32_t cp, char out[4]);
uint32_t btext_utf8_count(const char *s);
uint32_t btext_utf8_byte_offset(const char *s, uint32_t cp_index);

uint32_t btext_shape(const char *s, const struct btext_shape_plan *plan, struct btext_shaped_glyph *out, uint32_t cap);
uint32_t btext_bidi_reorder(const struct btext_shaped_glyph *in, uint32_t count, uint32_t direction, struct btext_shaped_glyph *out, uint32_t cap);

void btext_draw_char(struct desktop_shm_window *shm, struct btext_manager *mgr, int32_t x, int32_t y, uint32_t cp, const struct btext_render_options *opts);
void btext_draw_line(struct desktop_shm_window *shm, struct btext_manager *mgr, int32_t x, int32_t y, const char *s, uint32_t max_px, int ellipsis, const struct btext_render_options *opts);
void btext_draw_block(struct desktop_shm_window *shm, struct btext_manager *mgr, int32_t x, int32_t y, uint32_t w, uint32_t h, const char *s, uint32_t flags, int32_t scroll_y, uint8_t line_h, const struct btext_render_options *opts);

void btext_selection_init(struct btext_selection *sel, uint32_t text_len);
void btext_selection_move(struct btext_selection *sel, int32_t delta, int extend);
uint32_t btext_clipboard_normalize(const char *mime, const char *in, char *out, uint32_t cap);
uint32_t btext_format_datetime(uint64_t epoch_seconds, char *out, uint32_t cap);
void btext_benchmark(struct btext_manager *mgr, struct btext_benchmark_result *out, uint32_t loops);

#endif
