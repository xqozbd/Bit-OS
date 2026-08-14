#include "text.h"

#include "sys.h"
#include "../src/drivers/video/font8x8_basic.h"

static uint32_t slen(const char *s) { uint32_t n = 0; while (s && s[n]) ++n; return n; }

static void scopy(char *dst, uint32_t cap, const char *src) {
    uint32_t i = 0;
    if (!dst || cap == 0) return;
    if (!src) { dst[0] = 0; return; }
    while (src[i] && i + 1 < cap) { dst[i] = src[i]; ++i; }
    dst[i] = 0;
}

static uint32_t mix(uint32_t a, uint32_t b, uint32_t t) {
    uint32_t ar = (a >> 16) & 255u, ag = (a >> 8) & 255u, ab = a & 255u;
    uint32_t br = (b >> 16) & 255u, bg = (b >> 8) & 255u, bb = b & 255u;
    uint32_t r = (ar * t + br * (255u - t)) / 255u;
    uint32_t g = (ag * t + bg * (255u - t)) / 255u;
    uint32_t bl = (ab * t + bb * (255u - t)) / 255u;
    return (r << 16) | (g << 8) | bl;
}

static void put_px(struct desktop_shm_window *shm, int32_t x, int32_t y, uint32_t rgb) {
    if (!shm || x < 0 || y < 0) return;
    if ((uint32_t)x >= shm->width || (uint32_t)y >= shm->height) return;
    shm->pixels[(uint64_t)y * shm->stride + (uint64_t)x] = rgb;
}

static int font_has(const struct btext_font *f, uint32_t cp) {
    return f && cp >= f->first_cp && cp <= f->last_cp;
}

static void builtin_glyph_rows(uint32_t cp, uint32_t flags, uint8_t rows[BTEXT_GLYPH_ROWS]) {
    uint32_t i;
    for (i = 0; i < BTEXT_GLYPH_ROWS; ++i) rows[i] = 0;
    if (cp < 128u && !(flags & BTEXT_FONT_EMOJI)) {
        for (i = 0; i < BTEXT_GLYPH_ROWS; ++i) rows[i] = (uint8_t)font8x8_basic[cp][i];
        return;
    }
    if (flags & BTEXT_FONT_EMOJI) {
        static const uint8_t face[8] = { 0x3c, 0x42, 0xa5, 0x81, 0xa5, 0x99, 0x42, 0x3c };
        for (i = 0; i < BTEXT_GLYPH_ROWS; ++i) rows[i] = face[i];
        return;
    }
    rows[0] = 0x7e; rows[1] = 0x42; rows[2] = 0x5a; rows[3] = 0x52;
    rows[4] = 0x5a; rows[5] = 0x42; rows[6] = 0x7e; rows[7] = 0x00;
}

void btext_manager_init(struct btext_manager *mgr) {
    uint32_t i;
    if (!mgr) return;
    mgr->font_count = 0;
    mgr->tick = 1;
    mgr->hits = mgr->misses = mgr->evictions = 0;
    mgr->aa_mode = BTEXT_AA_GRAYSCALE;
    mgr->hinting = BTEXT_HINT_LIGHT;
    for (i = 0; i < BTEXT_GLYPH_CACHE; ++i) mgr->cache[i].codepoint = 0xffffffffu;
    (void)btext_font_add(mgr, "BitOS Mono", 0x20, 0x7e, 8, 8, BTEXT_FONT_MONO);
    (void)btext_font_add(mgr, "BitOS Symbols", 0x00a0, 0xffff, 8, 8, BTEXT_FONT_SYMBOL);
    (void)btext_font_add(mgr, "BitOS Emoji", 0x1f300, 0x1faff, 8, 8, BTEXT_FONT_EMOJI);
}

int btext_font_add(struct btext_manager *mgr, const char *name, uint32_t first_cp, uint32_t last_cp, uint8_t width, uint8_t height, uint32_t flags) {
    struct btext_font *f;
    if (!mgr || mgr->font_count >= BTEXT_MAX_FONTS) return -1;
    f = &mgr->fonts[mgr->font_count++];
    scopy(f->name, BTEXT_FONT_NAME, name ? name : "font");
    f->first_cp = first_cp;
    f->last_cp = last_cp;
    f->width = width ? width : 8;
    f->height = height ? height : 8;
    f->flags = flags;
    return (int)mgr->font_count - 1;
}

const struct btext_font *btext_font_for_codepoint(struct btext_manager *mgr, uint32_t cp, uint8_t *font_index) {
    uint32_t i;
    if (!mgr) return 0;
    for (i = 0; i < mgr->font_count; ++i) {
        if (font_has(&mgr->fonts[i], cp)) {
            if (font_index) *font_index = (uint8_t)i;
            return &mgr->fonts[i];
        }
    }
    if (font_index) *font_index = 0;
    return mgr->font_count ? &mgr->fonts[0] : 0;
}

const struct btext_glyph *btext_glyph_get(struct btext_manager *mgr, uint32_t cp) {
    uint32_t i;
    uint32_t victim = 0;
    uint32_t oldest = 0xffffffffu;
    uint8_t font_index = 0;
    const struct btext_font *font;
    if (!mgr) return 0;
    if (cp == 0 || cp == '\t') cp = ' ';
    for (i = 0; i < BTEXT_GLYPH_CACHE; ++i) {
        if (mgr->cache[i].codepoint == cp) {
            mgr->cache[i].last_used = ++mgr->tick;
            ++mgr->hits;
            return &mgr->cache[i];
        }
        if (mgr->cache[i].last_used < oldest) { oldest = mgr->cache[i].last_used; victim = i; }
    }
    if (mgr->cache[victim].codepoint != 0xffffffffu) ++mgr->evictions;
    font = btext_font_for_codepoint(mgr, cp, &font_index);
    mgr->cache[victim].codepoint = cp;
    mgr->cache[victim].font_index = font_index;
    mgr->cache[victim].width = font ? font->width : 8;
    mgr->cache[victim].height = font ? font->height : 8;
    mgr->cache[victim].last_used = ++mgr->tick;
    builtin_glyph_rows(cp, font ? font->flags : 0, mgr->cache[victim].rows);
    ++mgr->misses;
    return &mgr->cache[victim];
}

int btext_utf8_decode(const char *s, uint32_t len, uint32_t *cp, uint32_t *consumed) {
    uint8_t c0;
    if (!s || len == 0) return -1;
    c0 = (uint8_t)s[0];
    if (c0 < 0x80u) { if (cp) *cp = c0; if (consumed) *consumed = 1; return 0; }
    if ((c0 & 0xe0u) == 0xc0u && len >= 2 && (((uint8_t)s[1] & 0xc0u) == 0x80u)) {
        if (cp) *cp = ((uint32_t)(c0 & 0x1fu) << 6) | ((uint8_t)s[1] & 0x3fu);
        if (consumed) *consumed = 2;
        return 0;
    }
    if ((c0 & 0xf0u) == 0xe0u && len >= 3 && (((uint8_t)s[1] & 0xc0u) == 0x80u) && (((uint8_t)s[2] & 0xc0u) == 0x80u)) {
        if (cp) *cp = ((uint32_t)(c0 & 0x0fu) << 12) | (((uint8_t)s[1] & 0x3fu) << 6) | ((uint8_t)s[2] & 0x3fu);
        if (consumed) *consumed = 3;
        return 0;
    }
    if ((c0 & 0xf8u) == 0xf0u && len >= 4 && (((uint8_t)s[1] & 0xc0u) == 0x80u) && (((uint8_t)s[2] & 0xc0u) == 0x80u) && (((uint8_t)s[3] & 0xc0u) == 0x80u)) {
        if (cp) *cp = ((uint32_t)(c0 & 0x07u) << 18) | (((uint8_t)s[1] & 0x3fu) << 12) | (((uint8_t)s[2] & 0x3fu) << 6) | ((uint8_t)s[3] & 0x3fu);
        if (consumed) *consumed = 4;
        return 0;
    }
    if (cp) *cp = 0xfffdu;
    if (consumed) *consumed = 1;
    return 1;
}

uint32_t btext_utf8_encode(uint32_t cp, char out[4]) {
    if (!out) return 0;
    if (cp < 0x80u) { out[0] = (char)cp; return 1; }
    if (cp < 0x800u) { out[0] = (char)(0xc0u | (cp >> 6)); out[1] = (char)(0x80u | (cp & 0x3fu)); return 2; }
    if (cp < 0x10000u) { out[0] = (char)(0xe0u | (cp >> 12)); out[1] = (char)(0x80u | ((cp >> 6) & 0x3fu)); out[2] = (char)(0x80u | (cp & 0x3fu)); return 3; }
    out[0] = (char)(0xf0u | (cp >> 18)); out[1] = (char)(0x80u | ((cp >> 12) & 0x3fu)); out[2] = (char)(0x80u | ((cp >> 6) & 0x3fu)); out[3] = (char)(0x80u | (cp & 0x3fu)); return 4;
}

uint32_t btext_utf8_count(const char *s) {
    uint32_t n = 0, i = 0, c = 0, used = 0, len = slen(s);
    while (s && i < len) { (void)btext_utf8_decode(s + i, len - i, &c, &used); i += used ? used : 1; ++n; }
    return n;
}

uint32_t btext_utf8_byte_offset(const char *s, uint32_t cp_index) {
    uint32_t n = 0, i = 0, c = 0, used = 0, len = slen(s);
    while (s && i < len && n < cp_index) { (void)btext_utf8_decode(s + i, len - i, &c, &used); i += used ? used : 1; ++n; }
    return i;
}

static int rtl_cp(uint32_t cp) { return (cp >= 0x0590u && cp <= 0x08ffu); }

uint32_t btext_shape(const char *s, const struct btext_shape_plan *plan, struct btext_shaped_glyph *out, uint32_t cap) {
    uint32_t i = 0, len = slen(s), count = 0, cp = 0, used = 0, dir = plan ? plan->direction : BTEXT_DIR_AUTO;
    if (!out || cap == 0) return 0;
    while (s && i < len && count < cap) {
        (void)btext_utf8_decode(s + i, len - i, &cp, &used);
        if (cp == '\n') { i += used ? used : 1; continue; }
        out[count].codepoint = cp;
        out[count].cluster = i;
        out[count].advance_x = 8;
        out[count].offset_x = 0;
        out[count].offset_y = 0;
        out[count].direction = (uint8_t)(dir == BTEXT_DIR_AUTO ? (rtl_cp(cp) ? BTEXT_DIR_RTL : BTEXT_DIR_LTR) : dir);
        ++count;
        i += used ? used : 1;
    }
    return count;
}

uint32_t btext_bidi_reorder(const struct btext_shaped_glyph *in, uint32_t count, uint32_t direction, struct btext_shaped_glyph *out, uint32_t cap) {
    uint32_t i;
    if (!in || !out || cap == 0) return 0;
    if (count > cap) count = cap;
    if (direction == BTEXT_DIR_RTL) for (i = 0; i < count; ++i) out[i] = in[count - 1u - i];
    else for (i = 0; i < count; ++i) out[i] = in[i];
    return count;
}

void btext_draw_char(struct desktop_shm_window *shm, struct btext_manager *mgr, int32_t x, int32_t y, uint32_t cp, const struct btext_render_options *opts) {
    const struct btext_glyph *g = btext_glyph_get(mgr, cp);
    uint32_t row, col, fg = opts ? opts->fg : 0xffffffu, bg = opts ? opts->bg : 0u;
    uint32_t aa = opts ? opts->aa_mode : (mgr ? mgr->aa_mode : BTEXT_AA_GRAYSCALE);
    if (!g) return;
    for (row = 0; row < g->height; ++row) {
        uint8_t bits = g->rows[row];
        for (col = 0; col < g->width; ++col) {
            if (bits & (1u << col)) put_px(shm, x + (int32_t)col, y + (int32_t)row, fg);
            else if (aa == BTEXT_AA_SUBPIXEL && col > 0 && col + 1u < g->width && (bits & ((1u << (col - 1u)) | (1u << (col + 1u))))) put_px(shm, x + (int32_t)col, y + (int32_t)row, mix(fg, bg, 96));
            else put_px(shm, x + (int32_t)col, y + (int32_t)row, bg);
        }
    }
}

void btext_draw_line(struct desktop_shm_window *shm, struct btext_manager *mgr, int32_t x, int32_t y, const char *s, uint32_t max_px, int ellipsis, const struct btext_render_options *opts) {
    uint32_t i = 0, len = slen(s), cp = 0, used = 0, drawn = 0, max_chars = max_px ? max_px / 8u : 0xffffffffu;
    uint32_t total = btext_utf8_count(s);
    uint32_t limit = total;
    if (max_chars && limit > max_chars) limit = max_chars;
    if (ellipsis && max_chars >= 3u && total > max_chars) limit = max_chars - 3u;
    while (s && i < len && drawn < limit) {
        (void)btext_utf8_decode(s + i, len - i, &cp, &used);
        btext_draw_char(shm, mgr, x + (int32_t)(drawn * 8u), y, cp, opts);
        i += used ? used : 1;
        ++drawn;
    }
    if (ellipsis && max_chars >= 3u && total > max_chars) {
        btext_draw_char(shm, mgr, x + (int32_t)(drawn++ * 8u), y, '.', opts);
        btext_draw_char(shm, mgr, x + (int32_t)(drawn++ * 8u), y, '.', opts);
        btext_draw_char(shm, mgr, x + (int32_t)(drawn * 8u), y, '.', opts);
    }
}

void btext_draw_block(struct desktop_shm_window *shm, struct btext_manager *mgr, int32_t x, int32_t y, uint32_t w, uint32_t h, const char *s, uint32_t flags, int32_t scroll_y, uint8_t line_h, const struct btext_render_options *opts) {
    char line[BTEXT_MAX_SHAPED];
    uint32_t li = 0, i = 0, len = slen(s), max_chars = w / 8u;
    int32_t yy = y - scroll_y;
    while (s && i < len) {
        if (s[i] == '\n') {
            line[li] = 0;
            if (yy + 8 > y && yy < y + (int32_t)h) btext_draw_line(shm, mgr, x, yy, line, w, (flags & 1u) != 0, opts);
            li = 0; yy += line_h ? line_h : 10; ++i; continue;
        }
        if ((flags & 2u) && max_chars && li + 1u >= max_chars) {
            line[li] = 0;
            if (yy + 8 > y && yy < y + (int32_t)h) btext_draw_line(shm, mgr, x, yy, line, w, 0, opts);
            li = 0; yy += line_h ? line_h : 10;
        }
        if (li + 1u < sizeof(line)) line[li++] = s[i];
        ++i;
    }
    line[li] = 0;
    if (yy + 8 > y && yy < y + (int32_t)h) btext_draw_line(shm, mgr, x, yy, line, w, (flags & 1u) != 0, opts);
}

void btext_selection_init(struct btext_selection *sel, uint32_t text_len) {
    if (!sel) return;
    sel->anchor = sel->caret = 0;
    sel->length = text_len;
}

void btext_selection_move(struct btext_selection *sel, int32_t delta, int extend) {
    int32_t next;
    if (!sel) return;
    next = (int32_t)sel->caret + delta;
    if (next < 0) next = 0;
    if ((uint32_t)next > sel->length) next = (int32_t)sel->length;
    sel->caret = (uint32_t)next;
    if (!extend) sel->anchor = sel->caret;
}

uint32_t btext_clipboard_normalize(const char *mime, const char *in, char *out, uint32_t cap) {
    uint32_t i = 0, o = 0;
    (void)mime;
    if (!out || cap == 0) return 0;
    while (in && in[i] && o + 1u < cap) {
        if (in[i] == '\r') { if (in[i + 1] == '\n') ++i; out[o++] = '\n'; }
        else if ((uint8_t)in[i] < 0x20u && in[i] != '\n' && in[i] != '\t') { }
        else out[o++] = in[i];
        ++i;
    }
    out[o] = 0;
    return o;
}

static int leap(uint64_t y) { return ((y % 4u) == 0 && ((y % 100u) != 0 || (y % 400u) == 0)); }

uint32_t btext_format_datetime(uint64_t epoch_seconds, char *out, uint32_t cap) {
    static const uint8_t mdays[12] = {31,28,31,30,31,30,31,31,30,31,30,31};
    uint64_t days = epoch_seconds / 86400u, rem = epoch_seconds % 86400u, year = 1970, mon = 0, d;
    uint32_t hour = (uint32_t)(rem / 3600u), min = (uint32_t)((rem / 60u) % 60u), sec = (uint32_t)(rem % 60u);
    char tmp[24]; uint32_t n = 0;
    while (days >= (uint64_t)(leap(year) ? 366 : 365)) { days -= (uint64_t)(leap(year) ? 366 : 365); ++year; }
    while (mon < 12u) { d = mdays[mon] + (mon == 1u && leap(year) ? 1u : 0u); if (days < d) break; days -= d; ++mon; }
#define DIG2(v) tmp[n++] = (char)('0' + ((v) / 10u) % 10u); tmp[n++] = (char)('0' + (v) % 10u)
    tmp[n++] = (char)('0' + (year / 1000u) % 10u); tmp[n++] = (char)('0' + (year / 100u) % 10u); tmp[n++] = (char)('0' + (year / 10u) % 10u); tmp[n++] = (char)('0' + year % 10u); tmp[n++] = '-'; DIG2((uint32_t)mon + 1u); tmp[n++] = '-'; DIG2((uint32_t)days + 1u); tmp[n++] = ' '; DIG2(hour); tmp[n++] = ':'; DIG2(min); tmp[n++] = ':'; DIG2(sec); tmp[n] = 0;
#undef DIG2
    scopy(out, cap, tmp);
    return n;
}

void btext_benchmark(struct btext_manager *mgr, struct btext_benchmark_result *out, uint32_t loops) {
    static const char sample[] = "BitOS desktop text benchmark: UTF-8, fallback fonts, emoji \xf0\x9f\x98\x80, cache.";
    uint32_t l, i, len = slen(sample), cp = 0, used = 0;
    uint64_t sum = 0;
    if (!mgr) return;
    if (!loops) loops = 1;
    for (l = 0; l < loops; ++l) {
        i = 0;
        while (i < len) {
            const struct btext_glyph *g;
            (void)btext_utf8_decode(sample + i, len - i, &cp, &used);
            g = btext_glyph_get(mgr, cp);
            if (g) sum += ((uint64_t)g->codepoint << 8) ^ g->rows[l & 7u];
            i += used ? used : 1;
        }
    }
    if (out) {
        out->glyphs = btext_utf8_count(sample) * loops;
        out->cache_hits = mgr->hits;
        out->cache_misses = mgr->misses;
        out->cache_evictions = mgr->evictions;
        out->checksum = sum;
    }
}
