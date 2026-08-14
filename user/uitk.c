#include "uitk.h"

#include "sys.h"

static uint32_t ulen(const char *s) {
    uint32_t n = 0;
    while (s && s[n]) ++n;
    return n;
}

static void ucopy(char *dst, uint32_t cap, const char *src) {
    uint32_t i = 0;
    if (!dst || cap == 0) return;
    if (!src) {
        dst[0] = '\0';
        return;
    }
    while (src[i] && i + 1 < cap) {
        dst[i] = src[i];
        ++i;
    }
    dst[i] = '\0';
}

static void uappend(char *dst, uint32_t cap, const char *src) {
    uint32_t i = ulen(dst);
    uint32_t j = 0;
    if (!dst || cap == 0 || !src) return;
    while (src[j] && i + 1 < cap) {
        dst[i++] = src[j++];
    }
    dst[i] = '\0';
}

static void uappend_ch(char *dst, uint32_t cap, char ch) {
    uint32_t n = ulen(dst);
    if (!dst || cap == 0 || n + 1 >= cap) return;
    dst[n++] = ch;
    dst[n] = '\0';
}

static void uappend_u32(char *dst, uint32_t cap, uint32_t v) {
    char tmp[16];
    uint32_t i = 0;
    if (v == 0) {
        uappend(dst, cap, "0");
        return;
    }
    while (v && i + 1 < (uint32_t)sizeof(tmp)) {
        tmp[i++] = (char)('0' + (v % 10u));
        v /= 10u;
    }
    while (i) uappend_ch(dst, cap, tmp[--i]);
}

static int rect_contains(const struct uitk_rect *r, int32_t x, int32_t y) {
    if (!r || x < r->x || y < r->y) return 0;
    return (uint32_t)(x - r->x) < r->w && (uint32_t)(y - r->y) < r->h;
}

static uint32_t visible_state(const struct uitk_tree *tree, const struct uitk_node *node) {
    uint32_t state = node->a11y.state;
    if (node->id == tree->focus) state |= UITK_STATE_FOCUSED;
    if (node->id == tree->hot) state |= UITK_STATE_HOVERED;
    if (node->id == tree->active) state |= UITK_STATE_PRESSED;
    if (node->flags & UITK_FLAG_DISABLED) state |= UITK_STATE_DISABLED;
    if (node->selection >= 0) state |= UITK_STATE_SELECTED;
    if (node->flags & UITK_FLAG_MODAL) state |= UITK_STATE_MODAL;
    if (node->flags & UITK_FLAG_ACTIVE) state |= UITK_STATE_ACTIVE;
    return state;
}

static void pixel(struct desktop_shm_window *shm, int32_t x, int32_t y, uint32_t rgb) {
    if (!shm || x < 0 || y < 0) return;
    if ((uint32_t)x >= shm->width || (uint32_t)y >= shm->height) return;
    shm->pixels[(uint64_t)y * shm->stride + (uint64_t)x] = rgb;
}

static void fill_rect(struct desktop_shm_window *shm, int32_t x, int32_t y, uint32_t w, uint32_t h, uint32_t rgb) {
    uint32_t yy;
    uint32_t xx;
    for (yy = 0; yy < h; ++yy) {
        for (xx = 0; xx < w; ++xx) pixel(shm, x + (int32_t)xx, y + (int32_t)yy, rgb);
    }
}

static void stroke_rect(struct desktop_shm_window *shm, int32_t x, int32_t y, uint32_t w, uint32_t h, uint32_t rgb) {
    if (w == 0 || h == 0) return;
    fill_rect(shm, x, y, w, 1, rgb);
    fill_rect(shm, x, y + (int32_t)h - 1, w, 1, rgb);
    fill_rect(shm, x, y, 1, h, rgb);
    fill_rect(shm, x + (int32_t)w - 1, y, 1, h, rgb);
}

static void draw_text_line(struct desktop_shm_window *shm, struct btext_manager *mgr, int32_t x, int32_t y, const char *s, uint32_t fg, uint32_t bg, uint32_t max_chars, int ellipsis) {
    struct btext_render_options opts = { mgr ? mgr->aa_mode : BTEXT_AA_GRAYSCALE, mgr ? mgr->hinting : BTEXT_HINT_LIGHT, fg, bg };
    btext_draw_line(shm, mgr, x, y, s, max_chars ? max_chars * 8u : 0u, ellipsis, &opts);
}

static void draw_text_block(struct desktop_shm_window *shm, struct btext_manager *mgr, const struct uitk_theme *theme, const struct uitk_rect *rect, const char *s, uint32_t fg, uint32_t bg, uint32_t flags, int32_t scroll_y) {
    struct btext_render_options opts = { mgr ? mgr->aa_mode : BTEXT_AA_GRAYSCALE, mgr ? mgr->hinting : BTEXT_HINT_LIGHT, fg, bg };
    uint32_t text_flags = ((flags & UITK_FLAG_ELLIPSIS) ? 1u : 0u) | ((flags & UITK_FLAG_WRAP) ? 2u : 0u);
    btext_draw_block(shm, mgr, rect->x, rect->y, rect->w, rect->h, s, text_flags, scroll_y, theme->line_h, &opts);
}

static const struct uitk_icon *find_icon(const struct uitk_tree *tree, const char *name) {
    uint32_t i;
    if (!tree || !name || !name[0]) return 0;
    for (i = 0; i < tree->atlas.count; ++i) {
        const struct uitk_icon *icon = &tree->atlas.icons[i];
        uint32_t j = 0;
        while (icon->name[j] && name[j] && icon->name[j] == name[j]) ++j;
        if (icon->name[j] == '\0' && name[j] == '\0') return icon;
    }
    return 0;
}

static void draw_icon(struct desktop_shm_window *shm, const struct uitk_tree *tree, const struct uitk_rect *r, const char *name, uint32_t fg, uint32_t bg) {
    const struct uitk_icon *icon = find_icon(tree, name);
    uint32_t y;
    uint32_t x;
    int32_t ox = r->x + (int32_t)(r->w > 8 ? (r->w - 8u) / 2u : 0u);
    int32_t oy = r->y + (int32_t)(r->h > 8 ? (r->h - 8u) / 2u : 0u);
    if (!icon) return;
    for (y = 0; y < 8; ++y) {
        for (x = 0; x < 8; ++x) pixel(shm, ox + (int32_t)x, oy + (int32_t)y, (icon->rows[y] & (1u << (7u - x))) ? fg : bg);
    }
}

static int is_focusable(const struct uitk_node *node) {
    if (!node) return 0;
    if (!(node->flags & UITK_FLAG_VISIBLE)) return 0;
    if (node->flags & UITK_FLAG_DISABLED) return 0;
    return (node->flags & UITK_FLAG_FOCUSABLE) != 0;
}

static void apply_role_defaults(struct uitk_node *node) {
    switch (node->kind) {
    case UITK_BUTTON:
        node->flags |= UITK_FLAG_FOCUSABLE;
        node->a11y.role = UITK_ROLE_BUTTON;
        node->pref_h = 24;
        break;
    case UITK_INPUT:
        node->flags |= UITK_FLAG_FOCUSABLE;
        node->a11y.role = UITK_ROLE_TEXTBOX;
        node->pref_h = 24;
        break;
    case UITK_TEXTAREA:
        node->flags |= UITK_FLAG_FOCUSABLE | UITK_FLAG_MULTILINE | UITK_FLAG_SCROLLABLE | UITK_FLAG_WRAP;
        node->a11y.role = UITK_ROLE_TEXTAREA;
        node->pref_h = 96;
        break;
    case UITK_LIST:
        node->flags |= UITK_FLAG_FOCUSABLE | UITK_FLAG_SCROLLABLE;
        node->a11y.role = UITK_ROLE_LIST;
        node->pref_h = 120;
        break;
    case UITK_TABLE:
        node->flags |= UITK_FLAG_FOCUSABLE | UITK_FLAG_SCROLLABLE;
        node->a11y.role = UITK_ROLE_TABLE;
        node->pref_h = 140;
        break;
    case UITK_MENUBAR:
        node->a11y.role = UITK_ROLE_MENU;
        node->pref_h = 22;
        node->flags |= UITK_FLAG_HEADER;
        break;
    case UITK_CONTEXT_MENU:
        node->flags |= UITK_FLAG_CONTEXT | UITK_FLAG_FOCUSABLE;
        node->a11y.role = UITK_ROLE_MENU;
        node->pref_w = 160;
        node->pref_h = 120;
        break;
    case UITK_DIALOG:
        node->flags |= UITK_FLAG_MODAL;
        node->a11y.role = UITK_ROLE_DIALOG;
        node->pref_w = 360;
        node->pref_h = 220;
        break;
    case UITK_LABEL:
        node->a11y.role = UITK_ROLE_LABEL;
        node->pref_h = 16;
        break;
    case UITK_PANEL:
        node->a11y.role = UITK_ROLE_PANEL;
        break;
    case UITK_ICON:
        node->a11y.role = UITK_ROLE_ICON;
        node->pref_w = 20;
        node->pref_h = 20;
        break;
    default:
        break;
    }
}

void uitk_theme_default(struct uitk_theme *theme) {
    if (!theme) return;
    theme->bg = 0x15202Bu;
    theme->panel = 0x1C2A38u;
    theme->panel_alt = 0x223244u;
    theme->text = 0xF3F7FBu;
    theme->text_dim = 0xB4C1CFu;
    theme->border = 0x6A94BFu;
    theme->accent = 0x4F7AA3u;
    theme->accent_hover = 0x6A94BFu;
    theme->accent_pressed = 0x31526Fu;
    theme->focus = 0xF1C76Bu;
    theme->selection = 0x35536Fu;
    theme->menu_bg = 0x1A2633u;
    theme->dialog_bg = 0x18222Du;
    theme->ok = 0x4F8A66u;
    theme->warn = 0xA35D4Fu;
    theme->spacing = 8;
    theme->padding = 8;
    theme->radius = 0;
    theme->font_w = 8;
    theme->font_h = 8;
    theme->line_h = 10;
}

int uitk_icon_add(struct uitk_icon_atlas *atlas, const char *name, const uint8_t rows[8]) {
    uint32_t i;
    if (!atlas || atlas->count >= UITK_MAX_ICONS) return -1;
    i = atlas->count++;
    ucopy(atlas->icons[i].name, UITK_MAX_ICON_NAME, name);
    for (uint32_t y = 0; y < 8; ++y) atlas->icons[i].rows[y] = rows[y];
    return (int)i;
}

void uitk_icon_atlas_default(struct uitk_icon_atlas *atlas) {
    static const uint8_t app_rows[8] = { 0x7E, 0x42, 0x5A, 0x5A, 0x5A, 0x42, 0x7E, 0x00 };
    static const uint8_t folder_rows[8] = { 0x3C, 0x7E, 0x42, 0x7E, 0x7E, 0x7E, 0x00, 0x00 };
    static const uint8_t gear_rows[8] = { 0x18, 0x3C, 0x66, 0x5A, 0x66, 0x3C, 0x18, 0x00 };
    static const uint8_t text_rows[8] = { 0x7E, 0x18, 0x18, 0x18, 0x18, 0x18, 0x18, 0x00 };
    if (!atlas) return;
    atlas->count = 0;
    (void)uitk_icon_add(atlas, "app", app_rows);
    (void)uitk_icon_add(atlas, "folder", folder_rows);
    (void)uitk_icon_add(atlas, "gear", gear_rows);
    (void)uitk_icon_add(atlas, "text", text_rows);
}

void uitk_init(struct uitk_tree *tree, uint32_t width, uint32_t height, const struct uitk_theme *theme) {
    uint32_t i;
    if (!tree) return;
    for (i = 0; i < UITK_MAX_NODES; ++i) tree->nodes[i].id = -1;
    tree->node_count = 0;
    tree->root = -1;
    tree->focus = -1;
    tree->hot = -1;
    tree->active = -1;
    tree->modal = -1;
    tree->menu = -1;
    tree->action = -1;
    tree->context_target = -1;
    tree->last_buttons = 0;
    tree->width = width;
    tree->height = height;
    tree->snapshot[0] = '\0';
    if (theme) tree->theme = *theme; else uitk_theme_default(&tree->theme);
    uitk_icon_atlas_default(&tree->atlas);
    btext_manager_init(&tree->text);
    (void)uitk_root(tree);
}

int uitk_root(struct uitk_tree *tree) {
    if (!tree || tree->root >= 0) return tree ? tree->root : -1;
    tree->root = uitk_add_node(tree, -1, UITK_ROOT, "root");
    uitk_set_rect(tree, tree->root, 0, 0, tree->width, tree->height);
    uitk_set_padding(tree, tree->root, tree->theme.padding, tree->theme.spacing);
    return tree->root;
}
int uitk_add_node(struct uitk_tree *tree, int parent, uint32_t kind, const char *text) {
    struct uitk_node *node;
    int id;
    if (!tree || tree->node_count >= UITK_MAX_NODES) return -1;
    id = (int)tree->node_count++;
    node = &tree->nodes[id];
    *node = (struct uitk_node){0};
    node->id = id;
    node->parent = parent;
    node->first_child = -1;
    node->last_child = -1;
    node->next_sibling = -1;
    node->kind = kind;
    node->flags = UITK_FLAG_VISIBLE;
    node->pref_w = 0;
    node->pref_h = 24;
    node->min_w = 32;
    node->min_h = 16;
    node->grow = 1;
    node->padding = tree->theme.padding;
    node->gap = tree->theme.spacing;
    node->columns = 2;
    node->rows = 1;
    node->selection = -1;
    node->hot_index = -1;
    node->cursor = 0;
    ucopy(node->text, UITK_MAX_TEXT, text);
    ucopy(node->a11y.name, UITK_MAX_NAME, text);
    apply_role_defaults(node);
    if (parent >= 0) {
        struct uitk_node *p = &tree->nodes[parent];
        if (p->first_child < 0) p->first_child = id;
        else tree->nodes[p->last_child].next_sibling = id;
        p->last_child = id;
    }
    return id;
}

#define UITK_ADD_WRAPPER(name, kind) \
int name(struct uitk_tree *tree, int parent, const char *text) { return uitk_add_node(tree, parent, kind, text); }

UITK_ADD_WRAPPER(uitk_add_panel, UITK_PANEL)
UITK_ADD_WRAPPER(uitk_add_row, UITK_ROW)
UITK_ADD_WRAPPER(uitk_add_column, UITK_COLUMN)
UITK_ADD_WRAPPER(uitk_add_label, UITK_LABEL)
UITK_ADD_WRAPPER(uitk_add_button, UITK_BUTTON)
UITK_ADD_WRAPPER(uitk_add_scroll, UITK_SCROLL)
UITK_ADD_WRAPPER(uitk_add_list, UITK_LIST)
UITK_ADD_WRAPPER(uitk_add_table, UITK_TABLE)
UITK_ADD_WRAPPER(uitk_add_menubar, UITK_MENUBAR)
UITK_ADD_WRAPPER(uitk_add_context_menu, UITK_CONTEXT_MENU)
UITK_ADD_WRAPPER(uitk_add_dialog, UITK_DIALOG)
UITK_ADD_WRAPPER(uitk_add_icon, UITK_ICON)

int uitk_add_grid(struct uitk_tree *tree, int parent, uint16_t columns, const char *name) {
    int id = uitk_add_node(tree, parent, UITK_GRID, name);
    if (id >= 0) tree->nodes[id].columns = columns ? columns : 1;
    return id;
}

int uitk_add_input(struct uitk_tree *tree, int parent, const char *placeholder, const char *value) {
    int id = uitk_add_node(tree, parent, UITK_INPUT, placeholder);
    if (id >= 0) {
        ucopy(tree->nodes[id].aux, UITK_MAX_TEXT, placeholder);
        ucopy(tree->nodes[id].value, UITK_MAX_TEXT, value);
        tree->nodes[id].cursor = (int32_t)ulen(tree->nodes[id].value);
    }
    return id;
}

int uitk_add_textarea(struct uitk_tree *tree, int parent, const char *placeholder, const char *value) {
    int id = uitk_add_node(tree, parent, UITK_TEXTAREA, placeholder);
    if (id >= 0) {
        ucopy(tree->nodes[id].aux, UITK_MAX_TEXT, placeholder);
        ucopy(tree->nodes[id].value, UITK_MAX_TEXT, value);
        tree->nodes[id].cursor = (int32_t)ulen(tree->nodes[id].value);
    }
    return id;
}

void uitk_set_text(struct uitk_tree *tree, int id, const char *text) { if (tree && id >= 0) ucopy(tree->nodes[id].text, UITK_MAX_TEXT, text); }
void uitk_set_value(struct uitk_tree *tree, int id, const char *value) { if (tree && id >= 0) { ucopy(tree->nodes[id].value, UITK_MAX_TEXT, value); tree->nodes[id].cursor = (int32_t)ulen(tree->nodes[id].value); } }
void uitk_set_aux(struct uitk_tree *tree, int id, const char *value) { if (tree && id >= 0) ucopy(tree->nodes[id].aux, UITK_MAX_TEXT, value); }
void uitk_set_icon(struct uitk_tree *tree, int id, const char *name) { if (tree && id >= 0) ucopy(tree->nodes[id].icon, UITK_MAX_ICON_NAME, name); }
void uitk_set_flags(struct uitk_tree *tree, int id, uint32_t flags) { if (tree && id >= 0) tree->nodes[id].flags = flags | UITK_FLAG_VISIBLE; }
void uitk_set_rect(struct uitk_tree *tree, int id, int32_t x, int32_t y, uint32_t w, uint32_t h) { if (tree && id >= 0) tree->nodes[id].rect = (struct uitk_rect){ x, y, w, h }; }
void uitk_set_grid_pos(struct uitk_tree *tree, int id, uint16_t col, uint16_t row, uint16_t col_span, uint16_t row_span) { if (tree && id >= 0) { tree->nodes[id].grid_col = col; tree->nodes[id].grid_row = row; tree->nodes[id].col_span = col_span ? col_span : 1; tree->nodes[id].row_span = row_span ? row_span : 1; } }
void uitk_set_grow(struct uitk_tree *tree, int id, uint32_t grow) { if (tree && id >= 0) tree->nodes[id].grow = grow ? grow : 1; }
void uitk_set_padding(struct uitk_tree *tree, int id, uint16_t padding, uint16_t gap) { if (tree && id >= 0) { tree->nodes[id].padding = padding; tree->nodes[id].gap = gap; } }
void uitk_set_selection(struct uitk_tree *tree, int id, int32_t selection) { if (tree && id >= 0) tree->nodes[id].selection = selection; }
void uitk_set_a11y(struct uitk_tree *tree, int id, uint32_t role, const char *name, uint32_t state) { if (tree && id >= 0) { tree->nodes[id].a11y.role = role; tree->nodes[id].a11y.state = state; ucopy(tree->nodes[id].a11y.name, UITK_MAX_NAME, name); } }

static uint32_t child_count(const struct uitk_tree *tree, const struct uitk_node *node) {
    uint32_t n = 0;
    int child = node->first_child;
    while (child >= 0) {
        ++n;
        child = tree->nodes[child].next_sibling;
    }
    return n;
}

static void layout_children(struct uitk_tree *tree, int id);

static void layout_linear(struct uitk_tree *tree, int id, int vertical) {
    struct uitk_node *node = &tree->nodes[id];
    uint32_t count = child_count(tree, node);
    uint32_t gap = node->gap;
    uint32_t pad = node->padding;
    uint32_t avail_w = node->rect.w > pad * 2u ? node->rect.w - pad * 2u : 0;
    uint32_t avail_h = node->rect.h > pad * 2u ? node->rect.h - pad * 2u : 0;
    uint32_t total_grow = 0;
    uint32_t fixed = 0;
    int child = node->first_child;
    uint32_t pos = 0;
    if (count == 0) return;
    while (child >= 0) {
        struct uitk_node *c = &tree->nodes[child];
        total_grow += c->grow ? c->grow : 1;
        fixed += vertical ? (c->pref_h ? c->pref_h : 24u) : (c->pref_w ? c->pref_w : 96u);
        child = c->next_sibling;
    }
    if (count > 1) fixed += gap * (count - 1u);
    child = node->first_child;
    while (child >= 0) {
        struct uitk_node *c = &tree->nodes[child];
        uint32_t share = vertical ? avail_h : avail_w;
        if (share > fixed) share = ((share - fixed) * (c->grow ? c->grow : 1)) / (total_grow ? total_grow : 1);
        else share = 0;
        if (vertical) {
            c->rect.x = node->rect.x + (int32_t)pad;
            c->rect.y = node->rect.y + (int32_t)pad + (int32_t)pos;
            c->rect.w = avail_w;
            c->rect.h = (c->pref_h ? c->pref_h : 24u) + share;
            pos += c->rect.h + gap;
        } else {
            c->rect.x = node->rect.x + (int32_t)pad + (int32_t)pos;
            c->rect.y = node->rect.y + (int32_t)pad;
            c->rect.w = (c->pref_w ? c->pref_w : 96u) + share;
            c->rect.h = avail_h;
            pos += c->rect.w + gap;
        }
        layout_children(tree, child);
        child = c->next_sibling;
    }
}

static void layout_grid(struct uitk_tree *tree, int id) {
    struct uitk_node *node = &tree->nodes[id];
    uint32_t cols = node->columns ? node->columns : 1;
    uint32_t rows;
    uint32_t idx = 0;
    uint32_t count = child_count(tree, node);
    uint32_t pad = node->padding;
    uint32_t gap = node->gap;
    uint32_t inner_w = node->rect.w > pad * 2u ? node->rect.w - pad * 2u : 0;
    uint32_t inner_h = node->rect.h > pad * 2u ? node->rect.h - pad * 2u : 0;
    uint32_t col_w;
    uint32_t row_h;
    int child = node->first_child;
    if (count == 0) return;
    rows = (count + cols - 1u) / cols;
    col_w = cols ? (inner_w - (cols > 1 ? gap * (cols - 1u) : 0u)) / cols : inner_w;
    row_h = rows ? (inner_h - (rows > 1 ? gap * (rows - 1u) : 0u)) / rows : inner_h;
    while (child >= 0) {
        struct uitk_node *c = &tree->nodes[child];
        uint32_t col = (c->grid_col || c->grid_row) ? c->grid_col : (idx % cols);
        uint32_t row = (c->grid_col || c->grid_row) ? c->grid_row : (idx / cols);
        uint32_t span_c = c->col_span ? c->col_span : 1;
        uint32_t span_r = c->row_span ? c->row_span : 1;
        c->rect.x = node->rect.x + (int32_t)pad + (int32_t)(col * (col_w + gap));
        c->rect.y = node->rect.y + (int32_t)pad + (int32_t)(row * (row_h + gap));
        c->rect.w = col_w * span_c + gap * (span_c - 1u);
        c->rect.h = row_h * span_r + gap * (span_r - 1u);
        layout_children(tree, child);
        ++idx;
        child = c->next_sibling;
    }
}

static void layout_children(struct uitk_tree *tree, int id) {
    struct uitk_node *node = &tree->nodes[id];
    switch (node->kind) {
    case UITK_ROOT:
    case UITK_PANEL:
    case UITK_COLUMN:
    case UITK_DIALOG:
    case UITK_SCROLL:
        layout_linear(tree, id, 1);
        break;
    case UITK_ROW:
    case UITK_MENUBAR:
        layout_linear(tree, id, 0);
        break;
    case UITK_GRID:
        layout_grid(tree, id);
        break;
    default:
        break;
    }
}

void uitk_layout(struct uitk_tree *tree) {
    if (!tree || tree->root < 0) return;
    tree->nodes[tree->root].rect = (struct uitk_rect){ 0, 0, tree->width, tree->height };
    layout_children(tree, tree->root);
}
static int hit_test_node(const struct uitk_tree *tree, int id, int32_t x, int32_t y) {
    const struct uitk_node *node = &tree->nodes[id];
    int child;
    if (!(node->flags & UITK_FLAG_VISIBLE)) return -1;
    if (!rect_contains(&node->rect, x, y)) return -1;
    child = node->first_child;
    while (child >= 0) {
        int hit = hit_test_node(tree, child, x, y);
        if (hit >= 0) return hit;
        child = tree->nodes[child].next_sibling;
    }
    return id;
}

static int next_focus(const struct uitk_tree *tree, int start) {
    int seen = 0;
    uint32_t i;
    for (i = 0; i < tree->node_count; ++i) {
        if ((int)i == start) {
            seen = 1;
            continue;
        }
        if (seen && is_focusable(&tree->nodes[i])) return (int)i;
    }
    for (i = 0; i < tree->node_count; ++i) if (is_focusable(&tree->nodes[i])) return (int)i;
    return -1;
}

static void text_backspace(struct uitk_node *node) {
    uint32_t len = ulen(node->value);
    uint32_t cur;
    if (len == 0 || node->cursor <= 0) return;
    cur = (uint32_t)node->cursor;
    for (uint32_t i = cur - 1u; i < len; ++i) node->value[i] = node->value[i + 1u];
    node->cursor--;
}

static void text_insert(struct uitk_node *node, char ch) {
    uint32_t len = ulen(node->value);
    uint32_t cur = (uint32_t)(node->cursor < 0 ? 0 : node->cursor);
    if (len + 1 >= UITK_MAX_TEXT) return;
    if (!(node->flags & UITK_FLAG_MULTILINE) && (ch == '\n' || ch == '\r')) return;
    for (uint32_t i = len + 1u; i > cur; --i) node->value[i] = node->value[i - 1u];
    node->value[cur] = ch;
    node->cursor++;
}

static int item_row_at(const struct uitk_node *node, int32_t y, uint32_t line_h) {
    int32_t local = y - node->rect.y + node->scroll_y - (int32_t)node->padding;
    if (local < 0) return -1;
    return local / (int32_t)line_h;
}

void uitk_pointer(struct uitk_tree *tree, int32_t x, int32_t y, uint32_t buttons, int32_t wheel_y) {
    int hit;
    if (!tree || tree->root < 0) return;
    hit = hit_test_node(tree, tree->root, x, y);
    tree->hot = hit;
    if (wheel_y && hit >= 0) {
        struct uitk_node *node = &tree->nodes[hit];
        if (node->flags & UITK_FLAG_SCROLLABLE) {
            node->scroll_y -= wheel_y * (int32_t)tree->theme.line_h * 2;
            if (node->scroll_y < 0) node->scroll_y = 0;
        }
    }
    if ((buttons & 1u) && !(tree->last_buttons & 1u)) {
        tree->active = hit;
        if (hit >= 0 && is_focusable(&tree->nodes[hit])) tree->focus = hit;
    } else if (!(buttons & 1u) && (tree->last_buttons & 1u)) {
        if (tree->active >= 0 && tree->active == hit) {
            struct uitk_node *node = &tree->nodes[hit];
            tree->action = hit;
            if (node->kind == UITK_LIST || node->kind == UITK_TABLE || node->kind == UITK_CONTEXT_MENU) {
                int row = item_row_at(node, y, tree->theme.line_h + 2u);
                if (row >= 0) node->selection = row;
            }
            if (node->kind == UITK_CONTEXT_MENU) tree->menu = hit;
        }
        tree->active = -1;
    }
    tree->last_buttons = buttons;
}

void uitk_key(struct uitk_tree *tree, uint32_t keycode, uint32_t flags, uint32_t modifiers) {
    struct uitk_node *node;
    (void)modifiers;
    if (!tree || (flags & INPUT_FLAG_RELEASE)) return;
    if (keycode == '\t') {
        tree->focus = next_focus(tree, tree->focus);
        return;
    }
    if (tree->focus < 0 || tree->focus >= (int)tree->node_count) return;
    node = &tree->nodes[tree->focus];
    if (keycode == '\r' || keycode == '\n' || keycode == ' ') {
        if (node->kind == UITK_BUTTON || node->kind == UITK_CONTEXT_MENU) tree->action = tree->focus;
        else if (node->kind == UITK_TEXTAREA) text_insert(node, '\n');
        return;
    }
    if (keycode == 8u || keycode == 127u) {
        if (node->kind == UITK_INPUT || node->kind == UITK_TEXTAREA) text_backspace(node);
        return;
    }
    if (keycode == 'j' && (node->kind == UITK_LIST || node->kind == UITK_TABLE)) {
        node->selection++;
        return;
    }
    if (keycode == 'k' && (node->kind == UITK_LIST || node->kind == UITK_TABLE) && node->selection > 0) {
        node->selection--;
        return;
    }
    if (keycode == 27u) {
        tree->menu = -1;
        tree->modal = -1;
        return;
    }
    if (keycode >= 32u && keycode < 127u) {
        if (node->kind == UITK_INPUT || node->kind == UITK_TEXTAREA) text_insert(node, (char)keycode);
    }
}

static void render_items(struct desktop_shm_window *shm, struct uitk_tree *tree, const struct uitk_node *node, uint32_t bg, uint32_t fg) {
    const char *src = node->text[0] ? node->text : node->value;
    char line[UITK_MAX_TEXT];
    uint32_t li = 0;
    uint32_t row = 0;
    uint32_t y = node->rect.y + node->padding;
    uint32_t step = tree->theme.line_h + 2u;
    uint32_t usable_w = node->rect.w > node->padding * 2u ? node->rect.w - node->padding * 2u : node->rect.w;
    for (uint32_t i = 0;; ++i) {
        char ch = src[i];
        if (ch == '|' && node->kind == UITK_TABLE) ch = ' ';
        if (ch == '\n' || ch == '\0') {
            uint32_t row_bg = (node->selection >= 0 && row == (uint32_t)node->selection) ? tree->theme.selection : bg;
            line[li] = '\0';
            fill_rect(shm, node->rect.x + node->padding, (int32_t)y - node->scroll_y, usable_w, step, row_bg);
            draw_text_line(shm, &tree->text, node->rect.x + (int32_t)node->padding + 2, (int32_t)y - node->scroll_y, line, fg, row_bg, usable_w / tree->theme.font_w, 1);
            li = 0;
            ++row;
            y += step;
            if (ch == '\0') break;
            continue;
        }
        if (li + 1 < (uint32_t)sizeof(line)) line[li++] = ch;
    }
}

static void render_node(struct uitk_tree *tree, struct desktop_shm_window *shm, int id) {
    struct uitk_node *node = &tree->nodes[id];
    struct uitk_theme *theme = &tree->theme;
    uint32_t state = visible_state(tree, node);
    int child;
    if (!(node->flags & UITK_FLAG_VISIBLE)) return;
    switch (node->kind) {
    case UITK_ROOT:
        fill_rect(shm, 0, 0, shm->width, shm->height, theme->bg);
        break;
    case UITK_PANEL:
    case UITK_ROW:
    case UITK_COLUMN:
    case UITK_GRID:
    case UITK_SCROLL:
        fill_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, (node->flags & UITK_FLAG_HEADER) ? theme->panel_alt : theme->panel);
        stroke_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->border);
        break;
    case UITK_LABEL:
        draw_text_block(shm, &tree->text, theme, &node->rect, node->text, theme->text, theme->panel, node->flags, node->scroll_y);
        break;
    case UITK_BUTTON: {
        uint32_t bg = (state & UITK_STATE_DISABLED) ? theme->panel_alt : ((state & UITK_STATE_PRESSED) ? theme->accent_pressed : ((state & UITK_STATE_HOVERED) ? theme->accent_hover : theme->accent));
        fill_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, bg);
        stroke_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, (state & UITK_STATE_FOCUSED) ? theme->focus : theme->border);
        draw_text_line(shm, &tree->text, node->rect.x + 8, node->rect.y + (int32_t)(node->rect.h / 2u) - 4, node->text, theme->text, bg, node->rect.w / theme->font_w, 1);
        break;
    }
    case UITK_INPUT:
    case UITK_TEXTAREA: {
        struct uitk_rect inner = node->rect;
        uint32_t cols;
        fill_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->panel_alt);
        stroke_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, (state & UITK_STATE_FOCUSED) ? theme->focus : theme->border);
        inner.x += 4;
        inner.y += 4;
        inner.w = inner.w > 8 ? inner.w - 8 : inner.w;
        inner.h = inner.h > 8 ? inner.h - 8 : inner.h;
        if (node->value[0]) draw_text_block(shm, &tree->text, theme, &inner, node->value, theme->text, theme->panel_alt, node->flags, node->scroll_y);
        else draw_text_block(shm, &tree->text, theme, &inner, node->aux, theme->text_dim, theme->panel_alt, node->flags | UITK_FLAG_ELLIPSIS, 0);
        if (state & UITK_STATE_FOCUSED) {
            cols = inner.w / theme->font_w;
            if (cols == 0) cols = 1;
            fill_rect(shm,
                      inner.x + (node->cursor % (int32_t)cols) * theme->font_w,
                      inner.y + (node->cursor / (int32_t)cols) * theme->line_h - node->scroll_y,
                      1,
                      theme->font_h,
                      theme->focus);
        }
        break;
    }
    case UITK_LIST:
    case UITK_TABLE:
        fill_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->panel_alt);
        stroke_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, (state & UITK_STATE_FOCUSED) ? theme->focus : theme->border);
        render_items(shm, tree, node, theme->panel_alt, theme->text);
        break;
    case UITK_MENUBAR:
        fill_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->menu_bg);
        stroke_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->border);
        break;
    case UITK_CONTEXT_MENU:
        fill_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->menu_bg);
        stroke_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->focus);
        render_items(shm, tree, node, theme->menu_bg, theme->text);
        break;
    case UITK_DIALOG:
        fill_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->dialog_bg);
        stroke_rect(shm, node->rect.x, node->rect.y, node->rect.w, node->rect.h, theme->focus);
        draw_text_line(shm, &tree->text, node->rect.x + 8, node->rect.y + 6, node->text, theme->text, theme->dialog_bg, node->rect.w / theme->font_w, 1);
        break;
    case UITK_ICON:
        draw_icon(shm, tree, &node->rect, node->icon[0] ? node->icon : node->text, theme->text, theme->panel);
        break;
    default:
        break;
    }
    child = node->first_child;
    while (child >= 0) {
        render_node(tree, shm, child);
        child = tree->nodes[child].next_sibling;
    }
}

void uitk_render(struct uitk_tree *tree, struct desktop_shm_window *shm) {
    if (!tree || !shm || tree->root < 0) return;
    render_node(tree, shm, tree->root);
}

int uitk_take_action(struct uitk_tree *tree) {
    int action;
    if (!tree) return -1;
    action = tree->action;
    tree->action = -1;
    return action;
}
const char *uitk_snapshot(struct uitk_tree *tree) {
    uint32_t i;
    if (!tree) return "";
    tree->snapshot[0] = '\0';
    for (i = 0; i < tree->node_count; ++i) {
        const struct uitk_node *node = &tree->nodes[i];
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, "id=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, i);
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " kind=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, node->kind);
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " x=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, (uint32_t)(node->rect.x < 0 ? 0 : node->rect.x));
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " y=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, (uint32_t)(node->rect.y < 0 ? 0 : node->rect.y));
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " w=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, node->rect.w);
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " h=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, node->rect.h);
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " role=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, node->a11y.role);
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " state=");
        uappend_u32(tree->snapshot, UITK_MAX_SNAPSHOT, visible_state(tree, node));
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, " text=");
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, node->text);
        uappend(tree->snapshot, UITK_MAX_SNAPSHOT, "\n");
    }
    return tree->snapshot;
}
