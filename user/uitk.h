#ifndef USER_UITK_H
#define USER_UITK_H

#include <stdint.h>

#include "desktop.h"
#include "text.h"

#define UITK_MAX_NODES 128u
#define UITK_MAX_TEXT 160u
#define UITK_MAX_NAME 48u
#define UITK_MAX_ICON_NAME 16u
#define UITK_MAX_ICONS 16u
#define UITK_MAX_SNAPSHOT 8192u

enum uitk_kind {
    UITK_ROOT = 0,
    UITK_PANEL,
    UITK_ROW,
    UITK_COLUMN,
    UITK_GRID,
    UITK_LABEL,
    UITK_BUTTON,
    UITK_INPUT,
    UITK_TEXTAREA,
    UITK_SCROLL,
    UITK_LIST,
    UITK_TABLE,
    UITK_MENUBAR,
    UITK_CONTEXT_MENU,
    UITK_DIALOG,
    UITK_ICON
};

enum uitk_role {
    UITK_ROLE_NONE = 0,
    UITK_ROLE_WINDOW,
    UITK_ROLE_PANEL,
    UITK_ROLE_LABEL,
    UITK_ROLE_BUTTON,
    UITK_ROLE_TEXTBOX,
    UITK_ROLE_TEXTAREA,
    UITK_ROLE_LIST,
    UITK_ROLE_TABLE,
    UITK_ROLE_MENU,
    UITK_ROLE_MENUITEM,
    UITK_ROLE_DIALOG,
    UITK_ROLE_ICON
};

enum {
    UITK_STATE_DISABLED = 1u << 0,
    UITK_STATE_SELECTED = 1u << 1,
    UITK_STATE_FOCUSED = 1u << 2,
    UITK_STATE_PRESSED = 1u << 3,
    UITK_STATE_HOVERED = 1u << 4,
    UITK_STATE_MODAL = 1u << 5,
    UITK_STATE_ACTIVE = 1u << 6
};

enum {
    UITK_FLAG_VISIBLE = 1u << 0,
    UITK_FLAG_FOCUSABLE = 1u << 1,
    UITK_FLAG_DISABLED = 1u << 2,
    UITK_FLAG_WRAP = 1u << 3,
    UITK_FLAG_ELLIPSIS = 1u << 4,
    UITK_FLAG_MULTILINE = 1u << 5,
    UITK_FLAG_MODAL = 1u << 6,
    UITK_FLAG_SCROLLABLE = 1u << 7,
    UITK_FLAG_HEADER = 1u << 8,
    UITK_FLAG_CONTEXT = 1u << 9,
    UITK_FLAG_ACTIVE = 1u << 10
};

struct uitk_rect {
    int32_t x;
    int32_t y;
    uint32_t w;
    uint32_t h;
};

struct uitk_theme {
    uint32_t bg;
    uint32_t panel;
    uint32_t panel_alt;
    uint32_t text;
    uint32_t text_dim;
    uint32_t border;
    uint32_t accent;
    uint32_t accent_hover;
    uint32_t accent_pressed;
    uint32_t focus;
    uint32_t selection;
    uint32_t menu_bg;
    uint32_t dialog_bg;
    uint32_t ok;
    uint32_t warn;
    uint16_t spacing;
    uint16_t padding;
    uint16_t radius;
    uint8_t font_w;
    uint8_t font_h;
    uint8_t line_h;
};

struct uitk_a11y {
    uint32_t role;
    uint32_t state;
    char name[UITK_MAX_NAME];
};

struct uitk_icon {
    char name[UITK_MAX_ICON_NAME];
    uint8_t rows[8];
};

struct uitk_icon_atlas {
    uint32_t count;
    struct uitk_icon icons[UITK_MAX_ICONS];
};

struct uitk_node {
    int32_t id;
    int32_t parent;
    int32_t first_child;
    int32_t last_child;
    int32_t next_sibling;
    uint32_t kind;
    uint32_t flags;
    struct uitk_rect rect;
    uint32_t pref_w;
    uint32_t pref_h;
    uint32_t min_w;
    uint32_t min_h;
    uint32_t grow;
    uint16_t padding;
    uint16_t gap;
    uint16_t columns;
    uint16_t rows;
    uint16_t grid_col;
    uint16_t grid_row;
    uint16_t col_span;
    uint16_t row_span;
    int32_t scroll_x;
    int32_t scroll_y;
    int32_t content_h;
    int32_t content_w;
    int32_t cursor;
    int32_t selection;
    int32_t hot_index;
    int32_t item_count;
    char text[UITK_MAX_TEXT];
    char value[UITK_MAX_TEXT];
    char aux[UITK_MAX_TEXT];
    char icon[UITK_MAX_ICON_NAME];
    struct uitk_a11y a11y;
};

struct uitk_tree {
    struct uitk_theme theme;
    struct uitk_icon_atlas atlas;
    struct btext_manager text;
    uint32_t node_count;
    int32_t root;
    int32_t focus;
    int32_t hot;
    int32_t active;
    int32_t modal;
    int32_t menu;
    int32_t action;
    int32_t context_target;
    uint32_t last_buttons;
    uint32_t width;
    uint32_t height;
    struct uitk_node nodes[UITK_MAX_NODES];
    char snapshot[UITK_MAX_SNAPSHOT];
};

void uitk_theme_default(struct uitk_theme *theme);
void uitk_icon_atlas_default(struct uitk_icon_atlas *atlas);
int uitk_icon_add(struct uitk_icon_atlas *atlas, const char *name, const uint8_t rows[8]);
void uitk_init(struct uitk_tree *tree, uint32_t width, uint32_t height, const struct uitk_theme *theme);
int uitk_root(struct uitk_tree *tree);
int uitk_add_node(struct uitk_tree *tree, int parent, uint32_t kind, const char *text);
int uitk_add_panel(struct uitk_tree *tree, int parent, const char *name);
int uitk_add_row(struct uitk_tree *tree, int parent, const char *name);
int uitk_add_column(struct uitk_tree *tree, int parent, const char *name);
int uitk_add_grid(struct uitk_tree *tree, int parent, uint16_t columns, const char *name);
int uitk_add_label(struct uitk_tree *tree, int parent, const char *text);
int uitk_add_button(struct uitk_tree *tree, int parent, const char *text);
int uitk_add_input(struct uitk_tree *tree, int parent, const char *placeholder, const char *value);
int uitk_add_textarea(struct uitk_tree *tree, int parent, const char *placeholder, const char *value);
int uitk_add_scroll(struct uitk_tree *tree, int parent, const char *name);
int uitk_add_list(struct uitk_tree *tree, int parent, const char *items);
int uitk_add_table(struct uitk_tree *tree, int parent, const char *rows);
int uitk_add_menubar(struct uitk_tree *tree, int parent, const char *name);
int uitk_add_context_menu(struct uitk_tree *tree, int parent, const char *items);
int uitk_add_dialog(struct uitk_tree *tree, int parent, const char *title);
int uitk_add_icon(struct uitk_tree *tree, int parent, const char *name);
void uitk_set_text(struct uitk_tree *tree, int id, const char *text);
void uitk_set_value(struct uitk_tree *tree, int id, const char *value);
void uitk_set_aux(struct uitk_tree *tree, int id, const char *value);
void uitk_set_icon(struct uitk_tree *tree, int id, const char *name);
void uitk_set_flags(struct uitk_tree *tree, int id, uint32_t flags);
void uitk_set_rect(struct uitk_tree *tree, int id, int32_t x, int32_t y, uint32_t w, uint32_t h);
void uitk_set_grid_pos(struct uitk_tree *tree, int id, uint16_t col, uint16_t row, uint16_t col_span, uint16_t row_span);
void uitk_set_grow(struct uitk_tree *tree, int id, uint32_t grow);
void uitk_set_padding(struct uitk_tree *tree, int id, uint16_t padding, uint16_t gap);
void uitk_set_selection(struct uitk_tree *tree, int id, int32_t selection);
void uitk_set_a11y(struct uitk_tree *tree, int id, uint32_t role, const char *name, uint32_t state);
void uitk_layout(struct uitk_tree *tree);
void uitk_render(struct uitk_tree *tree, struct desktop_shm_window *shm);
void uitk_pointer(struct uitk_tree *tree, int32_t x, int32_t y, uint32_t buttons, int32_t wheel_y);
void uitk_key(struct uitk_tree *tree, uint32_t keycode, uint32_t flags, uint32_t modifiers);
int uitk_take_action(struct uitk_tree *tree);
const char *uitk_snapshot(struct uitk_tree *tree);

#endif
