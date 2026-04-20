#include "uitk.h"
#include "sys.h"

static int contains(const char *haystack, const char *needle) {
    uint32_t i = 0;
    uint32_t j;
    if (!haystack || !needle || !needle[0]) return 0;
    while (haystack[i]) {
        j = 0;
        while (needle[j] && haystack[i + j] == needle[j]) ++j;
        if (!needle[j]) return 1;
        ++i;
    }
    return 0;
}

void _start(void) {
    struct uitk_tree ui;
    const char *snap;
    int root;
    int main_col;
    int row;
    int grid;
    (void)root;
    uitk_init(&ui, 640, 360, 0);
    root = ui.root;
    main_col = uitk_add_column(&ui, ui.root, "main");
    row = uitk_add_row(&ui, main_col, "toolbar");
    (void)uitk_add_button(&ui, row, "Save");
    (void)uitk_add_input(&ui, row, "search", "term");
    grid = uitk_add_grid(&ui, main_col, 2, "content");
    (void)uitk_add_label(&ui, grid, "Left");
    (void)uitk_add_textarea(&ui, grid, "notes", "hello\nworld");
    (void)uitk_add_list(&ui, main_col, "One\nTwo\nThree");
    (void)uitk_add_table(&ui, main_col, "Name|Value\nWidth|640");
    (void)uitk_add_context_menu(&ui, ui.root, "Open\nClose");
    (void)uitk_add_dialog(&ui, ui.root, "Snapshot");
    uitk_layout(&ui);
    snap = uitk_snapshot(&ui);
    if (!contains(snap, "kind=6") || !contains(snap, "kind=4") || !contains(snap, "text=Save")) {
        uputs("uitktest: snapshot mismatch\n");
        uputs(snap);
        sys_exit(1);
    }
    uputs("uitktest: ok\n");
    sys_exit(0);
}
