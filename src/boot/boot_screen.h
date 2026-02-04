#ifndef BOOT_SCREEN_H
#define BOOT_SCREEN_H

void boot_screen_print_loading(void);
void boot_screen_print_main(void);
void boot_screen_print_debug(void);
void boot_screen_set_status(const char *status);

#endif /* BOOT_SCREEN_H */
