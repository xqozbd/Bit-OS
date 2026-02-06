#ifndef BOOT_PARAMS_H
#define BOOT_PARAMS_H

const char *boot_param_get(const char *key);
int boot_param_has(const char *key);
const char *boot_cmdline_raw(void);
void boot_params_init(const char *cmdline);

#endif /* BOOT_PARAMS_H */
