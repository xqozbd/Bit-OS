#ifndef SYS_SYSCTL_H
#define SYS_SYSCTL_H

#include <stddef.h>

typedef int (*sysctl_get_fn)(char *out, size_t max, void *ctx);
typedef int (*sysctl_set_fn)(const char *val, void *ctx);

void sysctl_init(void);
int sysctl_register(const char *key, sysctl_get_fn get, sysctl_set_fn set, void *ctx);
int sysctl_get(const char *key, char *out, size_t max);
int sysctl_set(const char *key, const char *val);
void sysctl_dump(void);

#endif /* SYS_SYSCTL_H */
