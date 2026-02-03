#ifndef STRUTIL_H
#define STRUTIL_H

#include <stddef.h>
#include <stdint.h>

size_t str_len(const char *s);
int str_eq(const char *a, const char *b);
int str_eqn(const char *a, const char *b, size_t n);
int str_to_u64(const char *s, uint64_t *out);
int str_parse_size_bytes(const char *s, uint64_t *out_bytes);
int str_parse_seconds(const char *s, uint64_t *out_seconds);

#endif /* STRUTIL_H */
