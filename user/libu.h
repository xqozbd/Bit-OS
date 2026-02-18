#ifndef LIBU_H
#define LIBU_H

#include <stdint.h>
#include <stddef.h>

size_t ustrlen(const char *s);
int ustrcmp(const char *a, const char *b);
void uputs(const char *s);
void uputc(char c);
int uatoi(const char *s);

#endif /* LIBU_H */