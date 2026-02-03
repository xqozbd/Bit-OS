#include "lib/strutil.h"

size_t str_len(const char *s) {
    size_t n = 0;
    while (s && s[n]) n++;
    return n;
}

int str_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

int str_eqn(const char *a, const char *b, size_t n) {
    if (!a || !b) return 0;
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return 0;
        if (a[i] == '\0') return 1;
    }
    return 1;
}

int str_to_u64(const char *s, uint64_t *out) {
    if (!s || !*s || !out) return 0;
    uint64_t v = 0;
    for (const char *p = s; *p; ++p) {
        if (*p < '0' || *p > '9') return 0;
        uint64_t nv = v * 10 + (uint64_t)(*p - '0');
        if (nv < v) return 0;
        v = nv;
    }
    *out = v;
    return 1;
}

static char to_lower(char c) {
    if (c >= 'A' && c <= 'Z') return (char)(c + 32);
    return c;
}

static int str_eq_lit(const char *s, const char *lit) {
    size_t i = 0;
    while (s[i] && lit[i]) {
        if (to_lower(s[i]) != lit[i]) return 0;
        i++;
    }
    return s[i] == '\0' && lit[i] == '\0';
}

int str_parse_size_bytes(const char *s, uint64_t *out_bytes) {
    if (!s || !*s || !out_bytes) return 0;
    uint64_t num = 0;
    size_t i = 0;
    while (s[i] >= '0' && s[i] <= '9') {
        uint64_t nv = num * 10 + (uint64_t)(s[i] - '0');
        if (nv < num) return 0;
        num = nv;
        i++;
    }
    if (i == 0) return 0;
    const char *suffix = &s[i];
    uint64_t mult = 1;
    if (*suffix == '\0') {
        mult = 1;
    } else if (str_eq_lit(suffix, "k") || str_eq_lit(suffix, "kb") || str_eq_lit(suffix, "kib")) {
        mult = 1024ull;
    } else if (str_eq_lit(suffix, "m") || str_eq_lit(suffix, "mb") || str_eq_lit(suffix, "mib") || str_eq_lit(suffix, "meg")) {
        mult = 1024ull * 1024ull;
    } else if (str_eq_lit(suffix, "g") || str_eq_lit(suffix, "gb") || str_eq_lit(suffix, "gib") || str_eq_lit(suffix, "gig")) {
        mult = 1024ull * 1024ull * 1024ull;
    } else {
        return 0;
    }
    *out_bytes = num * mult;
    return 1;
}

int str_parse_seconds(const char *s, uint64_t *out_seconds) {
    if (!s || !*s || !out_seconds) return 0;
    uint64_t num = 0;
    size_t i = 0;
    while (s[i] >= '0' && s[i] <= '9') {
        uint64_t nv = num * 10 + (uint64_t)(s[i] - '0');
        if (nv < num) return 0;
        num = nv;
        i++;
    }
    if (i == 0) return 0;
    const char *suffix = &s[i];
    uint64_t mult = 1;
    if (*suffix == '\0' || str_eq_lit(suffix, "s") || str_eq_lit(suffix, "sec") ||
        str_eq_lit(suffix, "second") || str_eq_lit(suffix, "seconds")) {
        mult = 1;
    } else if (str_eq_lit(suffix, "m") || str_eq_lit(suffix, "min") ||
               str_eq_lit(suffix, "mins") || str_eq_lit(suffix, "minute") || str_eq_lit(suffix, "minutes")) {
        mult = 60;
    } else if (str_eq_lit(suffix, "h") || str_eq_lit(suffix, "hr") || str_eq_lit(suffix, "hour") ||
               str_eq_lit(suffix, "hours")) {
        mult = 3600;
    } else if (str_eq_lit(suffix, "d") || str_eq_lit(suffix, "day") || str_eq_lit(suffix, "days")) {
        mult = 86400;
    } else {
        return 0;
    }
    *out_seconds = num * mult;
    return 1;
}
