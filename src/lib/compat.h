#ifndef COMPAT_H
#define COMPAT_H

/* IntelliSense/MSC compatibility: silence GNU attributes + asm errors */
#if !defined(__GNUC__) && !defined(__clang__)
#  define __attribute__(x)
#endif
#if defined(__INTELLISENSE__) && !defined(__x86_64__)
#  define __x86_64__ 1
#endif
#if defined(__INTELLISENSE__)
/* Force non-asm fallbacks for IntelliSense parsing. */
#  undef __GNUC__
#  undef __clang__
#endif

/* IntelliSense: provide atomic order constants to avoid parse errors. */
#if !defined(__GNUC__) && !defined(__clang__)
#  ifndef __ATOMIC_SEQ_CST
#    define __ATOMIC_SEQ_CST 5
#  endif
#endif

#endif /* COMPAT_H */
