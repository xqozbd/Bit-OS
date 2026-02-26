#ifndef MEMWATCH_H
#define MEMWATCH_H

#include <stdint.h>

int memwatch_start(void);
int memwatch_stop(void);
int memwatch_is_running(void);

#endif /* MEMWATCH_H */
