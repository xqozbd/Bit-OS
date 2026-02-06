#ifndef PCNET_H
#define PCNET_H

#include <stdint.h>

void pcnet_init(void);
void pcnet_log_status(void);
void pcnet_tick(void);
void pcnet_ping(const uint8_t ip[4]);
int pcnet_is_found(void);
int pcnet_is_ready(void);
int pcnet_has_error(void);

#endif /* PCNET_H */
