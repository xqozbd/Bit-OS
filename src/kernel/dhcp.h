#ifndef KERNEL_DHCP_H
#define KERNEL_DHCP_H

#include <stdint.h>

int dhcp_request(void);
int dhcp_get_dns(uint8_t out[4]);

#endif /* KERNEL_DHCP_H */
