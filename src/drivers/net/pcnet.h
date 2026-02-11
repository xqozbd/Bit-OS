#ifndef PCNET_H
#define PCNET_H

#include <stdint.h>

void pcnet_init(void);
void pcnet_log_status(void);
void pcnet_tick(void);
void pcnet_ping(const uint8_t ip[4]);
void pcnet_ping6(const uint8_t ip[16]);
int pcnet_ipv6_route_add(const uint8_t prefix[16], uint8_t prefix_len, const uint8_t next_hop[16]);
void pcnet_ipv6_route_list(void);
void pcnet_ipv6_set_forwarding(int enabled);
int pcnet_ipv6_get_forwarding(void);
int pcnet_udp_send(const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port,
                   const uint8_t *data, uint16_t len);
int pcnet_udp6_send(const uint8_t dst_ip[16], uint16_t src_port, uint16_t dst_port,
                    const uint8_t *data, uint16_t len);
int pcnet_udp_send_broadcast(uint16_t src_port, uint16_t dst_port,
                             const uint8_t *data, uint16_t len);
int pcnet_tcp_send(const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port,
                   uint32_t seq, uint32_t ack, uint8_t flags,
                   const uint8_t *data, uint16_t len);
int pcnet_is_found(void);
int pcnet_is_ready(void);
int pcnet_has_error(void);
void pcnet_set_ip(const uint8_t ip[4]);
void pcnet_set_gw(const uint8_t gw[4]);
void pcnet_set_mask(const uint8_t mask[4]);
void pcnet_get_ip(uint8_t out[4]);
void pcnet_get_gw(uint8_t out[4]);
void pcnet_get_mask(uint8_t out[4]);
void pcnet_get_mac(uint8_t out[6]);
void pcnet_get_ipv6(uint8_t out[16]);

#endif /* PCNET_H */
