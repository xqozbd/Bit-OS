#ifndef KERNEL_TCP_H
#define KERNEL_TCP_H

#include <stdint.h>

enum tcp_flags {
    TCP_FLAG_FIN = 0x01,
    TCP_FLAG_SYN = 0x02,
    TCP_FLAG_RST = 0x04,
    TCP_FLAG_PSH = 0x08,
    TCP_FLAG_ACK = 0x10
};

int tcp_init(void);
int tcp_listen(uint16_t port);
int tcp_accept(int listener_id);
int tcp_connect(const uint8_t ip[4], uint16_t port);
int tcp_send(int conn_id, const uint8_t *data, uint16_t len);
int tcp_recv(int conn_id, uint8_t *buf, uint16_t len);
int tcp_rx_available(int conn_id);
void tcp_close(int conn_id);

void tcp_on_rx(const uint8_t src_ip[4], const uint8_t dst_ip[4],
               uint16_t src_port, uint16_t dst_port,
               uint32_t seq, uint32_t ack, uint8_t flags,
               const uint8_t *payload, uint16_t payload_len);
void tcp_tick(void);

#endif /* KERNEL_TCP_H */
