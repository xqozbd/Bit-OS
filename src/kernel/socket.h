#ifndef KERNEL_SOCKET_H
#define KERNEL_SOCKET_H

#include <stdint.h>

enum socket_domain {
    SOCKET_AF_INET = 2,
    SOCKET_AF_INET6 = 10
};

enum socket_type {
    SOCKET_SOCK_STREAM = 1,
    SOCKET_SOCK_DGRAM = 2
};

int socket_init(void);
int socket_create(int domain, int type);
int socket_bind(int sid, uint16_t port);
int socket_connect(int sid, const uint8_t ip[4], uint16_t port);
int socket_connect6(int sid, const uint8_t ip[16], uint16_t port);
int socket_listen(int sid);
int socket_accept(int sid);
int socket_sendto(int sid, const uint8_t *data, uint16_t len,
                  const uint8_t ip[4], uint16_t port);
int socket_sendto6(int sid, const uint8_t *data, uint16_t len,
                   const uint8_t ip[16], uint16_t port);
int socket_recvfrom(int sid, uint8_t *buf, uint16_t len,
                    uint8_t *out_ip, uint16_t *out_port);
int socket_recvfrom6(int sid, uint8_t *buf, uint16_t len,
                     uint8_t *out_ip, uint16_t *out_port);
void socket_close(int sid);

void socket_net_rx(const uint8_t src_ip[4], uint16_t src_port,
                   uint16_t dst_port, const uint8_t *data, uint16_t len);
void socket_net6_rx(const uint8_t src_ip[16], uint16_t src_port,
                    uint16_t dst_port, const uint8_t *data, uint16_t len);

#endif /* KERNEL_SOCKET_H */
