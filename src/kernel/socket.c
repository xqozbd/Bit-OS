#include "kernel/socket.h"

#include <stddef.h>
#include <stdint.h>

#include "drivers/net/pcnet.h"
#include "kernel/heap.h"
#include "kernel/tcp.h"
#include "lib/log.h"

#define SOCKET_MAX 16
#define UDP_RX_Q 4
#define UDP_MAX_PAYLOAD 1472u

struct udp_pkt {
    uint8_t data[UDP_MAX_PAYLOAD];
    uint16_t len;
    uint8_t src_ip[4];
    uint16_t src_port;
    uint8_t used;
};

struct ksocket {
    uint8_t used;
    uint8_t type;
    uint16_t lport;
    uint8_t rip[4];
    uint16_t rport;
    uint8_t connected;
    int tcp_id;
    uint8_t rx_head;
    uint8_t rx_tail;
    struct udp_pkt rx[UDP_RX_Q];
};

static struct ksocket g_sockets[SOCKET_MAX];

int socket_init(void) {
    for (int i = 0; i < SOCKET_MAX; ++i) {
        g_sockets[i].used = 0;
        g_sockets[i].type = 0;
        g_sockets[i].lport = 0;
        g_sockets[i].rport = 0;
        g_sockets[i].connected = 0;
        g_sockets[i].tcp_id = -1;
        g_sockets[i].rx_head = 0;
        g_sockets[i].rx_tail = 0;
        for (int j = 0; j < UDP_RX_Q; ++j) {
            g_sockets[i].rx[j].used = 0;
            g_sockets[i].rx[j].len = 0;
            g_sockets[i].rx[j].src_port = 0;
        }
    }
    tcp_init();
    return 0;
}

int socket_create(int domain, int type) {
    if (domain != SOCKET_AF_INET) return -1;
    if (type != SOCKET_SOCK_DGRAM && type != SOCKET_SOCK_STREAM) return -1;
    for (int i = 0; i < SOCKET_MAX; ++i) {
        if (!g_sockets[i].used) {
            g_sockets[i].used = 1;
            g_sockets[i].type = (uint8_t)type;
            g_sockets[i].lport = 0;
            g_sockets[i].rport = 0;
            g_sockets[i].connected = 0;
            g_sockets[i].tcp_id = -1;
            g_sockets[i].rx_head = 0;
            g_sockets[i].rx_tail = 0;
            for (int j = 0; j < UDP_RX_Q; ++j) {
                g_sockets[i].rx[j].used = 0;
                g_sockets[i].rx[j].len = 0;
                g_sockets[i].rx[j].src_port = 0;
            }
            return i;
        }
    }
    return -1;
}

int socket_bind(int sid, uint16_t port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (s->type == SOCKET_SOCK_STREAM) {
        s->lport = port;
        return 0;
    }
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    s->lport = port;
    return 0;
}

int socket_connect(int sid, const uint8_t ip[4], uint16_t port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (s->type == SOCKET_SOCK_STREAM) {
        int tid = tcp_connect(ip, port);
        if (tid < 0) return -1;
        s->tcp_id = tid;
        return 0;
    }
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    if (!ip || port == 0) return -1;
    for (int i = 0; i < 4; ++i) s->rip[i] = ip[i];
    s->rport = port;
    s->connected = 1;
    return 0;
}

int socket_listen(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used || s->type != SOCKET_SOCK_STREAM) return -1;
    if (s->lport == 0) return -1;
    int tid = tcp_listen(s->lport);
    if (tid < 0) return -1;
    s->tcp_id = tid;
    return 0;
}

int socket_accept(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used || s->type != SOCKET_SOCK_STREAM) return -1;
    if (s->tcp_id < 0) return -1;
    int tid = tcp_accept(s->tcp_id);
    if (tid < 0) return -1;
    int new_sid = socket_create(SOCKET_AF_INET, SOCKET_SOCK_STREAM);
    if (new_sid < 0) return -1;
    g_sockets[new_sid].tcp_id = tid;
    return new_sid;
}

int socket_sendto(int sid, const uint8_t *data, uint16_t len,
                  const uint8_t ip[4], uint16_t port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (s->type == SOCKET_SOCK_STREAM) {
        if (s->tcp_id < 0) return -1;
        return tcp_send(s->tcp_id, data, len);
    }
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    if (!data || len == 0) return -1;
    const uint8_t *dst_ip = ip;
    uint16_t dst_port = port;
    if ((!dst_ip || dst_port == 0) && s->connected) {
        dst_ip = s->rip;
        dst_port = s->rport;
    }
    if (!dst_ip || dst_port == 0) return -1;
    uint16_t src_port = s->lport ? s->lport : 49152;
    int rc = pcnet_udp_send(dst_ip, src_port, dst_port, data, len);
    return rc == 0 ? (int)len : -1;
}

int socket_recvfrom(int sid, uint8_t *buf, uint16_t len,
                    uint8_t *out_ip, uint16_t *out_port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (s->type == SOCKET_SOCK_STREAM) {
        if (s->tcp_id < 0) return -1;
        return tcp_recv(s->tcp_id, buf, len);
    }
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    if (!buf || len == 0) return -1;
    struct udp_pkt *pkt = &s->rx[s->rx_tail];
    if (!pkt->used) return 0;
    uint16_t to_copy = pkt->len < len ? pkt->len : len;
    for (uint16_t i = 0; i < to_copy; ++i) buf[i] = pkt->data[i];
    if (out_ip) {
        for (int i = 0; i < 4; ++i) out_ip[i] = pkt->src_ip[i];
    }
    if (out_port) *out_port = pkt->src_port;
    pkt->used = 0;
    pkt->len = 0;
    s->rx_tail = (uint8_t)((s->rx_tail + 1) % UDP_RX_Q);
    return (int)to_copy;
}

void socket_close(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return;
    if (s->type == SOCKET_SOCK_STREAM) {
        if (s->tcp_id >= 0) tcp_close(s->tcp_id);
    }
    s->used = 0;
    s->type = 0;
    s->lport = 0;
    s->rport = 0;
    s->connected = 0;
    s->tcp_id = -1;
    s->rx_head = 0;
    s->rx_tail = 0;
    for (int j = 0; j < UDP_RX_Q; ++j) {
        s->rx[j].used = 0;
        s->rx[j].len = 0;
        s->rx[j].src_port = 0;
    }
}

void socket_net_rx(const uint8_t src_ip[4], uint16_t src_port,
                   uint16_t dst_port, const uint8_t *data, uint16_t len) {
    if (!src_ip || !data || len == 0) return;
    for (int i = 0; i < SOCKET_MAX; ++i) {
        struct ksocket *s = &g_sockets[i];
        if (!s->used || s->type != SOCKET_SOCK_DGRAM) continue;
        if (s->lport != 0 && s->lport != dst_port) continue;
        if (s->connected) {
            if (s->rport != src_port) continue;
            if (s->rip[0] != src_ip[0] || s->rip[1] != src_ip[1] ||
                s->rip[2] != src_ip[2] || s->rip[3] != src_ip[3]) {
                continue;
            }
        }
        struct udp_pkt *pkt = &s->rx[s->rx_head];
        if (pkt->used) {
            return;
        }
        uint16_t copy_len = len < UDP_MAX_PAYLOAD ? len : UDP_MAX_PAYLOAD;
        for (uint16_t j = 0; j < copy_len; ++j) pkt->data[j] = data[j];
        pkt->len = copy_len;
        for (int j = 0; j < 4; ++j) pkt->src_ip[j] = src_ip[j];
        pkt->src_port = src_port;
        pkt->used = 1;
        s->rx_head = (uint8_t)((s->rx_head + 1) % UDP_RX_Q);
        return;
    }
}
