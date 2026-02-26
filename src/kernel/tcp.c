#include "kernel/tcp.h"

#include <stddef.h>
#include <stdint.h>

#include "drivers/net/pcnet.h"
#include "kernel/heap.h"
#include "lib/log.h"

#define TCP_MAX_CONNS 8
#define TCP_RX_BUF 2048
#define TCP_RETX_TICKS 50
#define TCP_RETX_MAX 5

enum tcp_state {
    TCP_CLOSED = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK
};

struct tcp_conn {
    uint8_t used;
    uint8_t state;
    uint8_t rip[4];
    uint16_t lport;
    uint16_t rport;
    uint32_t snd_iss;
    uint32_t snd_nxt;
    uint32_t snd_una;
    uint32_t rcv_nxt;
    uint32_t retx_deadline;
    uint8_t retx_count;
    uint16_t last_len;
    uint8_t last_flags;
    uint8_t last_payload[512];

    uint8_t rx_buf[TCP_RX_BUF];
    uint16_t rx_head;
    uint16_t rx_tail;
};

static struct tcp_conn g_conns[TCP_MAX_CONNS];
static uint32_t g_ticks = 0;

static int alloc_conn(void) {
    for (int i = 0; i < TCP_MAX_CONNS; ++i) {
        if (!g_conns[i].used) {
            g_conns[i].used = 1;
            g_conns[i].state = TCP_CLOSED;
            g_conns[i].lport = 0;
            g_conns[i].rport = 0;
            g_conns[i].snd_iss = 0;
            g_conns[i].snd_nxt = 0;
            g_conns[i].snd_una = 0;
            g_conns[i].rcv_nxt = 0;
            g_conns[i].retx_deadline = 0;
            g_conns[i].retx_count = 0;
            g_conns[i].last_len = 0;
            g_conns[i].last_flags = 0;
            g_conns[i].rx_head = 0;
            g_conns[i].rx_tail = 0;
            return i;
        }
    }
    return -1;
}

static void free_conn(int id) {
    if (id < 0 || id >= TCP_MAX_CONNS) return;
    g_conns[id].used = 0;
    g_conns[id].state = TCP_CLOSED;
    g_conns[id].lport = 0;
    g_conns[id].rport = 0;
    g_conns[id].retx_deadline = 0;
    g_conns[id].retx_count = 0;
    g_conns[id].last_len = 0;
    g_conns[id].last_flags = 0;
    g_conns[id].rx_head = 0;
    g_conns[id].rx_tail = 0;
}

static void tcp_send_segment(struct tcp_conn *c, uint8_t flags,
                             const uint8_t *data, uint16_t len) {
    if (!c) return;
    pcnet_tcp_send(c->rip, c->lport, c->rport,
                   c->snd_nxt, c->rcv_nxt, flags, data, len);
    if (flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_PSH)) {
        if (len > sizeof(c->last_payload)) len = sizeof(c->last_payload);
        for (uint16_t i = 0; i < len; ++i) c->last_payload[i] = data ? data[i] : 0;
        c->last_len = len;
        c->last_flags = flags;
        c->retx_deadline = g_ticks + TCP_RETX_TICKS;
        c->retx_count = 0;
    }
    if (flags & TCP_FLAG_SYN) c->snd_nxt += 1;
    if (flags & TCP_FLAG_FIN) c->snd_nxt += 1;
    if (flags & TCP_FLAG_PSH) c->snd_nxt += len;
}

static struct tcp_conn *find_conn(const uint8_t src_ip[4], uint16_t src_port,
                                  uint16_t dst_port) {
    for (int i = 0; i < TCP_MAX_CONNS; ++i) {
        struct tcp_conn *c = &g_conns[i];
        if (!c->used) continue;
        if (c->state == TCP_LISTEN) {
            if (c->lport == dst_port) return c;
            continue;
        }
        if (c->lport != dst_port) continue;
        if (c->rport != src_port) continue;
        if (c->rip[0] != src_ip[0] || c->rip[1] != src_ip[1] ||
            c->rip[2] != src_ip[2] || c->rip[3] != src_ip[3]) continue;
        return c;
    }
    return NULL;
}

int tcp_init(void) {
    for (int i = 0; i < TCP_MAX_CONNS; ++i) {
        g_conns[i].used = 0;
    }
    g_ticks = 0;
    return 0;
}

int tcp_listen(uint16_t port) {
    if (port == 0) return -1;
    int id = alloc_conn();
    if (id < 0) return -1;
    g_conns[id].state = TCP_LISTEN;
    g_conns[id].lport = port;
    return id;
}

int tcp_accept(int listener_id) {
    if (listener_id < 0 || listener_id >= TCP_MAX_CONNS) return -1;
    struct tcp_conn *l = &g_conns[listener_id];
    if (!l->used || l->state != TCP_LISTEN) return -1;
    /* Any established child on same port */
    for (int i = 0; i < TCP_MAX_CONNS; ++i) {
        if (i == listener_id) continue;
        struct tcp_conn *c = &g_conns[i];
        if (!c->used) continue;
        if (c->state == TCP_ESTABLISHED && c->lport == l->lport) {
            return i;
        }
    }
    return -1;
}

int tcp_connect(const uint8_t ip[4], uint16_t port) {
    if (!ip || port == 0) return -1;
    int id = alloc_conn();
    if (id < 0) return -1;
    struct tcp_conn *c = &g_conns[id];
    c->lport = 40000 + (uint16_t)id;
    c->rport = port;
    for (int i = 0; i < 4; ++i) c->rip[i] = ip[i];
    c->snd_iss = (uint32_t)(0x1000u + (uint32_t)id * 0x100u);
    c->snd_nxt = c->snd_iss;
    c->snd_una = c->snd_iss;
    c->rcv_nxt = 0;
    c->state = TCP_SYN_SENT;
    tcp_send_segment(c, TCP_FLAG_SYN, NULL, 0);
    return id;
}

int tcp_send(int conn_id, const uint8_t *data, uint16_t len) {
    if (conn_id < 0 || conn_id >= TCP_MAX_CONNS) return -1;
    struct tcp_conn *c = &g_conns[conn_id];
    if (!c->used || c->state != TCP_ESTABLISHED) return -1;
    if (len == 0) return 0;
    tcp_send_segment(c, (uint8_t)(TCP_FLAG_ACK | TCP_FLAG_PSH), data, len);
    return (int)len;
}

int tcp_recv(int conn_id, uint8_t *buf, uint16_t len) {
    if (conn_id < 0 || conn_id >= TCP_MAX_CONNS) return -1;
    struct tcp_conn *c = &g_conns[conn_id];
    if (!c->used || !buf || len == 0) return -1;
    if (c->rx_head == c->rx_tail) return 0;
    uint16_t out = 0;
    while (out < len && c->rx_tail != c->rx_head) {
        buf[out++] = c->rx_buf[c->rx_tail];
        c->rx_tail = (uint16_t)((c->rx_tail + 1) % TCP_RX_BUF);
    }
    return (int)out;
}

int tcp_rx_available(int conn_id) {
    if (conn_id < 0 || conn_id >= TCP_MAX_CONNS) return 0;
    struct tcp_conn *c = &g_conns[conn_id];
    if (!c->used) return 0;
    return c->rx_head != c->rx_tail;
}

void tcp_close(int conn_id) {
    if (conn_id < 0 || conn_id >= TCP_MAX_CONNS) return;
    struct tcp_conn *c = &g_conns[conn_id];
    if (!c->used) return;
    if (c->state == TCP_ESTABLISHED) {
        c->state = TCP_FIN_WAIT1;
        tcp_send_segment(c, (uint8_t)(TCP_FLAG_FIN | TCP_FLAG_ACK), NULL, 0);
        return;
    }
    free_conn(conn_id);
}

void tcp_on_rx(const uint8_t src_ip[4], const uint8_t dst_ip[4],
               uint16_t src_port, uint16_t dst_port,
               uint32_t seq, uint32_t ack, uint8_t flags,
               const uint8_t *payload, uint16_t payload_len) {
    (void)dst_ip;
    struct tcp_conn *c = find_conn(src_ip, src_port, dst_port);
    if (!c) return;

    if (c->state == TCP_LISTEN) {
        if (flags & TCP_FLAG_SYN) {
            int id = alloc_conn();
            if (id < 0) return;
            struct tcp_conn *n = &g_conns[id];
            n->lport = dst_port;
            n->rport = src_port;
            for (int i = 0; i < 4; ++i) n->rip[i] = src_ip[i];
            n->snd_iss = (uint32_t)(0x2000u + (uint32_t)id * 0x100u);
            n->snd_nxt = n->snd_iss;
            n->snd_una = n->snd_iss;
            n->rcv_nxt = seq + 1;
            n->state = TCP_SYN_RECV;
            tcp_send_segment(n, (uint8_t)(TCP_FLAG_SYN | TCP_FLAG_ACK), NULL, 0);
        }
        return;
    }

    if (flags & TCP_FLAG_ACK) {
        if (ack > c->snd_una) {
            c->snd_una = ack;
            c->retx_deadline = 0;
            c->last_len = 0;
        }
    }

    if (c->state == TCP_SYN_SENT) {
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) &&
            ack == c->snd_nxt) {
            c->rcv_nxt = seq + 1;
            c->state = TCP_ESTABLISHED;
            tcp_send_segment(c, TCP_FLAG_ACK, NULL, 0);
        }
        return;
    }

    if (c->state == TCP_SYN_RECV) {
        if ((flags & TCP_FLAG_ACK) && ack == c->snd_nxt) {
            c->state = TCP_ESTABLISHED;
        }
        return;
    }

    if (c->state == TCP_FIN_WAIT1 && (flags & TCP_FLAG_ACK) && ack == c->snd_nxt) {
        c->state = TCP_FIN_WAIT2;
    }

    if (flags & TCP_FLAG_FIN) {
        c->rcv_nxt = seq + 1;
        tcp_send_segment(c, TCP_FLAG_ACK, NULL, 0);
        if (c->state == TCP_ESTABLISHED) {
            c->state = TCP_CLOSE_WAIT;
        } else if (c->state == TCP_FIN_WAIT2) {
            free_conn((int)(c - g_conns));
        }
    }

    if (payload_len > 0 && (flags & TCP_FLAG_PSH)) {
        if (seq == c->rcv_nxt) {
            uint16_t copy = payload_len;
            if (copy > TCP_RX_BUF) copy = TCP_RX_BUF;
            for (uint16_t i = 0; i < copy; ++i) {
                c->rx_buf[c->rx_head] = payload[i];
                c->rx_head = (uint16_t)((c->rx_head + 1) % TCP_RX_BUF);
                if (c->rx_head == c->rx_tail) {
                    c->rx_tail = (uint16_t)((c->rx_tail + 1) % TCP_RX_BUF);
                }
            }
            c->rcv_nxt += copy;
            tcp_send_segment(c, TCP_FLAG_ACK, NULL, 0);
        }
    }
}

void tcp_tick(void) {
    g_ticks++;
    for (int i = 0; i < TCP_MAX_CONNS; ++i) {
        struct tcp_conn *c = &g_conns[i];
        if (!c->used) continue;
        if (c->retx_deadline && g_ticks >= c->retx_deadline) {
            if (c->retx_count >= TCP_RETX_MAX) {
                log_printf("tcp: retransmit limit reached, closing conn %d\n", i);
                free_conn(i);
                continue;
            }
            c->retx_count++;
            tcp_send_segment(c, c->last_flags, c->last_payload, c->last_len);
        }
    }
}
