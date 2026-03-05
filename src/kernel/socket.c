#include "kernel/socket.h"

#include <stddef.h>
#include <stdint.h>

#include "drivers/net/pcnet.h"
#include "kernel/heap.h"
#include "kernel/netns.h"
#include "kernel/tcp.h"
#include "kernel/spinlock.h"
#include "kernel/waitq.h"
#include "lib/strutil.h"
#include "lib/log.h"

#define SOCKET_MAX 16
#define UDP_RX_Q 4
#define UDP_MAX_PAYLOAD 1472u
#define UNIX_PATH_MAX 108
#define UNIX_BUF_SIZE 2048
#define UNIX_ACCEPT_Q 8

struct unix_buf {
    uint8_t data[UNIX_BUF_SIZE];
    uint32_t rpos;
    uint32_t wpos;
    uint32_t count;
};

struct udp_pkt {
    uint8_t data[UDP_MAX_PAYLOAD];
    uint16_t len;
    uint8_t src_ip[4];
    uint8_t src_ip6[16];
    uint16_t src_port;
    uint8_t is_ipv6;
    uint8_t used;
};

struct ksocket {
    uint8_t used;
    uint8_t type;
    uint8_t domain;
    uint16_t lport;
    struct net_namespace *net_ns;
    uint8_t rip[4];
    uint8_t rip6[16];
    uint16_t rport;
    uint8_t connected;
    int tcp_id;
    uint8_t rx_head;
    uint8_t rx_tail;
    struct udp_pkt rx[UDP_RX_Q];
    uint8_t unix_bound;
    uint8_t unix_listen;
    int unix_peer;
    uint8_t unix_pending_head;
    uint8_t unix_pending_tail;
    int unix_pending[UNIX_ACCEPT_Q];
    char unix_path[UNIX_PATH_MAX];
    struct unix_buf unix_rx;
    spinlock_t unix_lock;
    struct waitq unix_rx_wait;
    struct waitq unix_conn_wait;
};

static struct ksocket g_sockets[SOCKET_MAX];

static struct net_namespace *socket_current_netns(void) {
    struct net_namespace *ns = netns_current();
    return ns ? ns : netns_root();
}

static int socket_netns_ok(const struct ksocket *s) {
    if (!s) return 0;
    return s->net_ns == socket_current_netns();
}

static void unix_reset(struct ksocket *s) {
    if (!s) return;
    s->unix_bound = 0;
    s->unix_listen = 0;
    s->unix_peer = -1;
    s->unix_pending_head = 0;
    s->unix_pending_tail = 0;
    for (int i = 0; i < UNIX_ACCEPT_Q; ++i) {
        s->unix_pending[i] = -1;
    }
    s->unix_path[0] = '\0';
    s->unix_rx.rpos = 0;
    s->unix_rx.wpos = 0;
    s->unix_rx.count = 0;
    spinlock_init(&s->unix_lock);
    waitq_init(&s->unix_rx_wait);
    waitq_init(&s->unix_conn_wait);
}

int socket_init(void) {
    for (int i = 0; i < SOCKET_MAX; ++i) {
        g_sockets[i].used = 0;
        g_sockets[i].type = 0;
        g_sockets[i].domain = 0;
        g_sockets[i].lport = 0;
        g_sockets[i].rport = 0;
        g_sockets[i].connected = 0;
        g_sockets[i].tcp_id = -1;
        g_sockets[i].rx_head = 0;
        g_sockets[i].rx_tail = 0;
        g_sockets[i].net_ns = NULL;
        for (int j = 0; j < UDP_RX_Q; ++j) {
            g_sockets[i].rx[j].used = 0;
            g_sockets[i].rx[j].len = 0;
            g_sockets[i].rx[j].src_port = 0;
            g_sockets[i].rx[j].is_ipv6 = 0;
        }
        unix_reset(&g_sockets[i]);
    }
    tcp_init();
    return 0;
}

int socket_create(int domain, int type) {
    if (domain != SOCKET_AF_INET && domain != SOCKET_AF_INET6 && domain != SOCKET_AF_UNIX) return -1;
    if (type != SOCKET_SOCK_DGRAM && type != SOCKET_SOCK_STREAM) return -1;
    for (int i = 0; i < SOCKET_MAX; ++i) {
        if (!g_sockets[i].used) {
            g_sockets[i].used = 1;
            g_sockets[i].type = (uint8_t)type;
            g_sockets[i].domain = (uint8_t)domain;
            g_sockets[i].lport = 0;
            g_sockets[i].rport = 0;
            g_sockets[i].connected = 0;
            g_sockets[i].tcp_id = -1;
            g_sockets[i].rx_head = 0;
            g_sockets[i].rx_tail = 0;
            g_sockets[i].net_ns = socket_current_netns();
            if (g_sockets[i].net_ns) netns_ref(g_sockets[i].net_ns);
            for (int j = 0; j < UDP_RX_Q; ++j) {
                g_sockets[i].rx[j].used = 0;
                g_sockets[i].rx[j].len = 0;
                g_sockets[i].rx[j].src_port = 0;
                g_sockets[i].rx[j].is_ipv6 = 0;
            }
            unix_reset(&g_sockets[i]);
            return i;
        }
    }
    return -1;
}

static int unix_find_listener(const char *path) {
    if (!path || !path[0]) return -1;
    for (int i = 0; i < SOCKET_MAX; ++i) {
        struct ksocket *s = &g_sockets[i];
        if (!s->used) continue;
        if (s->domain != SOCKET_AF_UNIX) continue;
        if (!s->unix_bound || !s->unix_listen) continue;
        if (str_eq(s->unix_path, path)) return i;
    }
    return -1;
}

static int unix_queue_push(struct ksocket *s, int sid) {
    if (!s) return -1;
    uint8_t next = (uint8_t)((s->unix_pending_tail + 1u) % UNIX_ACCEPT_Q);
    if (next == s->unix_pending_head) return -1;
    s->unix_pending[s->unix_pending_tail] = sid;
    s->unix_pending_tail = next;
    return 0;
}

static int unix_queue_pop(struct ksocket *s) {
    if (!s) return -1;
    if (s->unix_pending_head == s->unix_pending_tail) return -1;
    int sid = s->unix_pending[s->unix_pending_head];
    s->unix_pending[s->unix_pending_head] = -1;
    s->unix_pending_head = (uint8_t)((s->unix_pending_head + 1u) % UNIX_ACCEPT_Q);
    return sid;
}

int socket_bind(int sid, uint16_t port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (!socket_netns_ok(s)) return -1;
    if (s->domain == SOCKET_AF_UNIX) return -1;
    if (s->type == SOCKET_SOCK_STREAM) {
        s->lport = port;
        return 0;
    }
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    s->lport = port;
    return 0;
}

int socket_bind_path(int sid, const char *path, uint32_t len) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    if (!path || len == 0) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (s->domain != SOCKET_AF_UNIX) return -1;
    if (len >= UNIX_PATH_MAX) return -1;
    char buf[UNIX_PATH_MAX];
    for (uint32_t i = 0; i < len && i < UNIX_PATH_MAX - 1; ++i) {
        buf[i] = path[i];
        if (path[i] == '\0') {
            len = i;
            break;
        }
    }
    buf[len] = '\0';
    if (unix_find_listener(buf) >= 0) return -1;
    for (uint32_t i = 0; i <= len; ++i) {
        s->unix_path[i] = buf[i];
    }
    s->unix_bound = 1;
    return 0;
}

int socket_connect(int sid, const uint8_t ip[4], uint16_t port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (!socket_netns_ok(s)) return -1;
    if (s->domain != SOCKET_AF_INET) return -1;
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

int socket_connect6(int sid, const uint8_t ip[16], uint16_t port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (!socket_netns_ok(s)) return -1;
    if (s->domain != SOCKET_AF_INET6) return -1;
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    if (!ip || port == 0) return -1;
    for (int i = 0; i < 16; ++i) s->rip6[i] = ip[i];
    s->rport = port;
    s->connected = 1;
    return 0;
}

int socket_connect_path(int sid, const char *path, uint32_t len) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    if (!path || len == 0) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (s->domain != SOCKET_AF_UNIX) return -1;
    if (s->type != SOCKET_SOCK_STREAM) return -1;
    if (len >= UNIX_PATH_MAX) return -1;
    char buf[UNIX_PATH_MAX];
    for (uint32_t i = 0; i < len && i < UNIX_PATH_MAX - 1; ++i) {
        buf[i] = path[i];
        if (path[i] == '\0') {
            len = i;
            break;
        }
    }
    buf[len] = '\0';
    int listener = unix_find_listener(buf);
    if (listener < 0) return -1;
    int srv = socket_create(SOCKET_AF_UNIX, SOCKET_SOCK_STREAM);
    if (srv < 0) return -1;
    g_sockets[srv].unix_peer = sid;
    g_sockets[srv].connected = 1;
    s->unix_peer = srv;
    s->connected = 1;
    struct ksocket *ls = &g_sockets[listener];
    spinlock_lock(&ls->unix_lock);
    if (unix_queue_push(ls, srv) != 0) {
        spinlock_unlock(&ls->unix_lock);
        socket_close(srv);
        s->unix_peer = -1;
        s->connected = 0;
        return -1;
    }
    spinlock_unlock(&ls->unix_lock);
    return 0;
}

int socket_listen(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used || s->type != SOCKET_SOCK_STREAM) return -1;
    if (!socket_netns_ok(s)) return -1;
    if (s->domain == SOCKET_AF_UNIX) {
        if (!s->unix_bound) return -1;
        s->unix_listen = 1;
        return 0;
    }
    if (s->domain != SOCKET_AF_INET) return -1;
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
    if (!socket_netns_ok(s)) return -1;
    if (s->domain == SOCKET_AF_UNIX) {
        spinlock_lock(&s->unix_lock);
        int newsid = unix_queue_pop(s);
        spinlock_unlock(&s->unix_lock);
        return newsid;
    }
    if (s->domain != SOCKET_AF_INET) return -1;
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
    if (!socket_netns_ok(s)) return -1;
    if (s->domain == SOCKET_AF_UNIX) {
        if (!data || len == 0) return -1;
        if (s->unix_peer < 0) return -1;
        struct ksocket *peer = &g_sockets[s->unix_peer];
        spinlock_lock(&peer->unix_lock);
        uint32_t space = UNIX_BUF_SIZE - peer->unix_rx.count;
        if (space == 0) {
            spinlock_unlock(&peer->unix_lock);
            return 0;
        }
        uint32_t to_copy = len < space ? len : space;
        for (uint32_t i = 0; i < to_copy; ++i) {
            peer->unix_rx.data[peer->unix_rx.wpos] = data[i];
            peer->unix_rx.wpos = (peer->unix_rx.wpos + 1u) % UNIX_BUF_SIZE;
        }
        peer->unix_rx.count += to_copy;
        spinlock_unlock(&peer->unix_lock);
        return (int)to_copy;
    }
    if (s->domain != SOCKET_AF_INET) return -1;
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

int socket_sendto6(int sid, const uint8_t *data, uint16_t len,
                   const uint8_t ip[16], uint16_t port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (!socket_netns_ok(s)) return -1;
    if (s->domain != SOCKET_AF_INET6) return -1;
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    if (!data || len == 0) return -1;
    const uint8_t *dst_ip = ip;
    uint16_t dst_port = port;
    if ((!dst_ip || dst_port == 0) && s->connected) {
        dst_ip = s->rip6;
        dst_port = s->rport;
    }
    if (!dst_ip || dst_port == 0) return -1;
    uint16_t src_port = s->lport ? s->lport : 49152;
    int rc = pcnet_udp6_send(dst_ip, src_port, dst_port, data, len);
    return rc == 0 ? (int)len : -1;
}

int socket_recvfrom(int sid, uint8_t *buf, uint16_t len,
                    uint8_t *out_ip, uint16_t *out_port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (!socket_netns_ok(s)) return -1;
    if (s->domain == SOCKET_AF_UNIX) {
        if (!buf || len == 0) return -1;
        spinlock_lock(&s->unix_lock);
        if (s->unix_rx.count == 0) {
            spinlock_unlock(&s->unix_lock);
            return 0;
        }
        uint32_t to_copy = s->unix_rx.count < len ? s->unix_rx.count : len;
        for (uint32_t i = 0; i < to_copy; ++i) {
            buf[i] = s->unix_rx.data[s->unix_rx.rpos];
            s->unix_rx.rpos = (s->unix_rx.rpos + 1u) % UNIX_BUF_SIZE;
        }
        s->unix_rx.count -= to_copy;
        spinlock_unlock(&s->unix_lock);
        if (out_ip) out_ip[0] = 0;
        if (out_port) *out_port = 0;
        return (int)to_copy;
    }
    if (s->domain != SOCKET_AF_INET) return -1;
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

int socket_recvfrom6(int sid, uint8_t *buf, uint16_t len,
                     uint8_t *out_ip, uint16_t *out_port) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    if (!socket_netns_ok(s)) return -1;
    if (s->domain != SOCKET_AF_INET6) return -1;
    if (s->type != SOCKET_SOCK_DGRAM) return -1;
    if (!buf || len == 0) return -1;
    struct udp_pkt *pkt = &s->rx[s->rx_tail];
    if (!pkt->used) return 0;
    if (!pkt->is_ipv6) return 0;
    uint16_t to_copy = pkt->len < len ? pkt->len : len;
    for (uint16_t i = 0; i < to_copy; ++i) buf[i] = pkt->data[i];
    if (out_ip) {
        for (int i = 0; i < 16; ++i) out_ip[i] = pkt->src_ip6[i];
    }
    if (out_port) *out_port = pkt->src_port;
    pkt->used = 0;
    pkt->len = 0;
    pkt->is_ipv6 = 0;
    s->rx_tail = (uint8_t)((s->rx_tail + 1) % UDP_RX_Q);
    return (int)to_copy;
}

int socket_can_recv(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return 0;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return 0;
    if (!socket_netns_ok(s)) return 0;
    if (s->domain == SOCKET_AF_UNIX) {
        return s->unix_rx.count > 0 ? 1 : 0;
    }
    if (s->type == SOCKET_SOCK_STREAM) {
        if (s->tcp_id < 0) return 0;
        return tcp_rx_available(s->tcp_id);
    }
    if (s->type != SOCKET_SOCK_DGRAM) return 0;
    return s->rx[s->rx_tail].used ? 1 : 0;
}

int socket_can_send(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return 0;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return 0;
    if (!socket_netns_ok(s)) return 0;
    if (s->domain == SOCKET_AF_UNIX) return s->unix_peer >= 0;
    if (s->type == SOCKET_SOCK_STREAM) return s->tcp_id >= 0;
    if (s->type != SOCKET_SOCK_DGRAM) return 0;
    return 1;
}

int socket_domain(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return -1;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return -1;
    return s->domain;
}

void socket_close(int sid) {
    if (sid < 0 || sid >= SOCKET_MAX) return;
    struct ksocket *s = &g_sockets[sid];
    if (!s->used) return;
    if (s->domain == SOCKET_AF_UNIX) {
        if (s->unix_peer >= 0 && s->unix_peer < SOCKET_MAX) {
            struct ksocket *peer = &g_sockets[s->unix_peer];
            if (peer->used && peer->domain == SOCKET_AF_UNIX) {
                peer->unix_peer = -1;
            }
        }
    }
    if (s->type == SOCKET_SOCK_STREAM && s->domain == SOCKET_AF_INET) {
        if (s->tcp_id >= 0) tcp_close(s->tcp_id);
    }
    if (s->net_ns) {
        netns_unref(s->net_ns);
        s->net_ns = NULL;
    }
    s->used = 0;
    s->type = 0;
    s->domain = 0;
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
        s->rx[j].is_ipv6 = 0;
    }
    unix_reset(s);
}

void socket_net_rx(const uint8_t src_ip[4], uint16_t src_port,
                   uint16_t dst_port, const uint8_t *data, uint16_t len) {
    if (!src_ip || !data || len == 0) return;
    struct net_namespace *rx_ns = netns_root();
    for (int i = 0; i < SOCKET_MAX; ++i) {
        struct ksocket *s = &g_sockets[i];
        if (!s->used || s->type != SOCKET_SOCK_DGRAM) continue;
        if (s->domain != SOCKET_AF_INET) continue;
        if (s->net_ns != rx_ns) continue;
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
        pkt->is_ipv6 = 0;
        pkt->used = 1;
        s->rx_head = (uint8_t)((s->rx_head + 1) % UDP_RX_Q);
        return;
    }
}

void socket_net6_rx(const uint8_t src_ip[16], uint16_t src_port,
                    uint16_t dst_port, const uint8_t *data, uint16_t len) {
    if (!src_ip || !data || len == 0) return;
    struct net_namespace *rx_ns = netns_root();
    for (int i = 0; i < SOCKET_MAX; ++i) {
        struct ksocket *s = &g_sockets[i];
        if (!s->used || s->type != SOCKET_SOCK_DGRAM) continue;
        if (s->domain != SOCKET_AF_INET6) continue;
        if (s->net_ns != rx_ns) continue;
        if (s->lport != 0 && s->lport != dst_port) continue;
        if (s->connected) {
            if (s->rport != src_port) continue;
            for (int j = 0; j < 16; ++j) {
                if (s->rip6[j] != src_ip[j]) goto next_socket;
            }
        }
        {
            struct udp_pkt *pkt = &s->rx[s->rx_head];
            if (pkt->used) {
                return;
            }
            uint16_t copy_len = len < UDP_MAX_PAYLOAD ? len : UDP_MAX_PAYLOAD;
            for (uint16_t j = 0; j < copy_len; ++j) pkt->data[j] = data[j];
            pkt->len = copy_len;
            for (int j = 0; j < 16; ++j) pkt->src_ip6[j] = src_ip[j];
            pkt->src_port = src_port;
            pkt->is_ipv6 = 1;
            pkt->used = 1;
            s->rx_head = (uint8_t)((s->rx_head + 1) % UDP_RX_Q);
            return;
        }
    next_socket:
        continue;
    }
}
