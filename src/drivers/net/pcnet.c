#include "drivers/net/pcnet.h"

#include <stdint.h>
#include <stddef.h>
#include "lib/compat.h"

#include "arch/x86_64/io.h"
#include "arch/x86_64/paging.h"
#include "drivers/pci/pci.h"
#include "kernel/pmm.h"
#include "kernel/socket.h"
#include "kernel/tcp.h"
#include "kernel/firewall.h"
#include "kernel/netns.h"
#include "lib/log.h"

void *memset(void *s, int c, size_t n);

#define PCNET_VENDOR_ID 0x1022
#define PCNET_DEVICE_ID 0x2000
#define PCNET_DEVICE_ID_III 0x2001

#define PCNET_PORT_RDP   0x10
#define PCNET_PORT_RAP   0x12
#define PCNET_PORT_RESET 0x14
#define PCNET_PORT_BDP   0x16

#define PCNET_CSR0_STOP  (1u << 2)
#define PCNET_CSR0_INIT  (1u << 0)
#define PCNET_CSR0_STRT  (1u << 1)
#define PCNET_CSR0_IDON  (1u << 8)
#define PCNET_CSR0_IENA  (1u << 6)

#define PCNET_BCR20_SWSTYLE 20
#define PCNET_BCR20_32BIT   0x0002

#define PCNET_RING_ORDER 4
#define PCNET_RING_COUNT (1u << PCNET_RING_ORDER)
#define PCNET_RX_BUF_SIZE 1536u

struct pcnet_desc {
    uint32_t addr;
    uint16_t length;
    uint16_t status;
    uint32_t misc;
    uint32_t reserved;
} __attribute__((packed));

struct pcnet_init_block {
    uint16_t mode;
    uint16_t rlen_tlen;
    uint8_t phys_addr[6];
    uint16_t reserved;
    uint32_t rx_ring;
    uint32_t tx_ring;
} __attribute__((packed));

static int g_pcnet_found = 0;
static int g_pcnet_error = 0;
static uint16_t g_pcnet_io = 0;
static uint8_t g_pcnet_irq = 0;
static uint8_t g_pcnet_mac[6];
static uint8_t g_pcnet_ready = 0;

static struct pcnet_init_block *g_init = NULL;
static struct pcnet_desc *g_rx_ring = NULL;
static struct pcnet_desc *g_tx_ring = NULL;
static uint8_t *g_rx_bufs[PCNET_RING_COUNT];
static uint8_t *g_tx_bufs[PCNET_RING_COUNT];
static uint32_t g_rx_idx = 0;
static uint32_t g_tx_idx = 0;
static uint32_t g_last_arp_tick = 0;

static struct net_namespace *pcnet_tx_ns(void) {
    struct net_namespace *ns = netns_current();
    return ns ? ns : netns_root();
}

static struct net_namespace *pcnet_rx_ns(void) {
    return netns_root();
}

static inline void pcnet_write_rap(uint16_t io_base, uint16_t reg) {
    outw((uint16_t)(io_base + PCNET_PORT_RAP), reg);
}

static inline uint16_t pcnet_read_csr(uint16_t io_base, uint16_t reg) {
    pcnet_write_rap(io_base, reg);
    return inw((uint16_t)(io_base + PCNET_PORT_RDP));
}

static inline void pcnet_write_csr(uint16_t io_base, uint16_t reg, uint16_t val) {
    pcnet_write_rap(io_base, reg);
    outw((uint16_t)(io_base + PCNET_PORT_RDP), val);
}

static inline uint16_t pcnet_read_bcr(uint16_t io_base, uint16_t reg) {
    pcnet_write_rap(io_base, reg);
    return inw((uint16_t)(io_base + PCNET_PORT_BDP));
}

static inline void pcnet_write_bcr(uint16_t io_base, uint16_t reg, uint16_t val) {
    pcnet_write_rap(io_base, reg);
    outw((uint16_t)(io_base + PCNET_PORT_BDP), val);
}

static inline void pcnet_reset(uint16_t io_base) {
    (void)inw((uint16_t)(io_base + PCNET_PORT_RESET));
}

static void pcnet_read_mac(uint16_t io_base, uint8_t mac[6]) {
    for (uint8_t i = 0; i < 6; ++i) {
        mac[i] = inb((uint16_t)(io_base + i));
    }
}

static void pcnet_init_ipv6_from_mac(struct net_namespace *ns) {
    if (!ns) return;
    for (int i = 0; i < 16; ++i) ns->ipv6_addr[i] = 0;
    ns->ipv6_addr[0] = 0xfe;
    ns->ipv6_addr[1] = 0x80;
    ns->ipv6_addr[8] = (uint8_t)(g_pcnet_mac[0] ^ 0x02);
    ns->ipv6_addr[9] = g_pcnet_mac[1];
    ns->ipv6_addr[10] = g_pcnet_mac[2];
    ns->ipv6_addr[11] = 0xff;
    ns->ipv6_addr[12] = 0xfe;
    ns->ipv6_addr[13] = g_pcnet_mac[3];
    ns->ipv6_addr[14] = g_pcnet_mac[4];
    ns->ipv6_addr[15] = g_pcnet_mac[5];
    ns->ipv6_ready = 1;
}

static inline void *pcnet_phys_to_virt(uint64_t phys) {
    return (void *)(uintptr_t)(paging_hhdm_offset() + phys);
}

static void *pcnet_alloc_frame(uint64_t *out_phys) {
    uint64_t phys = pmm_alloc_frame();
    if (!phys) return NULL;
    *out_phys = phys;
    return pcnet_phys_to_virt(phys);
}

static void pcnet_desc_init_rx(struct pcnet_desc *d, uint64_t buf_phys) {
    d->addr = (uint32_t)buf_phys;
    d->length = (uint16_t)(0xF000u | ((uint16_t)(-((int32_t)PCNET_RX_BUF_SIZE)) & 0x0FFFu));
    d->status = 0x8000u; /* OWN */
    d->misc = 0;
    d->reserved = 0;
}

static void pcnet_desc_init_tx(struct pcnet_desc *d, uint64_t buf_phys) {
    d->addr = (uint32_t)buf_phys;
    d->length = (uint16_t)(0xF000u | ((uint16_t)(-((int32_t)PCNET_RX_BUF_SIZE)) & 0x0FFFu));
    d->status = 0;
    d->misc = 0;
    d->reserved = 0;
}

static void pcnet_build_init_block(uint64_t rx_phys, uint64_t tx_phys) {
    g_init->mode = 0;
    g_init->rlen_tlen = (uint16_t)((PCNET_RING_ORDER << 12) | (PCNET_RING_ORDER << 8));
    for (uint8_t i = 0; i < 6; ++i) g_init->phys_addr[i] = g_pcnet_mac[i];
    g_init->reserved = 0;
    g_init->rx_ring = (uint32_t)rx_phys;
    g_init->tx_ring = (uint32_t)tx_phys;
}

static void pcnet_write_init_addr(uint16_t io_base, uint64_t init_phys) {
    pcnet_write_csr(io_base, 1, (uint16_t)(init_phys & 0xFFFFu));
    pcnet_write_csr(io_base, 2, (uint16_t)((init_phys >> 16) & 0xFFFFu));
}

static void pcnet_send_raw(const uint8_t *data, uint16_t len) {
    if (!g_pcnet_ready || !data || len == 0) return;
    struct pcnet_desc *d = &g_tx_ring[g_tx_idx];
    if (d->status & 0x8000u) {
        return;
    }
    if (len > PCNET_RX_BUF_SIZE) len = PCNET_RX_BUF_SIZE;
    uint8_t *buf = g_tx_bufs[g_tx_idx];
    for (uint16_t i = 0; i < len; ++i) buf[i] = data[i];
    d->length = (uint16_t)(0xF000u | ((uint16_t)(-((int32_t)len)) & 0x0FFFu));
    d->status = 0x8300u; /* OWN + STP + ENP */
    g_tx_idx = (g_tx_idx + 1) & (PCNET_RING_COUNT - 1);
    pcnet_write_csr(g_pcnet_io, 0, pcnet_read_csr(g_pcnet_io, 0) | PCNET_CSR0_STRT);
}

static void pcnet_send_arp_request_to(const uint8_t target_ip[4], int log_it) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    uint8_t pkt[42];
    for (uint8_t i = 0; i < 6; ++i) pkt[i] = 0xFF;
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    pkt[14] = 0x00; pkt[15] = 0x01;
    pkt[16] = 0x08; pkt[17] = 0x00;
    pkt[18] = 0x06;
    pkt[19] = 0x04;
    pkt[20] = 0x00; pkt[21] = 0x01;
    for (uint8_t i = 0; i < 6; ++i) pkt[22 + i] = g_pcnet_mac[i];
    for (uint8_t i = 0; i < 4; ++i) pkt[28 + i] = ns->ip_addr[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[32 + i] = 0x00;
    for (uint8_t i = 0; i < 4; ++i) pkt[38 + i] = target_ip[i];
    pcnet_send_raw(pkt, sizeof(pkt));
    if (log_it) {
        log_printf("PCNet: ARP who-has %u.%u.%u.%u\n",
                   target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
    }
}

static void pcnet_send_arp_reply(const uint8_t *dst_mac, const uint8_t *dst_ip) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    uint8_t pkt[42];
    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x08;
    pkt[13] = 0x06;
    pkt[14] = 0x00; pkt[15] = 0x01;
    pkt[16] = 0x08; pkt[17] = 0x00;
    pkt[18] = 0x06;
    pkt[19] = 0x04;
    pkt[20] = 0x00; pkt[21] = 0x02;
    for (uint8_t i = 0; i < 6; ++i) pkt[22 + i] = g_pcnet_mac[i];
    for (uint8_t i = 0; i < 4; ++i) pkt[28 + i] = ns->ip_addr[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[32 + i] = dst_mac[i];
    for (uint8_t i = 0; i < 4; ++i) pkt[38 + i] = dst_ip[i];
    pcnet_send_raw(pkt, sizeof(pkt));
}

static void pcnet_handle_arp(const uint8_t *pkt, uint16_t len) {
    if (len < 42) return;
    struct net_namespace *ns = pcnet_rx_ns();
    if (!ns) return;
    uint16_t oper = ((uint16_t)pkt[20] << 8) | pkt[21];
    const uint8_t *sha = &pkt[22];
    const uint8_t *spa = &pkt[28];
    const uint8_t *tpa = &pkt[38];
    if (oper == 1) {
        if (tpa[0] == ns->ip_addr[0] && tpa[1] == ns->ip_addr[1] &&
            tpa[2] == ns->ip_addr[2] && tpa[3] == ns->ip_addr[3]) {
            log_printf("PCNet: ARP req from %u.%u.%u.%u\n",
                       spa[0], spa[1], spa[2], spa[3]);
            pcnet_send_arp_reply(sha, spa);
        }
    } else if (oper == 2) {
        log_printf("PCNet: ARP reply from %u.%u.%u.%u\n",
                   spa[0], spa[1], spa[2], spa[3]);
        for (uint8_t i = 0; i < 4; ++i) ns->arp_ip[i] = spa[i];
        for (uint8_t i = 0; i < 6; ++i) ns->arp_mac[i] = sha[i];
        ns->arp_valid = 1;
    }
}

static inline uint16_t net_htons(uint16_t v) {
    return (uint16_t)((v << 8) | (v >> 8));
}

static int ip_is_zero(const uint8_t ip[4]) {
    return ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0;
}

static int ip_is_broadcast(const uint8_t ip[4]) {
    return ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255;
}

static uint16_t net_checksum(const void *data, uint16_t len) {
    const uint8_t *p = (const uint8_t *)data;
    uint32_t sum = 0;
    for (uint16_t i = 0; i + 1 < len; i += 2) {
        sum += (uint16_t)((p[i] << 8) | p[i + 1]);
    }
    if (len & 1) sum += (uint16_t)(p[len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static uint16_t net_checksum_ipv6(const uint8_t src[16], const uint8_t dst[16],
                                  uint8_t next_header,
                                  const uint8_t *payload, uint16_t payload_len) {
    uint32_t sum = 0;
    for (int i = 0; i < 16; i += 2) {
        sum += (uint16_t)((src[i] << 8) | src[i + 1]);
        sum += (uint16_t)((dst[i] << 8) | dst[i + 1]);
    }
    sum += (uint16_t)((payload_len >> 16) & 0xFFFFu);
    sum += (uint16_t)(payload_len & 0xFFFFu);
    sum += (uint16_t)next_header;
    const uint8_t *p = payload;
    for (uint16_t i = 0; i + 1 < payload_len; i += 2) {
        sum += (uint16_t)((p[i] << 8) | p[i + 1]);
    }
    if (payload_len & 1) sum += (uint16_t)(p[payload_len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static int ipv6_eq(const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; ++i) if (a[i] != b[i]) return 0;
    return 1;
}

static int ipv6_is_linklocal(const uint8_t ip[16]) {
    return ip[0] == 0xfe && (ip[1] & 0xc0u) == 0x80u;
}

static void ipv6_solicited_node(const uint8_t target[16], uint8_t out[16]) {
    for (int i = 0; i < 16; ++i) out[i] = 0;
    out[0] = 0xff;
    out[1] = 0x02;
    out[11] = 0x01;
    out[12] = 0xff;
    out[13] = target[13];
    out[14] = target[14];
    out[15] = target[15];
}

static void ipv6_multicast_mac(const uint8_t ip[16], uint8_t out[6]) {
    out[0] = 0x33;
    out[1] = 0x33;
    out[2] = ip[12];
    out[3] = ip[13];
    out[4] = ip[14];
    out[5] = ip[15];
}

static void ipv6_neighbor_cache_set(struct net_namespace *ns,
                                    const uint8_t ip[16], const uint8_t mac[6]) {
    if (!ns) return;
    for (int i = 0; i < NETNS_IPV6_ND_CACHE_MAX; ++i) {
        if (ns->neighbors[i].valid && ipv6_eq(ns->neighbors[i].ip, ip)) {
            for (int j = 0; j < 6; ++j) ns->neighbors[i].mac[j] = mac[j];
            return;
        }
    }
    for (int i = 0; i < NETNS_IPV6_ND_CACHE_MAX; ++i) {
        if (!ns->neighbors[i].valid) {
            for (int j = 0; j < 16; ++j) ns->neighbors[i].ip[j] = ip[j];
            for (int j = 0; j < 6; ++j) ns->neighbors[i].mac[j] = mac[j];
            ns->neighbors[i].valid = 1;
            return;
        }
    }
    for (int j = 0; j < 16; ++j) ns->neighbors[0].ip[j] = ip[j];
    for (int j = 0; j < 6; ++j) ns->neighbors[0].mac[j] = mac[j];
    ns->neighbors[0].valid = 1;
}

static int ipv6_neighbor_cache_get(const struct net_namespace *ns,
                                   const uint8_t ip[16], uint8_t out_mac[6]) {
    if (!ns) return 0;
    for (int i = 0; i < NETNS_IPV6_ND_CACHE_MAX; ++i) {
        if (ns->neighbors[i].valid && ipv6_eq(ns->neighbors[i].ip, ip)) {
            for (int j = 0; j < 6; ++j) out_mac[j] = ns->neighbors[i].mac[j];
            return 1;
        }
    }
    return 0;
}

static void ipv6_route_init(struct net_namespace *ns) {
    if (!ns) return;
    for (int i = 0; i < NETNS_IPV6_ROUTE_MAX; ++i) ns->routes[i].valid = 0;
}

static int ipv6_prefix_match(const uint8_t ip[16], const uint8_t prefix[16], uint8_t prefix_len) {
    uint8_t full = (uint8_t)(prefix_len / 8);
    uint8_t rem = (uint8_t)(prefix_len % 8);
    for (uint8_t i = 0; i < full; ++i) {
        if (ip[i] != prefix[i]) return 0;
    }
    if (rem) {
        uint8_t mask = (uint8_t)(0xFFu << (8u - rem));
        if ((ip[full] & mask) != (prefix[full] & mask)) return 0;
    }
    return 1;
}

static int ipv6_route_lookup(const struct net_namespace *ns,
                             const uint8_t dst[16], uint8_t next_hop[16]) {
    if (!ns) return 0;
    int best = -1;
    uint8_t best_len = 0;
    for (int i = 0; i < NETNS_IPV6_ROUTE_MAX; ++i) {
        if (!ns->routes[i].valid) continue;
        if (ipv6_prefix_match(dst, ns->routes[i].prefix, ns->routes[i].prefix_len)) {
            if (best < 0 || ns->routes[i].prefix_len > best_len) {
                best = i;
                best_len = ns->routes[i].prefix_len;
            }
        }
    }
    if (best < 0) return 0;
    for (int i = 0; i < 16; ++i) next_hop[i] = ns->routes[best].next_hop[i];
    return 1;
}

int pcnet_ipv6_route_add(const uint8_t prefix[16], uint8_t prefix_len, const uint8_t next_hop[16]) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns || !prefix || !next_hop || prefix_len > 128) return -1;
    for (int i = 0; i < NETNS_IPV6_ROUTE_MAX; ++i) {
        if (!ns->routes[i].valid) {
            for (int j = 0; j < 16; ++j) ns->routes[i].prefix[j] = prefix[j];
            for (int j = 0; j < 16; ++j) ns->routes[i].next_hop[j] = next_hop[j];
            ns->routes[i].prefix_len = prefix_len;
            ns->routes[i].valid = 1;
            return 0;
        }
    }
    return -1;
}

void pcnet_ipv6_route_list(void) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (int i = 0; i < NETNS_IPV6_ROUTE_MAX; ++i) {
        if (!ns->routes[i].valid) continue;
        log_printf("ip6 route %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x/%u -> %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                   ns->routes[i].prefix[0], ns->routes[i].prefix[1],
                   ns->routes[i].prefix[2], ns->routes[i].prefix[3],
                   ns->routes[i].prefix[4], ns->routes[i].prefix[5],
                   ns->routes[i].prefix[6], ns->routes[i].prefix[7],
                   ns->routes[i].prefix[8], ns->routes[i].prefix[9],
                   ns->routes[i].prefix[10], ns->routes[i].prefix[11],
                   ns->routes[i].prefix[12], ns->routes[i].prefix[13],
                   ns->routes[i].prefix[14], ns->routes[i].prefix[15],
                   ns->routes[i].prefix_len,
                   ns->routes[i].next_hop[0], ns->routes[i].next_hop[1],
                   ns->routes[i].next_hop[2], ns->routes[i].next_hop[3],
                   ns->routes[i].next_hop[4], ns->routes[i].next_hop[5],
                   ns->routes[i].next_hop[6], ns->routes[i].next_hop[7],
                   ns->routes[i].next_hop[8], ns->routes[i].next_hop[9],
                   ns->routes[i].next_hop[10], ns->routes[i].next_hop[11],
                   ns->routes[i].next_hop[12], ns->routes[i].next_hop[13],
                   ns->routes[i].next_hop[14], ns->routes[i].next_hop[15]);
    }
}

void pcnet_ipv6_set_forwarding(int enabled) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    ns->ipv6_forwarding = enabled ? 1 : 0;
}

int pcnet_ipv6_get_forwarding(void) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return 0;
    return ns->ipv6_forwarding ? 1 : 0;
}

static uint16_t net_tcp_checksum(const uint8_t src_ip[4], const uint8_t dst_ip[4],
                                 const uint8_t *tcp, uint16_t tcp_len) {
    uint32_t sum = 0;
    sum += (uint16_t)((src_ip[0] << 8) | src_ip[1]);
    sum += (uint16_t)((src_ip[2] << 8) | src_ip[3]);
    sum += (uint16_t)((dst_ip[0] << 8) | dst_ip[1]);
    sum += (uint16_t)((dst_ip[2] << 8) | dst_ip[3]);
    sum += (uint16_t)0x0006u;
    sum += tcp_len;
    const uint8_t *p = tcp;
    for (uint16_t i = 0; i + 1 < tcp_len; i += 2) {
        sum += (uint16_t)((p[i] << 8) | p[i + 1]);
    }
    if (tcp_len & 1) sum += (uint16_t)(p[tcp_len - 1] << 8);
    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum);
}

static void pcnet_send_ipv4_icmp(uint8_t type, uint8_t code,
                                 const uint8_t dst_ip[4],
                                 const uint8_t dst_mac[6],
                                 uint16_t id, uint16_t seq,
                                 const uint8_t *payload, uint16_t payload_len) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    uint8_t pkt[14 + 20 + 8 + 32];
    if (payload_len > 32) payload_len = 32;
    uint16_t ip_len = (uint16_t)(20 + 8 + payload_len);
    uint16_t frame_len = (uint16_t)(14 + ip_len);

    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x08; pkt[13] = 0x00;

    uint8_t *ip = &pkt[14];
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2] = (uint8_t)(ip_len >> 8);
    ip[3] = (uint8_t)(ip_len & 0xFF);
    ip[4] = (uint8_t)(ns->ip_ident >> 8);
    ip[5] = (uint8_t)(ns->ip_ident & 0xFF);
    ip[6] = 0x00; ip[7] = 0x00;
    ip[8] = 64;
    ip[9] = 1;
    ip[10] = 0x00; ip[11] = 0x00;
    for (uint8_t i = 0; i < 4; ++i) ip[12 + i] = ns->ip_addr[i];
    for (uint8_t i = 0; i < 4; ++i) ip[16 + i] = dst_ip[i];
    uint16_t ip_ck = net_checksum(ip, 20);
    ip[10] = (uint8_t)(ip_ck >> 8);
    ip[11] = (uint8_t)(ip_ck & 0xFF);

    uint8_t *icmp = &ip[20];
    icmp[0] = type;
    icmp[1] = code;
    icmp[2] = 0x00; icmp[3] = 0x00;
    icmp[4] = (uint8_t)(id >> 8);
    icmp[5] = (uint8_t)(id & 0xFF);
    icmp[6] = (uint8_t)(seq >> 8);
    icmp[7] = (uint8_t)(seq & 0xFF);
    for (uint16_t i = 0; i < payload_len; ++i) icmp[8 + i] = payload ? payload[i] : 0;
    uint16_t icmp_ck = net_checksum(icmp, (uint16_t)(8 + payload_len));
    icmp[2] = (uint8_t)(icmp_ck >> 8);
    icmp[3] = (uint8_t)(icmp_ck & 0xFF);

    ns->ip_ident++;
    pcnet_send_raw(pkt, frame_len);
}

static void pcnet_send_ipv4_udp(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                                uint16_t src_port, uint16_t dst_port,
                                const uint8_t *payload, uint16_t payload_len) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    if (payload_len > 1200) payload_len = 1200;
    uint16_t ip_len = (uint16_t)(20 + 8 + payload_len);
    uint16_t frame_len = (uint16_t)(14 + ip_len);
    uint8_t pkt[14 + 20 + 8 + 1200];

    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x08; pkt[13] = 0x00;

    uint8_t *ip = &pkt[14];
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2] = (uint8_t)(ip_len >> 8);
    ip[3] = (uint8_t)(ip_len & 0xFF);
    ip[4] = (uint8_t)(ns->ip_ident >> 8);
    ip[5] = (uint8_t)(ns->ip_ident & 0xFF);
    ip[6] = 0x00; ip[7] = 0x00;
    ip[8] = 64;
    ip[9] = 17;
    ip[10] = 0x00; ip[11] = 0x00;
    for (uint8_t i = 0; i < 4; ++i) ip[12 + i] = ns->ip_addr[i];
    for (uint8_t i = 0; i < 4; ++i) ip[16 + i] = dst_ip[i];
    uint16_t ip_ck = net_checksum(ip, 20);
    ip[10] = (uint8_t)(ip_ck >> 8);
    ip[11] = (uint8_t)(ip_ck & 0xFF);

    uint8_t *udp = &ip[20];
    udp[0] = (uint8_t)(src_port >> 8);
    udp[1] = (uint8_t)(src_port & 0xFF);
    udp[2] = (uint8_t)(dst_port >> 8);
    udp[3] = (uint8_t)(dst_port & 0xFF);
    udp[4] = (uint8_t)((payload_len + 8) >> 8);
    udp[5] = (uint8_t)((payload_len + 8) & 0xFF);
    udp[6] = 0x00;
    udp[7] = 0x00;
    for (uint16_t i = 0; i < payload_len; ++i) udp[8 + i] = payload ? payload[i] : 0;

    ns->ip_ident++;
    pcnet_send_raw(pkt, frame_len);
}

static void pcnet_send_ipv4_tcp(const uint8_t dst_ip[4], const uint8_t dst_mac[6],
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const uint8_t *payload, uint16_t payload_len) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    if (payload_len > 1200) payload_len = 1200;
    uint16_t tcp_len = (uint16_t)(20 + payload_len);
    uint16_t ip_len = (uint16_t)(20 + tcp_len);
    uint16_t frame_len = (uint16_t)(14 + ip_len);
    uint8_t pkt[14 + 20 + 20 + 1200];

    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x08; pkt[13] = 0x00;

    uint8_t *ip = &pkt[14];
    ip[0] = 0x45;
    ip[1] = 0x00;
    ip[2] = (uint8_t)(ip_len >> 8);
    ip[3] = (uint8_t)(ip_len & 0xFF);
    ip[4] = (uint8_t)(ns->ip_ident >> 8);
    ip[5] = (uint8_t)(ns->ip_ident & 0xFF);
    ip[6] = 0x00; ip[7] = 0x00;
    ip[8] = 64;
    ip[9] = 6;
    ip[10] = 0x00; ip[11] = 0x00;
    for (uint8_t i = 0; i < 4; ++i) ip[12 + i] = ns->ip_addr[i];
    for (uint8_t i = 0; i < 4; ++i) ip[16 + i] = dst_ip[i];
    uint16_t ip_ck = net_checksum(ip, 20);
    ip[10] = (uint8_t)(ip_ck >> 8);
    ip[11] = (uint8_t)(ip_ck & 0xFF);

    uint8_t *tcp = &ip[20];
    tcp[0] = (uint8_t)(src_port >> 8);
    tcp[1] = (uint8_t)(src_port & 0xFF);
    tcp[2] = (uint8_t)(dst_port >> 8);
    tcp[3] = (uint8_t)(dst_port & 0xFF);
    tcp[4] = (uint8_t)(seq >> 24);
    tcp[5] = (uint8_t)(seq >> 16);
    tcp[6] = (uint8_t)(seq >> 8);
    tcp[7] = (uint8_t)(seq & 0xFF);
    tcp[8] = (uint8_t)(ack >> 24);
    tcp[9] = (uint8_t)(ack >> 16);
    tcp[10] = (uint8_t)(ack >> 8);
    tcp[11] = (uint8_t)(ack & 0xFF);
    tcp[12] = 0x50; /* data offset = 5 */
    tcp[13] = flags;
    tcp[14] = 0x10; tcp[15] = 0x00; /* window */
    tcp[16] = 0x00; tcp[17] = 0x00; /* checksum */
    tcp[18] = 0x00; tcp[19] = 0x00; /* urgent */
    for (uint16_t i = 0; i < payload_len; ++i) tcp[20 + i] = payload ? payload[i] : 0;
    uint16_t tcp_ck = net_tcp_checksum(ns->ip_addr, dst_ip, tcp, tcp_len);
    tcp[16] = (uint8_t)(tcp_ck >> 8);
    tcp[17] = (uint8_t)(tcp_ck & 0xFF);

    ns->ip_ident++;
    pcnet_send_raw(pkt, frame_len);
}

static void pcnet_send_ipv6_icmp(uint8_t type, uint8_t code,
                                 const uint8_t dst_ip[16],
                                 const uint8_t dst_mac[6],
                                 uint16_t id, uint16_t seq,
                                 const uint8_t *payload, uint16_t payload_len) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns || !ns->ipv6_ready) return;
    if (payload_len > 32) payload_len = 32;
    uint16_t icmp_len = (uint16_t)(8 + payload_len);
    uint16_t frame_len = (uint16_t)(14 + 40 + icmp_len);
    uint8_t pkt[14 + 40 + 8 + 32];

    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x86; pkt[13] = 0xdd;

    uint8_t *ip6 = &pkt[14];
    ip6[0] = 0x60;
    ip6[1] = 0x00; ip6[2] = 0x00; ip6[3] = 0x00;
    ip6[4] = (uint8_t)(icmp_len >> 8);
    ip6[5] = (uint8_t)(icmp_len & 0xFF);
    ip6[6] = 58;
    ip6[7] = 64;
    for (uint8_t i = 0; i < 16; ++i) ip6[8 + i] = ns->ipv6_addr[i];
    for (uint8_t i = 0; i < 16; ++i) ip6[24 + i] = dst_ip[i];

    uint8_t *icmp = &ip6[40];
    icmp[0] = type;
    icmp[1] = code;
    icmp[2] = 0; icmp[3] = 0;
    icmp[4] = (uint8_t)(id >> 8);
    icmp[5] = (uint8_t)(id & 0xFF);
    icmp[6] = (uint8_t)(seq >> 8);
    icmp[7] = (uint8_t)(seq & 0xFF);
    for (uint16_t i = 0; i < payload_len; ++i) icmp[8 + i] = payload ? payload[i] : 0;
    uint16_t csum = net_checksum_ipv6(ns->ipv6_addr, dst_ip, 58, icmp, icmp_len);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)(csum & 0xFF);

    pcnet_send_raw(pkt, frame_len);
}

static void pcnet_send_ipv6_udp(const uint8_t dst_ip[16], const uint8_t dst_mac[6],
                                uint16_t src_port, uint16_t dst_port,
                                const uint8_t *payload, uint16_t payload_len) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns || !ns->ipv6_ready) return;
    if (payload_len > 1200) payload_len = 1200;
    uint16_t udp_len = (uint16_t)(8 + payload_len);
    uint16_t frame_len = (uint16_t)(14 + 40 + udp_len);
    uint8_t pkt[14 + 40 + 8 + 1200];

    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x86; pkt[13] = 0xdd;

    uint8_t *ip6 = &pkt[14];
    ip6[0] = 0x60;
    ip6[1] = 0x00; ip6[2] = 0x00; ip6[3] = 0x00;
    ip6[4] = (uint8_t)(udp_len >> 8);
    ip6[5] = (uint8_t)(udp_len & 0xFF);
    ip6[6] = 17;
    ip6[7] = 64;
    for (uint8_t i = 0; i < 16; ++i) ip6[8 + i] = ns->ipv6_addr[i];
    for (uint8_t i = 0; i < 16; ++i) ip6[24 + i] = dst_ip[i];

    uint8_t *udp = &ip6[40];
    udp[0] = (uint8_t)(src_port >> 8);
    udp[1] = (uint8_t)(src_port & 0xFF);
    udp[2] = (uint8_t)(dst_port >> 8);
    udp[3] = (uint8_t)(dst_port & 0xFF);
    udp[4] = (uint8_t)(udp_len >> 8);
    udp[5] = (uint8_t)(udp_len & 0xFF);
    udp[6] = 0x00;
    udp[7] = 0x00;
    for (uint16_t i = 0; i < payload_len; ++i) udp[8 + i] = payload ? payload[i] : 0;

    uint16_t csum = net_checksum_ipv6(ns->ipv6_addr, dst_ip, 17, udp, udp_len);
    udp[6] = (uint8_t)(csum >> 8);
    udp[7] = (uint8_t)(csum & 0xFF);

    pcnet_send_raw(pkt, frame_len);
}

static void pcnet_send_ipv6_ns(const uint8_t target_ip[16]) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns || !ns->ipv6_ready) return;
    uint8_t mcast_ip[16];
    ipv6_solicited_node(target_ip, mcast_ip);
    uint8_t dst_mac[6];
    ipv6_multicast_mac(mcast_ip, dst_mac);

    uint8_t pkt[14 + 40 + 32];
    uint16_t icmp_len = 32;
    uint16_t frame_len = (uint16_t)(14 + 40 + icmp_len);

    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x86; pkt[13] = 0xdd;

    uint8_t *ip6 = &pkt[14];
    ip6[0] = 0x60;
    ip6[1] = 0x00; ip6[2] = 0x00; ip6[3] = 0x00;
    ip6[4] = 0x00; ip6[5] = (uint8_t)icmp_len;
    ip6[6] = 58;
    ip6[7] = 255;
    for (uint8_t i = 0; i < 16; ++i) ip6[8 + i] = ns->ipv6_addr[i];
    for (uint8_t i = 0; i < 16; ++i) ip6[24 + i] = mcast_ip[i];

    uint8_t *icmp = &ip6[40];
    icmp[0] = 135;
    icmp[1] = 0;
    icmp[2] = 0; icmp[3] = 0;
    icmp[4] = 0; icmp[5] = 0; icmp[6] = 0; icmp[7] = 0;
    for (uint8_t i = 0; i < 16; ++i) icmp[8 + i] = target_ip[i];
    icmp[24] = 1; /* option: source link-layer addr */
    icmp[25] = 1; /* length in 8-byte units */
    for (uint8_t i = 0; i < 6; ++i) icmp[26 + i] = g_pcnet_mac[i];

    uint16_t csum = net_checksum_ipv6(ns->ipv6_addr, mcast_ip, 58, icmp, icmp_len);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)(csum & 0xFF);
    pcnet_send_raw(pkt, frame_len);
}

static void pcnet_send_ipv6_na(const uint8_t dst_ip[16], const uint8_t dst_mac[6],
                               const uint8_t target_ip[16], uint8_t solicited) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns || !ns->ipv6_ready) return;
    uint8_t pkt[14 + 40 + 32];
    uint16_t icmp_len = 32;
    uint16_t frame_len = (uint16_t)(14 + 40 + icmp_len);

    for (uint8_t i = 0; i < 6; ++i) pkt[i] = dst_mac[i];
    for (uint8_t i = 0; i < 6; ++i) pkt[6 + i] = g_pcnet_mac[i];
    pkt[12] = 0x86; pkt[13] = 0xdd;

    uint8_t *ip6 = &pkt[14];
    ip6[0] = 0x60;
    ip6[1] = 0x00; ip6[2] = 0x00; ip6[3] = 0x00;
    ip6[4] = 0x00; ip6[5] = (uint8_t)icmp_len;
    ip6[6] = 58;
    ip6[7] = 255;
    for (uint8_t i = 0; i < 16; ++i) ip6[8 + i] = ns->ipv6_addr[i];
    for (uint8_t i = 0; i < 16; ++i) ip6[24 + i] = dst_ip[i];

    uint8_t *icmp = &ip6[40];
    icmp[0] = 136;
    icmp[1] = 0;
    icmp[2] = 0; icmp[3] = 0;
    icmp[4] = (uint8_t)(0x60u | (solicited ? 0x40u : 0x00u));
    icmp[5] = 0; icmp[6] = 0; icmp[7] = 0;
    for (uint8_t i = 0; i < 16; ++i) icmp[8 + i] = target_ip[i];
    icmp[24] = 2; /* option: target link-layer addr */
    icmp[25] = 1; /* length in 8-byte units */
    for (uint8_t i = 0; i < 6; ++i) icmp[26 + i] = g_pcnet_mac[i];

    uint16_t csum = net_checksum_ipv6(ns->ipv6_addr, dst_ip, 58, icmp, icmp_len);
    icmp[2] = (uint8_t)(csum >> 8);
    icmp[3] = (uint8_t)(csum & 0xFF);
    pcnet_send_raw(pkt, frame_len);
}

static void pcnet_handle_ipv4(const uint8_t *pkt, uint16_t len) {
    if (len < 14 + 20) return;
    struct net_namespace *ns = pcnet_rx_ns();
    if (!ns) return;
    const uint8_t *ip = &pkt[14];
    if ((ip[0] >> 4) != 4) return;
    uint8_t ihl = (uint8_t)(ip[0] & 0x0F);
    if (ihl < 5) return;
    uint16_t ip_len = (uint16_t)((ip[2] << 8) | ip[3]);
    if (ip_len < (uint16_t)(ihl * 4)) return;
    if (len < 14 + ip_len) return;
    if (!ip_is_zero(ns->ip_addr)) {
        if (ip[16] != ns->ip_addr[0] || ip[17] != ns->ip_addr[1] ||
            ip[18] != ns->ip_addr[2] || ip[19] != ns->ip_addr[3]) {
            if (!ip_is_broadcast(&ip[16])) return;
        }
    }
    if (ip[9] == 1) {
        const uint8_t *icmp = ip + ihl * 4;
        uint16_t icmp_len = (uint16_t)(ip_len - ihl * 4);
        if (icmp_len < 8) return;
        if (!firewall_ipv4_allow(1, &ip[12], &ip[16], 0, 0)) return;
        uint8_t type = icmp[0];
        if (type == 8) {
            uint16_t id = (uint16_t)((icmp[4] << 8) | icmp[5]);
            uint16_t seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
            pcnet_send_ipv4_icmp(0, 0, &ip[12], &pkt[6], id, seq,
                                 &icmp[8], (uint16_t)(icmp_len - 8));
        } else if (type == 0) {
            log_printf("PCNet: ICMP echo reply\n");
        }
        return;
    }
    if (ip[9] == 17) {
        const uint8_t *udp = ip + ihl * 4;
        uint16_t udp_len = (uint16_t)((udp[4] << 8) | udp[5]);
        if (udp_len < 8) return;
        if (udp_len > (uint16_t)(ip_len - ihl * 4)) return;
        uint16_t src_port = (uint16_t)((udp[0] << 8) | udp[1]);
        uint16_t dst_port = (uint16_t)((udp[2] << 8) | udp[3]);
        if (!firewall_ipv4_allow(17, &ip[12], &ip[16], src_port, dst_port)) return;
        const uint8_t *payload = udp + 8;
        uint16_t payload_len = (uint16_t)(udp_len - 8);
        socket_net_rx(&ip[12], src_port, dst_port, payload, payload_len);
        return;
    }
    if (ip[9] == 6) {
        const uint8_t *tcp = ip + ihl * 4;
        uint16_t tcp_len = (uint16_t)(ip_len - ihl * 4);
        if (tcp_len < 20) return;
        uint16_t src_port = (uint16_t)((tcp[0] << 8) | tcp[1]);
        uint16_t dst_port = (uint16_t)((tcp[2] << 8) | tcp[3]);
        if (!firewall_ipv4_allow(6, &ip[12], &ip[16], src_port, dst_port)) return;
        uint32_t seq = ((uint32_t)tcp[4] << 24) | ((uint32_t)tcp[5] << 16) |
                       ((uint32_t)tcp[6] << 8) | (uint32_t)tcp[7];
        uint32_t ack = ((uint32_t)tcp[8] << 24) | ((uint32_t)tcp[9] << 16) |
                       ((uint32_t)tcp[10] << 8) | (uint32_t)tcp[11];
        uint8_t data_off = (uint8_t)(tcp[12] >> 4);
        uint16_t hdr_len = (uint16_t)(data_off * 4);
        if (hdr_len < 20 || hdr_len > tcp_len) return;
        uint8_t flags = tcp[13];
        const uint8_t *payload = tcp + hdr_len;
        uint16_t payload_len = (uint16_t)(tcp_len - hdr_len);
        tcp_on_rx(&ip[12], &ip[16], src_port, dst_port, seq, ack, flags, payload, payload_len);
    }
}

static void pcnet_handle_ipv6(const uint8_t *pkt, uint16_t len) {
    if (len < 14 + 40) return;
    struct net_namespace *ns = pcnet_rx_ns();
    if (!ns) return;
    const uint8_t *ip6 = &pkt[14];
    if ((ip6[0] >> 4) != 6) return;
    uint16_t payload_len = (uint16_t)((ip6[4] << 8) | ip6[5]);
    if (payload_len + 40u > (uint16_t)(len - 14)) return;
    uint8_t next = ip6[6];
    if (next == 58) {
        const uint8_t *icmp = ip6 + 40;
        if (payload_len < 8) return;
        uint8_t type = icmp[0];
        if (type == 128) {
            if (!ns->ipv6_ready) return;
            int dst_is_me = 1;
            for (int i = 0; i < 16; ++i) {
                if (ip6[24 + i] != ns->ipv6_addr[i]) { dst_is_me = 0; break; }
            }
            if (!dst_is_me) return;
            uint16_t id = (uint16_t)((icmp[4] << 8) | icmp[5]);
            uint16_t seq = (uint16_t)((icmp[6] << 8) | icmp[7]);
            pcnet_send_ipv6_icmp(129, 0, &ip6[8], &pkt[6], id, seq,
                                 &icmp[8], (uint16_t)(payload_len - 8));
        } else if (type == 135) {
            if (payload_len < 24) return;
            const uint8_t *target = &icmp[8];
            if (!ipv6_eq(target, ns->ipv6_addr)) return;
            uint8_t dst_ip[16];
            for (int i = 0; i < 16; ++i) dst_ip[i] = ip6[8 + i];
            pcnet_send_ipv6_na(dst_ip, &pkt[6], target, 1);
        } else if (type == 136) {
            if (payload_len < 24) return;
            const uint8_t *target = &icmp[8];
            ipv6_neighbor_cache_set(ns, target, &pkt[6]);
        }
        return;
    }
    if (next == 17) {
        const uint8_t *udp = ip6 + 40;
        if (payload_len < 8) return;
        uint16_t udp_len = (uint16_t)((udp[4] << 8) | udp[5]);
        if (udp_len < 8 || udp_len > payload_len) return;
        uint16_t src_port = (uint16_t)((udp[0] << 8) | udp[1]);
        uint16_t dst_port = (uint16_t)((udp[2] << 8) | udp[3]);
        const uint8_t *payload = udp + 8;
        uint16_t payload_len2 = (uint16_t)(udp_len - 8);
        socket_net6_rx(&ip6[8], src_port, dst_port, payload, payload_len2);
        return;
    }
}

static void pcnet_poll_rx(void) {
    if (!g_pcnet_ready) return;
    for (uint32_t i = 0; i < PCNET_RING_COUNT; ++i) {
        struct pcnet_desc *d = &g_rx_ring[g_rx_idx];
        if (d->status & 0x8000u) break;
        uint16_t len = (uint16_t)(d->misc & 0x0FFFu);
        uint8_t *buf = g_rx_bufs[g_rx_idx];
        if (len >= 14) {
            uint16_t eth = (uint16_t)((buf[12] << 8) | buf[13]);
            if (eth == 0x0806) {
                pcnet_handle_arp(buf, len);
            } else if (eth == 0x0800) {
                pcnet_handle_ipv4(buf, len);
            } else if (eth == 0x86DD) {
                pcnet_handle_ipv6(buf, len);
            }
        }
        pcnet_desc_init_rx(d, (uint64_t)(d->addr));
        g_rx_idx = (g_rx_idx + 1) & (PCNET_RING_COUNT - 1);
    }
}

static int pcnet_probe(const struct pci_device *dev) {
    if (!dev) return 0;
    if (dev->vendor_id != PCNET_VENDOR_ID) return 0;
    if (dev->device_id != PCNET_DEVICE_ID && dev->device_id != PCNET_DEVICE_ID_III) return 0;
    g_pcnet_found = 1;

    uint32_t bar0 = dev->bar[0];
    if ((bar0 & 0x1) == 0) {
        log_printf("PCNet: BAR0 not I/O space, skipping\n");
        g_pcnet_error = 1;
        return 0;
    }

    uint16_t io_base = (uint16_t)(bar0 & ~0x3u);
    pci_enable_io(dev);
    pci_enable_bus_mastering(dev);

    pcnet_reset(io_base);
    pcnet_write_csr(io_base, 0, PCNET_CSR0_STOP);

    pcnet_read_mac(io_base, g_pcnet_mac);
    pcnet_init_ipv6_from_mac(netns_root());
    ipv6_route_init(netns_root());
    g_pcnet_io = io_base;
    g_pcnet_irq = dev->irq_line;
    log_printf("PCNet: io=0x%x irq=%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned)io_base, (unsigned)dev->irq_line,
               g_pcnet_mac[0], g_pcnet_mac[1], g_pcnet_mac[2],
               g_pcnet_mac[3], g_pcnet_mac[4], g_pcnet_mac[5]);

    uint64_t init_phys = 0, rx_phys = 0, tx_phys = 0;
    g_init = (struct pcnet_init_block *)pcnet_alloc_frame(&init_phys);
    g_rx_ring = (struct pcnet_desc *)pcnet_alloc_frame(&rx_phys);
    g_tx_ring = (struct pcnet_desc *)pcnet_alloc_frame(&tx_phys);
    if (!g_init || !g_rx_ring || !g_tx_ring) {
        log_printf("PCNet: ring alloc failed\n");
        g_pcnet_error = 1;
        return 0;
    }
    memset(g_init, 0, sizeof(*g_init));
    memset(g_rx_ring, 0, sizeof(struct pcnet_desc) * PCNET_RING_COUNT);
    memset(g_tx_ring, 0, sizeof(struct pcnet_desc) * PCNET_RING_COUNT);

    for (uint32_t i = 0; i < PCNET_RING_COUNT; ++i) {
        uint64_t rphys = 0;
        uint64_t tphys = 0;
        g_rx_bufs[i] = (uint8_t *)pcnet_alloc_frame(&rphys);
        g_tx_bufs[i] = (uint8_t *)pcnet_alloc_frame(&tphys);
        if (!g_rx_bufs[i] || !g_tx_bufs[i]) {
            log_printf("PCNet: buffer alloc failed\n");
            g_pcnet_error = 1;
            return 0;
        }
        pcnet_desc_init_rx(&g_rx_ring[i], rphys);
        pcnet_desc_init_tx(&g_tx_ring[i], tphys);
    }

    pcnet_build_init_block(rx_phys, tx_phys);

    uint16_t bcr20 = pcnet_read_bcr(io_base, PCNET_BCR20_SWSTYLE);
    pcnet_write_bcr(io_base, PCNET_BCR20_SWSTYLE, (uint16_t)(bcr20 | PCNET_BCR20_32BIT));

    pcnet_write_init_addr(io_base, init_phys);
    pcnet_write_csr(io_base, 0, PCNET_CSR0_INIT);
    for (uint32_t spin = 0; spin < 1000000u; ++spin) {
        uint16_t csr0 = pcnet_read_csr(io_base, 0);
        if (csr0 & PCNET_CSR0_IDON) break;
    }
    pcnet_write_csr(io_base, 0, PCNET_CSR0_IDON);
    pcnet_write_csr(io_base, 0, PCNET_CSR0_STRT | PCNET_CSR0_IENA);
    g_pcnet_ready = 1;

    return 1;
}

void pcnet_init(void) {
    static struct pci_driver pcnet_driver = {
        .vendor_id = PCNET_VENDOR_ID,
        .device_id = PCI_DEVICE_ANY,
        .class_code = 0x02,
        .subclass = 0x00,
        .name = "pcnet",
        .probe = pcnet_probe
    };
    pci_register_driver(&pcnet_driver);
}

void pcnet_log_status(void) {
    if (!g_pcnet_found) {
        log_printf("PCNet: not found\n");
        uint32_t count = pci_device_count();
        for (uint32_t i = 0; i < count; ++i) {
            const struct pci_device *dev = pci_device_at(i);
            if (!dev || dev->class_code != 0x02) continue;
            if (dev->vendor_id == PCNET_VENDOR_ID) continue;
            log_printf("PCNet: detected other NIC vendor=0x%x device=0x%x\n",
                       (unsigned)dev->vendor_id, (unsigned)dev->device_id);
        }
        log_printf("PCNet: hint: set VMware NIC to \"PCnet-PCI II (Am79C970A)\".\n");
        return;
    }
    if (g_pcnet_error) {
        log_printf("PCNet: found, init failed (BAR0 not I/O)\n");
        return;
    }
    if (!g_pcnet_ready) {
        log_printf("PCNet: found, rings not initialized\n");
        return;
    }
    log_printf("PCNet: io=0x%x irq=%u mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
               (unsigned)g_pcnet_io, (unsigned)g_pcnet_irq,
               g_pcnet_mac[0], g_pcnet_mac[1], g_pcnet_mac[2],
               g_pcnet_mac[3], g_pcnet_mac[4], g_pcnet_mac[5]);
}

int pcnet_is_found(void) {
    return g_pcnet_found;
}

int pcnet_is_ready(void) {
    return g_pcnet_ready;
}

int pcnet_has_error(void) {
    return g_pcnet_error;
}

void pcnet_tick(void) {
    if (!g_pcnet_ready) return;
    struct net_namespace *ns = pcnet_rx_ns();
    if (!ns) return;
    pcnet_poll_rx();
    tcp_tick();
    if (++g_last_arp_tick >= 500) {
        g_last_arp_tick = 0;
        pcnet_send_arp_request_to(ns->gw_addr, 0);
    }
}

int pcnet_udp_send(const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port,
                   const uint8_t *data, uint16_t len) {
    if (!g_pcnet_ready || !dst_ip || !data || len == 0) return -1;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return -1;
    if (ip_is_broadcast(dst_ip)) {
        uint8_t dst_mac[6];
        for (uint8_t i = 0; i < 6; ++i) dst_mac[i] = 0xFF;
        pcnet_send_ipv4_udp(dst_ip, dst_mac, src_port, dst_port, data, len);
        return 0;
    }
    uint8_t dst_mac[6];
    int have_mac = 0;
    if (ns->arp_valid &&
        ns->arp_ip[0] == dst_ip[0] && ns->arp_ip[1] == dst_ip[1] &&
        ns->arp_ip[2] == dst_ip[2] && ns->arp_ip[3] == dst_ip[3]) {
        for (uint8_t i = 0; i < 6; ++i) dst_mac[i] = ns->arp_mac[i];
        have_mac = 1;
    }
    if (!have_mac) {
        pcnet_send_arp_request_to(dst_ip, 1);
        return -1;
    }
    pcnet_send_ipv4_udp(dst_ip, dst_mac, src_port, dst_port, data, len);
    return 0;
}

int pcnet_udp6_send(const uint8_t dst_ip[16], uint16_t src_port, uint16_t dst_port,
                    const uint8_t *data, uint16_t len) {
    struct net_namespace *ns = pcnet_tx_ns();
    if (!g_pcnet_ready || !ns || !ns->ipv6_ready || !dst_ip || !data || len == 0) return -1;
    uint8_t dst_mac[6];
    uint8_t nh[16];
    const uint8_t *target = dst_ip;
    if (dst_ip[0] == 0xff) {
        ipv6_multicast_mac(dst_ip, dst_mac);
        pcnet_send_ipv6_udp(dst_ip, dst_mac, src_port, dst_port, data, len);
        return 0;
    }
    if (ipv6_is_linklocal(dst_ip)) {
        for (int i = 0; i < 16; ++i) nh[i] = dst_ip[i];
    } else {
        if (!ipv6_route_lookup(ns, dst_ip, nh)) return -1;
        target = nh;
    }
    if (!ipv6_neighbor_cache_get(ns, target, dst_mac)) {
        pcnet_send_ipv6_ns(target);
        return -1;
    }
    pcnet_send_ipv6_udp(dst_ip, dst_mac, src_port, dst_port, data, len);
    return 0;
}

int pcnet_udp_send_broadcast(uint16_t src_port, uint16_t dst_port,
                             const uint8_t *data, uint16_t len) {
    uint8_t bcast[4] = {255, 255, 255, 255};
    return pcnet_udp_send(bcast, src_port, dst_port, data, len);
}

int pcnet_tcp_send(const uint8_t dst_ip[4], uint16_t src_port, uint16_t dst_port,
                   uint32_t seq, uint32_t ack, uint8_t flags,
                   const uint8_t *data, uint16_t len) {
    if (!g_pcnet_ready || !dst_ip) return -1;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return -1;
    uint8_t dst_mac[6];
    int have_mac = 0;
    if (ns->arp_valid &&
        ns->arp_ip[0] == dst_ip[0] && ns->arp_ip[1] == dst_ip[1] &&
        ns->arp_ip[2] == dst_ip[2] && ns->arp_ip[3] == dst_ip[3]) {
        for (uint8_t i = 0; i < 6; ++i) dst_mac[i] = ns->arp_mac[i];
        have_mac = 1;
    }
    if (!have_mac) {
        pcnet_send_arp_request_to(dst_ip, 1);
        return -1;
    }
    pcnet_send_ipv4_tcp(dst_ip, dst_mac, src_port, dst_port, seq, ack, flags, data, len);
    return 0;
}

void pcnet_ping(const uint8_t ip[4]) {
    if (!g_pcnet_ready || !ip) {
        log_printf("ping: network not ready\n");
        return;
    }
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    uint8_t dst_mac[6];
    int have_mac = 0;
    if (ns->arp_valid &&
        ns->arp_ip[0] == ip[0] && ns->arp_ip[1] == ip[1] &&
        ns->arp_ip[2] == ip[2] && ns->arp_ip[3] == ip[3]) {
        for (uint8_t i = 0; i < 6; ++i) dst_mac[i] = ns->arp_mac[i];
        have_mac = 1;
    }
    if (!have_mac) {
        pcnet_send_arp_request_to(ip, 1);
        log_printf("ping: ARP resolving %u.%u.%u.%u\n",
                   ip[0], ip[1], ip[2], ip[3]);
        return;
    }
    const uint8_t payload[8] = {'b','i','t','o','s','p','i','n'};
    pcnet_send_ipv4_icmp(8, 0, ip, dst_mac, 0x1234, 1, payload, sizeof(payload));
    log_printf("ping: sent to %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
}

void pcnet_ping6(const uint8_t ip[16]) {
    if (!g_pcnet_ready || !ip) {
        log_printf("ping6: network not ready\n");
        return;
    }
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns || !ns->ipv6_ready) {
        log_printf("ping6: IPv6 not ready\n");
        return;
    }
    uint8_t dst_mac[6];
    uint8_t dst_ip[16];
    for (int i = 0; i < 16; ++i) dst_ip[i] = ip[i];
    if (ip[0] == 0xff) {
        ipv6_multicast_mac(dst_ip, dst_mac);
    } else {
        uint8_t nh[16];
        if (ipv6_is_linklocal(dst_ip)) {
            for (int i = 0; i < 16; ++i) nh[i] = dst_ip[i];
        } else if (!ipv6_route_lookup(ns, dst_ip, nh)) {
            log_printf("ping6: no route\n");
            return;
        }
        if (!ipv6_neighbor_cache_get(ns, nh, dst_mac)) {
            pcnet_send_ipv6_ns(nh);
            log_printf("ping6: resolving neighbor\n");
            return;
        }
    }
    const uint8_t payload[8] = {'b','i','t','o','s','6','p','n'};
    pcnet_send_ipv6_icmp(128, 0, dst_ip, dst_mac, 0x1234, 1, payload, sizeof(payload));
    log_printf("ping6: sent\n");
}

void pcnet_set_ip(const uint8_t ip[4]) {
    if (!ip) return;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (uint8_t i = 0; i < 4; ++i) ns->ip_addr[i] = ip[i];
    ns->arp_valid = 0;
}

void pcnet_set_gw(const uint8_t gw[4]) {
    if (!gw) return;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (uint8_t i = 0; i < 4; ++i) ns->gw_addr[i] = gw[i];
    ns->arp_valid = 0;
}

void pcnet_set_mask(const uint8_t mask[4]) {
    if (!mask) return;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (uint8_t i = 0; i < 4; ++i) ns->netmask[i] = mask[i];
}

void pcnet_get_ip(uint8_t out[4]) {
    if (!out) return;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (uint8_t i = 0; i < 4; ++i) out[i] = ns->ip_addr[i];
}

void pcnet_get_gw(uint8_t out[4]) {
    if (!out) return;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (uint8_t i = 0; i < 4; ++i) out[i] = ns->gw_addr[i];
}

void pcnet_get_mask(uint8_t out[4]) {
    if (!out) return;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (uint8_t i = 0; i < 4; ++i) out[i] = ns->netmask[i];
}

void pcnet_get_mac(uint8_t out[6]) {
    if (!out) return;
    for (uint8_t i = 0; i < 6; ++i) out[i] = g_pcnet_mac[i];
}

void pcnet_get_ipv6(uint8_t out[16]) {
    if (!out) return;
    struct net_namespace *ns = pcnet_tx_ns();
    if (!ns) return;
    for (uint8_t i = 0; i < 16; ++i) out[i] = ns->ipv6_addr[i];
}
