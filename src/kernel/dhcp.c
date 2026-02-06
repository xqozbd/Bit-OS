#include "kernel/dhcp.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "lib/compat.h"
#include "drivers/net/pcnet.h"
#include "kernel/socket.h"
#include "kernel/sleep.h"
#include "lib/log.h"

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67

#define DHCP_OP_REQUEST 1
#define DHCP_OP_REPLY   2

#define DHCP_MAGIC_COOKIE 0x63825363u

#define DHCP_MSG_DISCOVER 1
#define DHCP_MSG_OFFER    2
#define DHCP_MSG_REQUEST  3
#define DHCP_MSG_ACK      5

static uint8_t g_dns_ip[4] = {0, 0, 0, 0};

struct dhcp_packet {
    uint8_t op;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr;
    uint32_t yiaddr;
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16];
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t options[312];
} __attribute__((packed));

static void ip_from_u32(uint32_t v, uint8_t out[4]) {
    out[0] = (uint8_t)((v >> 24) & 0xFF);
    out[1] = (uint8_t)((v >> 16) & 0xFF);
    out[2] = (uint8_t)((v >> 8) & 0xFF);
    out[3] = (uint8_t)(v & 0xFF);
}

static void dhcp_build_discover(struct dhcp_packet *pkt, uint32_t xid,
                                const uint8_t mac[6]) {
    memset(pkt, 0, sizeof(*pkt));
    pkt->op = DHCP_OP_REQUEST;
    pkt->htype = 1;
    pkt->hlen = 6;
    pkt->xid = xid;
    pkt->flags = 0x8000;
    for (int i = 0; i < 6; ++i) pkt->chaddr[i] = mac[i];

    uint8_t *opt = pkt->options;
    opt[0] = 99; opt[1] = 130; opt[2] = 83; opt[3] = 99;
    opt += 4;
    *opt++ = 53; *opt++ = 1; *opt++ = DHCP_MSG_DISCOVER;
    *opt++ = 55; *opt++ = 3; *opt++ = 1; *opt++ = 3; *opt++ = 51;
    *opt++ = 255;
}

static void dhcp_build_request(struct dhcp_packet *pkt, uint32_t xid,
                               const uint8_t mac[6],
                               const uint8_t req_ip[4],
                               const uint8_t server_ip[4]) {
    memset(pkt, 0, sizeof(*pkt));
    pkt->op = DHCP_OP_REQUEST;
    pkt->htype = 1;
    pkt->hlen = 6;
    pkt->xid = xid;
    pkt->flags = 0x8000;
    for (int i = 0; i < 6; ++i) pkt->chaddr[i] = mac[i];

    uint8_t *opt = pkt->options;
    opt[0] = 99; opt[1] = 130; opt[2] = 83; opt[3] = 99;
    opt += 4;
    *opt++ = 53; *opt++ = 1; *opt++ = DHCP_MSG_REQUEST;
    *opt++ = 50; *opt++ = 4;
    for (int i = 0; i < 4; ++i) *opt++ = req_ip[i];
    *opt++ = 54; *opt++ = 4;
    for (int i = 0; i < 4; ++i) *opt++ = server_ip[i];
    *opt++ = 55; *opt++ = 3; *opt++ = 1; *opt++ = 3; *opt++ = 51;
    *opt++ = 255;
}

static int dhcp_parse_options(const uint8_t *opt, uint16_t len,
                              uint8_t *msg_type,
                              uint8_t subnet[4],
                              uint8_t router[4],
                              uint8_t server_id[4],
                              uint8_t dns[4]) {
    if (len < 4) return 0;
    if (opt[0] != 99 || opt[1] != 130 || opt[2] != 83 || opt[3] != 99) return 0;
    uint16_t i = 4;
    while (i < len) {
        uint8_t tag = opt[i++];
        if (tag == 255) break;
        if (tag == 0) continue;
        if (i >= len) break;
        uint8_t olen = opt[i++];
        if (i + olen > len) break;
        if (tag == 53 && olen == 1) {
            *msg_type = opt[i];
        } else if (tag == 1 && olen == 4) {
            for (int j = 0; j < 4; ++j) subnet[j] = opt[i + j];
        } else if (tag == 3 && olen >= 4) {
            for (int j = 0; j < 4; ++j) router[j] = opt[i + j];
        } else if (tag == 6 && olen >= 4) {
            for (int j = 0; j < 4; ++j) dns[j] = opt[i + j];
        } else if (tag == 54 && olen == 4) {
            for (int j = 0; j < 4; ++j) server_id[j] = opt[i + j];
        }
        i = (uint16_t)(i + olen);
    }
    return 1;
}

int dhcp_request(void) {
    if (!pcnet_is_ready()) {
        log_printf("DHCP: network not ready\n");
        return -1;
    }

    uint8_t saved_ip[4], saved_gw[4], saved_mask[4];
    pcnet_get_ip(saved_ip);
    pcnet_get_gw(saved_gw);
    pcnet_get_mask(saved_mask);

    uint8_t zero_ip[4] = {0, 0, 0, 0};
    pcnet_set_ip(zero_ip);

    int sid = socket_create(SOCKET_AF_INET, SOCKET_SOCK_DGRAM);
    if (sid < 0) {
        log_printf("DHCP: socket create failed\n");
        pcnet_set_ip(saved_ip);
        return -1;
    }
    socket_bind(sid, DHCP_CLIENT_PORT);

    uint8_t mac[6] = {0};
    pcnet_get_mac(mac);

    struct dhcp_packet pkt;
    uint32_t xid = 0x12345678u;
    dhcp_build_discover(&pkt, xid, mac);
    uint8_t bcast_ip[4] = {255, 255, 255, 255};
    if (socket_sendto(sid, (const uint8_t *)&pkt, sizeof(pkt), bcast_ip, DHCP_SERVER_PORT) < 0) {
        log_printf("DHCP: discover send failed\n");
        socket_close(sid);
        pcnet_set_ip(saved_ip);
        return -1;
    }
    log_printf("DHCP: discover sent\n");

    uint8_t offer_ip[4] = {0};
    uint8_t server_ip[4] = {0};
    uint8_t subnet[4] = {0};
    uint8_t router[4] = {0};
    uint8_t dns[4] = {0};
    int got_offer = 0;

    for (int attempt = 0; attempt < 20 && !got_offer; ++attempt) {
        uint8_t buf[600];
        uint8_t src_ip[4];
        uint16_t src_port = 0;
        int n = socket_recvfrom(sid, buf, sizeof(buf), src_ip, &src_port);
        if (n <= 0) {
            sleep_ms(100);
            continue;
        }
        if ((uint16_t)n < sizeof(struct dhcp_packet)) continue;
        struct dhcp_packet *rx = (struct dhcp_packet *)buf;
        if (rx->op != DHCP_OP_REPLY || rx->xid != xid) continue;

        uint8_t msg_type = 0;
        if (!dhcp_parse_options(rx->options, (uint16_t)sizeof(rx->options),
                                &msg_type, subnet, router, server_ip, dns)) {
            continue;
        }
        if (msg_type != DHCP_MSG_OFFER) continue;

        ip_from_u32(rx->yiaddr, offer_ip);
        got_offer = 1;
    }

    if (!got_offer) {
        log_printf("DHCP: no offer, using static IP\n");
        socket_close(sid);
        pcnet_set_ip(saved_ip);
        pcnet_set_gw(saved_gw);
        pcnet_set_mask(saved_mask);
        return -1;
    }

    dhcp_build_request(&pkt, xid, mac, offer_ip, server_ip);
    socket_sendto(sid, (const uint8_t *)&pkt, sizeof(pkt), bcast_ip, DHCP_SERVER_PORT);
    log_printf("DHCP: request sent\n");

    int got_ack = 0;
    for (int attempt = 0; attempt < 20 && !got_ack; ++attempt) {
        uint8_t buf[600];
        uint8_t src_ip[4];
        uint16_t src_port = 0;
        int n = socket_recvfrom(sid, buf, sizeof(buf), src_ip, &src_port);
        if (n <= 0) {
            sleep_ms(100);
            continue;
        }
        if ((uint16_t)n < sizeof(struct dhcp_packet)) continue;
        struct dhcp_packet *rx = (struct dhcp_packet *)buf;
        if (rx->op != DHCP_OP_REPLY || rx->xid != xid) continue;

        uint8_t msg_type = 0;
        if (!dhcp_parse_options(rx->options, (uint16_t)sizeof(rx->options),
                                &msg_type, subnet, router, server_ip, dns)) {
            continue;
        }
        if (msg_type != DHCP_MSG_ACK) continue;
        ip_from_u32(rx->yiaddr, offer_ip);
        got_ack = 1;
    }

    if (!got_ack) {
        log_printf("DHCP: no ACK, using static IP\n");
        socket_close(sid);
        pcnet_set_ip(saved_ip);
        pcnet_set_gw(saved_gw);
        pcnet_set_mask(saved_mask);
        return -1;
    }

    pcnet_set_ip(offer_ip);
    if (router[0] || router[1] || router[2] || router[3]) {
        pcnet_set_gw(router);
    }
    if (subnet[0] || subnet[1] || subnet[2] || subnet[3]) {
        pcnet_set_mask(subnet);
    }
    if (dns[0] || dns[1] || dns[2] || dns[3]) {
        for (int i = 0; i < 4; ++i) g_dns_ip[i] = dns[i];
    }
    log_printf("DHCP: lease IP %u.%u.%u.%u\n",
               offer_ip[0], offer_ip[1], offer_ip[2], offer_ip[3]);
    socket_close(sid);
    return 0;
}

int dhcp_get_dns(uint8_t out[4]) {
    if (!out) return -1;
    for (int i = 0; i < 4; ++i) out[i] = g_dns_ip[i];
    if (out[0] == 0 && out[1] == 0 && out[2] == 0 && out[3] == 0) return -1;
    return 0;
}
