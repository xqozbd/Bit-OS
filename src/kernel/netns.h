#ifndef KERNEL_NETNS_H
#define KERNEL_NETNS_H

#include "kernel/firewall.h"

#include <stdint.h>

#ifndef FW_RULES_MAX
#define FW_RULES_MAX 32
#endif

#define NETNS_IPV6_ND_CACHE_MAX 8
#define NETNS_IPV6_ROUTE_MAX 4

struct ipv6_neighbor {
    uint8_t ip[16];
    uint8_t mac[6];
    uint8_t valid;
};

struct ipv6_route {
    uint8_t prefix[16];
    uint8_t prefix_len;
    uint8_t next_hop[16];
    uint8_t valid;
};

struct net_namespace {
    uint32_t id;
    uint32_t refcount;
    uint8_t ip_addr[4];
    uint8_t gw_addr[4];
    uint8_t netmask[4];
    uint8_t arp_ip[4];
    uint8_t arp_mac[6];
    uint8_t arp_valid;
    uint16_t ip_ident;
    uint8_t ipv6_addr[16];
    uint8_t ipv6_ready;
    uint8_t ipv6_forwarding;
    struct ipv6_neighbor neighbors[NETNS_IPV6_ND_CACHE_MAX];
    struct ipv6_route routes[NETNS_IPV6_ROUTE_MAX];
    struct fw_rule rules[FW_RULES_MAX];
    uint32_t rule_count;
};

struct net_namespace *netns_root(void);
struct net_namespace *netns_current(void);
void netns_ref(struct net_namespace *ns);
void netns_unref(struct net_namespace *ns);
void netns_clone(struct net_namespace *dst, const struct net_namespace *src);

#endif /* KERNEL_NETNS_H */
