#include "kernel/netns.h"
#include "kernel/task.h"

#include <stddef.h>

#include "kernel/heap.h"

#ifndef __ATOMIC_SEQ_CST
#define __ATOMIC_SEQ_CST 5
#endif

static struct net_namespace g_root_netns;
static uint8_t g_root_netns_init = 0;

static void netns_rules_reset(struct net_namespace *ns) {
    if (!ns) return;
    ns->rule_count = 0;
    for (uint32_t i = 0; i < FW_RULES_MAX; ++i) {
        ns->rules[i].proto = FW_PROTO_ANY;
        ns->rules[i].src_ip_any = 1;
        ns->rules[i].dst_ip_any = 1;
        ns->rules[i].src_port_any = 1;
        ns->rules[i].dst_port_any = 1;
        ns->rules[i].action = FW_ACTION_ACCEPT;
    }
}

static void netns_defaults(struct net_namespace *ns) {
    if (!ns) return;
    ns->ip_addr[0] = 10;
    ns->ip_addr[1] = 0;
    ns->ip_addr[2] = 2;
    ns->ip_addr[3] = 15;
    ns->gw_addr[0] = 10;
    ns->gw_addr[1] = 0;
    ns->gw_addr[2] = 2;
    ns->gw_addr[3] = 2;
    ns->netmask[0] = 255;
    ns->netmask[1] = 255;
    ns->netmask[2] = 255;
    ns->netmask[3] = 0;
    ns->arp_valid = 0;
    for (int i = 0; i < 4; ++i) ns->arp_ip[i] = 0;
    for (int i = 0; i < 6; ++i) ns->arp_mac[i] = 0;
    ns->ip_ident = 1;
    for (int i = 0; i < 16; ++i) ns->ipv6_addr[i] = 0;
    ns->ipv6_ready = 0;
    ns->ipv6_forwarding = 0;
    for (int i = 0; i < NETNS_IPV6_ND_CACHE_MAX; ++i) {
        ns->neighbors[i].valid = 0;
    }
    for (int i = 0; i < NETNS_IPV6_ROUTE_MAX; ++i) {
        ns->routes[i].valid = 0;
    }
    netns_rules_reset(ns);
}

struct net_namespace *netns_root(void) {
    if (!g_root_netns_init) {
        g_root_netns_init = 1;
        g_root_netns.id = 1;
        g_root_netns.refcount = 1;
        netns_defaults(&g_root_netns);
    }
    return &g_root_netns;
}

struct net_namespace *netns_current(void) {
    struct task *t = task_current();
    if (t && t->net_ns) return t->net_ns;
    return netns_root();
}

void netns_ref(struct net_namespace *ns) {
    if (!ns) return;
    __atomic_fetch_add(&ns->refcount, 1u, __ATOMIC_SEQ_CST);
}

void netns_unref(struct net_namespace *ns) {
    if (!ns) return;
    if (__atomic_fetch_sub(&ns->refcount, 1u, __ATOMIC_SEQ_CST) == 1u) {
        if (ns != &g_root_netns) kfree(ns);
    }
}

void netns_clone(struct net_namespace *dst, const struct net_namespace *src) {
    if (!dst || !src) return;
    *dst = *src;
    dst->refcount = 1;
}
