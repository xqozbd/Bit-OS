#include "kernel/firewall.h"

#include <stddef.h>

#include "kernel/netns.h"
#include "lib/log.h"
#include "lib/strutil.h"

static struct net_namespace *firewall_ns(void) {
    struct net_namespace *ns = netns_current();
    return ns ? ns : netns_root();
}

void firewall_init(void) {
    firewall_clear();
}

void firewall_clear(void) {
    struct net_namespace *ns = firewall_ns();
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

int firewall_add_rule(const struct fw_rule *rule) {
    struct net_namespace *ns = firewall_ns();
    if (!ns) return -1;
    if (!rule) return -1;
    if (ns->rule_count >= FW_RULES_MAX) return -1;
    ns->rules[ns->rule_count++] = *rule;
    return 0;
}

static int ip_match(const uint8_t a[4], const uint8_t b[4]) {
    return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

int firewall_ipv4_allow(uint8_t proto,
                        const uint8_t src_ip[4], const uint8_t dst_ip[4],
                        uint16_t src_port, uint16_t dst_port) {
    struct net_namespace *ns = firewall_ns();
    if (!ns) return 1;
    for (uint32_t i = 0; i < ns->rule_count; ++i) {
        const struct fw_rule *r = &ns->rules[i];
        if (r->proto != FW_PROTO_ANY && r->proto != proto) continue;
        if (!r->src_ip_any && !ip_match(r->src_ip, src_ip)) continue;
        if (!r->dst_ip_any && !ip_match(r->dst_ip, dst_ip)) continue;
        if (!r->src_port_any && r->src_port != src_port) continue;
        if (!r->dst_port_any && r->dst_port != dst_port) continue;
        return r->action == FW_ACTION_ACCEPT;
    }
    return 1;
}

void firewall_log_rules(void) {
    struct net_namespace *ns = firewall_ns();
    if (!ns) return;
    log_printf("Firewall rules: %u\n", (unsigned)ns->rule_count);
    for (uint32_t i = 0; i < ns->rule_count; ++i) {
        const struct fw_rule *r = &ns->rules[i];
        const char *p = "any";
        if (r->proto == FW_PROTO_ICMP) p = "icmp";
        else if (r->proto == FW_PROTO_TCP) p = "tcp";
        else if (r->proto == FW_PROTO_UDP) p = "udp";
        log_printf("[%u] %s %s %s:%s -> %s:%s\n",
                   (unsigned)i,
                   r->action == FW_ACTION_ACCEPT ? "accept" : "drop",
                   p,
                   r->src_ip_any ? "any" : "",
                   r->src_port_any ? "any" : "",
                   r->dst_ip_any ? "any" : "",
                   r->dst_port_any ? "any" : "");
        if (!r->src_ip_any || !r->dst_ip_any || !r->src_port_any || !r->dst_port_any) {
            log_printf("    src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u\n",
                       r->src_ip[0], r->src_ip[1], r->src_ip[2], r->src_ip[3],
                       (unsigned)r->src_port,
                       r->dst_ip[0], r->dst_ip[1], r->dst_ip[2], r->dst_ip[3],
                       (unsigned)r->dst_port);
        }
    }
}
