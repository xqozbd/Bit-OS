#ifndef KERNEL_FIREWALL_H
#define KERNEL_FIREWALL_H

#include <stdint.h>

enum fw_action {
    FW_ACTION_ACCEPT = 0,
    FW_ACTION_DROP = 1
};

enum fw_proto {
    FW_PROTO_ANY = 0,
    FW_PROTO_ICMP = 1,
    FW_PROTO_TCP = 6,
    FW_PROTO_UDP = 17
};

struct fw_rule {
    uint8_t proto;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t src_ip_any;
    uint8_t dst_ip_any;
    uint8_t src_port_any;
    uint8_t dst_port_any;
    uint8_t action;
};

void firewall_init(void);
void firewall_clear(void);
int firewall_add_rule(const struct fw_rule *rule);
int firewall_ipv4_allow(uint8_t proto,
                        const uint8_t src_ip[4], const uint8_t dst_ip[4],
                        uint16_t src_port, uint16_t dst_port);
void firewall_log_rules(void);

#endif /* KERNEL_FIREWALL_H */
