#ifndef XHCI_H
#define XHCI_H

struct xhci_port_info {
    unsigned char connected;
    unsigned char speed;
    unsigned int portsc;
};

int xhci_init(void);
int xhci_is_ready(void);
unsigned char xhci_port_count(void);
int xhci_port_info(unsigned char port_index, struct xhci_port_info *out);

#endif /* XHCI_H */
