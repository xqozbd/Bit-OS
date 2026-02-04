#ifndef PCI_H
#define PCI_H

#include <stdint.h>

#define PCI_VENDOR_ANY 0xFFFFu
#define PCI_DEVICE_ANY 0xFFFFu
#define PCI_CLASS_ANY  0xFFu
#define PCI_SUBCLASS_ANY 0xFFu

struct pci_device {
    uint8_t bus;
    uint8_t slot;
    uint8_t func;
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    uint8_t prog_if;
    uint8_t revision;
    uint8_t header_type;
    uint8_t irq_line;
    uint8_t irq_pin;
    uint32_t bar[6];
};

struct pci_driver {
    uint16_t vendor_id;
    uint16_t device_id;
    uint8_t class_code;
    uint8_t subclass;
    int (*probe)(const struct pci_device *dev);
};

void pci_init(void);
void pci_register_driver(struct pci_driver *drv);

uint32_t pci_read_config32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
uint16_t pci_read_config16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
uint8_t pci_read_config8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset);
void pci_write_config32(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint32_t value);
void pci_write_config16(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint16_t value);
void pci_write_config8(uint8_t bus, uint8_t slot, uint8_t func, uint8_t offset, uint8_t value);

void pci_enable_bus_mastering(const struct pci_device *dev);
void pci_enable_io(const struct pci_device *dev);
void pci_enable_mem(const struct pci_device *dev);

#endif /* PCI_H */
