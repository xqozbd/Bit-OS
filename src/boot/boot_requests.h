#ifndef BOOT_REQUESTS_H
#define BOOT_REQUESTS_H

#include "lib/compat.h"
#include "boot/limine.h"

extern volatile uint64_t limine_base_revision[];
extern volatile struct limine_framebuffer_request framebuffer_request;
extern volatile struct limine_hhdm_request hhdm_request;
extern volatile struct limine_memmap_request memmap_request;
extern volatile struct limine_mp_request mp_request;
extern volatile struct limine_bootloader_info_request bootloader_request;
extern volatile struct limine_executable_file_request exec_file_request;
extern volatile struct limine_executable_address_request exec_addr_request;
extern volatile struct limine_module_request module_request;

#endif /* BOOT_REQUESTS_H */
