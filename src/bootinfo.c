#include <stdint.h>

#include "bootinfo.h"
#include "boot_requests.h"
#include "log.h"
#include "meminfo.h"

void bootinfo_log(void) {
    if (bootloader_request.response) {
        log_printf("Bootloader: %s %s\n",
                   bootloader_request.response->name ? bootloader_request.response->name : "(unknown)",
                   bootloader_request.response->version ? bootloader_request.response->version : "");
    }

    if (exec_file_request.response && exec_file_request.response->executable_file) {
        struct limine_file *k = exec_file_request.response->executable_file;
        log_printf("Kernel: %s (%u bytes)\n",
                   k->path ? k->path : "(unknown)",
                   (unsigned)k->size);
    }

    if (module_request.response) {
        log_printf("Modules: %u\n", (unsigned)module_request.response->module_count);
        for (uint64_t i = 0; i < module_request.response->module_count; ++i) {
            struct limine_file *m = module_request.response->modules[i];
            if (!m) continue;
            log_printf("  - %s (%u bytes)\n",
                       m->path ? m->path : "(unknown)",
                       (unsigned)m->size);
        }
    }
}

void systeminfo_log(void) {
    uint64_t ram_bytes = get_usable_ram_bytes();
    if (ram_bytes > 0) {
        uint64_t gb_int = 0, gb_tenths = 0;
        format_gb_1dp(ram_bytes, &gb_int, &gb_tenths);
        log_printf("Usable RAM: %u.%u GB\n", (unsigned)gb_int, (unsigned)gb_tenths);
    } else {
        log_printf("Usable RAM: unknown\n");
    }

    if (mp_request.response) {
        log_printf("CPU cores: %u\n", (unsigned)mp_request.response->cpu_count);
    } else {
        log_printf("CPU cores: unknown\n");
    }
}
