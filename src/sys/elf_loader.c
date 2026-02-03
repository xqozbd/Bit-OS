#include "sys/elf_loader.h"

#include <stdint.h>
#include <stddef.h>

#include "sys/fs_mock.h"
#include "lib/log.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"

/* From memutils.c */
void *memset(void *s, int c, size_t n);
void *memcpy(void *restrict dest, const void *restrict src, size_t n);

enum { ELF_MAGIC = 0x464C457Fu };

struct elf64_ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

enum { PT_LOAD = 1 };

static int map_segment(uint64_t vaddr, uint64_t memsz) {
    uint64_t start = vaddr & ~0xFFFull;
    uint64_t end = (vaddr + memsz + 0xFFF) & ~0xFFFull;
    for (uint64_t va = start; va < end; va += 0x1000ull) {
        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) return -1;
        if (paging_map_4k(va, phys, 0) != 0) return -1;
    }
    return 0;
}

int elf_load_and_run(const char *path) {
    const uint8_t *data = NULL;
    uint64_t size = 0;
    int node = fs_resolve(fs_root(), path);
    if (node < 0) {
        log_printf("elf: not found\n");
        return -1;
    }
    if (!fs_read_file(node, &data, &size) || !data || size < sizeof(struct elf64_ehdr)) {
        log_printf("elf: unreadable\n");
        return -2;
    }

    const struct elf64_ehdr *eh = (const struct elf64_ehdr *)data;
    uint32_t magic = *(const uint32_t *)&eh->e_ident[0];
    if (magic != ELF_MAGIC || eh->e_ident[4] != 2 || eh->e_ident[5] != 1) {
        log_printf("elf: bad header\n");
        return -3;
    }
    if (eh->e_phoff == 0 || eh->e_phnum == 0 || eh->e_phentsize != sizeof(struct elf64_phdr)) {
        log_printf("elf: no program headers\n");
        return -4;
    }

    if (eh->e_entry < 0xFFFF800000000000ull) {
        log_printf("elf: entry not in higher-half, unsupported\n");
        return -5;
    }

    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(struct elf64_phdr) > size) {
        log_printf("elf: phdrs out of range\n");
        return -6;
    }

    const struct elf64_phdr *ph = (const struct elf64_phdr *)(data + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_offset + ph[i].p_filesz > size) {
            log_printf("elf: segment out of range\n");
            return -7;
        }
        if (ph[i].p_vaddr < 0xFFFF800000000000ull) {
            log_printf("elf: segment not in higher-half\n");
            return -8;
        }
        if (map_segment(ph[i].p_vaddr, ph[i].p_memsz) != 0) {
            log_printf("elf: map failed\n");
            return -9;
        }
        if (ph[i].p_filesz > 0) {
            memcpy((void *)(uintptr_t)ph[i].p_vaddr, data + ph[i].p_offset, (size_t)ph[i].p_filesz);
        }
        if (ph[i].p_memsz > ph[i].p_filesz) {
            uint64_t bss = ph[i].p_vaddr + ph[i].p_filesz;
            uint64_t bss_len = ph[i].p_memsz - ph[i].p_filesz;
            memset((void *)(uintptr_t)bss, 0, (size_t)bss_len);
        }
    }

    log_printf("elf: running entry %p (kernel mode)\n", (void *)(uintptr_t)eh->e_entry);
    void (*entry)(void) = (void (*)(void))(uintptr_t)eh->e_entry;
    entry();
    return 0;
}
