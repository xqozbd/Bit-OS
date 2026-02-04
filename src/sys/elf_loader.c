#include "sys/elf_loader.h"

#include <stdint.h>
#include <stddef.h>

#include "sys/vfs.h"
#include "lib/log.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "arch/x86_64/cpu.h"

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

struct elf64_shdr {
    uint32_t sh_name;
    uint32_t sh_type;
    uint64_t sh_flags;
    uint64_t sh_addr;
    uint64_t sh_offset;
    uint64_t sh_size;
    uint32_t sh_link;
    uint32_t sh_info;
    uint64_t sh_addralign;
    uint64_t sh_entsize;
};

struct elf64_rela {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
};

struct elf64_sym {
    uint32_t st_name;
    uint8_t  st_info;
    uint8_t  st_other;
    uint16_t st_shndx;
    uint64_t st_value;
    uint64_t st_size;
};

enum { PT_LOAD = 1 };
enum { SHT_RELA = 4, SHT_SYMTAB = 2, SHT_STRTAB = 3 };
enum { R_X86_64_64 = 1, R_X86_64_RELATIVE = 8 };

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

static int apply_relocations(const uint8_t *data, uint64_t size, const struct elf64_ehdr *eh) {
    if (eh->e_shoff == 0 || eh->e_shnum == 0 || eh->e_shentsize != sizeof(struct elf64_shdr)) {
        return 0;
    }
    if (eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(struct elf64_shdr) > size) {
        log_printf("elf: shdrs out of range\n");
        return -1;
    }

    const struct elf64_shdr *sh = (const struct elf64_shdr *)(data + eh->e_shoff);
    for (uint16_t i = 0; i < eh->e_shnum; ++i) {
        if (sh[i].sh_type != SHT_RELA) continue;
        if (sh[i].sh_offset + sh[i].sh_size > size || sh[i].sh_entsize != sizeof(struct elf64_rela)) {
            log_printf("elf: rela out of range\n");
            return -2;
        }
        const struct elf64_rela *rela = (const struct elf64_rela *)(data + sh[i].sh_offset);
        uint64_t count = sh[i].sh_size / sizeof(struct elf64_rela);

        const struct elf64_sym *symtab = NULL;
        const char *strtab = NULL;
        if (sh[i].sh_link < eh->e_shnum) {
            const struct elf64_shdr *sym_sh = &sh[sh[i].sh_link];
            if (sym_sh->sh_type == SHT_SYMTAB && sym_sh->sh_offset + sym_sh->sh_size <= size) {
                symtab = (const struct elf64_sym *)(data + sym_sh->sh_offset);
                if (sym_sh->sh_link < eh->e_shnum) {
                    const struct elf64_shdr *str_sh = &sh[sym_sh->sh_link];
                    if (str_sh->sh_type == SHT_STRTAB && str_sh->sh_offset + str_sh->sh_size <= size) {
                        strtab = (const char *)(data + str_sh->sh_offset);
                    }
                }
            }
        }

        for (uint64_t r = 0; r < count; ++r) {
            uint32_t type = (uint32_t)(rela[r].r_info & 0xffffffffu);
            uint32_t sym = (uint32_t)(rela[r].r_info >> 32);
            uint64_t *where = (uint64_t *)(uintptr_t)rela[r].r_offset;
            switch (type) {
                case R_X86_64_RELATIVE:
                    *where = (uint64_t)rela[r].r_addend;
                    break;
                case R_X86_64_64:
                    if (symtab) {
                        uint64_t sval = symtab[sym].st_value;
                        *where = sval + (uint64_t)rela[r].r_addend;
                    } else {
                        log_printf("elf: R_X86_64_64 without symtab\n");
                    }
                    break;
                default:
                    (void)strtab;
                    log_printf("elf: unsupported reloc type %u\n", (unsigned)type);
                    break;
            }
        }
    }
    return 0;
}

static void *build_stack(int argc, char **argv, char **envp, uint64_t *out_rsp, uint64_t *out_argv, uint64_t *out_envp) {
    const uint64_t stack_pages = 4;
    const uint64_t stack_size = stack_pages * 0x1000ull;
    uint64_t stack_base = 0xFFFF8000F0000000ull;
    for (uint64_t off = 0; off < stack_size; off += 0x1000ull) {
        uint64_t phys = pmm_alloc_frame();
        if (phys == 0) return NULL;
        if (paging_map_4k(stack_base + off, phys, 0) != 0) return NULL;
    }
    uint64_t sp = stack_base + stack_size;

    /* Copy strings */
    uint64_t str_top = sp;
    for (int i = argc - 1; i >= 0; --i) {
        const char *s = argv ? argv[i] : NULL;
        if (!s) continue;
        size_t len = 0;
        while (s[len]) len++;
        str_top -= (len + 1);
        memcpy((void *)(uintptr_t)str_top, s, len + 1);
        argv[i] = (char *)(uintptr_t)str_top;
    }
    if (envp) {
        for (int i = 0; envp[i]; ++i) {
            size_t len = 0;
            while (envp[i][len]) len++;
            str_top -= (len + 1);
            memcpy((void *)(uintptr_t)str_top, envp[i], len + 1);
            envp[i] = (char *)(uintptr_t)str_top;
        }
    }

    /* Align and build pointers */
    uint64_t ptr = (str_top & ~0xFULL);
    ptr -= 8;
    *(uint64_t *)(uintptr_t)ptr = 0; /* envp NULL */
    uint64_t envp_ptr = ptr;
    if (envp) {
        int envc = 0;
        while (envp[envc]) envc++;
        for (int i = envc - 1; i >= 0; --i) {
            ptr -= 8;
            *(uint64_t *)(uintptr_t)ptr = (uint64_t)(uintptr_t)envp[i];
        }
        envp_ptr = ptr;
    }
    ptr -= 8;
    *(uint64_t *)(uintptr_t)ptr = 0; /* argv NULL */
    uint64_t argv_ptr = ptr;
    for (int i = argc - 1; i >= 0; --i) {
        ptr -= 8;
        *(uint64_t *)(uintptr_t)ptr = (uint64_t)(uintptr_t)argv[i];
    }
    argv_ptr = ptr;
    ptr -= 8;
    *(uint64_t *)(uintptr_t)ptr = (uint64_t)argc;

    *out_rsp = ptr;
    *out_argv = argv_ptr;
    *out_envp = envp_ptr;
    return (void *)(uintptr_t)stack_base;
}

int elf_load_and_run(const char *path, int argc, char **argv, char **envp) {
    const uint8_t *data = NULL;
    uint64_t size = 0;
    int node = vfs_resolve(vfs_resolve(0, "/"), path);
    if (node < 0) {
        log_printf("elf: not found\n");
        return -1;
    }
    if (!vfs_read_file(node, &data, &size) || !data || size < sizeof(struct elf64_ehdr)) {
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

    if (apply_relocations(data, size, eh) != 0) {
        log_printf("elf: relocations failed\n");
        return -10;
    }

    uint64_t rsp = 0, argv_ptr = 0, envp_ptr = 0;
    if (!build_stack(argc, argv, envp, &rsp, &argv_ptr, &envp_ptr)) {
        log_printf("elf: stack setup failed\n");
        return -11;
    }

    log_printf("elf: running entry %p (kernel mode)\n", (void *)(uintptr_t)eh->e_entry);
    void (*entry)(int, char **, char **) = (void (*)(int, char **, char **))(uintptr_t)eh->e_entry;
#if defined(__GNUC__) || defined(__clang__)
    __asm__ volatile(
        "mov %0, %%rsp\n"
        "mov %1, %%rdi\n"
        "mov %2, %%rsi\n"
        "mov %3, %%rdx\n"
        "xor %%rbp, %%rbp\n"
        "call *%4\n"
        :
        : "r"(rsp), "r"((uint64_t)argc), "r"(argv_ptr), "r"(envp_ptr), "r"(entry)
        : "memory");
#else
    (void)rsp; (void)argv_ptr; (void)envp_ptr;
    entry(argc, argv, envp);
#endif
    return 0;
}
