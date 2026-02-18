#include "sys/elf_loader.h"

#include <stdint.h>
#include <stddef.h>

#include "sys/vfs.h"
#include "lib/log.h"
#include "arch/x86_64/paging.h"
#include "kernel/pmm.h"
#include "arch/x86_64/cpu.h"
#include "arch/x86_64/usermode.h"

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

struct elf64_dyn {
    int64_t d_tag;
    union {
        uint64_t d_val;
        uint64_t d_ptr;
    } d_un;
};

enum { PT_LOAD = 1, PT_DYNAMIC = 2 };
enum { ET_EXEC = 2, ET_DYN = 3 };
enum { PF_X = 1, PF_W = 2, PF_R = 4 };
enum { SHT_RELA = 4, SHT_SYMTAB = 2, SHT_STRTAB = 3 };
enum { R_X86_64_NONE = 0, R_X86_64_64 = 1, R_X86_64_GLOB_DAT = 6, R_X86_64_JUMP_SLOT = 7, R_X86_64_RELATIVE = 8 };
enum {
    DT_NULL = 0,
    DT_NEEDED = 1,
    DT_HASH = 4,
    DT_STRTAB = 5,
    DT_SYMTAB = 6,
    DT_RELA = 7,
    DT_RELASZ = 8,
    DT_RELAENT = 9,
    DT_STRSZ = 10,
    DT_SYMENT = 11,
    DT_PLTREL = 20,
    DT_JMPREL = 23,
    DT_PLTRELSZ = 2
};

#define ELF64_R_SYM(info) ((uint32_t)((info) >> 32))
#define ELF64_R_TYPE(info) ((uint32_t)(info))
#define ELF64_ST_BIND(info) ((uint8_t)((info) >> 4))

enum { ELF_MAX_OBJS = 8, ELF_MAX_NEEDED = 16 };

struct elf_obj {
    const uint8_t *file;
    uint64_t file_size;
    uint64_t base;
    uint64_t entry;
    const struct elf64_ehdr *eh;
    const struct elf64_phdr *ph;
    const struct elf64_dyn *dyn;
    uint64_t dyn_size;
    const struct elf64_sym *symtab;
    const char *strtab;
    uint64_t strsz;
    uint64_t syment;
    uint32_t sym_count;
    const struct elf64_rela *rela;
    uint64_t rela_sz;
    const struct elf64_rela *jmprel;
    uint64_t jmprel_sz;
    uint64_t needed_off[ELF_MAX_NEEDED];
    uint32_t needed_count;
};

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

static uint64_t align_up_u64(uint64_t v, uint64_t a) {
    return (v + a - 1) & ~(a - 1);
}

static int str_eq(const char *a, const char *b) {
    uint64_t i = 0;
    if (!a || !b) return 0;
    while (a[i] && b[i]) {
        if (a[i] != b[i]) return 0;
        i++;
    }
    return a[i] == '\0' && b[i] == '\0';
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

static int calc_load_span(const uint8_t *data, uint64_t size, const struct elf64_ehdr *eh,
                          uint64_t *out_min, uint64_t *out_max) {
    if (!out_min || !out_max) return -1;
    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(struct elf64_phdr) > size) return -2;
    const struct elf64_phdr *ph = (const struct elf64_phdr *)(data + eh->e_phoff);
    uint64_t min_vaddr = ~0ull;
    uint64_t max_vaddr = 0;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_offset + ph[i].p_filesz > size) return -3;
        if (ph[i].p_vaddr >= 0x0000800000000000ull) return -4;
        if (ph[i].p_memsz == 0) continue;
        if (ph[i].p_vaddr < min_vaddr) min_vaddr = ph[i].p_vaddr;
        uint64_t end = ph[i].p_vaddr + ph[i].p_memsz;
        if (end > max_vaddr) max_vaddr = end;
    }
    if (min_vaddr == ~0ull) return -5;
    *out_min = min_vaddr;
    *out_max = max_vaddr;
    return 0;
}

static void parse_dynamic(struct elf_obj *obj) {
    if (!obj || !obj->dyn || obj->dyn_size == 0) return;
    uint64_t count = obj->dyn_size / sizeof(struct elf64_dyn);
    for (uint64_t i = 0; i < count; ++i) {
        int64_t tag = obj->dyn[i].d_tag;
        uint64_t val = obj->dyn[i].d_un.d_val;
        if (tag == DT_NULL) break;
        if (tag == DT_STRTAB) obj->strtab = (const char *)(uintptr_t)(obj->base + val);
        if (tag == DT_SYMTAB) obj->symtab = (const struct elf64_sym *)(uintptr_t)(obj->base + val);
        if (tag == DT_STRSZ) obj->strsz = val;
        if (tag == DT_SYMENT) obj->syment = val;
        if (tag == DT_RELA) obj->rela = (const struct elf64_rela *)(uintptr_t)(obj->base + val);
        if (tag == DT_RELASZ) obj->rela_sz = val;
        if (tag == DT_JMPREL) obj->jmprel = (const struct elf64_rela *)(uintptr_t)(obj->base + val);
        if (tag == DT_PLTRELSZ) obj->jmprel_sz = val;
        if (tag == DT_HASH) {
            const uint32_t *hash = (const uint32_t *)(uintptr_t)(obj->base + val);
            if (hash) obj->sym_count = hash[1];
        }
        if (tag == DT_NEEDED && obj->needed_count < ELF_MAX_NEEDED) {
            obj->needed_off[obj->needed_count++] = val;
        }
    }
}

static uint64_t resolve_symbol(const char *name, struct elf_obj *objs, uint32_t obj_count) {
    if (!name || !objs) return 0;
    for (uint32_t o = 0; o < obj_count; ++o) {
        struct elf_obj *obj = &objs[o];
        if (!obj->symtab || !obj->strtab || obj->sym_count == 0) continue;
        for (uint32_t i = 0; i < obj->sym_count; ++i) {
            const struct elf64_sym *sym = &obj->symtab[i];
            if (sym->st_shndx == 0) continue;
            uint8_t bind = ELF64_ST_BIND(sym->st_info);
            if (bind == 0) continue;
            const char *sname = obj->strtab + sym->st_name;
            if (str_eq(sname, name)) {
                return obj->base + sym->st_value;
            }
        }
    }
    return 0;
}

static int apply_rela_list(struct elf_obj *obj, const struct elf64_rela *rela, uint64_t rela_sz,
                           struct elf_obj *objs, uint32_t obj_count) {
    if (!obj || !rela || rela_sz == 0) return 0;
    uint64_t count = rela_sz / sizeof(struct elf64_rela);
    for (uint64_t i = 0; i < count; ++i) {
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        uint32_t symi = ELF64_R_SYM(rela[i].r_info);
        uint64_t *where = (uint64_t *)(uintptr_t)(obj->base + rela[i].r_offset);
        switch (type) {
            case R_X86_64_NONE:
                break;
            case R_X86_64_RELATIVE:
                *where = obj->base + (uint64_t)rela[i].r_addend;
                break;
            case R_X86_64_64:
            case R_X86_64_GLOB_DAT:
            case R_X86_64_JUMP_SLOT: {
                if (!obj->symtab || !obj->strtab || symi >= obj->sym_count) return -1;
                const struct elf64_sym *sym = &obj->symtab[symi];
                const char *sname = obj->strtab + sym->st_name;
                uint64_t sval = 0;
                if (sym->st_shndx != 0) {
                    sval = obj->base + sym->st_value;
                } else {
                    sval = resolve_symbol(sname, objs, obj_count);
                }
                if (sval == 0) return -2;
                *where = sval + (uint64_t)rela[i].r_addend;
                break;
            }
            default:
                return -3;
        }
    }
    return 0;
}

static int load_object_at(struct elf_obj *obj, const uint8_t *data, uint64_t size,
                          uint64_t pml4, uint64_t base, uint64_t *out_max_vaddr) {
    if (!obj || !data || size < sizeof(struct elf64_ehdr)) return -1;
    const struct elf64_ehdr *eh = (const struct elf64_ehdr *)data;
    uint32_t magic = *(const uint32_t *)&eh->e_ident[0];
    if (magic != ELF_MAGIC || eh->e_ident[4] != 2 || eh->e_ident[5] != 1) return -2;
    if (eh->e_phoff == 0 || eh->e_phnum == 0 || eh->e_phentsize != sizeof(struct elf64_phdr)) return -3;
    if (eh->e_phoff + (uint64_t)eh->e_phnum * sizeof(struct elf64_phdr) > size) return -4;
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) return -5;

    const struct elf64_phdr *ph = (const struct elf64_phdr *)(data + eh->e_phoff);
    uint64_t max_vaddr = 0;
    const struct elf64_dyn *dyn = NULL;
    uint64_t dyn_sz = 0;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn = (const struct elf64_dyn *)(uintptr_t)(base + ph[i].p_vaddr);
            dyn_sz = ph[i].p_memsz;
        }
        if (ph[i].p_type != PT_LOAD) continue;
        if (ph[i].p_offset + ph[i].p_filesz > size) return -6;
        if (ph[i].p_vaddr >= 0x0000800000000000ull) return -7;
        uint64_t seg_base = base + ph[i].p_vaddr;
        uint64_t start = seg_base & ~0xFFFull;
        uint64_t end = (seg_base + ph[i].p_memsz + 0xFFF) & ~0xFFFull;
        uint64_t map_flags = (ph[i].p_flags & PF_X) ? 0 : PTE_NX;
        for (uint64_t va = start; va < end; va += 0x1000ull) {
            uint64_t phys = pmm_alloc_frame();
            if (phys == 0) return -8;
            if (paging_map_user_4k(pml4, va, phys, map_flags) != 0) return -9;
        }
        if (ph[i].p_filesz > 0) {
            memcpy((void *)(uintptr_t)seg_base, data + ph[i].p_offset, (size_t)ph[i].p_filesz);
        }
        if (ph[i].p_memsz > ph[i].p_filesz) {
            uint64_t bss = seg_base + ph[i].p_filesz;
            uint64_t bss_len = ph[i].p_memsz - ph[i].p_filesz;
            memset((void *)(uintptr_t)bss, 0, (size_t)bss_len);
        }
        if (ph[i].p_vaddr + ph[i].p_memsz > max_vaddr) {
            max_vaddr = ph[i].p_vaddr + ph[i].p_memsz;
        }
    }

    obj->file = data;
    obj->file_size = size;
    obj->base = base;
    obj->entry = base + eh->e_entry;
    obj->eh = eh;
    obj->ph = ph;
    obj->dyn = dyn;
    obj->dyn_size = dyn_sz;
    obj->symtab = NULL;
    obj->strtab = NULL;
    obj->strsz = 0;
    obj->syment = 0;
    obj->sym_count = 0;
    obj->rela = NULL;
    obj->rela_sz = 0;
    obj->jmprel = NULL;
    obj->jmprel_sz = 0;
    obj->needed_count = 0;

    if (out_max_vaddr) *out_max_vaddr = max_vaddr;
    parse_dynamic(obj);
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

static int build_user_stack(uint64_t pml4_phys, uint64_t top, uint64_t size,
                            int argc, char **argv, char **envp, uint64_t *out_rsp) {
    uint64_t rsp = 0;
    if (user_stack_build(pml4_phys, top, size, &rsp) != 0) return -1;

    uint64_t sp = top;
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

    uint64_t ptr = (str_top & ~0xFULL);
    ptr -= 8;
    *(uint64_t *)(uintptr_t)ptr = 0;
    if (envp) {
        int envc = 0;
        while (envp[envc]) envc++;
        for (int i = envc - 1; i >= 0; --i) {
            ptr -= 8;
            *(uint64_t *)(uintptr_t)ptr = (uint64_t)(uintptr_t)envp[i];
        }
    }
    ptr -= 8;
    *(uint64_t *)(uintptr_t)ptr = 0;
    for (int i = argc - 1; i >= 0; --i) {
        ptr -= 8;
        *(uint64_t *)(uintptr_t)ptr = (uint64_t)(uintptr_t)argv[i];
    }
    ptr -= 8;
    *(uint64_t *)(uintptr_t)ptr = (uint64_t)argc;

    if (out_rsp) *out_rsp = ptr;
    return 0;
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

int elf_load_user(const char *path, int argc, char **argv, char **envp,
                  struct user_addr_space *out_layout,
                  uint64_t *out_entry, uint64_t *out_pml4, uint64_t *out_rsp) {
    const uint8_t *data = NULL;
    uint64_t size = 0;
    int node = vfs_resolve(vfs_resolve(0, "/"), path);
    if (node < 0) return -1;
    if (!vfs_read_file(node, &data, &size) || !data || size < sizeof(struct elf64_ehdr)) {
        return -2;
    }

    const struct elf64_ehdr *eh = (const struct elf64_ehdr *)data;
    uint32_t magic = *(const uint32_t *)&eh->e_ident[0];
    if (magic != ELF_MAGIC || eh->e_ident[4] != 2 || eh->e_ident[5] != 1) return -3;
    if (eh->e_type != ET_EXEC && eh->e_type != ET_DYN) return -4;
    if (eh->e_entry >= 0x0000800000000000ull && eh->e_type != ET_DYN) return -5;

    uint64_t new_pml4 = paging_new_user_pml4();
    if (new_pml4 == 0) return -7;

    uint64_t old_cr3 = cpu_read_cr3();
    paging_switch_to(new_pml4);

    struct user_addr_space layout;
    paging_user_layout_default(&layout);

    struct elf_obj objs[ELF_MAX_OBJS];
    uint32_t obj_count = 0;
    uint64_t next_base = layout.mmap_base;

    uint64_t base_main = 0;
    if (eh->e_type == ET_DYN) {
        uint64_t min_vaddr = 0, max_vaddr = 0;
        if (calc_load_span(data, size, eh, &min_vaddr, &max_vaddr) != 0) {
            paging_switch_to(old_cr3);
            return -8;
        }
        base_main = align_up_u64(next_base, 0x1000ull);
        base_main -= (min_vaddr & 0xFFFull);
        if (base_main < next_base) base_main += 0x1000ull;
    }

    uint64_t max_vaddr_main = 0;
    if (load_object_at(&objs[obj_count], data, size, new_pml4, base_main, &max_vaddr_main) != 0) {
        paging_switch_to(old_cr3);
        return -9;
    }
    obj_count++;

    if (eh->e_type == ET_DYN) {
        next_base = align_up_u64(base_main + max_vaddr_main, 0x1000ull) + 0x10000ull;
        if (next_base > layout.mmap_limit) {
            paging_switch_to(old_cr3);
            return -10;
        }
    }

    const char *loaded_names[ELF_MAX_OBJS];
    uint32_t loaded_count = 0;
    const char *need_queue[ELF_MAX_NEEDED * 2];
    uint32_t need_count = 0;
    uint32_t need_head = 0;

    if (objs[0].needed_count && objs[0].strtab) {
        for (uint32_t i = 0; i < objs[0].needed_count && need_count < (ELF_MAX_NEEDED * 2); ++i) {
            need_queue[need_count++] = objs[0].strtab + objs[0].needed_off[i];
        }
    }

    while (need_head < need_count && obj_count < ELF_MAX_OBJS) {
        const char *name = need_queue[need_head++];
        int already = 0;
        for (uint32_t i = 0; i < loaded_count; ++i) {
            if (str_eq(loaded_names[i], name)) {
                already = 1;
                break;
            }
        }
        if (already) continue;

        char path_buf[128];
        uint64_t pi = 0;
        if (name[0] != '/') {
            const char *prefix = "/lib/";
            for (uint64_t i = 0; prefix[i] && pi + 1 < sizeof(path_buf); ++i) {
                path_buf[pi++] = prefix[i];
            }
        }
        for (uint64_t i = 0; name[i] && pi + 1 < sizeof(path_buf); ++i) {
            path_buf[pi++] = name[i];
        }
        path_buf[pi] = '\0';

        const uint8_t *lib_data = NULL;
        uint64_t lib_size = 0;
        int lib_node = vfs_resolve(vfs_resolve(0, "/"), path_buf);
        if (lib_node < 0 || !vfs_read_file(lib_node, &lib_data, &lib_size) || !lib_data) {
            paging_switch_to(old_cr3);
            return -11;
        }

        const struct elf64_ehdr *leh = (const struct elf64_ehdr *)lib_data;
        uint64_t min_vaddr = 0, lib_span_max = 0;
        if (calc_load_span(lib_data, lib_size, leh, &min_vaddr, &lib_span_max) != 0) {
            paging_switch_to(old_cr3);
            return -12;
        }
        uint64_t lib_base = align_up_u64(next_base, 0x1000ull);
        lib_base -= (min_vaddr & 0xFFFull);
        if (lib_base < next_base) lib_base += 0x1000ull;

        uint64_t lib_max_vaddr = 0;
        if (load_object_at(&objs[obj_count], lib_data, lib_size, new_pml4, lib_base, &lib_max_vaddr) != 0) {
            paging_switch_to(old_cr3);
            return -13;
        }
        loaded_names[loaded_count++] = name;
        obj_count++;

        next_base = align_up_u64(lib_base + lib_max_vaddr, 0x1000ull) + 0x10000ull;
        if (next_base > layout.mmap_limit) {
            paging_switch_to(old_cr3);
            return -14;
        }

        if (objs[obj_count - 1].needed_count && objs[obj_count - 1].strtab) {
            for (uint32_t i = 0; i < objs[obj_count - 1].needed_count && need_count < (ELF_MAX_NEEDED * 2); ++i) {
                need_queue[need_count++] = objs[obj_count - 1].strtab + objs[obj_count - 1].needed_off[i];
            }
        }
    }

    if (objs[0].dyn) {
        for (uint32_t i = 0; i < obj_count; ++i) {
            if (apply_rela_list(&objs[i], objs[i].rela, objs[i].rela_sz, objs, obj_count) != 0) {
                paging_switch_to(old_cr3);
                return -15;
            }
            if (apply_rela_list(&objs[i], objs[i].jmprel, objs[i].jmprel_sz, objs, obj_count) != 0) {
                paging_switch_to(old_cr3);
                return -16;
            }
        }
    } else {
        if (apply_relocations(data, size, eh) != 0) {
            paging_switch_to(old_cr3);
            return -17;
        }
    }

    uint64_t stack_top = layout.stack_top;
    uint64_t stack_size = layout.stack_size;
    uint64_t user_rsp = 0;
    if (build_user_stack(new_pml4, stack_top, stack_size, argc, argv, envp, &user_rsp) != 0) {
        paging_switch_to(old_cr3);
        return -18;
    }

    paging_switch_to(old_cr3);

    if (next_base > layout.mmap_base) {
        layout.mmap_base = align_up_u64(next_base, 0x1000ull);
    }

    if (out_entry) *out_entry = objs[0].entry;
    if (out_pml4) *out_pml4 = new_pml4;
    if (out_rsp) *out_rsp = user_rsp;
    if (out_layout) *out_layout = layout;
    return 0;
}
