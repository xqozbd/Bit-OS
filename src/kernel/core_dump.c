#include "kernel/core_dump.h"

#include <stddef.h>
#include <stdint.h>

#include "kernel/heap.h"
#include "kernel/task.h"
#include "lib/log.h"
#include "lib/strutil.h"
#include "sys/vfs.h"

extern void *memcpy(void *restrict dest, const void *restrict src, size_t n);

#define ELF_MAG0 0x7F
#define ELF_MAG1 'E'
#define ELF_MAG2 'L'
#define ELF_MAG3 'F'

#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define EV_CURRENT 1
#define ET_CORE 4
#define EM_X86_64 62
#define PT_NOTE 4

struct elf64_ehdr {
    uint8_t e_ident[16];
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
} __attribute__((packed));

struct elf64_phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} __attribute__((packed));

struct elf64_nhdr {
    uint32_t n_namesz;
    uint32_t n_descsz;
    uint32_t n_type;
} __attribute__((packed));

struct core_note {
    uint32_t pid;
    uint32_t tid;
    uint64_t rip;
    uint64_t rsp;
    uint64_t fault_addr;
    uint64_t err;
    char reason[32];
};

static inline uint64_t align4(uint64_t v) {
    return (v + 3u) & ~3u;
}

static void ensure_dir(const char *path) {
    if (!path || !path[0]) return;
    int node = vfs_resolve(0, path);
    if (node < 0) {
        (void)vfs_create(0, path, 1);
    }
}

void task_core_mark(struct task *t, const char *reason,
                    uint64_t fault_addr, uint64_t rip,
                    uint64_t rsp, uint64_t err) {
    if (!t) return;
    t->core_pending = 1;
    t->core_fault_addr = fault_addr;
    t->core_rip = rip;
    t->core_rsp = rsp;
    t->core_err = err;
    if (reason) {
        size_t i = 0;
        for (; i + 1 < sizeof(t->core_reason) && reason[i]; ++i) {
            t->core_reason[i] = reason[i];
        }
        t->core_reason[i] = '\0';
    } else {
        t->core_reason[0] = '\0';
    }
}

static int write_core_file(struct task *t) {
    if (!t) return 0;
    ensure_dir("/var");
    ensure_dir("/var/crash");

    char path[128];
    char pid_buf[16];
    size_t n = 0;
    uint32_t pid = t->pid;
    if (pid == 0) pid = 1;
    {
        uint32_t v = pid;
        char tmp[16];
        size_t tn = 0;
        if (v == 0) { tmp[tn++] = '0'; }
        while (v && tn < sizeof(tmp)) {
            tmp[tn++] = (char)('0' + (v % 10u));
            v /= 10u;
        }
        for (size_t i = 0; i < tn; ++i) {
            pid_buf[i] = tmp[tn - 1 - i];
        }
        pid_buf[tn] = '\0';
    }
    const char *prefix = "/var/crash/core.";
    for (size_t i = 0; prefix[i] && n + 1 < sizeof(path); ++i) path[n++] = prefix[i];
    for (size_t i = 0; pid_buf[i] && n + 1 < sizeof(path); ++i) path[n++] = pid_buf[i];
    path[n] = '\0';

    int node = vfs_create(0, path, 0);
    if (node < 0) {
        node = vfs_resolve(0, path);
    }
    if (node < 0) return 0;

    struct core_note note;
    note.pid = t->pid;
    note.tid = t->tid;
    note.rip = t->core_rip;
    note.rsp = t->core_rsp;
    note.fault_addr = t->core_fault_addr;
    note.err = t->core_err;
    for (size_t i = 0; i < sizeof(note.reason); ++i) note.reason[i] = 0;
    for (size_t i = 0; i + 1 < sizeof(note.reason) && t->core_reason[i]; ++i) {
        note.reason[i] = t->core_reason[i];
    }

    const char name[] = "CORE";
    uint32_t namesz = (uint32_t)(sizeof(name)); /* includes NUL */
    uint32_t descsz = (uint32_t)sizeof(note);
    uint64_t note_size = sizeof(struct elf64_nhdr) + align4(namesz) + align4(descsz);

    struct elf64_ehdr eh;
    for (size_t i = 0; i < sizeof(eh); ++i) ((uint8_t *)&eh)[i] = 0;
    eh.e_ident[0] = ELF_MAG0;
    eh.e_ident[1] = ELF_MAG1;
    eh.e_ident[2] = ELF_MAG2;
    eh.e_ident[3] = ELF_MAG3;
    eh.e_ident[4] = ELFCLASS64;
    eh.e_ident[5] = ELFDATA2LSB;
    eh.e_ident[6] = EV_CURRENT;
    eh.e_type = ET_CORE;
    eh.e_machine = EM_X86_64;
    eh.e_version = EV_CURRENT;
    eh.e_phoff = sizeof(struct elf64_ehdr);
    eh.e_ehsize = (uint16_t)sizeof(struct elf64_ehdr);
    eh.e_phentsize = (uint16_t)sizeof(struct elf64_phdr);
    eh.e_phnum = 1;

    struct elf64_phdr ph;
    for (size_t i = 0; i < sizeof(ph); ++i) ((uint8_t *)&ph)[i] = 0;
    ph.p_type = PT_NOTE;
    ph.p_offset = sizeof(struct elf64_ehdr) + sizeof(struct elf64_phdr);
    ph.p_filesz = note_size;
    ph.p_memsz = note_size;
    ph.p_align = 4;

    uint64_t total = ph.p_offset + note_size;
    uint8_t *buf = (uint8_t *)kmalloc((size_t)total);
    if (!buf) return 0;
    for (uint64_t i = 0; i < total; ++i) buf[i] = 0;

    size_t off = 0;
    memcpy(buf + off, &eh, sizeof(eh));
    off += sizeof(eh);
    memcpy(buf + off, &ph, sizeof(ph));
    off += sizeof(ph);

    struct elf64_nhdr nh;
    nh.n_namesz = namesz;
    nh.n_descsz = descsz;
    nh.n_type = 1;
    memcpy(buf + off, &nh, sizeof(nh));
    off += sizeof(nh);
    memcpy(buf + off, name, namesz);
    off += align4(namesz);
    memcpy(buf + off, &note, sizeof(note));
    off += align4(descsz);

    (void)vfs_write_file(node, buf, total, 0);
    kfree(buf);
    return 1;
}

void task_core_dump_try(struct task *t) {
    if (!t || !t->core_pending) return;
    if (write_core_file(t)) {
        log_printf("core-dump: wrote /var/crash/core.%u\n", (unsigned)t->pid);
    } else {
        log_printf("core-dump: failed for pid=%u\n", (unsigned)t->pid);
    }
    t->core_pending = 0;
}
