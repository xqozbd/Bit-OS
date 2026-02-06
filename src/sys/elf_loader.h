#ifndef ELF_LOADER_H
#define ELF_LOADER_H

#include <stdint.h>
#include <stddef.h>

int elf_load_and_run(const char *path, int argc, char **argv, char **envp);
int elf_load_user(const char *path, int argc, char **argv, char **envp,
                  uint64_t *out_entry, uint64_t *out_pml4, uint64_t *out_rsp,
                  uint64_t *out_stack_top, uint64_t *out_stack_size);

#endif /* ELF_LOADER_H */
