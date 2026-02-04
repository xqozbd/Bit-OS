#ifndef ELF_LOADER_H
#define ELF_LOADER_H

int elf_load_and_run(const char *path, int argc, char **argv, char **envp);

#endif /* ELF_LOADER_H */
