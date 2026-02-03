# Nuke built-in rules.
.SUFFIXES:

# Final kernel output name
override OUTPUT := bitos

# Force x86_64 cross toolchain (Ubuntu)
TOOLCHAIN_PREFIX ?= x86_64-linux-gnu-

CC := $(TOOLCHAIN_PREFIX)gcc
LD := $(TOOLCHAIN_PREFIX)ld
AS := nasm

# Base flags
CFLAGS := -g -O2 -pipe
CPPFLAGS :=
NASMFLAGS := -g
LDFLAGS :=

# Internal C flags (DO NOT REMOVE)
override CFLAGS += \
    -Wall \
    -Wextra \
    -std=gnu11 \
    -ffreestanding \
    -fno-stack-protector \
    -fno-stack-check \
    -fno-lto \
    -fno-pie \
    -fno-PIC \
    -ffunction-sections \
    -fdata-sections \
    -m64 \
    -march=x86-64 \
    -mabi=sysv \
    -mno-red-zone \
    -mcmodel=kernel

# Preprocessor flags
override CPPFLAGS := \
    -I src \
    -MMD \
    -MP

# NASM flags
override NASMFLAGS := \
    -f elf64 \
    -Wall \
    $(patsubst -g,-g -F dwarf,$(NASMFLAGS))

# Linker flags (Limine-safe)
override LDFLAGS += \
    -m elf_x86_64 \
    -nostdlib \
    -static \
    -z max-page-size=0x1000 \
    --gc-sections \
    -T linker.lds

# Source discovery
override SRCFILES := $(shell find -L src -type f 2>/dev/null | LC_ALL=C sort)
override CFILES := $(filter %.c,$(SRCFILES))
override ASFILES := $(filter %.S,$(SRCFILES))
override NASMFILES := $(filter %.asm,$(SRCFILES))

override OBJ := \
    $(addprefix obj/,$(CFILES:.c=.c.o)) \
    $(addprefix obj/,$(ASFILES:.S=.S.o)) \
    $(addprefix obj/,$(NASMFILES:.asm=.asm.o))

override HEADER_DEPS := \
    $(addprefix obj/,$(CFILES:.c=.c.d)) \
    $(addprefix obj/,$(ASFILES:.S=.S.d))

# Default target
.PHONY: all
all: bin/$(OUTPUT)

# Include header deps
-include $(HEADER_DEPS)

# Link kernel
bin/$(OUTPUT): linker.lds $(OBJ)
	mkdir -p "$(dir $@)"
	$(LD) $(LDFLAGS) $(OBJ) -o $@

# Compile C
obj/%.c.o: %.c
	mkdir -p "$(dir $@)"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Compile GAS
obj/%.S.o: %.S
	mkdir -p "$(dir $@)"
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

# Compile NASM
obj/%.asm.o: %.asm
	mkdir -p "$(dir $@)"
	$(AS) $(NASMFLAGS) $< -o $@

# Clean
.PHONY: clean
clean:
	rm -rf bin obj
