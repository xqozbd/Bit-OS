# BitOS TODO

## Completed
- [x] Grab info from CMOS such as time and date.
- [x] Set up IDT and exception handlers (avoid triple-faults, enable debug output).
- [x] Add serial logger (COM1) for early-boot diagnostics.
- [x] Implement physical memory map parsing (Limine memmap request).
- [x] Build a simple physical frame allocator (bitmap).
- [x] Add paging + higher-half mapping.
- [x] Create a minimal kernel heap allocator.
- [x] Add a framebuffer status banner (BitOS version/build info).
- [x] Add keyboard input (PS/2 or HID later).
- [x] Interrupt-driven PS/2 keyboard (IRQ1) with key repeat.
- [x] Add a minimal console with built-in commands (help, ls, cd, pwd, time, mem, echo, ver, clear).
- [x] SMP bring-up (Limine MP).
- [x] PIT/APIC timer + timekeeping (uptime and RTC sync).
- [x] Page fault handler with fault reason logging.
- [x] Limine module loading as an initramfs.
- [x] Basic VFS layer and in-memory FS for `ls/cd/cat`.
- [x] Shell history + line editing (up/down, backspace).
- [x] Heap free list (kfree).
- [x] Heap reallocation support (krealloc).
- [x] Shell tab completion.
- [x] Syscall ABI and userspace ELF loader.
- [x] Add in a cursor.
- [x] SMP bring-up and per-CPU data.

## Next
- [ ] Add in networking. Write ethernet AMD PCNet PCI driver (VirtualBox supports this card)
 
