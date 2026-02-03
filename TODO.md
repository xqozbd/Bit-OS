# BitOS TODO

- Set up IDT and exception handlers (avoid triple-faults, enable debug output).
- Add serial logger (COM1) for early-boot diagnostics.
- Implement physical memory map parsing (Limine memmap request).
- Build a simple physical frame allocator (bitmap).
- Add paging + higher-half mapping.
- Create a minimal kernel heap allocator.
- Add a framebuffer status banner (BitOS version/build info).
- Add keyboard input (PS/2 or HID later).
