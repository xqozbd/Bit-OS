# BitOS TODO
- [x] Grab info from CMOS such as time and date.
- [x] Set up IDT and exception handlers (avoid triple-faults, enable debug output).
- [x] Add serial logger (COM1) for early-boot diagnostics.
- [x] Implement physical memory map parsing (Limine memmap request).
- [x] Build a simple physical frame allocator (bitmap).
- [x] Add paging + higher-half mapping.
- [ ] Create a minimal kernel heap allocator.
- [ ] Add a framebuffer status banner (BitOS version/build info).
- [ ] Add keyboard input (PS/2 or HID later).
