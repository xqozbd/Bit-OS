## v0.1.0

## Features Added: 
APIC/PIT Timer added 
PS/2 Mouse and keyboard support added 
AMD PCNet PCI driver started 
Memory Paging added 
Console and bootscreen added 
Basic Commands added 
WatchDog added 
And much more.

## Features Removed:
None

## Features Changed: 
None

## v0.1.1b

## Features Added:
Kernel & Architecture: IDT/Exception handlers, SMP bring-up, APIC timer scheduling, and high-res TSC calibration. 

Memory Management: Physical frame allocator (bitmap), kernel heap (kfree/krealloc), and user/kernel page separation with fault recovery. 

Process & Scheduling: Preemptive scheduler with per-CPU run queues, kernel thread API, and task model (PIDs/stacks). 

Userspace Support: Syscall ABI, ELF loader (relocations/stack setup), and brk/sbrk memory allocation. 

Filesystem & I/O: VFS layer with path normalization, initramfs support, and in-memory FS (ls/cd/cat). Networking: PCI enumeration, PCNet driver (TX/RX rings), and basic stack (ARP/IPv4/ICMP). 

Power Management: ACPI AML interpreter, P/C-states, thermal zones, and S3/S4 support. UI & Console: Framebuffer mouse cursor, shell tab completion/history, line discipline (Ctrl+C/V), and serial debugging (COM1). 

General: RTC/CMOS time sync, crash dumps to RAM, and basic system commands (shutdown, debug info).

## Features Removed: 
None

## Features Changed: 
Booting sequence. 
Clear screen printing BitOS's version when the banner already does so.

## v0.1.1

## Features Added:
Kernel & Architecture: Interrupt masking / IRQ priority routing, GDT/TSS + Ring-3 entry path, and kernel panic backtrace (stack walk).

Scheduling & Memory: Per-CPU run queue load balancing, user address space layout defaults + page-table clone helpers, and userland mmap/munmap support.

Process & Syscalls: Userspace fork/exec/exit support, per-process file descriptor table + basic open/read/close syscalls, and signals (kill/ignore) with default handlers.

Storage & Filesystems: Block device layer + buffered IO, MBR/GPT partition parsing, VMware ATA PIO and AHCI SATA driver, VFS mount root, FAT32 write support (create/write/truncate), ext2 read-only driver (superblock/group/inode/dir), ext2 bitmap allocators (block/inode), ext2 create/write/truncate, ext2 unlink/rename, ext2 fsck-lite at mount, and block cache writeback polling.

Pseudo-FS: /dev, /proc, /sys skeletons plus /proc tasks and /sys drivers entries.

Networking: UDP sockets + socket syscalls, TCP sockets (connect/listen/accept + basic retransmit), TCP three-way handshake + retransmission improvements, DHCP client, and DNS stub (dotted-quad parsing).

Init & Userland: Simple init process that spawns a user shell (init/busybox/sh).

Kernel Memory: SLAB/SLUB allocator and SLAB caches for VFS nodes and inodes.

USB: xHCI controller init (MMIO map/reset + rings + port status logging) plus device manager staging (enumeration + HID keyboard/mouse and MSC hooks).

Console: VT100/ANSI color escape support.

Boot: Configurable boot params (Limine cmdline) and proper shutdown/restart (ACPI S5 + reset fallback).

Reliability: Crash isolation so user task faults no longer halt the kernel, kernel timer wheel for efficient sleep timers, and block writeback flush on shutdown/restart.

## Features Removed:
None

## Features Changed:
Build warnings cleaned up (log/acpi prototypes).
Driver registry output: show "not found" directly for skipped devices.
Watchdog behavior now configurable via cmdline (watchdog=off/log/reboot/halt) and verbose logging toggle (log=verbose).

## v0.1.1

## Features Added:
- VFS write path: added open flags (O_CREAT/O_TRUNC/O_APPEND), file creation, truncate, and size helpers across ext2/fat32.
- Journaling: redo log for ext2 root (`/.journal`) with replay on mount.
- Syscalls: listdir, mount, umount, append-aware write.
- Console: page-by-page scrollback with prompt restore, command additions (mount/umount/dd).
- Userland: new utilities `ls`, `ps`, `top`, `mount`, `umount`, `dd`; shared syscall stub header; per-binary linker script stripping notes.
- Initramfs content: service config (`/etc/services.conf`), motd, sample files under `/home/guest`, and demo log under `/var/log`.

## Features Changed:
- Kernel console scrollback made line-based and robustly restores prompt when returning to bottom.
- Init now starts services from config with simple dependencies; ISO build compiles all userland tools into initramfs using dedicated linker script.

## Features Removed:
None
