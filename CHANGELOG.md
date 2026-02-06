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
Interrupt masking / IRQ priority routing (PIC mask/unmask + LAPIC TPR).
Driver registry (init order + status).
ACPI parsing stub (device discovery + table list command).
ACPI table presence summary (MADT/MCFG/HPET/FADT).
Kernel panic backtrace (stack walk).
Configurable boot params (Limine cmdline).
Proper shutdown/restart (ACPI S5 + reset fallback).

## Features Removed:
None

## Features Changed:
Build warnings cleaned up (log/acpi prototypes).
Driver registry output: show "not found" directly for skipped devices.
