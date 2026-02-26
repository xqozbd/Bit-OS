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
Kernel & Architecture: Interrupt masking / IRQ priority routing, GDT/TSS + Ring-3 entry path, kernel panic backtrace (stack walk), stack canaries, and NX enforcement for user pages.

Scheduling & Memory: Per-CPU run queue load balancing, user address space layout defaults + basic ASLR (heap/stack/mmap), page-table clone helpers, userland mmap/munmap support, swap-backed virtual memory paging via swap file, file-backed memory-mapped files, and kernel heap fragmentation reduction (best-fit + tail trim).

Process & Syscalls: Userspace fork/exec/exit support, per-process file descriptor table + basic open/read/close syscalls, signals (kill/ignore) with default handlers, PID namespaces (isolated ps/proc view), mount namespaces (isolated VFS root/mounts), network namespaces (isolated sockets and firewall state), and resource limits / cgroup-like groups (tasks, fds, sockets, memory).

Storage & Filesystems: Block device layer + buffered IO, MBR/GPT partition parsing, VMware ATA PIO and AHCI SATA driver, VFS mount root, FAT32 write support (create/write/truncate), ext2 read-only driver (superblock/group/inode/dir), ext2 bitmap allocators (block/inode), ext2 create/write/truncate, ext2 unlink/rename, ext2 fsck-lite at mount, and block cache writeback polling.

Pseudo-FS: /dev, /proc, /sys skeletons plus /proc tasks and /sys drivers entries.

Networking: UDP sockets + socket syscalls, TCP sockets (connect/listen/accept + basic retransmit), TCP three-way handshake + retransmission improvements, DHCP client, DNS stub (dotted-quad parsing), basic firewall rules, and IPv6 parsing + ICMPv6 ping6 with ND + static routes + UDP over IPv6.

Init & Userland: Simple init process that spawns a user shell (init/busybox/sh), plus a Busybox-style multicall userland suite (`/bin/busybox` with applet links), and a userspace cron service (`/bin/cron`) driven by `/etc/cron.conf`.

Input & Shell: Multi-language keyboard layouts (US/DE), configurable key repeat delay/rate via sysctl, and basic `sh` script execution in busybox.

Shell: Environment variables, pipes and redirection (`|`, `<`, `>`, `>>`), and job control with foreground process groups (`&`, `fg`, `bg`, Ctrl+Z) via pipe/dup2/waitpid/execve and TTY foreground syscalls.

Console & Accounts: Basic TTY/PTY support with virtual console switching (Alt+F1..F4), file permission enforcement with `chmod`/`chown`, and UID/GID-backed login via `/etc/passwd`.

Security & FS: Added `umask`, sticky/SUID/SGID handling, exec permission checks, and simple read-ahead during ext2 file reads.

Kernel Memory: SLAB/SLUB allocator and SLAB caches for VFS nodes and inodes.

USB: xHCI controller init (MMIO map/reset + rings + port status logging) plus device manager staging (enumeration + HID keyboard/mouse and MSC hooks).

Console: VT100/ANSI color escape support.

Boot: Configurable boot params (Limine cmdline) and proper shutdown/restart (ACPI S5 + reset fallback), plus boot config file parsing from `/etc/boot.conf` or `/boot/boot.conf`.

Power Management: ACPI S3/S4 suspend/resume path with timer and input reinit on resume, plus ACPI thermal zone monitoring with periodic polling.

Reliability: Crash isolation so user task faults no longer halt the kernel, kernel timer wheel for efficient sleep timers, RTC-based alarm timers for wakeups, crash dump persistence to reserved RAM with disk flush (`/crashdump.log`), and block writeback flush on shutdown/restart.

VFS write path: added open flags (O_CREAT/O_TRUNC/O_APPEND), file creation, truncate, and size helpers across ext2/fat32.

Journaling: redo log for ext2 root (`/.journal`) with replay on mount.

Syscalls: listdir, mount, umount, append-aware write.

Console: page-by-page scrollback with prompt restore, command additions (mount/umount/dd), kernel logging levels (info/warn/error/debug), and sysctl-style kernel tunables.

Userland: new utilities `ls`, `ps`, `top`, `mount`, `umount`, `dd`; shared syscall stub header; per-binary linker script stripping notes.

Initramfs content: service config (`/etc/services.conf`), motd, sample files under `/home/guest`, and demo log under `/var/log`.

Userland ELF: dynamic linking in the user loader (DT_NEEDED + RELA relocations), shared library loading from `/lib`, and a PIE demo binary (`/bin/hello`) backed by `libu.so`.

VFS: tmpfs-backed `/tmp` mount.

Login & Accounts: login flow now supports first-boot user creation and adding additional users via `/etc/passwd`.

Filesystem: directory lookup cache, inode link-count enforcement on unlink, hard links and symbolic links (with readlink + symlink resolution), plus device node permission defaults for `/dev`.

Boot: auto-detect first valid FAT32/ext2 partition for mounting without hardcoding partition 0.

Logging & Debug: panic-time persistent log ring dump to `/var/log/kpanic.log` (with `/kpanic.log` fallback), and serial debug console input (COM1) wired into the shell.

Diagnostics: kernel heap/slab leak counters with `sysctl` exposure and a `leaks` console command.

Kernel: assertion/debug macros (KASSERT/KDEBUG), plus nicer scheduling latency via preempt-on-wake and CPU-aware enqueue.

Scheduling: per-task nice values and CPU affinity masks with syscalls.

Syscalls: added `usleep` and `nanosleep` alongside existing `sleep`.

Init: services now fall back to `/initramfs/etc/services.conf` and `/initramfs/*` binaries if the root FS is missing entries.

Time & Syscalls: userspace timer APIs (`clock_gettime`, `timer_hz`, `uptime_ticks`) with monotonic clocks, `/etc/timezone` parsing plus `time.tz_offset_min` sysctl, and basic `poll` for I/O multiplexing.

Syscall ABI: standardized negative errno returns (POSIX-like) with `ENOSYS` for unknown syscalls.

Filesystem: `/etc` and `/var/log` ensured at boot for configuration and logging.

Modules & Hotplug: kernel module registry with load/unload commands, plus periodic PCI/USB hotplug monitoring and rescan logging.

Security: syscall pointer validation rejects user access to kernel addresses (basic EFAULT gating).

RNG & Devices: simple kernel RNG with `/dev/random` and `/dev/urandom`.

Kernel: FPU state save/restore on task switch.


## Features Changed:
Build warnings cleaned up (log/acpi prototypes).

Driver registry output: show "not found" directly for skipped devices.

Watchdog behavior now configurable via cmdline (watchdog=off/log/reboot/halt) and verbose logging toggle (log=verbose).

Kernel console scrollback made line-based and robustly restores prompt when returning to bottom.

Init now starts services from config with simple dependencies; ISO build compiles all userland tools into initramfs using dedicated linker script.


## Features Removed:
None
