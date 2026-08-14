## v0.1.2

Desktop Boot Handoff: made `/bin/init` force the desktop target selected by the kernel instead of re-parsing argv during first userspace bring-up; this removes the hang immediately after `Boot: init started` and lets the compositor/login startup sequence run.

Userspace Entry ABI: switched init, compositor, desktop-app dispatcher, and busybox entry points to naked stack-preserving trampolines so argc/argv/envp are read from the real loader stack instead of a compiler-adjusted frame; this fixes init hanging immediately after `Boot: init started` and allows `/bin/wm` plus `/bin/dlogin` to take over the framebuffer.

Desktop Startup Visibility: init now clears the old kernel boot text and paints a userspace framebuffer startup screen with live stage checkpoints before launching the compositor/login path, and the kernel yields to init immediately after spawning it so desktop handoff starts deterministically.

## Features Added:
Desktop Runtime: added a shared desktop-app bundle (`deskapp`) with role-based launch aliases for `terminal`, `dlogin`, `files`, `settings`, `editor`, `launcher`, `clipboard`, `screenshot`, `procmon`, `crashreport`, `updatenotify`, and `open`.

Desktop Apps: added a PTY-backed terminal window, windowed/fallback desktop login app, file browser MVP, plain-text editor, settings app MVP, launcher app, clipboard editor, screenshot utility, process monitor, crash reporter, and update notifier stub.

Desktop Integration: added `/usr/share/applications`-style desktop entries, pinned shell app defaults for terminal/files/editor/launcher, MIME association table support via `/etc/mimeapps.list`, and default update feed/config payloads in the initramfs.

Window Manager / Shell Wiring: launcher defaults now expose the desktop app set, and pinned-app defaults now point at the new desktop-oriented binaries instead of the older shell/demo utilities.

Build / Initramfs: initramfs build now stages the desktop app bundle automatically, creates alias binaries from `deskapp`, and falls back to a Python `newc` archive builder when `cpio` is unavailable.

Desktop UI Toolkit: added a shared retained-mode userspace toolkit (`user/uitk.[ch]`) with row/column/grid layout, themed buttons/labels/inputs/textareas, scroll/list/table widgets, menu/context-menu/dialog primitives, icon atlas rendering, focus traversal, and accessibility metadata scaffolding.

Desktop App Integration: the desktop `settings` and `launcher` apps now render through the shared toolkit instead of ad-hoc drawing paths, including toolkit-driven actions, selection state, modal dialogs, and menu handling.

Toolkit Validation / Build: added a snapshot-style toolkit harness (`/bin/uitktest`), linked the toolkit into the desktop app bundle during initramfs staging, and normalized `iso.sh` to LF line endings so the build script runs cleanly under WSL/bash.

Text Rendering Stack: added shared userspace text services (`user/text.[ch]`) with a fallback font manager, LRU glyph cache, UTF-8 helpers, shaping/bidi skeletons, grayscale/subpixel AA options, hinting knobs, emoji fallback glyphs, selection/caret helpers, clipboard text normalization, locale-style datetime formatting, and `/bin/textbench` render-throughput coverage.

Desktop App Dispatch: replaced the desktop app bundle hardcoded launch chain with a route table, and moved initramfs app source/alias lists into scalable build variables so new desktop apps can be registered without editing control flow.

Userspace Syscall ABI: fixed the 4th-6th syscall argument register binding (`r10`, `r8`, `r9`) in `user/sys.h`; this unblocks `mmap`, `execve` environment passing, framebuffer mapping, and the compositor/login UI handoff.

## Features Removed:
None

## Features Changed:
Desktop boot images now include a first-pass userspace app stack instead of only shell-centric demo binaries.

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

Kernel: SSE/AVX XSAVE/XRSTOR context with per-CPU init, kernel stack guard overflow detection, kernel profiling counters, ELF core dump generation on task crash, userspace leak sanitizer on task exit, disk quota accounting, and kernel pipe buffers.

Sync & IPC: spinlocks/atomic helpers for SMP, futex wait/wake, kernel semaphores and condition variables exposed to userspace, advisory file locking (flock), UNIX domain sockets (AF_UNIX stream), and per-thread TLS FS base support with save/restore on context switch.

Userland & Diagnostics: libc extensions (string/memory/math/stdio), userspace logging API, /proc/cpuinfo + /proc/stat reporting (CPUID flags, kernel counters), TTY raw/cooked mode switches, and kernel memory sanitizer hooks (poison on alloc/free).

Graphics & Boot Video: framebuffer path supports packed-mask true-color formats (including 24-bit), kernel font rendering remains framebuffer-native, and boot video comes from Limine-provided UEFI/VBE framebuffer mode.

Audio: added a kernel audio skeleton with a PC speaker backend, queued tone events, and timer-sliced playback driven by a dedicated kernel worker thread; added `beep [freq_hz] [duration_ms]` console command.

Kernel Threads: device polling workers are active for PCI/USB hotplug and memory-pressure monitoring.

Process Isolation & VM: userspace tasks now run with per-task page tables (CR3/PML4 switching on schedule), and anonymous `mmap` pages are swap-backed with reclaim/eviction and swap-in on fault.

Memory Debugging: added `umem [pid]` console command to inspect live userspace memory maps, mapped bytes, resident pages, and swapped pages.

Synchronization: added kernel-level mutex primitive (`kmutex`) with ownership checks and recursive lock support for in-kernel coordination.

Scheduler Testing: added `preempttest [seconds] [threads]` command to spawn CPU-pinned workers and report context-switch/preemption activity across multiple CPUs.

Crash Recovery: added configurable kernel crash handling policy (`crash.mode` via sysctl, `crash=` boot param) with halt (default) or recovery reboot path after fatal exceptions/panics.

Sandboxing: added a userspace sandbox policy syscall (`sys_sandbox`) with per-task restrictions for device access, network sockets, mount/umount, and filesystem writes outside `/tmp`; added a `sandbox` busybox applet to launch commands under selected restrictions.

Desktop Stack: added `/dev/fb0` and `/dev/input` pseudo-devices, framebuffer mode IOCTL (`FB_IOCTL_GET_MODE`), framebuffer mmap support, input event queue (`struct input_event`) with poll/read integration, and a userspace window manager/compositor demo (`/bin/wm`) using a simple shared-memory window protocol and userspace font/text rendering.

Desktop Input Interfaces: `/dev/input` now exposes expanded keyboard/mouse events (scancode, keycode, modifiers, repeat, wheel, monotonic timestamps), per-reader fanout with dropped-event accounting, nonblocking reads, secure-input ownership, runtime keymap switching, pointer acceleration/confinement controls, hotplug event records, and shortcut reservation IOCTLs.

Desktop Display Interfaces: expanded `/dev/fb0` IOCTLs with mode/info enumeration (`GET_INFO`, `GET_MODES`, `SET_MODE` validation), clip and partial page-flip paths, vsync-wait fallback timing, display metadata (`rotation`, `dpi`), strict framebuffer bounds validation in draw syscalls, and framebuffer mmap policy checks with per-task map tracking.

Desktop UI Toolkit: added basic userspace widget primitives (panels, buttons, menus) in the WM path, including hit-testing, hover/pressed states, and menu item selection.

Desktop Shell: added a taskbar + Start launcher in userspace WM, with a launch menu that can spawn user programs (e.g. `/bin/sh`, `/bin/top`, `/bin/ps`, `/bin/hello`).

Compositor & Window Server: expanded the userspace WM into a protocol-driven compositor with a shared runtime (/tmp/wm.ipc), file-backed shared-memory window buffers, dynamic create/destroy/map/unmap handling, z-order + click-to-focus, keyboard/pointer focus dispatch, enter/leave events, damage-driven redraw scheduling, cursor composition, resize/configure-ack flow, maximize/fullscreen/minimize states, capability/version publication, per-client rate limiting, and heartbeat/hung-client detection.

Desktop Shell: expanded the WM shell layer with a fixed bottom taskbar, launcher menu, running-app task buttons with active highlighting, realtime clock, session menu (logout/reboot/shutdown), four workspace buttons, quick-launch pins loaded from `/etc/wm_pinned.conf`, `Alt+Tab` and `Alt+F2` shortcuts, a run dialog, a notification/status area, and a richer userspace-rendered desktop background.

Desktop Boot MVP: default boot target now routes through `/bin/init` in desktop mode, with `boot.mode=desktop|console` support, ordered startup gates (`input -> fb -> compositor -> shell`), compositor readiness watchdog (`/tmp/wm.ready`), auto-restart with backoff, and fallback to console login if compositor is unstable.

Desktop Reliability: desktop boot outcome now persists to `/var/log/boot-desktop.log`; safe mode now propagates to userspace init/WM and disables optional startup services/effects.

Crash Path: added best-effort framebuffer backbuffer flush before fatal halt/recovery transition.


## Features Changed:
Build warnings cleaned up (log/acpi prototypes).

Driver registry output: show "not found" directly for skipped devices.

Watchdog behavior now configurable via cmdline (watchdog=off/log/reboot/halt) and verbose logging toggle (log=verbose).

Crash behavior is now policy-driven (halt or reboot) instead of hard-coded halt-only handling.

Kernel console scrollback made line-based and robustly restores prompt when returning to bottom.

Init now starts services from config with simple dependencies; ISO build compiles all userland tools into initramfs using dedicated linker script.

Init spawn preference now chooses `/bin/init` before `/bin/login` to ensure desktop boot supervision runs by default.


## Features Removed:
None
