# BitOS

BitOS is a small x86_64 hobby operating system focused on clarity, simplicity, and rapid iteration. It boots via Limine, runs a framebuffer console, and provides a growing set of kernel services and drivers.

## What It Does
- Boots on x86_64 (tested in VirtualBox and VMware) via Limine.
- Initializes IDT, paging, heap/SLAB, SMP (Limine MP), and a preemptive scheduler.
- Framebuffer console with line editing, history, tab completion, and VT100 colors.
- Serial logging and serial console input (COM1).
- VFS with mount points, ext2 + FAT32 read/write, tmpfs `/tmp`, `/dev`/`/proc`/`/sys`.
- Userspace: fork/exec/exit, pipes/redirection, basic busybox-style shell.
- Networking: PCI enumeration, PCNet driver, IPv4/IPv6 + ICMP ping.
- Power management: ACPI S3/S4 suspend/resume, thermal zone monitoring.
- Crash dumps and persistent panic logs to disk.

## Commands
Run `help` in the console to list available commands. Typical commands include:
`help`, `clear`, `time`, `mem`, `leaks`, `memtest`, `cputest`, `ps`, `ls`, `cd`, `pwd`, `cat`,
`mount`, `umount`, `dd`, `ping`, `ping6`, `ip6`, `sysctl`, `dmesg`, `shutdown`, `restart`, `s3`, `s4`.

## Build
This project is built inside **WSL Ubuntu** on Windows. You need the x86_64 cross toolchain (`x86_64-linux-gnu-*`), `make`, and `xorriso`, plus Limine binaries.
Use LF line endings (not CRLF) for scripts like `all` and `iso.sh`.

From WSL (Ubuntu), in the project directory:
```
./all
```

The build generates `BitOS.iso` for booting in a VM. If you see Limine missing errors, place Limine release binaries in `./limine/` as required by `iso.sh`.

(Side note from xqozbd, I'm in the process of making a script (once inside WSL) that will grab all the tools and the limine binaries required to build the OS and build it for you.)

## Run (VirtualBox)
- Use a 64-bit VM.
- Enable EFI or BIOS as needed by your Limine setup.
- If you want PCNet to show up, set the VM NIC to **PCnet-FAST III (Am79C973)**.
- Attach `BitOS.iso` as the VM's optical drive and boot it.

## Run (VMware Workstation)
- Use a 64-bit VM.
- Attach `BitOS.iso` as the CD/DVD drive and set it to connect at power on.
- If you want PCNet to show up, ensure the network adapter is set to NAT.
- If you see "Could not determine boot drive", double-check the ISO is attached as CD/DVD (SATA is fine).

## Project Structure
- `src/arch/x86_64` - CPU, IDT, paging, timer, SMP, APIC/PIT.
- `src/boot` - boot requests and boot screen.
- `src/drivers` - PCI, PS/2, RTC, video, networking.
- `src/kernel` - core kernel logic (console, heap, scheduler, watchdog).
- `src/lib` - shared utilities and logging.
- `src/sys` - syscalls, initramfs, VFS, commands.

## Notes
- Persistent crash logs are written to `/var/log/kpanic.log` (fallback `/kpanic.log`).
- Crash dumps are saved as `/crashdump.log` or `/var/log/crashdump.log`.
- Login is controlled by `/etc/services.conf` (`login /bin/login`).

## Quick Links
- [LICENSE](LICENSE)
- [CHANGELOG.md](CHANGELOG.md)
- [TODO.md](TODO.md)
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
