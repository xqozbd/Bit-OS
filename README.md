# BitOS

BitOS is a small x86_64 hobby operating system focused on clarity, simplicity, and rapid iteration. It boots via Limine, runs a framebuffer console, and provides a growing set of kernel services and drivers.

## What It Does
- Boots on x86_64 (tested in VirtualBox with Limine).
- Initializes IDT, paging, heap, and SMP (Limine MP).
- Provides a framebuffer console with line editing and a caret.
- Has a basic in-memory VFS with `ls`, `cd`, `pwd`, and `cat`.
- Includes a watchdog, RTC sync, and timekeeping.
- Supports PCI enumeration and a PCNet (AMD) PCI probe + MAC read.
- Implements a minimal syscall ABI stub and kernel-mode ELF loader.
- Includes a preemptive scheduler with per-CPU run queues and basic accounting.

## Commands
Run `help` in the console to list available commands. Typical commands include:
`help`, `clear`, `time`, `mem`, `memtest`, `cputest`, `ls`, `cd`, `pwd`, `cat`, `echo`, `ver`, `restart`.

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

## Project Structure
- `src/arch/x86_64` - CPU, IDT, paging, timer, SMP, APIC/PIT.
- `src/boot` - boot requests and boot screen.
- `src/drivers` - PCI, PS/2, RTC, video, networking.
- `src/kernel` - core kernel logic (console, heap, scheduler, watchdog).
- `src/lib` - shared utilities and logging.
- `src/sys` - syscalls, initramfs, VFS, commands.

## License
See `LICENSE`.

## TODO (Expandable)
<details>
<summary>Open TODO.md</summary>

`TODO.md`
</details>



this project is the reason i wanna blow my brains out everynight - xqozbd 2/4/26
