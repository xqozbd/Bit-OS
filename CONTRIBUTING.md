# Contributing

BitOS is a low-level OS project. Changes should be small, testable, and intentional. This guide explains how to set up the project, make changes, and submit a clean PR.

## Scope and Expectations
- Keep commits focused. One feature or fix per commit.
- Prefer small, reviewable PRs.
- Avoid formatting-only churn in large diffs.
- Do not refactor unrelated code.
- Use ASCII in new files unless there is a clear reason not to.

## Repo Layout
- `src/arch/` architecture-specific code
- `src/kernel/` core kernel subsystems
- `src/drivers/` device drivers
- `src/sys/` userspace and syscall glue
- `src/lib/` shared utilities
- `iso_root/` boot image contents
- `limine/` bootloader assets

## Build and Run
- Build: `./all`
- The build produces `BitOS.iso` and prints its size.
- If you add a new file, wire it into the build (GNUmakefile and any scripts).
- If you add a command or syscall, add a short usage note in `README.md` or `CHANGELOG.md`.

## Testing Expectations
- At minimum, build successfully with `./all`.
- For kernel changes, boot in a VM and verify the behavior.
- For filesystem or network changes, add a minimal smoke test scenario in your PR description.

## Code Style
- `-Wall -Wextra` clean for C.
- Use `static` for internal helpers.
- Prefer explicit control flow over clever code.
- Avoid allocations in hot paths unless required.
- Keep logs concise and actionable.

## Common Change Types
### Syscalls
- Add the number in `src/sys/syscall.h`.
- Implement handler in `src/sys/syscall.c`.
- Add a libc wrapper in `src/sys/libc.h`.
- Document in README or CHANGELOG.

### Commands
- Add to command list in `src/sys/commands.c`.
- Keep help text short and consistent.
- If it needs persistent config, add a file under `/etc`.

### Drivers
- Keep PCI probing side-effects minimal.
- Log device IDs and init status.
- Register with driver registry if applicable.

### Filesystems
- Avoid blocking operations in the hot path.
- Include a basic mount/read/write validation step.
- Document any on-disk format assumptions.

## PR Checklist
- Summary of changes
- How to test
- Known limitations or follow-ups
- Any data format changes or migrations

## Bug Reports
Include:
- Build log
- Repro steps
- VM or host details (VirtualBox/VMware, CPU model, RAM)
- Screenshots for visual issues

## Security
If you believe you found a security issue, report it privately instead of opening a public issue.
