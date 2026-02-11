# Contributing

BitOS is a low-level OS project. Changes should be small, testable, and intentional. This guide explains how to set up the project, make changes, and submit a clean PR.

**Scope and Expectations**
- Keep commits focused. One feature or fix per commit.
- Prefer small, reviewable PRs.
- Avoid formatting-only churn in large diffs.
- Do not refactor unrelated code.
- Use ASCII in new files unless there is a clear reason not to.
- Do not change public behavior without documenting it.
- Keep changes reproducible and easy to test.

**Repo Layout**
- `src/arch/` architecture-specific code
- `src/kernel/` core kernel subsystems
- `src/drivers/` device drivers
- `src/sys/` userspace and syscall glue
- `src/lib/` shared utilities
- `iso_root/` boot image contents
- `limine/` bootloader assets

**Environment**
- Build environment is assumed to be Linux or WSL2 with a cross-compiler.
- Use LF line endings for scripts. CRLF breaks `./all` and `iso.sh`.
- If you edit scripts on Windows, run a line ending fix before build.
- Keep tools deterministic. Avoid local-only paths in committed files.

**Build and Run**
- Build: `./all`
- The build produces `BitOS.iso` and prints its size.
- If you add a new file, wire it into the build and any scripts.
- If you add a command or syscall, add a short usage note in `README.md` or `CHANGELOG.md`.
- If you change the boot flow, document it in `README.md`.

**Testing Expectations**
- At minimum, build successfully with `./all`.
- For kernel changes, boot in a VM and verify the behavior.
- For filesystem or network changes, add a minimal smoke test scenario in your PR description.
- If you add a command, show a sample invocation in the PR.
- If you change boot params, list them in the PR.

**Code Style**
- `-Wall -Wextra` clean for C.
- Use `static` for internal helpers.
- Prefer explicit control flow over clever code.
- Avoid allocations in hot paths unless required.
- Keep logs concise and actionable.
- Keep function size reasonable. Split if it becomes hard to review.
- Avoid global state unless it is the expected design for that subsystem.

**Logging and Debugging**
- Use consistent log prefixes for subsystems.
- Avoid spamming logs in hot paths.
- Debug-only logs should be guarded by a flag or build setting.

**Common Change Types**
**Syscalls**
- Add the number in `src/sys/syscall.h`.
- Implement handler in `src/sys/syscall.c`.
- Add a libc wrapper in `src/sys/libc.h`.
- Document in README or CHANGELOG.

**Commands**
- Add to command list in `src/sys/commands.c`.
- Keep help text short and consistent.
- If it needs persistent config, add a file under `/etc`.

**Drivers**
- Keep PCI probing side-effects minimal.
- Log device IDs and init status.
- Register with driver registry if applicable.
- Do not assume a specific VM. Prefer capability checks.

**Filesystems**
- Avoid blocking operations in the hot path.
- Include a basic mount/read/write validation step.
- Document any on-disk format assumptions.
- Include a failure mode description in the PR.

**Networking**
- Validate packet lengths before accessing headers.
- Do not trust input data.
- Keep checksums correct and documented.

**PR Checklist**
- Summary of changes
- How to test
- Known limitations or follow-ups
- Any data format changes or migrations
- VM configuration used for testing

**Bug Reports**
Include:
- Build log
- Repro steps
- VM or host details (VirtualBox/VMware, CPU model, RAM)
- Screenshots for visual issues
