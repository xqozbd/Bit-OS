# Contributing

BitOS is a low-level OS project. Keep changes small, testable, and intentional.

## Before You Open a PR
- Keep commits focused. One feature or fix per commit.
- Prefer small, reviewable PRs.
- Avoid formatting-only churn in large diffs.
- Do not refactor unrelated code.
- Use ASCII in new files unless there is a clear reason not to.

## Build and Test
- Build: `./all`
- If you add a new file, make sure it is wired into the build.
- If you add a command or syscall, add a short usage note in `README.md` or `CHANGELOG.md`.

## Code Style
- `-Wall -Wextra` clean for C.
- Use `static` for internal helpers.
- Keep control flow explicit and readable.
- Avoid allocations in hot paths unless required.

## PR Checklist
- Summary of changes
- How to test
- Known limitations or follow-ups

## Bug Reports
Include:
- Build log
- Repro steps
- VM or host details (VirtualBox/VMware, CPU model, RAM)
- Screenshots for visual issues

## Security
If you believe you found a security issue, report it privately instead of opening a public issue.
