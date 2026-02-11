# Security Policy

BitOS is a low-level OS project. Please report security issues privately so we can confirm impact and ship a fix before public disclosure.

**Supported Versions**
- Only the latest `main` branch is supported for security fixes.
- Release tags are not guaranteed to receive backports.
- If you are on an older tag, rebase or cherry-pick the fix from `main`.

**Reporting a Vulnerability**
- Preferred: use GitHub Security Advisories and click "Report a vulnerability" if it is enabled.
- If that option is not available, open a private issue with the label `security` and mark it confidential.
- Do not file a public issue for a security report.

**What to Include**
- Clear description of the issue and impact.
- Steps to reproduce with minimal dependencies.
- Affected files, subsystems, and commit range if known.
- Proof of concept code or logs.
- Build and run environment details:
  - Host OS and version
  - VM type and version (VirtualBox or VMware)
  - CPU model and RAM
  - Build log if relevant
- Whether the issue is reliable or timing sensitive.

**Severity Guidance**
- Critical: kernel memory corruption, privilege escalation, or arbitrary code execution.
- High: information disclosure or persistent integrity compromise.
- Medium: denial of service or crash with limited scope.
- Low: non-exploitable bugs, minor leaks, or hard-to-trigger issues.

**Response Timeline**
- Initial response within 7 days.
- Status updates at least every 14 days until closure.
- Fix priority depends on severity and reproducibility.

**Disclosure**
- Please do not publicly disclose until a fix or mitigation is available.
- We will coordinate disclosure and credit if desired.
- If you want attribution, include your preferred name and link.

**Out of Scope**
- Issues in dependencies outside this repo unless a concrete impact in BitOS is shown.
- Vulnerabilities requiring physical access or hardware-level attacks unless they are specific to BitOS behavior.
- Non-security bugs or performance issues. File those as normal issues.
