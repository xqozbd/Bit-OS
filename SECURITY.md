# Security Policy

This project is a low-level OS and runs close to hardware. Please report security issues privately.

**Supported Versions**
- Only the latest `main` branch is supported for security fixes.
- Release tags are not guaranteed to receive backports.

**Reporting a Vulnerability**
- Preferred: use GitHub Security Advisories and click "Report a vulnerability" if it is enabled.
- If that option is not available, open a private issue with the label `security` and mark it confidential.

**What to Include**
- Clear description of the issue and impact.
- Steps to reproduce.
- Affected files or subsystems.
- Build and run environment details:
  - Host OS and version
  - VM type and version (VirtualBox or VMware)
  - CPU model and RAM
  - Build log if relevant
- Any proof of concept code or logs.

**Response Timeline**
- Initial response within 7 days.
- Status updates at least every 14 days until closure.

**Disclosure**
- Please do not publicly disclose until a fix or mitigation is available.
- We will coordinate disclosure and credit if desired.

**Out of Scope**
- Issues in dependencies outside this repo unless a concrete impact in BitOS is shown.
- Vulnerabilities requiring physical access or hardware-level attacks unless they are specific to BitOS behavior.
