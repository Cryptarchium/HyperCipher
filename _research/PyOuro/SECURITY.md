# Security Policy

## Supported Versions
At this time, only the latest release (`master` branch) is officially supported for security updates. 

Since PyOuro is a Digital Rights Management (DRM) and Anti-Tampering framework, security is our absolute highest priority. 

## Reporting a Vulnerability

If you discover a technique that successfully bypasses PyOuro's protections (e.g. Memory Dumping, Interpreter Hooking, Cryptographic flaws, or Licensing bypasses), we want to hear about it immediately!

**Please do NOT open a public GitHub issue for an active bypass.** 

Instead, please email the security team at `gabriele.locascio99@gmail.com` with the following details:
1. A description of the vulnerability or bypass technique.
2. The exact operating system and Python version used.
3. Proof of Concept (PoC) code or steps to reproduce the exploit.

We will acknowledge receipt of your vulnerability report within 48 hours and work with you to patch the architecture. 

## Red Team Contributions
If you are a Reverse Engineer and you manage to break the protection, congratulations! We encourage you to submit your findings so we can integrate mitigations (such as Kernel-Level checks, Anti-Debug techniques, etc.) into the `docs/SECURITY_ROADMAP.md` roadmap.
