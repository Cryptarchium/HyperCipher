# Contributing to PyVault

First off, thank you for considering contributing to PyVault! It's people like you that make this open-source DRM tool stronger and more resilient.

## How Can I Contribute?

### 1. Reverse Engineering & Red Teaming
The best way to improve PyVault is to break it. If you have experience with reverse engineering, memory dumping (Cheat Engine, x64dbg), or API hooking (Frida):
- Try to bypass the RSA Licensing check.
- Try to extract the `master_key` from memory.
- Try to dump the Python bytecode while the application is running.

If you succeed, please read the [SECURITY.md](SECURITY.md) file and report the vulnerability privately so we can design a mitigation.

### 2. Implementing the "Roadmap" (C/C++ Skills Needed)
We are actively looking for developers with low-level C and C++ experience to help implement the mitigations listed in `docs/SECURITY_ROADMAP.md`. Specifically:
- **Cross-Platform OS-Level Anti-Debugging**: Implementing `ptrace` for Linux/macOS and PEB scanning for Windows directly inside the Cython Bootloader.
- **Native Hardware Fingerprinting**: Writing C extensions that use `DeviceIoControl` (Windows) or `IOKit` (macOS) to fetch hardware serials, bypassing Python's `subprocess` module completely.

### 3. Pull Requests
1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the Branch (`git push origin feature/AmazingFeature`).
5. Open a Pull Request.

## Coding Standards
- PyVault's core is written in Python and Cython.
- Ensure that any new Python code is compatible with Cython compilation. Avoid highly dynamic features (like `eval` or `exec`) in the core logic unless absolutely necessary, as they are difficult to secure.
- Comment complex cryptographic logic thoroughly.

Welcome to the PyVault Security Team!
