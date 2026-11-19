<div align="center">
  <img src="https://raw.githubusercontent.com/Gabro29/PyOuro/main/assets/logo.png" alt="PyOuro Logo" width="300" style="border-radius: 10px;" />
  <h1>PyOuro</h1>
  <p><strong>A cryptographic trust anchor and DRM framework for Python</strong></p>
</div>

---

## Overview

Python's interpreted nature makes standard source code distribution inherently vulnerable to reverse engineering. Common compilation and obfuscation techniques (such as Cython or PyInstaller) provide structural hurdles but can be reliably circumvented through memory dumping and bytecode extraction.

PyOuro addresses these limitations by shifting from obfuscation to cryptographic sealing. It binds the execution of the application directly to the host's hardware identity, ensuring that the payload remains encrypted until runtime and cannot be executed on unauthorized machines.

## Core Architecture

### 1. Hardware Cryptographic Binding
License validation relies on AES-GCM encryption rather than boolean checks. The developer's master key is encrypted using a cipher derived from the client machine's physical Hardware ID (UUID, BIOS, SMART Data). Moving the software to an unauthorized machine results in a mathematical decryption failure (`InvalidTag`).

### 2. In-Memory Decryption and RAM Wiping
The source code is compiled to bytecode and encrypted into a payload file (`payload.pyob`). Decryption occurs strictly in-memory during execution. To mitigate advanced process freezing and memory dumping attacks, PyOuro implements secure RAM wiping. If a security validation fails, the framework leverages `ctypes` to overwrite the AES keys and decrypted payload in memory with zeros before forcing a process exit.

### 3. OS-Level Anti-Debugging
PyOuro detects debuggers at multiple levels. Beyond standard Python hook detection (`sys.gettrace`), it leverages native OS kernel syscalls to detect and reject system-level debuggers (`IsDebuggerPresent` on Windows, `TracerPid` on Linux, and `ptrace` on macOS). Furthermore, PyOuro enforces standalone distribution via PyInstaller and cryptographically signs the bundled Python interpreter DLL, preventing runtime interpreter hooking.

### 4. Anti-Forensics and SSD Wear Leveling Mitigation
To prevent data remanence on solid-state drives, PyOuro feeds the source code directly into the Cython compiler at build time. Plain-text `.py` files are never written to the temporary build directories, preventing forensic recovery from unallocated NAND flash sectors.

### 5. I/O Atomicity and DoS Protection
PyOuro maintains a hardware-bound, encrypted timestamp database (`APP_time.dat`) to prevent time-shifting and replay attacks. To handle concurrent execution and prevent local Denial of Service (DoS) attacks on the state files, it uses cross-platform blocking file locks with strict timeout mechanisms.

### 6. Opaque Failure States
To hinder static analysis, PyOuro avoids descriptive error messages in its distributed binaries. Security check failures result in silent exits or opaque error codes (e.g., `Fatal Error: E01`), ensuring that an attacker cannot determine which specific protection layer was triggered.

## Installation

1. Install PyOuro:
   ```bash
   pip install pyouro
   ```
   *(Optional) To build standalone executables with PyInstaller:*
   ```bash
   pip install pyouro[standalone]
   ```

2. Initialize your project:
   ```bash
   pyouro init --entry-point main.py --payload core.py
   ```
   This generates the required cryptographic keys (`private.pem`, `public.pem`) and the `pyouro.toml` configuration file.

## Usage

### Building the Project
Compile the Python scripts into a secure, standalone executable bundle. PyInstaller is orchestrated automatically to seal the interpreter:
```bash
pyouro build 
```

### Issuing Licenses
Licenses are generated using the client's Hardware ID.
```bash
# Full license
pyouro license --hw-id "MB_12345|OS_67890" --type FULL

# 30-day trial license
pyouro license --hw-id "MB_12345|OS_67890" --type DEMO --expiry 30d
```

### Maintenance Commands
- `pyouro doctor`: Verifies the integrity of the local PyOuro environment.
- `pyouro clean`: Removes cryptographic artifacts and distribution files (creates automatic backups).
- `pyouro rebuild`: Performs a clean and build in one step.

## Security Roadmap

The `docs/SECURITY_ROADMAP.md` file tracks the history of resolved vulnerabilities and planned architectural improvements. The next major iteration focuses on:
- **Native C/C++ Hardware Fingerprinting**: Bypassing high-level OS utilities to query kernel APIs directly (`DeviceIoControl`, `IOKit`), preventing advanced rootkits from spoofing the hardware ID.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
