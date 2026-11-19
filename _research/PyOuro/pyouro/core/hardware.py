import platform
import subprocess
import hashlib
import sys

def get_windows_hwid() -> str:
    components = []
    # 1. Motherboard Serial Number
    try:
        sys_root = r"C:\Windows"
        ps_path = os.path.join(sys_root, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe')
        ps_cmd = "(Get-CimInstance Win32_BaseBoard | Select-Object -First 1).SerialNumber"
        
        output = subprocess.check_output(
            [ps_path, "-NoProfile", "-Command", ps_cmd],
            shell=False, text=True, stderr=subprocess.DEVNULL, timeout=5,
            env={'SystemRoot': sys_root}
        )
        serial = output.strip()
        if serial:
            components.append(f"MB_{serial}")
    except Exception:
        pass
        
    # 2. MachineGuid (OS Install ID)
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Cryptography") as key:
            machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
            if machine_guid:
                components.append(f"OS_{machine_guid}")
    except Exception:
        pass

    return "|".join(components)

def get_linux_hwid() -> str:
    components = []
    # 1. Machine ID (usually stable across reboots)
    try:
        with open("/etc/machine-id", "r") as f:
            components.append(f"OS_{f.read().strip()}")
    except Exception:
        pass
        
    # 2. DMI Board Serial (might require root, fail gracefully)
    try:
        with open("/sys/class/dmi/id/board_serial", "r") as f:
            components.append(f"MB_{f.read().strip()}")
    except Exception:
        pass
        
    return "|".join(components)

def get_macos_hwid() -> str:
    components = []
    # Mac Hardware UUID
    try:
        import os
        output = subprocess.check_output(
            ["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"], 
            shell=False, text=True, stderr=subprocess.DEVNULL, timeout=5,
            env={}
        )
        # Search for IOPlatformSerialNumber
        for line in output.splitlines():
            if "IOPlatformSerialNumber" in line:
                serial = line.split('"')[-2] if '"' in line else line.strip()
                if serial:
                    components.append(f"MB_{serial}")
                break
    except Exception:
        pass
        
    return "|".join(components)

def get_hardware_id() -> str:
    """
    Returns a stable SHA256 hardware identifier for the current machine.
    Explicitly excludes MAC addresses and volatile components.
    """
    os_name = platform.system().lower()
    raw_hwid = ""
    
    if os_name == "windows":
        raw_hwid = get_windows_hwid()
    elif os_name == "linux":
        raw_hwid = get_linux_hwid()
    elif os_name == "darwin":
        raw_hwid = get_macos_hwid()
    else:
        raise RuntimeError(f"Unsupported Operating System: {os_name}")
        
    # If all methods fail, fail-secure instead of falling back to hostname
    if not raw_hwid.strip() or raw_hwid == "|":
        raise RuntimeError("CRITICAL ERROR: Failed to reliably detect Hardware ID. System cannot be secured.")
        
    return hashlib.sha256(raw_hwid.encode('utf-8')).hexdigest()
