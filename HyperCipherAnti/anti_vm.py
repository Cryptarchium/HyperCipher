# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiVM (Stage 5)
==================================
Entegre cok katmanli sanal-makine / hipervizor tespit modulu.
Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi (en guclu kaynaklar):
  [1] VMAware (kernelwernel, ~90 teknik, ~70 marka, skorlu mimari):
      tek kontrole guvenme; her teknik 0-100 skor, esik-ustu karar.
      Bu modul: GUCLU=100 / ZAYIF=30 / esik=60 (1 guclu veya 2+ zayif).
      VMAware kalibrasyonu (HYPERVISOR_BIT=100, MAC=60-destekleyici,
      esik=150/300) ile tutarli olceklenmis port.
  [2] vm-detect (InnerWarden, 20 prob, agirlikli skor):
      dmi_product/vendor/bios, hypervisor_dir, cpuinfo_flag,
      systemd_virt, pci_devices, kernel_modules, mac, scsi, acpi,
      dmesg, disk_model, qemu_fw_cfg, chassis, hwmon, temperature,
      device_tree, hostname. Tasinabilir alt-kume port edildi.
  [3] VMDetect (cev-api, Windows firmware-forensics):
      EnumSystemFirmwareTables/GetSystemFirmwareTable (ACPI+RSMB)
      ham tablo taramasi + OEMID; hardened-VMware'i yakalayan katman.
      Bu modul: ctypes ile ayni API'yi best-effort cagirir, ham
      blob'da keyword tarar; erisilemezse sessiz False.
  [4] VirtualPyDetector (VPD, Python, multi-layer):
      CPU vendor, MAC OUI, driver enum, process, timing, registry,
      filesystem. Capraz-platform iskelet buradan alinmistir.
  [5] al-khaser / pafish (paranoid-fish grid):
      WMI Win32_BIOS/BaseBoard/ComputerSystem/VideoController,
      registry HKLM\\HARDWARE\\DESCRIPTION\\System, driver
      C:\\Windows\\System32\\drivers\\VBox*.sys, servis/process
      (VBoxService/VBoxTray/vmtoolsd), MAC OUI 08:00:27, disk
      "VBOX HARDDISK", SCSI port->bus->LUN identifier.
  [6] systemd-detect-virt(1) marka tablosu:
      qemu/kvm/zvm/vmware/microsoft/oracle/powervm/xen/bochs/uml/
      parallels/bhyve/qnx/acrn + container ayirimi. Marka esleme
      bu tabloya gore normalize edilir (cloud = sanallastirilmis
      sayilir; dokumante).
  [7] Nogitsune/hooxbox/QEMU-anti-detection (hardener'larin neyi
      gizledigi = dedektorun nereye bakmasi gerektigi):
      DMI/SMBIOS, CPUID brand/hypervisor-bit, MAC OUI, disk model+seri,
      PCI vendor, ACPI OEM/Creator, TSC/RDTSC timing, paravirt leaf.
      Hardener'larin ilk gizledigi yerler en agir sinyallerdir.
  [8] VmwareHardenedLoader (multi-layer anti-detection):
      SMBIOS/ACPI spoof + CPUID mask + timing norm + backdoor port.
      Tutarsizlik ilkesi buradan: DMI temiz ama PCI/MAC kirliyse
      hardened-VM suphesi => trip (capraz-dogrulama katmani).

Entegrasyon prensibi (VMAware-skorlu kanit mimarisi): HICBIR tek zayif
kontrole guvenme. Katmanlar GUCLU (tek basina karar: dmi, cpu, firmware,
systemd, hypervisor_dir, pci) ve ZAYIF (destekleyici: mac, disk, modules,
processes, timing, cross_validation) olarak siniflidir. Karar: 1 guclu
sinyal YADA en az 2 bagimsiz zayif sinyal => VM. Tek zayif sinyal (ornegin
yalnizca timing, yalnizca bir MAC OUI) ASLA tek basina karar vermez.
Hepsi best-effort kosar, hata -> bilinmiyor (False) doner, ASLA crash
vermez. Hata mesaji OP AKTIR (hangi katman tetiklendi soylenmez).
Pin/hook butunlugu AYRI politikadir (is_environment_tampered):
hook edildi != VM'desin; guard() ikisini de denetler.

Bilinen limitler (tasinabilir cozum yok, dokumante):
  - CPUID instruction'ina dogrudan erisim yok (eBPF bile yapamaz);
    yerine /proc/cpuinfo hypervisor flag + model adi okunur.
  - RDTSC timing user-space'ta gurultuludur; esik bilerek comert tutulur
    (sadece bariz anomali trip eder, CPU throttle false-positive vermez).
  - Bulut (AWS/GCP/Azure) teknik olarak VM'dir; vendor() markayi soyler,
    is_virtualized() True doner. Mesru bulutta calisacaksa assert yerine
    vendor() ile izin-listesi yapilmasi onerilir.
  - py-spy tarzi external sampler ve kernel-seviyesi spoof (eBPF dmi_spoof
    gibi) in-process gorunmez; capraz-dogrulama tutarsizligi yakalamaya
    calisir ama garanti vermez.

Kullanim:
    from HyperCipherAnti import anti_vm
    anti_vm.assert_no_vm()              # suphe varsa VirtualMachineDetected
    if anti_vm.is_virtualized(): ...    # sessiz kontrol
    brand = anti_vm.vendor()             # "vmware"/"virtualbox"/.../"bare-metal"/"unknown"
    stop = anti_vm.start_watchdog(interval=2.0)  # arka plan izleme
    stop()                               # izlemeyi durdur
"""

from __future__ import annotations

import ctypes
import os
import platform
import re
import struct
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

__all__ = [
    "VirtualMachineDetected",
    "is_virtualized",
    "check_all",
    "evidence",
    "score",
    "assert_no_vm",
    "is_environment_tampered",
    "assert_no_tamper",
    "vendor",
    "set_verbose",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
    "status",
]


class VirtualMachineDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Pin'li referanslar (import aninda sabitle; canli degerle caprazla)
# ---------------------------------------------------------------------------

_SYS_PLATFORM = sys.platform
_PLATFORM_SYS = platform.system().lower()
_OS_ENVIRON = os.environ
_PERF_COUNTER = time.perf_counter
_MONOTONIC = time.monotonic
_OS_EXIT = os._exit
_UUID_GETNODE = uuid.getnode
_BUILTIN_OPEN = open
_OS_LISTDIR = os.listdir
_OS_PATH_EXISTS = os.path.exists
_OS_PATH_ISFILE = os.path.isfile
_OS_PATH_ISDIR = os.path.isdir
_OS_PATH_JOIN = os.path.join
_OS_ACCESS = os.access
_SUBPROCESS_RUN = subprocess.run
_TIME_SLEEP = time.sleep
_RE_SEARCH = re.search
_RE_FINDALL = re.findall
_RE_MATCH = re.match
_RE_COMPILE = re.compile
_RE_SPLIT = re.split
_PIN_MOD_WINREG = sys.modules.get("winreg")
_PIN_MOD_CTYPES = sys.modules.get("ctypes")
_PIN_MOD_STRUCT = sys.modules.get("struct")
_PIN_MOD_THREADING = sys.modules.get("threading")
_PIN_MOD_SUBPROCESS = sys.modules.get("subprocess")
_PIN_MOD_UUID = sys.modules.get("uuid")
try:
    _PIN_STRUCT_UNPACK = struct.unpack_from
except Exception:
    _PIN_STRUCT_UNPACK = None
try:
    _PIN_THREAD_EVENT = threading.Event
except Exception:
    _PIN_THREAD_EVENT = None
try:
    _PIN_THREAD_THREAD = threading.Thread
except Exception:
    _PIN_THREAD_THREAD = None


# ---------------------------------------------------------------------------
# Imza tablolari
# ---------------------------------------------------------------------------

# DMI/SMBIOS/BIOS/CPU/disk kalibi -> marka. Hepsi kucuk harf karsilastirilir.
# Deger: marka etiketi. "cloud-*" de sanallastirilmis sayilir.
_DMI_BRANDS: Tuple[Tuple[str, str], ...] = (
    ("innotek", "virtualbox"),
    ("virtualbox", "virtualbox"),
    ("vbox", "virtualbox"),
    ("oracle vm", "virtualbox"),
    ("vmware", "vmware"),
    ("microsoft hv", "hyper-v"),
    ("hyper-v", "hyper-v"),
    ("viridian", "hyper-v"),
    ("virtual machine", "hyper-v"),
    ("qemu", "qemu"),
    ("kvm", "kvm"),
    ("bochs", "bochs"),
    ("parallels", "parallels"),
    ("xen", "xen"),
    ("xensource", "xen"),
    ("bhyve", "bhyve"),
    ("acrn", "acrn"),
    ("powervm", "powervm"),
    ("uml", "uml"),
    ("amazon ec2", "cloud-aws"),
    ("google compute", "cloud-gcp"),
    ("google cloud", "cloud-gcp"),
    ("azure", "cloud-azure"),
    ("droplet", "cloud-do"),
    ("digitalocean", "cloud-do"),
    ("linode", "cloud-linode"),
    ("vultr", "cloud-vultr"),
    ("hetzner", "cloud-hetzner"),
    ("ovh", "cloud-ovh"),
    ("openstack", "cloud-openstack"),
    ("nutanix", "nutanix"),
    ("efi development kit", "qemu"),
    ("ovmf", "qemu"),
    ("seabios", "qemu"),
    ("edk ii", "qemu"),
)

# PCI vendor ID -> marka (VMAware/VMDetect haritasi).
_PCI_VENDORS: Dict[str, str] = {
    "15ad": "vmware",
    "1414": "hyper-v",
    "80ee": "virtualbox",
    "1af4": "qemu",
    "1b36": "qemu",
    "5853": "xen",
    "1ab8": "parallels",
    "1234": "bochs",
}

# MAC OUI (ilk 3 byte) -> marka. uuid.getnode + sysfs taramasi.
# 00:03:FF Hyper-V (YARA-VM kumesinde bagimsiz kaynak); nitro YOK
# (Acer Nitro oyuncu-laptoplarinda FP uretir, kaldirildi).
_MAC_OUIS: Dict[str, str] = {
    "08:00:27": "virtualbox",
    "00:0c:29": "vmware",
    "00:1c:14": "vmware",
    "00:50:56": "vmware",
    "00:05:69": "vmware",
    "00:03:ff": "hyper-v",
    "00:15:5d": "hyper-v",
    "52:54:00": "qemu",
    "00:16:3e": "xen",
    "00:16:e3": "xen",
    "00:1c:42": "parallels",
}

# Disk model anahtarlari -> marka.
_DISK_BRANDS: Tuple[Tuple[str, str], ...] = (
    ("vbox", "virtualbox"),
    ("virtualbox", "virtualbox"),
    ("vmware", "vmware"),
    ("virtual disk", "hyper-v"),
    ("msft", "hyper-v"),
    ("qemu", "qemu"),
    ("virtio", "qemu"),
    ("amazon", "cloud-aws"),
    ("ebs", "cloud-aws"),
    ("google", "cloud-gcp"),
)

# Kernel modul / surucu adi -> marka.
_MODULE_BRANDS: Tuple[Tuple[str, str], ...] = (
    ("vboxguest", "virtualbox"),
    ("vboxsf", "virtualbox"),
    ("vboxvideo", "virtualbox"),
    ("vmw_balloon", "vmware"),
    ("vmwgfx", "vmware"),
    ("vmxnet", "vmware"),
    ("hv_vmbus", "hyper-v"),
    ("hv_storvsc", "hyper-v"),
    ("hv_netvsc", "hyper-v"),
    ("virtio", "qemu"),
    ("xen_blkfront", "xen"),
    ("xen_netfront", "xen"),
    ("bochs", "bochs"),
)

# Process / servis / dosya artefaktlari (kucuk harf icerir-karsilastirma).
_PROCESS_KEYWORDS: Tuple[str, ...] = (
    "vboxservice",
    "vboxtray",
    "vmtoolsd",
    "vmwaretray",
    "vmwareuser",
    "qemu-ga",
    "vdagent",
    "xenstore",
    "prl_cc",
    "prl_tools",
    "vmusrvc",
)

_DRIVER_FILES: Tuple[str, ...] = (
    "vboxguest.sys",
    "vboxmouse.sys",
    "vboxsf.sys",
    "vboxvideo.sys",
    "vmmouse.sys",
    "vmhgfs.sys",
    "vmxnet.sys",
    "vmusbmouse.sys",
)

_GUEST_PATHS: Tuple[str, ...] = (
    "/usr/sbin/VBoxService",
    "/opt/VBoxGuestAdditions",
    "/dev/vboxguest",
)

# systemd-detect-virt marka kumesi (vendor() normalizasyonu icin).
_SYSTEMD_VM_IDS = frozenset({
    "qemu", "kvm", "amazon", "zvm", "vmware", "microsoft", "oracle",
    "powervm", "xen", "bochs", "uml", "parallels", "bhyve", "qnx",
    "acrn", "apple", "google", "sre", "wsl",
})


# ---------------------------------------------------------------------------
# Kucuk yardimcilar (best-effort, asla exception sizdirmaz)
# ---------------------------------------------------------------------------

def _read_text(path: str, limit: int = 4096) -> Optional[str]:
    try:
        with _BUILTIN_OPEN(path, "r", errors="ignore") as fh:
            return fh.read(limit)
    except Exception:
        return None


def _read_bytes(path: str, limit: int = 65536) -> Optional[bytes]:
    try:
        with _BUILTIN_OPEN(path, "rb") as fh:
            return fh.read(limit)
    except Exception:
        return None


def _low(hay: str) -> str:
    try:
        return hay.lower()
    except Exception:
        return ""


_SHORT_RX: Dict[str, Any] = {}


def _short_rx(key: str) -> Any:
    try:
        rx = _SHORT_RX.get(key)
    except Exception:
        rx = None
    if rx is None:
        try:
            rx = _RE_COMPILE(r"\b%s\b" % re.escape(key))
            _SHORT_RX[key] = rx
        except Exception:
            return None
    return rx


_GENERIC_KEYS = frozenset({"virtual machine"})


def _table_hit(low: str, table: Tuple[Tuple[str, str], ...]) -> Optional[str]:
    for phase in (0, 1, 2):
        for key, brand in table:
            try:
                short = len(key) <= 3
                generic = key in _GENERIC_KEYS
                if phase == 0 and (short or generic):
                    continue
                if phase == 1 and (not short or generic):
                    continue
                if phase == 2 and not generic:
                    continue
                if short:
                    rx = _short_rx(key)
                    if rx is not None and rx.search(low):
                        return brand
                elif key in low:
                    return brand
            except Exception:
                continue
    return None


def _brand_of(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    return _table_hit(_low(text), _DMI_BRANDS)


def _valid_system32(cand: str) -> bool:
    try:
        if not _OS_PATH_ISDIR(cand):
            return False
        for core in ("kernel32.dll", "ntdll.dll"):
            try:
                if not _OS_PATH_ISFILE(_OS_PATH_JOIN(cand, core)):
                    return False
            except Exception:
                return False
        return True
    except Exception:
        return False


def _system32() -> Optional[str]:
    try:
        if _SYS_PLATFORM == "win32":
            try:
                k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
                try:
                    buf = ctypes.create_unicode_buffer(260)
                    n = k32.GetSystemDirectoryW(buf, 260)
                except Exception:
                    n = 0
                if n and 0 < int(n) < 260:
                    try:
                        if _OS_PATH_ISDIR(buf.value):
                            return buf.value
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                sysroot = _OS_ENVIRON.get("SystemRoot", r"C:\Windows")
            except Exception:
                sysroot = r"C:\Windows"
            for cand in (_OS_PATH_JOIN(sysroot, "System32"), r"C:\Windows\System32"):
                try:
                    if _valid_system32(cand):
                        return cand
                except Exception:
                    continue
    except Exception:
        pass
    return None


_WIN_TOOL_SUBS: Tuple[str, ...] = ("", r"WindowsPowerShell\v1.0")

_WIN_TOOL_EXTS: Tuple[str, ...] = ("", ".exe", ".com")

_POSIX_TOOL_DIRS: Tuple[str, ...] = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")

_TOOL_CACHE: Dict[str, Any] = {}


def _tool_path(name: str) -> Optional[str]:
    try:
        hit = _TOOL_CACHE.get(name, "MISS")
        if hit != "MISS" and isinstance(hit, tuple) and len(hit) == 3:
            try:
                path, omtime, osize = hit
                if path is None:
                    return None
                st = os.stat(path)
                if int(st.st_mtime) == int(omtime) and int(st.st_size) == int(osize):
                    return path
            except Exception:
                pass
            try:
                del _TOOL_CACHE[name]
            except Exception:
                pass
    except Exception:
        pass
    resolved: Optional[str] = None
    try:
        if _SYS_PLATFORM == "win32":
            s32 = _system32()
            if s32:
                for sub in _WIN_TOOL_SUBS:
                    basedir = _OS_PATH_JOIN(s32, sub) if sub else s32
                    for ext in _WIN_TOOL_EXTS:
                        cand = _OS_PATH_JOIN(basedir, name + ext)
                        try:
                            if _OS_PATH_ISFILE(cand):
                                resolved = cand
                                break
                        except Exception:
                            continue
                    if resolved is not None:
                        break
        else:
            for directory in _POSIX_TOOL_DIRS:
                cand = _OS_PATH_JOIN(directory, name)
                try:
                    if _OS_PATH_ISFILE(cand) and _OS_ACCESS(cand, os.X_OK):
                        resolved = cand
                        break
                except Exception:
                    continue
    except Exception:
        resolved = None
    try:
        if resolved is None:
            _TOOL_CACHE[name] = (None, 0, 0)
        else:
            try:
                st = os.stat(resolved)
                _TOOL_CACHE[name] = (resolved, int(st.st_mtime), int(st.st_size))
            except Exception:
                _TOOL_CACHE[name] = (resolved, -1, -1)
    except Exception:
        pass
    return resolved


def _driver_dir() -> Optional[str]:
    try:
        if _SYS_PLATFORM == "win32":
            s32 = _system32()
            if s32:
                cand = _OS_PATH_JOIN(s32, "drivers")
                try:
                    if _OS_PATH_ISDIR(cand):
                        return cand
                except Exception:
                    pass
    except Exception:
        pass
    return None


_PROC_FAILS = {"n": 0}


def _proc_fail() -> None:
    try:
        _PROC_FAILS["n"] = int(_PROC_FAILS.get("n", 0)) + 1
    except Exception:
        pass


def _proc_ok() -> None:
    try:
        _PROC_FAILS["n"] = 0
    except Exception:
        pass


def _run_capture(argv: List[str], timeout: float = 4.0,
                 limit: int = 65536) -> Optional[str]:
    """Subprocess best-effort calistir; hata/zamanasimi -> None."""
    try:
        if not argv:
            return None
        exe = _tool_path(argv[0])
        if exe is None:
            return None
        try:
            proc = _SUBPROCESS_RUN(
                [exe] + list(argv[1:]),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                timeout=timeout,
                check=False,
            )
        except Exception:
            _proc_fail()
            return None
        try:
            out = proc.stdout.decode("utf-8", "ignore") if proc.stdout else ""
        except Exception:
            out = ""
        _proc_ok()
        return out[:limit] if out else ""
    except Exception:
        _proc_fail()
        return None


def _check_privileged_gap() -> bool:
    try:
        if not _SYS_PLATFORM.startswith("linux"):
            return False
        try:
            cooked = False
            for path in _LINUX_DMI_FILES:
                try:
                    txt = _read_text(path, 64)
                    if txt is not None:
                        cooked = True
                        break
                except Exception:
                    continue
        except Exception:
            cooked = False
        if not cooked:
            return False
        try:
            raw = _read_bytes("/sys/firmware/dmi/tables/DMI", 16)
        except Exception:
            raw = None
        try:
            tables = _OS_LISTDIR("/sys/firmware/acpi/tables")
            tables_ok = bool(tables)
        except Exception:
            tables_ok = False
        return raw is None and not tables_ok
    except Exception:
        return False


def _check_proc_health() -> bool:
    try:
        return int(_PROC_FAILS.get("n", 0)) >= 3
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 0) Pin tutarsizligi (anti_debug/anti_trace ile ayni ilke)
# ---------------------------------------------------------------------------

def _check_pinned_mismatch() -> bool:
    """Pin'li referans canli degerden farkliysa hook/bozma suphesi -> True.

    VM tespiti icin dogrudan sinyal degil; altyapi butunlugu adina
    capraz-dogrulamada kullanilir. Pin bozulmussa ortam guvenilmez.
    """
    try:
        if _UUID_GETNODE is not uuid.getnode:
            return True
    except Exception:
        return False
    try:
        if _PERF_COUNTER is not time.perf_counter:
            return True
    except Exception:
        return False
    try:
        if _MONOTONIC is not time.monotonic:
            return True
    except Exception:
        return False
    try:
        if _SYS_PLATFORM is not sys.platform:
            return True
    except Exception:
        return False
    try:
        if _OS_EXIT is not os._exit:
            return True
    except Exception:
        return False
    try:
        if _OS_ENVIRON is not os.environ:
            return True
    except Exception:
        return False
    try:
        if _PLATFORM_SYS != platform.system().lower():
            return True
    except Exception:
        return False
    for live, pinned in (
        (open, _BUILTIN_OPEN),
        (os.listdir, _OS_LISTDIR),
        (os.path.exists, _OS_PATH_EXISTS),
        (os.path.isfile, _OS_PATH_ISFILE),
        (os.path.isdir, _OS_PATH_ISDIR),
        (os.path.join, _OS_PATH_JOIN),
        (os.access, _OS_ACCESS),
        (subprocess.run, _SUBPROCESS_RUN),
        (time.sleep, _TIME_SLEEP),
        (re.search, _RE_SEARCH),
        (re.findall, _RE_FINDALL),
        (re.match, _RE_MATCH),
        (re.compile, _RE_COMPILE),
        (re.split, _RE_SPLIT),
        (struct.unpack_from, _PIN_STRUCT_UNPACK),
        (threading.Event, _PIN_THREAD_EVENT),
        (threading.Thread, _PIN_THREAD_THREAD),
    ):
        try:
            if pinned is None:
                continue
            if live is not pinned:
                return True
        except Exception:
            continue
    for modname, pinned in (
        ("winreg", _PIN_MOD_WINREG),
        ("ctypes", _PIN_MOD_CTYPES),
        ("struct", _PIN_MOD_STRUCT),
        ("threading", _PIN_MOD_THREADING),
        ("subprocess", _PIN_MOD_SUBPROCESS),
        ("uuid", _PIN_MOD_UUID),
    ):
        try:
            if pinned is None:
                continue
            try:
                live = sys.modules.get(modname)
            except Exception:
                continue
            if live is not None and live is not pinned:
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# 1) DMI / SMBIOS kimligi (en agir sinyal)
# ---------------------------------------------------------------------------

_LINUX_DMI_FILES = (
    "/sys/class/dmi/id/sys_vendor",
    "/sys/class/dmi/id/product_name",
    "/sys/class/dmi/id/product_version",
    "/sys/class/dmi/id/bios_vendor",
    "/sys/class/dmi/id/bios_version",
    "/sys/class/dmi/id/board_vendor",
    "/sys/class/dmi/id/board_name",
    "/sys/class/dmi/id/chassis_vendor",
)


def _check_dmi() -> bool:
    # Linux sysfs.
    try:
        if _SYS_PLATFORM.startswith("linux"):
            for path in _LINUX_DMI_FILES:
                txt = _read_text(path, 512)
                if txt and _brand_of(txt):
                    return True
            # Ham SMBIOS tablosu (dmidecode bypass katmani).
            raw = _read_bytes("/sys/firmware/dmi/tables/DMI", 131072)
            if raw:
                try:
                    txt = raw.decode("utf-8", "ignore")
                except Exception:
                    txt = ""
                if txt and _brand_of(txt):
                    return True
    except Exception:
        pass
    # Windows registry: BIOS/System kimligi (pafish grid).
    try:
        if _SYS_PLATFORM == "win32":
            import winreg
            for sub, names in (
                (r"HARDWARE\DESCRIPTION\System\BIOS", ("SystemManufacturer", "SystemProductName", "BIOSVendor")),
                (r"HARDWARE\DESCRIPTION\System", ("SystemBiosVersion", "VideoBiosVersion")),
            ):
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub)
                except OSError:
                    continue
                try:
                    for i in range(32):
                        try:
                            name, val, _typ = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        try:
                            if names and name not in names:
                                continue
                            if isinstance(val, (list, tuple)):
                                val = " ".join(str(x) for x in val)
                            if _brand_of(str(val)):
                                try:
                                    winreg.CloseKey(key)
                                except Exception:
                                    pass
                                return True
                        except Exception:
                            continue
                finally:
                    try:
                        winreg.CloseKey(key)
                    except Exception:
                        pass
    except Exception:
        pass
    # macOS: ioreg best-effort (fiziksel Mac'te sessiz False).
    try:
        if _SYS_PLATFORM == "darwin":
            out = _run_capture(["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"], 4.0)
            if out and _brand_of(out):
                return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 2) CPU hipervizor bayragi + model adi
# ---------------------------------------------------------------------------

def _check_cpu() -> bool:
    # Linux: /proc/cpuinfo (parcali tara; cok CPU'lu host'ta bayrak sonda kalabilir).
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                with _BUILTIN_OPEN("/proc/cpuinfo", "r", errors="ignore") as fh:
                    while True:
                        try:
                            chunk = fh.read(65536)
                        except Exception:
                            break
                        if not chunk:
                            break
                        low = _low(chunk)
                        if _RE_SEARCH(r"(?m)^(flags|features)\s*:.*\bhypervisor\b", low):
                            return True
                        for probe in ("qemu virtual cpu", "virtualbox", "vmware",
                                      "kvm virtual", "bochs", "xen virtual",
                                      "parallels", "microsoft hv"):
                            if probe in low:
                                return True
            except Exception:
                txt = _read_text("/proc/cpuinfo", 131072)
                if txt:
                    low = _low(txt)
                    if _RE_SEARCH(r"(?m)^(flags|features)\s*:.*\bhypervisor\b", low):
                        return True
                    for probe in ("qemu virtual cpu", "virtualbox", "vmware",
                                  "kvm virtual", "bochs", "xen virtual"):
                        if probe in low:
                            return True
            for path in ("/proc/sys/kernel/osrelease", "/proc/version"):
                txt = _read_text(path, 512)
                if txt:
                    low = _low(txt)
                    if "microsoft" in low or "wsl" in low:
                        return True
    except Exception:
        pass
    # Windows: once winreg CentralProcessor (ARACSIZ, wmic/powershell
    # gerektirmez — MED-fix: toolsuz-path ilk denenir; metasploit checkvm
    # deseni). Registry duzenlenebilir-display-string'dir, o yuzden SADECE
    # pozitif-kanit olarak kullanilir (yokluk trip degildir).
    try:
        if _SYS_PLATFORM == "win32":
            import winreg
            try:
                for sub in (r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                            r"HARDWARE\DESCRIPTION\System\CentralProcessor\1"):
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub)
                    except OSError:
                        continue
                    try:
                        i = 0
                        while i < 16:
                            try:
                                _n, val, _t = winreg.EnumValue(key, i)
                            except OSError:
                                break
                            i += 1
                            try:
                                if isinstance(val, str) and _brand_of(val):
                                    try:
                                        winreg.CloseKey(key)
                                    except Exception:
                                        pass
                                    return True
                            except Exception:
                                continue
                    finally:
                        try:
                            winreg.CloseKey(key)
                        except Exception:
                            pass
            except Exception:
                pass
    except Exception:
        pass
    # Windows: Win32_Processor Name/Manufacturer (wmic -> powershell -> registry).
    try:
        if _SYS_PLATFORM == "win32":
            out = _run_capture(["wmic", "cpu", "get", "Name,Manufacturer", "/format:list"], 3.0)
            if out and _brand_of(out):
                return True
            if not out:
                ps = ("Get-CimInstance Win32_Processor | "
                      "ForEach-Object { $_.Name + ' ' + $_.Manufacturer }")
                out2 = _run_capture(["powershell", "-NoProfile", "-Command", ps], 4.0)
                if out2 and _brand_of(out2):
                    return True
    except Exception:
        pass
    # macOS: sysctl machdep.cpu brand (VMware/Parallels konuk CPU'su iz birakir).
    try:
        if _SYS_PLATFORM == "darwin":
            out = _run_capture(["sysctl", "-n", "machdep.cpu.brand_string"], 4.0)
            if out and _brand_of(out):
                return True
            if not out:
                # MED-fix: aracsiz sysctlbyname (libc) — sysctl binary yoksa.
                try:
                    import ctypes as _ct
                    try:
                        libc = _ct.CDLL("/usr/lib/libc.dylib", use_errno=True)
                    except Exception:
                        libc = _ct.CDLL("libc.dylib", use_errno=True)
                    libc.sysctlbyname.restype = _ct.c_int
                    buf = _ct.create_string_buffer(256)
                    sz = _ct.c_size_t(256)
                    if libc.sysctlbyname(b"machdep.cpu.brand_string", buf,
                                         _ct.byref(sz), None, 0) == 0:
                        try:
                            brand = buf.value.decode("utf-8", "ignore")
                        except Exception:
                            brand = ""
                        if brand and _brand_of(brand):
                            return True
                except Exception:
                    pass
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 3) MAC OUI
# ---------------------------------------------------------------------------

def _iter_mac_strings() -> List[str]:
    found: List[str] = []
    # uuid.getnode (tasinabilir).
    try:
        node = _UUID_GETNODE()
        if node and (node >> 40) & 0x01 == 0:  # multicast degilse gercek MAC olasi
            mac = ":".join("%02x" % ((node >> (8 * i)) & 0xFF) for i in reversed(range(6)))
            found.append(mac)
    except Exception:
        pass
    # Linux sysfs tum arayuzler.
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                ifaces = _OS_LISTDIR("/sys/class/net")
            except Exception:
                ifaces = []
            for iface in ifaces:
                if iface == "lo":
                    continue
                txt = _read_text("/sys/class/net/%s/address" % iface, 64)
                if txt:
                    cand = txt.strip()
                    if _RE_MATCH(r"(?i)^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", cand):
                        found.append(cand)
    except Exception:
        pass
    # Windows: getmac best-effort.
    try:
        if _SYS_PLATFORM == "win32":
            out = _run_capture(["getmac", "/FO", "CSV", "/NH"], 3.0)
            if out:
                for mac in _RE_FINDALL(r"(?i)[0-9a-f]{2}(?:[-:][0-9a-f]{2}){5}", out):
                    found.append(mac)
    except Exception:
        pass
    return found


def _check_mac() -> bool:
    try:
        for mac in _iter_mac_strings():
            if not mac:
                continue
            prefix = mac.replace("-", ":").lower()[:8]
            if prefix in _MAC_OUIS:
                return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# 4) PCI vendor ID
# ---------------------------------------------------------------------------

def _check_pci() -> bool:
    # Linux sysfs.
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                devs = _OS_LISTDIR("/sys/bus/pci/devices")
            except Exception:
                devs = []
            for dev in devs[:256]:
                txt = _read_text("/sys/bus/pci/devices/%s/vendor" % dev, 32)
                if not txt:
                    continue
                ven = txt.strip().lower().replace("0x", "")
                if ven in _PCI_VENDORS:
                    return True
    except Exception:
        pass
    # Windows registry Enum\\PCI (VMDetect'in ucuz izdusu; ham firmware
    # tablosu _check_firmware'da ayrica taranir).
    try:
        if _SYS_PLATFORM == "win32":
            import winreg
            try:
                root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\PCI")
            except OSError:
                root = None
            if root is None:
                return False
            try:
                i = 0
                while i < 512:
                    try:
                        sub = winreg.EnumKey(root, i)
                    except OSError:
                        break
                    i += 1
                    m = _RE_SEARCH(r"VEN_([0-9A-Fa-f]{4})", sub)
                    if not m:
                        continue
                    if m.group(1).lower() in _PCI_VENDORS:
                        try:
                            winreg.CloseKey(root)
                        except Exception:
                            pass
                        return True
            finally:
                try:
                    winreg.CloseKey(root)
                except Exception:
                    pass
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 5) Disk modeli
# ---------------------------------------------------------------------------

def _disk_brand_of(text: Optional[str]) -> Optional[str]:
    if not text:
        return None
    return _table_hit(_low(text), _DISK_BRANDS)


def _check_disk() -> bool:
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                blocks = _OS_LISTDIR("/sys/block")
            except Exception:
                blocks = []
            for blk in blocks:
                if blk.startswith(("loop", "ram", "dm-", "md")):
                    continue
                model = _read_text("/sys/block/%s/device/model" % blk, 128)
                if model and (_disk_brand_of(model) or _brand_of(model)):
                    return True
                vend = _read_text("/sys/block/%s/device/vendor" % blk, 128)
                if vend and (_disk_brand_of(vend) or _brand_of(vend)):
                    return True
            try:
                sdevs = _OS_LISTDIR("/sys/class/scsi_device")
            except Exception:
                sdevs = []
            for sdev in sdevs[:256]:
                for leaf in ("vendor", "model"):
                    txt = _read_text("/sys/class/scsi_device/%s/device/%s" % (sdev, leaf), 128)
                    if txt and (_disk_brand_of(txt) or _brand_of(txt)):
                        return True
    except Exception:
        pass
    try:
        if _SYS_PLATFORM == "win32":
            import winreg
            try:
                root = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Services\Disk\Enum",
                )
            except OSError:
                root = None
            if root is not None:
                try:
                    i = 0
                    while i < 64:
                        try:
                            _name, val, _typ = winreg.EnumValue(root, i)
                        except OSError:
                            break
                        i += 1
                        try:
                            if _disk_brand_of(str(val)) or _brand_of(str(val)):
                                try:
                                    winreg.CloseKey(root)
                                except Exception:
                                    pass
                                return True
                        except Exception:
                            continue
                finally:
                    try:
                        winreg.CloseKey(root)
                    except Exception:
                        pass
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 6) Konuk modul / surucu
# ---------------------------------------------------------------------------

def _check_modules() -> bool:
    # Linux /proc/modules.
    try:
        if _SYS_PLATFORM.startswith("linux"):
            txt = _read_text("/proc/modules", 131072)
            if txt:
                low = _low(txt)
                for key, _brand in _MODULE_BRANDS:
                    if key in low:
                        return True
    except Exception:
        pass
    # Windows driver dosyalari.
    try:
        if _SYS_PLATFORM == "win32":
            drvdir = _driver_dir()
            names: List[str] = []
            if drvdir:
                try:
                    names = _OS_LISTDIR(drvdir)
                except Exception:
                    names = []
            low_names = [_low(n) for n in names]
            for want in _DRIVER_FILES:
                if want in low_names:
                    return True
            # Yedek: akan surucu listesi (driverquery CSV).
            # NOT: ciplak "vbox" aranmaz; VBoxUSB gibi host-only suruculer
            # fiziksel makinede false-positive uretir. Sadece konuk-ici
            # (guest-additions) suruculer trip eder.
            out = _run_capture(["driverquery", "/FO", "CSV", "/NH"], 4.0)
            if out:
                low = _low(out)
                for key in ("vboxguest", "vboxmouse", "vboxsf", "vboxvideo",
                            "vboxwddm", "vmmouse", "vmhgfs", "vmxnet",
                            "vm3dmp", "vmci", "vmusbmouse", "qemu-ga",
                            "xenbus", "xennet", "xenvbd", "prl_"):
                    if key in low:
                        return True
    except Exception:
        pass
    # macOS: kextstat best-effort.
    try:
        if _SYS_PLATFORM == "darwin":
            out = _run_capture(["kextstat", "-l"], 5.0)
            if out:
                low = _low(out)
                if "virtualbox" in low or "vmware" in low or "parallels" in low:
                    return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 7) Process / servis / dosya artefakti
# ---------------------------------------------------------------------------

def _iter_process_names() -> List[str]:
    names: List[str] = []
    # Linux /proc taramasi (comm + cmdline).
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                pids = [p for p in _OS_LISTDIR("/proc") if p.isdigit()]
            except Exception:
                pids = []
            for pid in pids[:4096]:
                comm = _read_text("/proc/%s/comm" % pid, 256)
                if comm:
                    names.append(comm.strip())
                try:
                    raw = _read_bytes("/proc/%s/cmdline" % pid, 512)
                    if raw:
                        names.append(raw.replace(b"\x00", b" ").decode("utf-8", "ignore").strip())
                except Exception:
                    pass
    except Exception:
        pass
    # tasklist / ps best-effort.
    try:
        if _SYS_PLATFORM == "win32":
            out = _run_capture(["tasklist", "/FO", "CSV", "/NH"], 4.0)
            if out:
                names.extend(_RE_FINDALL(r'"([^"]+\.exe)"', out, flags=re.IGNORECASE))
        else:
            out = _run_capture(["ps", "-e", "-o", "comm="], 5.0)
            if out:
                names.extend([ln.strip() for ln in out.splitlines() if ln.strip()])
    except Exception:
        pass
    return names


def _check_processes() -> bool:
    try:
        for name in _iter_process_names():
            low = _low(name)
            try:
                tokens = set(_RE_SPLIT(r"[^a-z0-9]+", low))
            except Exception:
                tokens = set()
            for key in _PROCESS_KEYWORDS:
                try:
                    if key in tokens:
                        return True
                    if len(key) > 6 and key in low:
                        return True
                except Exception:
                    continue
    except Exception:
        return False
    # Konuk dosya artefaktlari (Linux).
    try:
        if _SYS_PLATFORM.startswith("linux"):
            for path in _GUEST_PATHS:
                try:
                    if _OS_PATH_EXISTS(path):
                        return True
                except Exception:
                    continue
            try:
                txt = _read_text("/etc/ld.so.preload", 4096)
                if txt and txt.strip():
                    return True
            except Exception:
                pass
    except Exception:
        pass
    try:
        if _SYS_PLATFORM == "win32":
            s32 = _system32()
            if s32:
                for cand in (
                    _OS_PATH_JOIN(s32, "drivers", "VBoxGuest.sys"),
                    _OS_PATH_JOIN(s32, "VBoxService.exe"),
                ):
                    try:
                        if _OS_PATH_EXISTS(cand):
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 8) Firmware tablolari (ACPI/SMBIOS ham tarama, VMDetect izdusu)
# ---------------------------------------------------------------------------

_FIRMWARE_KEYWORDS = (
    "vbox", "virtualbox", "innotek", "vmware", "qemu", "bochs",
    "xen", "parallels", "bhyve", "kvm", "hyper-v", "microsoft hv",
    "viridian", "vmbus", "vm_generationcounter", "acpi0010",
)


def _firmware_blob_hit(blob: bytes) -> bool:
    try:
        low = blob.lower()
    except Exception:
        return False
    for key in _FIRMWARE_KEYWORDS:
        try:
            if key.encode("ascii") in low:
                return True
        except Exception:
            continue
    return False


def _check_firmware() -> bool:
    # Windows: EnumSystemFirmwareTables + GetSystemFirmwareTable (RSMB+ACPI).
    try:
        if _SYS_PLATFORM == "win32":
            try:
                k32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
            except Exception:
                k32 = None
            if k32 is not None:
                try:
                    k32.EnumSystemFirmwareTables.argtypes = [ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint]
                    k32.EnumSystemFirmwareTables.restype = ctypes.c_uint
                    k32.GetSystemFirmwareTable.argtypes = [
                        ctypes.c_uint, ctypes.c_uint, ctypes.c_void_p, ctypes.c_uint,
                    ]
                    k32.GetSystemFirmwareTable.restype = ctypes.c_uint
                    for provider in (0x41435049, 0x424D5352):  # 'ACPI', 'RSMB'
                        try:
                            need = k32.EnumSystemFirmwareTables(provider, None, 0)
                        except Exception:
                            continue
                        if not need or need > (1 << 20):
                            continue
                        buf = ctypes.create_string_buffer(need)
                        try:
                            got = k32.EnumSystemFirmwareTables(provider, buf, need)
                        except Exception:
                            continue
                        if not got:
                            continue
                        raw_ids = buf.raw[:got]
                        for off in range(0, len(raw_ids) - 3, 4):
                            try:
                                tbl = struct.unpack_from("<I", raw_ids, off)[0]
                            except Exception:
                                continue
                            try:
                                size = k32.GetSystemFirmwareTable(provider, tbl, None, 0)
                            except Exception:
                                continue
                            if not size or size > (1 << 24):
                                continue
                            tbuf = ctypes.create_string_buffer(size)
                            try:
                                got2 = k32.GetSystemFirmwareTable(provider, tbl, tbuf, size)
                            except Exception:
                                continue
                            if got2 and _firmware_blob_hit(tbuf.raw[:got2]):
                                return True
                except Exception:
                    pass
    except Exception:
        pass
    # Linux: ACPI tablolari + dmesg izi.
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                tables = _OS_LISTDIR("/sys/firmware/acpi/tables")
            except Exception:
                tables = []
            for tbl in tables[:64]:
                blob = _read_bytes("/sys/firmware/acpi/tables/%s" % tbl, 131072)
                if blob and _firmware_blob_hit(blob):
                    return True
            dmesg = _run_capture(["dmesg"], 4.0, 131072)
            if dmesg and _brand_of(dmesg):
                return True
            # QEMU fw_cfg arayuzu dogrudan kanit.
            try:
                if _OS_PATH_EXISTS("/sys/firmware/qemu_fw_cfg"):
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# 9b) Hipervizor dizin izleri (vm-detect skor-100 probu)
# ---------------------------------------------------------------------------

def _check_hypervisor_dir() -> bool:
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                htype = _read_text("/sys/hypervisor/type", 64)
            except Exception:
                htype = None
            if htype and htype.strip():
                return True
            try:
                uuid_txt = _read_text("/sys/hypervisor/uuid", 128)
            except Exception:
                uuid_txt = None
            if uuid_txt and uuid_txt.strip():
                return True
            try:
                caps = _read_text("/proc/xen/capabilities", 256)
            except Exception:
                caps = None
            if caps is not None:
                low = _low(caps)
                if "control_d" in low:
                    stripped = low.replace("control_d", "").strip(" \t\r\n,;")
                    if not stripped:
                        return False
                if low.strip():
                    return True
            try:
                if _OS_PATH_EXISTS("/proc/xen/xenbus"):
                    return True
            except Exception:
                pass
            try:
                if _OS_PATH_ISDIR("/proc/xen"):
                    return True
            except Exception:
                pass
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# 9) systemd-detect-virt (mevcutsa guclu sinyal)
# ---------------------------------------------------------------------------

def _check_systemd() -> bool:
    try:
        if not _SYS_PLATFORM.startswith("linux"):
            return False
        out = _run_capture(["systemd-detect-virt"], 4.0, 256)
        if out is None:
            return False
        ident = out.strip().lower()
        if not ident or ident == "none":
            return False
        if ident in _SYSTEMD_VM_IDS:
            return True
        if _brand_of(ident):
            return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# 10) Sensor yoklugu (ZAYIF destekleyici: hwmon+thermal ikisi de yoksa)
# ---------------------------------------------------------------------------

def _check_sensor_absence() -> bool:
    """Donanim sensoru yoklugu (InnerWarden hwmon/temperature deseni).

    Bare-metal'de /sys/class/hwmon ve /sys/class/thermal neredeyse her
    zaman doludur; VM'ler cogunlukla ikisini de sunmaz. Tek basina
    karar VEREMEZ (WEAK: verdict icin 2 zayif gerekir); yalnizca Linux'ta
    ve /sys/class mevcutken degerlendirilir. Konteyner/minimal kernel
    FP'sine karsi IKISI BIRLIKTE yoksa trip eder.
    """
    try:
        if not _SYS_PLATFORM.startswith("linux"):
            return False
        try:
            if not _OS_PATH_EXISTS("/sys/class"):
                return False
        except Exception:
            return False
        try:
            hwmon = _OS_LISTDIR("/sys/class/hwmon")
        except Exception:
            hwmon = None
        try:
            thermal = _OS_LISTDIR("/sys/class/thermal")
        except Exception:
            thermal = None
        if hwmon is None and thermal is None:
            return False
        hwmon_empty = (hwmon is not None and len(hwmon) == 0)
        thermal_empty = (thermal is not None and len(thermal) == 0)
        if hwmon_empty and thermal_empty:
            return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# 10b) Kasa tipi (ZAYIF: chassis type 1/2 VM gostergesi)
# ---------------------------------------------------------------------------

def _check_chassis() -> bool:
    """SMBIOS kasa tipi 1 (Other) / 2 (Unknown) VM'lerde yaygindir.

    Bare-metal'de nadiren 1 gorulur; bu yuzden WEAK (tek basina karar
    veremez). Sayisal karsilastirma yapilir, string icerik degil.
    """
    try:
        if not _SYS_PLATFORM.startswith("linux"):
            return False
        txt = _read_text("/sys/class/dmi/id/chassis_type", 16)
        if not txt:
            return False
        try:
            val = int(txt.strip().split()[0])
        except Exception:
            return False
        return val in (1, 2)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# 11) Timing anomalisi (comert esik; sadece bariz sapma trip eder)
# ---------------------------------------------------------------------------

_TIMING_THRESHOLD_SEC = 0.250  # 10ms sleep'e karsilik 250ms+ asiri sapma


def _qpc_dt(seconds: float = 0.01) -> Optional[float]:
    """LOW-fix: QPC-direkt olcum (hook-bagimsiz capraz-saat).

    Research (reverseengineering.app QPC-timing + evasions QPC): QPC
    donanim/hipervizor-destekli monoton sayactir; time.sleep +
    time.perf_counter ikilisi hook'lanirsa QPC sapmayi ele verir.
    Donus: saniye (None=olculemez).
    """
    try:
        if _SYS_PLATFORM != "win32":
            return None
        import ctypes as _ct
        try:
            k32 = _ct.windll.kernel32
            k32.QueryPerformanceFrequency.restype = _ct.c_bool
            k32.QueryPerformanceCounter.restype = _ct.c_bool
            freq = _ct.c_int64(0)
            if not k32.QueryPerformanceFrequency(_ct.byref(freq)) or not freq.value:
                return None
            t0 = _ct.c_int64(0)
            t1 = _ct.c_int64(0)
            if not k32.QueryPerformanceCounter(_ct.byref(t0)):
                return None
            try:
                _TIME_SLEEP(seconds)
            except Exception:
                return None
            if not k32.QueryPerformanceCounter(_ct.byref(t1)):
                return None
            return (t1.value - t0.value) / float(freq.value)
        except Exception:
            return None
    except Exception:
        return None


def _check_timing(threshold: float = _TIMING_THRESHOLD_SEC) -> bool:
    try:
        try:
            t0 = _PERF_COUNTER()
            _TIME_SLEEP(0.01)
            dt = _PERF_COUNTER() - t0
        except Exception:
            return False
        # LOW-fix: QPC capraz-dogrulama (Windows). Hook'lu saatler QPC'den
        # >100ms saparsa kasti-kor spermi = trip (hook-kaniti).
        try:
            qpc = _qpc_dt(0.01)
            if qpc is not None and qpc > 0:
                try:
                    if abs(qpc - dt) > 0.100 and (qpc > threshold or dt > threshold):
                        return True
                except Exception:
                    pass
                if qpc > threshold:
                    try:
                        t1 = _PERF_COUNTER()
                        _TIME_SLEEP(0.01)
                        dt2 = _PERF_COUNTER() - t1
                    except Exception:
                        return False
                    qpc2 = _qpc_dt(0.01)
                    if dt2 > threshold and (qpc2 is None or qpc2 > threshold):
                        return True
                    return False
        except Exception:
            pass
        if dt > threshold:
            # Tek olcum gurultulu olabilir; ikinci olcumle dogrula.
            # (Saat-gerisi (dt<0) bilerek oy DEGIL: NTP adimi VM kaniti degil.)
            try:
                t1 = _PERF_COUNTER()
                _TIME_SLEEP(0.01)
                dt2 = _PERF_COUNTER() - t1
            except Exception:
                return False
            if dt2 > threshold and dt > threshold:
                return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# 11) Capraz-dogrulama (hardened-VM / tutarsizlik avcisi)
# ---------------------------------------------------------------------------

def _dmi_texts() -> List[str]:
    texts: List[str] = []
    try:
        if _SYS_PLATFORM.startswith("linux"):
            for path in _LINUX_DMI_FILES:
                txt = _read_text(path, 512)
                if txt and txt.strip():
                    texts.append(txt.strip())
    except Exception:
        pass
    try:
        if _SYS_PLATFORM == "win32":
            import winreg
            for sub in (r"HARDWARE\DESCRIPTION\System\BIOS",
                        r"HARDWARE\DESCRIPTION\System"):
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sub)
                except OSError:
                    continue
                try:
                    i = 0
                    while i < 32:
                        try:
                            _name, val, _typ = winreg.EnumValue(key, i)
                        except OSError:
                            break
                        i += 1
                        try:
                            if isinstance(val, (list, tuple)):
                                val = " ".join(str(x) for x in val)
                            s = str(val).strip()
                            if s:
                                texts.append(s)
                        except Exception:
                            continue
                finally:
                    try:
                        winreg.CloseKey(key)
                    except Exception:
                        pass
    except Exception:
        pass
    return texts


def _hw_brands() -> List[str]:
    brands: List[str] = []
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                devs = _OS_LISTDIR("/sys/bus/pci/devices")
            except Exception:
                devs = []
            for dev in devs[:256]:
                try:
                    txt = _read_text("/sys/bus/pci/devices/%s/vendor" % dev, 32)
                    if not txt:
                        continue
                    ven = txt.strip().lower().replace("0x", "")
                    if ven in _PCI_VENDORS and _PCI_VENDORS[ven] not in brands:
                        brands.append(_PCI_VENDORS[ven])
                except Exception:
                    continue
    except Exception:
        pass
    try:
        for mac in _iter_mac_strings():
            try:
                if not mac:
                    continue
                prefix = mac.replace("-", ":").lower()[:8]
                if prefix in _MAC_OUIS and _MAC_OUIS[prefix] not in brands:
                    brands.append(_MAC_OUIS[prefix])
            except Exception:
                continue
    except Exception:
        pass
    try:
        if _SYS_PLATFORM.startswith("linux"):
            try:
                blocks = _OS_LISTDIR("/sys/block")
            except Exception:
                blocks = []
            for blk in blocks:
                try:
                    if blk.startswith(("loop", "ram", "dm-", "md")):
                        continue
                    for leaf in ("model", "vendor"):
                        txt = _read_text("/sys/block/%s/device/%s" % (blk, leaf), 128)
                        b = _disk_brand_of(txt) if txt else None
                        if b is None and txt:
                            b = _brand_of(txt)
                        if b and b not in brands:
                            brands.append(b)
                except Exception:
                    continue
    except Exception:
        pass
    return brands


def _cpu_hypervisor_flag() -> bool:
    """CPU hipervizor-bayragi (Linux /proc/cpuinfo flags: hypervisor).

    MED-fix (b): DMI'yi temiz-spoof'layan saldirgan CPU-bayragini unutur —
    bayrak VAR + hicbir VM markasi YOK = tutarsizlik (trip). Ters yonu
    (marka var, bayrak yok) cpu/DMI katmanlari zaten yakalar.
    """
    try:
        if not _SYS_PLATFORM.startswith("linux"):
            return False
        try:
            with _BUILTIN_OPEN("/proc/cpuinfo", "r", errors="ignore") as fh:
                while True:
                    try:
                        chunk = fh.read(65536)
                    except Exception:
                        break
                    if not chunk:
                        break
                    try:
                        if _RE_SEARCH(r"(?m)^(flags|features)\s*:.*\bhypervisor\b",
                                      _low(chunk)):
                            return True
                    except Exception:
                        continue
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_cross_validation() -> bool:
    """Marka tutarsizligi: donanim baska marka, DMI baska/temiz ise trip.

    Ornegin PCI/Virtio + MAC qemu varken DMI 'Dell' diyorsa bu spoof'lanmis
    konuktur. Ayni marka tutarliysa (normal VM) False doner.
    MED-fix (b): hipervizor CPU-bayragi + sifir VM-markasi da trip'ler
    (full-stack spoof'un unuttugu bit).
    """
    try:
        hw = _hw_brands()
        if not hw:
            try:
                if _cpu_hypervisor_flag():
                    return True
            except Exception:
                pass
            return False
        try:
            texts = _dmi_texts()
        except Exception:
            texts = []
        if not texts:
            return True
        try:
            dmi_brand = _brand_of(" ".join(texts))
        except Exception:
            dmi_brand = None
        if dmi_brand is None:
            return True
        try:
            if dmi_brand not in hw:
                return True
        except Exception:
            return True
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_VERBOSE_FLAG = [False]


def _verbose() -> bool:
    try:
        if _VERBOSE_FLAG[0]:
            return True
    except Exception:
        pass
    try:
        return _OS_ENVIRON.get("HYPERCIPHER_ANTIVM_VERBOSE", "") == "1"
    except Exception:
        return False


def set_verbose(on: bool) -> bool:
    """LOW-fix: proses-ici bayrak (env MUTASYONU YOK).

    Eski surum os.environ'u yaziyordu (cocuk-proses mirasi + gozlemlenebilir
    yan-etki). Simdi in-process flag; env degiskeni override olarak okunmaya
    devam eder (geriye-uyumluluk).
    """
    try:
        _VERBOSE_FLAG[0] = bool(on)
        return True
    except Exception:
        return False


def _raw_results() -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    for name, fn in (
        ("dmi", _check_dmi),
        ("cpu", _check_cpu),
        ("mac", _check_mac),
        ("pci", _check_pci),
        ("disk", _check_disk),
        ("modules", _check_modules),
        ("processes", _check_processes),
        ("firmware", _check_firmware),
        ("hypervisor_dir", _check_hypervisor_dir),
        ("systemd", _check_systemd),
        ("sensor_absence", _check_sensor_absence),
        ("chassis", _check_chassis),
        ("pinned_mismatch", _check_pinned_mismatch),
        ("cross_validation", _check_cross_validation),
        ("proc_health", _check_proc_health),
        ("privileged_gap", _check_privileged_gap),
        ("timing", _check_timing),
    ):
        try:
            results[name] = bool(fn())
        except Exception:
            results[name] = False
    return results


def check_all() -> Dict[str, bool]:
    """Tum katmanlari calistir, detayli (debug amacli) sozluk doner.

    Uretimde KAPALI: HYPERCIPHER_ANTIVM_VERBOSE=1 yoksa yalnizca
    {"virtualized": bool} doner (gradient-descent oracle yok).
    Uretim karari icin is_virtualized() kullan.
    """
    try:
        if not _verbose():
            try:
                return {"virtualized": bool(is_virtualized())}
            except Exception:
                return {"virtualized": True}
    except Exception:
        pass
    return _raw_results()


# ---------------------------------------------------------------------------
# Skorlu verdict (VMAware esik deseni: guclu=100, zayif=30, esik=60)
# ---------------------------------------------------------------------------

_STRONG_LAYERS = frozenset({"dmi", "cpu", "firmware", "systemd", "hypervisor_dir", "pci"})
_WEAK_LAYERS = frozenset({"mac", "disk", "modules", "processes", "timing", "cross_validation", "proc_health", "privileged_gap", "sensor_absence", "chassis", "pinned_mismatch"})

_STRONG_SCORE = 100
_WEAK_SCORE = 30
_VM_THRESHOLD = 60

_LAYER_FUNCS: Tuple[Tuple[str, str], ...] = (
    ("dmi", "_check_dmi"),
    ("cpu", "_check_cpu"),
    ("mac", "_check_mac"),
    ("pci", "_check_pci"),
    ("disk", "_check_disk"),
    ("modules", "_check_modules"),
    ("processes", "_check_processes"),
    ("firmware", "_check_firmware"),
    ("hypervisor_dir", "_check_hypervisor_dir"),
    ("systemd", "_check_systemd"),
    ("sensor_absence", "_check_sensor_absence"),
    ("chassis", "_check_chassis"),
    ("pinned_mismatch", "_check_pinned_mismatch"),
    ("cross_validation", "_check_cross_validation"),
    ("proc_health", "_check_proc_health"),
    ("privileged_gap", "_check_privileged_gap"),
    ("timing", "_check_timing"),
)


def _resolve_layer(name: str) -> Optional[Callable[[], bool]]:
    try:
        return globals().get("_check_" + name)
    except Exception:
        return None


def evidence() -> Dict[str, bool]:
    """Ham kanit sozlugu (uretimde kapali; set_verbose(True) ile acilir)."""
    try:
        if not _verbose():
            try:
                return {"virtualized": bool(is_virtualized())}
            except Exception:
                return {"virtualized": True}
    except Exception:
        pass
    return _raw_results()


def evidence_full() -> Dict[str, object]:
    """LOW-fix: triyaj API — verbose-bagimsiz TAM sinyal sozlugu.

    check_all()/evidence()/score() oracle-kapali kalir (uretim); operator
    triyaj/forensics icin evidence_full() cagirir. Ayrica pinned_mismatch
    (hook-kaniti) her zaman rapora dahildir.
    """
    try:
        res = _raw_results()
    except Exception:
        res = {}
    try:
        s, w, _t = score_full(res)
    except Exception:
        s, w = 0, 0
    try:
        tampered = is_environment_tampered()
    except Exception:
        tampered = True
    try:
        brand = vendor()
    except Exception:
        brand = "unknown"
    return {"virtualized": bool(_verdict_from(res)), "signals": res,
            "strong": s, "weak": w, "tampered": tampered, "vendor": brand}


def score_full(results: Dict[str, bool] | None = None) -> Tuple[int, int, int]:
    """Verbose-bagimsiz skor (triage)."""
    try:
        res = results if results is not None else _raw_results()
    except Exception:
        return (0, 0, 0)
    strong = 0
    weak = 0
    try:
        for name in _STRONG_LAYERS:
            try:
                if res.get(name):
                    strong += 1
            except Exception:
                continue
        for name in _WEAK_LAYERS:
            try:
                if res.get(name):
                    weak += 1
            except Exception:
                continue
    except Exception:
        return (0, 0, 0)
    return (strong * _STRONG_SCORE + weak * _WEAK_SCORE, strong, weak)


def score() -> Tuple[int, int, int]:
    """(toplam_skor, guclu_vurus, zayif_vurus) — uretimde kapali (0,0,0)."""
    try:
        if not _verbose():
            return (0, 0, 0)
    except Exception:
        return (0, 0, 0)
    try:
        results = _raw_results()
    except Exception:
        return (0, 0, 0)
    strong = 0
    weak = 0
    try:
        for name in _STRONG_LAYERS:
            try:
                if results.get(name):
                    strong += 1
            except Exception:
                continue
        for name in _WEAK_LAYERS:
            try:
                if results.get(name):
                    weak += 1
            except Exception:
                continue
    except Exception:
        return (0, 0, 0)
    return (strong * _STRONG_SCORE + weak * _WEAK_SCORE, strong, weak)


def _verdict_from(results: Dict[str, bool]) -> bool:
    try:
        for name in _STRONG_LAYERS:
            try:
                if results.get(name):
                    return True
            except Exception:
                continue
        weak = 0
        try:
            cross = bool(results.get("cross_validation"))
        except Exception:
            cross = False
        for name in _WEAK_LAYERS:
            try:
                if name == "cross_validation":
                    continue
                if results.get(name):
                    weak += 1
                    if weak >= 2:
                        return True
            except Exception:
                continue
        if weak == 1 and cross:
            return True
    except Exception:
        return False
    return False


def _collect_results(include_timing: bool = True) -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    try:
        for name, _fn in _LAYER_FUNCS:
            if name == "timing" and not include_timing:
                results[name] = False
                continue
            fn = _resolve_layer(name)
            if fn is None:
                results[name] = False
                continue
            try:
                results[name] = bool(fn())
            except Exception:
                results[name] = False
    except Exception:
        pass
    return results


def is_virtualized(include_timing: bool = True) -> bool:
    try:
        return _verdict_from(_collect_results(include_timing=include_timing))
    except Exception:
        return True  # fail-closed
    return False


def is_environment_tampered() -> bool:
    """Pin/hook butunluk sinyali — ANTI-VM degil, AYRI politika.

    hook edildi != VM'desin. Debugger, enstrumantasyon, test-harness veya
    runtime-yama da tetikleyebilir. Uretimde fail-closed kullanmak icin
    assert_no_tamper() / guard() ile birlestir.
    """
    try:
        return bool(_check_pinned_mismatch())
    except Exception:
        return True  # fail-closed


def assert_no_tamper() -> None:
    """Ortam butunlugu bozulmussa opak VirtualMachineDetected firlatir."""
    if is_environment_tampered():
        raise VirtualMachineDetected("protected")
    return False


def vendor() -> str:
    """Marka tahmini: 'virtualbox'/'vmware'/'hyper-v'/.../'bare-metal'/'unknown'.

    API kontrati: vendor() == "bare-metal" ⟺ not is_virtualized().
    Ayni secmen kurulu (timing dahil) kullanilir; marka tasiyan katmanlar
    (DMI/systemd/MAC/PCI) sessizken verdict True ise "unknown" doner.
    Opak degildir (tespit-disi bilgi); karar icin degil, rapor/izin-listesi
    icin kullanilir.
    """
    try:
        # DMI oncelikli (en guvenilir marka kaynagi).
        try:
            if _SYS_PLATFORM.startswith("linux"):
                for path in _LINUX_DMI_FILES:
                    txt = _read_text(path, 512)
                    brand = _brand_of(txt) if txt else None
                    if brand:
                        return brand
            if _SYS_PLATFORM == "darwin":
                out = _run_capture(["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2"], 4.0)
                brand = _brand_of(out) if out else None
                if brand:
                    return brand
        except Exception:
            pass
        # systemd kesin marka soyler.
        try:
            if _SYS_PLATFORM.startswith("linux"):
                out = _run_capture(["systemd-detect-virt"], 4.0, 256)
                if out:
                    ident = out.strip().lower()
                    if ident in ("oracle",):
                        return "virtualbox"
                    if ident in ("microsoft",):
                        return "hyper-v"
                    if ident in _SYSTEMD_VM_IDS:
                        return ident
                    brand = _brand_of(ident)
                    if brand:
                        return brand
        except Exception:
            pass
        # MAC OUI marka net soyler.
        try:
            for mac in _iter_mac_strings():
                if not mac:
                    continue
                prefix = mac.replace("-", ":").lower()[:8]
                if prefix in _MAC_OUIS:
                    return _MAC_OUIS[prefix]
        except Exception:
            pass
        # PCI vendor.
        try:
            if _SYS_PLATFORM.startswith("linux"):
                try:
                    devs = _OS_LISTDIR("/sys/bus/pci/devices")
                except Exception:
                    devs = []
                for dev in devs[:256]:
                    txt = _read_text("/sys/bus/pci/devices/%s/vendor" % dev, 32)
                    if not txt:
                        continue
                    ven = txt.strip().lower().replace("0x", "")
                    if ven in _PCI_VENDORS:
                        return _PCI_VENDORS[ven]
            if _SYS_PLATFORM == "win32":
                import winreg
                try:
                    root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\PCI")
                except OSError:
                    root = None
                if root is not None:
                    try:
                        i = 0
                        while i < 512:
                            try:
                                sub = winreg.EnumKey(root, i)
                            except OSError:
                                break
                            i += 1
                            m = _RE_SEARCH(r"VEN_([0-9A-Fa-f]{4})", sub)
                            if m and m.group(1).lower() in _PCI_VENDORS:
                                try:
                                    winreg.CloseKey(root)
                                except Exception:
                                    pass
                                return _PCI_VENDORS[m.group(1).lower()]
                    finally:
                        try:
                            winreg.CloseKey(root)
                        except Exception:
                            pass
        except Exception:
            pass
        if is_virtualized():
            return "unknown"
    except Exception:
        return "unknown"
    return "bare-metal"


def assert_no_vm() -> None:
    """VM suphesi varsa opak VirtualMachineDetected firlatir."""
    if is_virtualized():
        raise VirtualMachineDetected("protected")


_WATCHDOGS: List[threading.Event] = []
_WATCHDOGS_LOCK = threading.Lock()
_VM_ADMINS: dict = {}
_VM_ADMIN_LOCKED = False
_VM_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _VM_ADMIN_DENIED
    try:
        if _VM_ADMIN_LOCKED:
            with _WATCHDOGS_LOCK:
                _VM_ADMIN_DENIED += 1
            return False
        try:
            fr = sys._getframe(1)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
        except Exception:
            return False
        if not name or not fn or fn.startswith("<"):
            return False
        try:
            if not os.path.isfile(fn):
                return False
        except Exception:
            return False
        with _WATCHDOGS_LOCK:
            _VM_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _vm_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _WATCHDOGS_LOCK:
            allowed = dict(_VM_ADMINS)
        if not allowed:
            return False
        try:
            fr = sys._getframe(2)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
            want = allowed.get(name)
            if (want is not None and fn == want and not fn.startswith("<")
                    and os.path.isfile(fn)):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def _vm_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _VM_ADMIN_DENIED
    try:
        with _WATCHDOGS_LOCK:
            _VM_ADMIN_DENIED += 1
    except Exception:
        pass
    raise VirtualMachineDetected("protected")


def start_watchdog(
    interval: float = 2.0,
    on_detect: Optional[Callable[[], None]] = None,
    daemon: bool = True,
) -> Callable[[], None]:
    """Arka planda periyodik kontrol. Tespitte varsayilan: sessiz os._exit(1).

    VM statik bir ozelliktir (ortam calisirken degismez); watchdog uc seyi
    yakalar: (a) gec beliren zayif sinyaller, (b) pin/hook butunlugu
    bozulmasi (AYRI politika: environment-tamper), (c) askida-kalma/suspend
    (execution-integrity sinyali — VM'ye ozgu degil, fail-closed yorumlanir).
    Pahali katmanlar (firmware taramasi) her tick'te degil, seyrek calisir.

    on_detect verilirse o cagrilir (ornek: state wipe + exit).
    Donen stop() fonksiyonu izlemeyi durdurur.
    """
    global _VM_ADMIN_LOCKED
    try:
        with _WATCHDOGS_LOCK:
            _VM_ADMIN_LOCKED = True
    except Exception:
        pass
    if interval < 0.5:
        interval = 0.5
    if interval > 30.0:
        interval = 30.0
    stop_event = threading.Event()
    with _WATCHDOGS_LOCK:
        _WATCHDOGS.append(stop_event)

    def _default_action() -> None:
        try:
            _OS_EXIT(1)  # sessiz, traceback yok, oracle yok
        except Exception:
            pass

    action = on_detect if callable(on_detect) else _default_action

    def _cheap_hit() -> bool:
        try:
            return bool(
                _verdict_from(_collect_results(include_timing=False))
                or _check_pinned_mismatch()
            )
        except Exception:
            return False

    def _full_hit() -> bool:
        try:
            if _cheap_hit():
                return True
            try:
                if _check_firmware():
                    return True
            except Exception:
                pass
            try:
                if _check_timing():
                    return True
            except Exception:
                pass
        except Exception:
            return False
        return False

    def _loop() -> None:
        tick = 0
        try:
            last = _MONOTONIC()
        except Exception:
            last = 0.0
        suspend_limit = max(10.0 * interval, 30.0)
        suspend_strikes = 0
        while not stop_event.is_set():
            try:
                try:
                    now = _MONOTONIC()
                    if last and (now - last) > suspend_limit:
                        last = now
                        try:
                            if _full_hit():
                                try:
                                    action()
                                except Exception:
                                    pass
                                return
                        except Exception:
                            pass
                        suspend_strikes += 1
                        if suspend_strikes >= 3:
                            try:
                                action()
                            except Exception:
                                pass
                            return
                        stop_event.wait(interval)
                        continue
                    last = now
                except Exception:
                    pass
                if tick == 0:
                    hit = _full_hit()
                else:
                    hit = _cheap_hit()
                    if not hit and tick % 10 == 0:
                        try:
                            if _check_firmware() or _check_timing():
                                hit = True
                        except Exception:
                            pass
                tick += 1
                if hit:
                    try:
                        action()
                    except Exception:
                        pass
                    return
            except Exception:
                pass
            stop_event.wait(interval)

    th = threading.Thread(target=_loop, name="hyper-antivm", daemon=daemon)
    try:
        th.start()
    except Exception:
        raise VirtualMachineDetected("protected")

    def _stop() -> None:
        if not _vm_check_admin():
            _vm_deny_admin("_stop")
        stop_event.set()
        with _WATCHDOGS_LOCK:
            try:
                _WATCHDOGS.remove(stop_event)
            except ValueError:
                pass

    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart). Donus: sayi."""
    if not _vm_check_admin():
        _vm_deny_admin("stop_all_watchdogs")
    n = 0
    with _WATCHDOGS_LOCK:
        events = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    for ev in events:
        try:
            ev.set()
            n += 1
        except Exception:
            continue
    return n


class _Guard:
    def __enter__(self) -> "_Guard":
        assert_no_vm()
        assert_no_tamper()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is None:
            assert_no_vm()
            assert_no_tamper()
            return False
        if is_virtualized() or is_environment_tampered():
            raise VirtualMachineDetected("protected") from exc  # type: ignore[misc]
        return False


def guard() -> _Guard:
    return _Guard()


def status() -> Dict[str, object]:
    """Ozet (uretimde kapali: yalnizca vendor; detay verbose ile)."""
    try:
        if not _verbose():
            try:
                brand = vendor()
            except Exception:
                brand = "unknown"
            return {"vendor": brand}
    except Exception:
        pass
    try:
        results = _raw_results()
    except Exception:
        results = {}
    try:
        hits = sum(1 for v in results.values() if v)
    except Exception:
        hits = 0
    try:
        brand = vendor()
    except Exception:
        brand = "unknown"
    try:
        tampered = is_environment_tampered()
    except Exception:
        tampered = True  # fail-closed
    return {"vendor": brand, "hits": hits, "details": results, "tampered": tampered}
