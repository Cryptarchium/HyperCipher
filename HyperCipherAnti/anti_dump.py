# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiDump (Stage 4)
=====================================
Entegre cok katmanli memory-dump korumasi. Stdlib-only, cross-platform,
fail-closed, sessiz (oracle vermez).

Arastirma sentezi (10 guclu teknik):
  [1] RLIMIT_CORE soft=0 (resource.setrlimit, reversible: hard korunur).
      CERT MEM06-C + CPython faulthandler.c (dahili ayni yontem) ile dogrulandi.
  [2] MADV_DONTDUMP (libc madvise, dogrudan tampon adresine).
      RLIMIT pipe-bypass'ina karsi (core_pattern '|...' ise soft=0 YETMEZ).
  [3] mlock (POSIX) / VirtualLock (Windows) -> swap/pagefile sizintisini keser.
  [4] faulthandler.disable() + is_enabled() + PYTHONFAULTHANDLER/PYTHONDEVMODE
      + sys._xoptions -> crash-traceback sizintisi (kaynak satirlari disari akar).
  [5] WerRegisterExcludedMemoryBlock (kernel32, Win10+) + WerAddExcludedApplication
      (HKCU) -> WER dump'undan cikarma (MS Learn werapi).
  [6] SilentProcessExit registry avi (winreg, stdlib) -> RtlReportSilentProcessExit
      hayalet-dump tuzagi (DeepInstinct/ZeroSalarium LSASS teknigi, savunma yonu).
  [7] Dumper-process taramasi: Toolhelp32 (Win) + /proc comm+cmdline (Linux).
      WerFault*/procdump*/gcore/dumpit/winpmem + /proc/<pid>/mem'i acik tutan av.
  [8] gc.DEBUG_SAVEALL (+PYTHONDUMPREFS env) + tracemalloc.is_tracing()
      + crash-sinyal baseline (SIGSEGV/SIGABRT/SIGBUS/SIGILL/SIGFPE degisimi).
  [9] SecureBuffer: bytearray + mlock + DONTDUMP + CryptProtectMemory(SAME_PROCESS)
      + ctypes.memset sifirlama. Anahtarlar RAM'de acik gezmez.
 [10] Sinyal disi yardimcilar: secure_zero(), exclude_from_wer(), harden().
 [11] WER LocalDumps avi (global/per-exe anahtar varsa toplama silahli) +
      break_dumps() (sinyal/faulthandler/gc/tracemalloc/excepthook restore).

Entegrasyon prensibi: HICBIR tek kontrole guvenme. Hepsi best-effort kosar,
hata -> bilinmiyor (False) doner, ASLA crash vermez. BIR tanesi bile True
donerse sonuc True. Hata mesaji OP AKTIR (hangi katman tetiklendi soylenmez).

DURUST SINIR (rezidu): kernel-seviyesi (PPL, /dev/mem, cold-boot), admin
ayricalikli dumper (SeDebugPrivilege ile MiniDumpWriteDump), ayni-ayricalik
tam-sahtecilik ve import-sirasi TOCTOU saf-Python'da durdurulamaz. Bu modul
crash-dump + firsatci-dumper + swap-hijyeni kapsar; sihirli degnek degildir.
ctypes/WinAPI butunlugu (derin windll yamasi) anti_hook'un alanidir -> tam
koruma icin iki modul birlikte kullanilmalidir.

Kullanim:
    from HyperCipherAnti import anti_dump
    anti_dump.harden()                 # tum guclendirmeleri uygula (best-effort)
    anti_dump.assert_no_dump()         # risk varsa DumpDetected
    if anti_dump.is_dumped(): ...      # sessiz kontrol
    buf = anti_dump.SecureBuffer(32)   # kilitli tampon
    buf.write(key_bytes); ...; buf.close()
    stop = anti_dump.start_watchdog(interval=1.0)
    stop()
"""

from __future__ import annotations

import ctypes
import gc
import mmap
import os
import signal
import sys
import threading
import time
import tracemalloc
from typing import Callable, Dict, List, Optional, Tuple

try:
    import faulthandler as _faulthandler
except Exception:
    _faulthandler = None  # type: ignore[assignment]

try:
    import resource as _resource
except Exception:
    _resource = None  # type: ignore[assignment]

try:
    import winreg as _winreg
except Exception:
    _winreg = None  # type: ignore[assignment]

__all__ = [
    "DumpDetected",
    "is_dumped",
    "check_all",
    "assert_no_dump",
    "harden",
    "secure_zero",
    "exclude_from_wer",
    "enforce_no_core",
    "enforce_faulthandler_off",
    "enforce_wer_excluded",
    "SecureBuffer",
    "break_dumps",
    "dumper_scan_health",
    "authorize_admin",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]


class DumpDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Import-aninda pin'ler (anti_debug/hook/trace konvansiyonu: sabit + canli capraz)
# ---------------------------------------------------------------------------

_OS_NAME = os.name
_PLATFORM = sys.platform
_PID = os.getpid()


def _live_pid() -> int:
    try:
        return _OS_GETPID()
    except Exception:
        try:
            return os.getpid()
        except Exception:
            return _PID
_TIME_MONO = time.monotonic
_GC_GET_DEBUG = gc.get_debug
_GC_GET_OBJECTS = gc.get_objects
_TRACEMALLOC_IS_TRACING = tracemalloc.is_tracing
_SYS_EXCEPTHOOK = sys.excepthook
_SYS_D_EXCEPTHOOK = sys.__excepthook__
_THREADING_EXCEPTHOOK = getattr(threading, "excepthook", None)
_SYS_UNRAISABLEHOOK = getattr(sys, "unraisablehook", None)
_SIG_GETSIGNAL = signal.getsignal
_SIG_SIGNAL = signal.signal
_OS_GETPID = os.getpid
_OS_LISTDIR = os.listdir
_OS_READLINK = os.readlink

_CRASH_SIGS: Tuple[str, ...] = ("SIGSEGV", "SIGABRT", "SIGBUS", "SIGILL",
                               "SIGFPE", "SIGTRAP", "SIGSYS", "SIGXCPU",
                               "SIGXFSZ")
_SIG_BASELINE: Dict[str, object] = {}
for _sn in _CRASH_SIGS:
    try:
        _sv = getattr(signal, _sn, None)
        if _sv is not None:
            _SIG_BASELINE[_sn] = signal.getsignal(_sv)
    except Exception:
        pass
del _sn, _sv

_XOPT_FAULT = "faulthandler"

_WIN_DUMPERS = frozenset({
    "werfault.exe", "werfaultsecure.exe", "wermgr.exe", "dwwin.exe", "dumprep.exe",
    "procdump.exe", "procdump64.exe", "procdump64a.exe", "dumpit.exe",
    "winpmem.exe", "winpmem64.exe", "debugdiag.exe", "adplus.exe", "userdump.exe",
    "avml.exe", "magnetramcapture.exe", "belkasoft ram capturer.exe",
    "ftk imager.exe", "gcore.exe", "createdump.exe", "dotnet-dump.exe",
    "dmp64.exe", "ramcapturer.exe", "livekd.exe", "kd.exe", "ntsd.exe",
})
_LINUX_DUMPERS = frozenset({
    "gcore", "procdump", "dotnet-dump", "createdump", "apport",
    "abrt-hook-ccpp", "avml", "memdump", "coredump",
    "gdb", "lldb", "eu-stack", "breakpad", "crashpad_handler",
    "perf", "lime", "dwarf",
})
_WIN_DUMPER_SUBS = (
    "dump", "mimikatz", "safetykatz", "nanodump", "dumpert",
    "procdump", "gcore", "winpmem", "windbg", "x64dbg", "x32dbg",
    "cheatengine", "cheat engine", "frida", "processhacker",
    "systeminformer", "dotnet-dump", "createdump", "avml",
    "ramcapture", "ramcapturer", "debugdiag", "adplus", "userdump", "livekd",
    "memdump", "coredump", "kd.exe", "ntsd", "dmp64",
)
_LINUX_DUMPER_SUBS = (
    "gcore", "procdump", "memdump", "dotnet-dump", "createdump",
    "eu-stack", "breakpad", "crashpad", "coredump", "winpmem",
)

_WD_LOCK = threading.Lock()
_WATCHDOGS: List[Tuple[threading.Thread, threading.Event]] = []
_DUMPER_SCAN_OK = True
_ADMIN_MODULES: Dict[str, str] = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def _note_scan_error(_src: str) -> None:
    """Tarama altyapisi hatasi: FP-trip yerine durust posture bayragi."""
    global _DUMPER_SCAN_OK
    try:
        with _WD_LOCK:
            _DUMPER_SCAN_OK = False
    except Exception:
        pass


def dumper_scan_health() -> bool:
    """Dumper-taramasi altyapisi saglikli mi (False=olculemedi, suphe degil)."""
    try:
        with _WD_LOCK:
            return bool(_DUMPER_SCAN_OK)
    except Exception:
        return False
_WIN_PROTO_INIT = False
_K32 = None
try:
    _K32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
except Exception:
    _K32 = None


def _win_k32():
    if _K32 is not None:
        return _K32
    try:
        return ctypes.windll.kernel32  # type: ignore[attr-defined]
    except Exception:
        return None


# ---------------------------------------------------------------------------
# [A] pinned-mismatch (kardes modullerle ayni konvansiyon)
# ---------------------------------------------------------------------------

def _check_pinned_mismatch() -> bool:
    try:
        if time.monotonic is not _TIME_MONO:
            return True
    except Exception:
        pass
    try:
        if gc.get_debug is not _GC_GET_DEBUG:
            return True
    except Exception:
        pass
    try:
        if gc.get_objects is not _GC_GET_OBJECTS:
            return True
    except Exception:
        pass
    try:
        if tracemalloc.is_tracing is not _TRACEMALLOC_IS_TRACING:
            return True
    except Exception:
        pass
    try:
        if sys.excepthook is not _SYS_EXCEPTHOOK:
            return True
    except Exception:
        pass
    try:
        if sys.__excepthook__ is not _SYS_D_EXCEPTHOOK:
            return True
    except Exception:
        pass
    try:
        if signal.getsignal is not _SIG_GETSIGNAL:
            return True
    except Exception:
        pass
    try:
        if signal.signal is not _SIG_SIGNAL:
            return True
    except Exception:
        pass
    try:
        if os.getpid is not _OS_GETPID:
            return True
    except Exception:
        pass
    try:
        if os.listdir is not _OS_LISTDIR:
            return True
    except Exception:
        pass
    try:
        if os.readlink is not _OS_READLINK:
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# [1] Core-dump durusu (POSIX: RLIMIT_CORE + core_pattern pipe + coredump_filter)
# ---------------------------------------------------------------------------

def _core_soft_limit() -> Optional[int]:
    try:
        if _resource is None:
            return None
        return int(_resource.getrlimit(_resource.RLIMIT_CORE)[0])
    except Exception:
        return None


def _core_pattern_piped() -> Optional[bool]:
    try:
        with open("/proc/sys/kernel/core_pattern", "r") as fh:
            return fh.read(1) == "|"
    except Exception:
        return None


def _coredump_anon_private() -> Optional[bool]:
    try:
        with open("/proc/self/coredump_filter", "r") as fh:
            return bool(int(fh.read().strip(), 16) & 0x1)
    except Exception:
        return None


def _check_core_posture() -> bool:
    """True = core-dump maruziyeti var (fail-closed mantigi)."""
    try:
        if _OS_NAME != "posix" or _PLATFORM.startswith(("win", "cygwin")):
            return False
        soft = _core_soft_limit()
        piped = _core_pattern_piped()
        anon = _coredump_anon_private()
        if piped is not False:
            # RLIMIT_CORE pipe'li handler'i DURDURMAZ (man core(5)). Anon-heap
            # dump'a giriyorsa MADV-disi alanlar sizabilir -> risk.
            # Desen okunamiyorsa da pipe varsay (fail-closed).
            return anon is not False
        if soft is None:
            return True  # olculemiyor -> fail-closed
        if soft != 0:
            # Anon-private dump disiysa heap guvende; bilinmiyorsa risk.
            return anon is not False
        return False
    except Exception:
        return False


def enforce_no_core() -> bool:
    """RLIMIT_CORE + dumpable=0 + coredump anon-bit temizle. Post-state doner.

    Pipe tuzagi (man core(5), LLVM #83703): core_pattern '|...' ile
    basliyorsa soft=0 YOK SAYILIR; sihirli deger 1 (tek bayt dump
    uretilemez) kullanilir. Yanlis deger sessiz-dump demektir."""
    try:
        if _resource is None:
            return False  # MEDIUM-4: Windows'ta RLIMIT yok; yapilmadiysa True YOK
        try:
            piped = _core_pattern_piped()
        except Exception:
            piped = None
        try:
            cur, mx = _resource.getrlimit(_resource.RLIMIT_CORE)
            want = 1 if piped is not False else 0
            if int(cur) != want:
                try:
                    hi = int(mx)
                except Exception:
                    hi = want
                if hi < want:
                    hi = want
                _resource.setrlimit(_resource.RLIMIT_CORE, (want, hi))
        except Exception:
            pass
        try:
            libc = ctypes.CDLL(None)
            libc.prctl.restype = ctypes.c_int
            libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong,
                                   ctypes.c_ulong, ctypes.c_ulong,
                                   ctypes.c_ulong]
            try:
                libc.prctl(4, 0, 0, 0, 0)
            except Exception:
                pass
        except Exception:
            pass
        try:
            with open("/proc/self/coredump_filter", "r+") as fh:
                try:
                    cur_mask = int(fh.read().strip(), 16)
                except Exception:
                    cur_mask = 0
                try:
                    fh.seek(0)
                    fh.write("0%x" % (cur_mask & ~0x1))
                    fh.truncate()
                except Exception:
                    pass
        except Exception:
            pass
        try:
            return not bool(_check_core_posture())
        except Exception:
            return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# [2] faulthandler durumu (crash-traceback sizintisi)
# ---------------------------------------------------------------------------

def _check_faulthandler() -> bool:
    try:
        if _faulthandler is not None:
            try:
                if bool(_faulthandler.is_enabled()):
                    return True
            except Exception:
                pass
        try:
            if os.environ.get("PYTHONFAULTHANDLER", "") == "1":
                return True
            if os.environ.get("PYTHONDEVMODE", "") == "1":
                return True
        except Exception:
            pass
        try:
            xopt = getattr(sys, "_xoptions", {}) or {}
            if bool(xopt.get(_XOPT_FAULT, False)):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


def enforce_faulthandler_off() -> bool:
    try:
        if _faulthandler is not None:
            try:
                _faulthandler.disable()
            except Exception:
                pass
            try:
                _faulthandler.cancel_dump_traceback_later()
            except Exception:
                pass
            try:
                unregister = getattr(_faulthandler, "unregister", None)
                if unregister is not None:
                    for signum in range(1, 65):
                        try:
                            unregister(signum)
                        except Exception:
                            continue
            except Exception:
                pass
        for ev in ("PYTHONFAULTHANDLER", "PYTHONDEVMODE"):
            try:
                os.environ.pop(ev, None)
            except Exception:
                pass
        try:
            return not bool(_check_faulthandler())
        except Exception:
            return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# [3] gc-retention + tracemalloc (bellekte sir birikmesi / profil izi)
# ---------------------------------------------------------------------------

def _check_gc_retention() -> bool:
    try:
        flags = int(_GC_GET_DEBUG())
        saveall = int(getattr(gc, "DEBUG_SAVEALL", 32))
        if flags & saveall:
            return True
    except Exception:
        pass
    try:
        # --with-pydebug refleak izi: cikista obje dokumu yapar.
        if os.environ.get("PYTHONDUMPREFS", "") == "1":
            return True
    except Exception:
        pass
    return False


def _check_tracemalloc() -> bool:
    try:
        return bool(_TRACEMALLOC_IS_TRACING())
    except Exception:
        return False


# ---------------------------------------------------------------------------
# [4] crash-sinyal handler baseline (SIGSEGV/SIGABRT/... degisimi)
# ---------------------------------------------------------------------------

def _check_crash_signals() -> bool:
    try:
        for name, baseline in _SIG_BASELINE.items():
            try:
                signum = getattr(signal, name, None)
                if signum is None:
                    continue
                if _SIG_GETSIGNAL(signum) != baseline:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# [5] Dumper-process taramasi (Win: Toolhelp32, Linux: /proc)
# ---------------------------------------------------------------------------

def _iter_win_processes() -> List[str]:
    out: List[str] = []
    try:
        k32 = _win_k32()
        if k32 is None:
            return out
        global _WIN_PROTO_INIT
        if not _WIN_PROTO_INIT:
            try:
                k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
                k32.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
                k32.Process32FirstW.restype = ctypes.c_int
                k32.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                k32.Process32NextW.restype = ctypes.c_int
                k32.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                k32.CloseHandle.restype = ctypes.c_int
                k32.CloseHandle.argtypes = [ctypes.c_void_p]
                _WIN_PROTO_INIT = True
            except Exception:
                return out
        TH32CS_SNAPPROCESS = 0x2
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        try:
            bad = snap is None or ctypes.c_longlong(int(snap)).value == -1
        except Exception:
            bad = snap is None
        if bad:
            return None
        try:
            class _PE32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_ulong),
                    ("cntUsage", ctypes.c_ulong),
                    ("th32ProcessID", ctypes.c_ulong),
                    ("th32DefaultHeapID", ctypes.c_void_p),
                    ("th32ModuleID", ctypes.c_ulong),
                    ("cntThreads", ctypes.c_ulong),
                    ("th32ParentProcessID", ctypes.c_ulong),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", ctypes.c_ulong),
                    ("szExeFile", ctypes.c_wchar * 260),
                ]
            pe = _PE32()
            pe.dwSize = ctypes.sizeof(_PE32)
            ok = k32.Process32FirstW(snap, ctypes.byref(pe))
            guard = 0
            while ok and guard < 4096:
                guard += 1
                try:
                    out.append(str(pe.szExeFile))
                except Exception:
                    pass
                try:
                    ok = k32.Process32NextW(snap, ctypes.byref(pe))
                except Exception:
                    break
        finally:
            try:
                k32.CloseHandle(snap)
            except Exception:
                pass
        return out
    except Exception:
        return None


def _iter_linux_procs() -> List[Tuple[int, str, str, str]]:
    out: List[Tuple[int, str, str]] = []
    try:
        pids = [p for p in _OS_LISTDIR("/proc") if p.isdigit()]
    except Exception:
        return out
    for p in pids[:4096]:
        try:
            pid = int(p)
            if pid == _live_pid():
                continue
            try:
                with open(f"/proc/{p}/comm", "r") as fh:
                    comm = fh.read().strip().split("\x00")[0][:128]
            except Exception:
                continue
            try:
                with open(f"/proc/{p}/cmdline", "rb") as fh:
                    cmd = fh.read(8192).replace(b"\x00", b" ").decode(
                        "utf-8", "ignore")[:2048]
            except Exception:
                cmd = ""
            try:
                exe = os.readlink(f"/proc/{p}/exe")
            except Exception:
                exe = ""
            out.append((pid, comm, cmd, exe))
        except Exception:
            continue
    return out


def _check_dumper_process(paranoid: bool = False) -> bool:
    try:
        if _OS_NAME == "nt":
            procs = _iter_win_processes()
            if procs is None:
                _note_scan_error("toolhelp")
                return False
            if not procs:
                # Canli Windows'ta 0 process imkansiz -> API sabotaji (fail-closed).
                return True
            for name in procs:
                try:
                    nl = name.strip().lower()
                    if nl in _WIN_DUMPERS:
                        return True
                    for sub in _WIN_DUMPER_SUBS:
                        try:
                            if sub in nl:
                                return True
                        except Exception:
                            continue
                except Exception:
                    continue
            return False
        if _OS_NAME == "posix":
            procs = _iter_linux_procs()
            try:
                has_proc = os.path.isdir("/proc")
            except Exception:
                has_proc = False
            if has_proc and not procs:
                return True
            mine = f"/proc/{_live_pid()}/mem"
            try:
                with open("/proc/self/status", "r") as _fh:
                    for _line in _fh:
                        if _line.startswith("TracerPid:"):
                            try:
                                if int(_line.split(":", 1)[1].strip().split()[0]) != 0:
                                    return True
                            except Exception:
                                return True
                            break
            except Exception:
                pass
            for pid, comm, cmd, exe in procs:
                try:
                    cl = comm.strip().lower()
                    if cl in _LINUX_DUMPERS:
                        return True
                    low = cmd.lower()
                    exl = exe.lower()
                    if ("gcore" in low or "procdump" in low or "memdump" in low
                            or mine in low or "/proc/self/mem" in low):
                        return True
                    for sub in _LINUX_DUMPER_SUBS:
                        try:
                            if sub in low or sub in cl or sub in exl:
                                return True
                        except Exception:
                            continue
                    if paranoid and "dump" in low and str(_PID) in low:
                        return True
                except Exception:
                    continue
            return False
        return False
    except Exception:
        return False


def _check_mem_fd_watch() -> bool:
    """Baska bir process /proc/<pid>/mem'imizi acik tutuyor mu? (Linux)."""
    try:
        if _OS_NAME != "posix" or not os.path.isdir("/proc"):
            return False
        target = f"/proc/{_live_pid()}/mem"
        for p in _OS_LISTDIR("/proc"):
            if not p.isdigit() or int(p) == _live_pid():
                continue
            fd_dir = f"/proc/{p}/fd"
            try:
                fds = _OS_LISTDIR(fd_dir)
            except Exception:
                continue
            for fd in fds:
                try:
                    if _OS_READLINK(f"{fd_dir}/{fd}") == target:
                        return True
                except Exception:
                    continue
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# [6] WER / SilentProcessExit avi (Windows, winreg stdlib)
# ---------------------------------------------------------------------------

_SPE_PATHS = (
    (0x80000002, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"),
    (0x80000001, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit"),
)
_IFEO_FLAG = 0x200  # FLG_MONITOR_SILENT_PROCESS_EXIT


def _own_exe_name() -> str:
    try:
        return os.path.basename(sys.executable or "").lower()
    except Exception:
        return ""


def _check_wer_armed() -> bool:
    try:
        if _OS_NAME != "nt" or _winreg is None:
            return False
        exe = _own_exe_name()
        if not exe:
            return False
        HKEYS = {0x80000002: _winreg.HKEY_LOCAL_MACHINE,
                 0x80000001: _winreg.HKEY_CURRENT_USER}
        for hive_id, sub in _SPE_PATHS:
            try:
                with _winreg.OpenKey(HKEYS[hive_id], sub + "\\" + exe) as key:
                    try:
                        mode, _ = _winreg.QueryValueEx(key, "ReportingMode")
                        if int(mode) & 0x2:
                            return True
                    except Exception:
                        # Anahtar var ama mod okunamadi -> fail-closed: kurulu say.
                        return True
            except FileNotFoundError:
                pass
            except Exception:
                continue
        try:
            with _winreg.OpenKey(
                    _winreg.HKEY_LOCAL_MACHINE,
                    r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\" + exe) as key:
                try:
                    flag, _ = _winreg.QueryValueEx(key, "GlobalFlag")
                    if int(flag) & _IFEO_FLAG:
                        return True
                except Exception:
                    pass
        except FileNotFoundError:
            pass
        except Exception:
            pass
        return False
    except Exception:
        return False


def _wer_dll():
    try:
        return ctypes.windll.wer  # type: ignore[attr-defined]
    except Exception:
        return None


_LOCALDUMPS_SUB = r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps"


def _localdumps_armed(hive: int, sub: str, root_container: bool = False) -> bool:
    try:
        if _winreg is None:
            return False
        try:
            with _winreg.OpenKey(hive, sub) as key:
                pass
        except Exception:
            return False
        try:
            with _winreg.OpenKey(hive, sub) as key:
                saw_count = False
                saw_type = False
                try:
                    count, _t = _winreg.QueryValueEx(key, "DumpCount")
                    saw_count = True
                    if int(count) == 0:
                        return False
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
                try:
                    dtype, _t = _winreg.QueryValueEx(key, "DumpType")
                    saw_type = True
                    if int(dtype) == 0:
                        return False
                except FileNotFoundError:
                    pass
                except Exception:
                    pass
                if root_container and not (saw_count or saw_type):
                    return False
                return True
        except Exception:
            return False
    except Exception:
        return False


def _check_wer_localdumps() -> bool:
    """LocalDumps SILAHLI ise True (DumpCount=0/DumpType=0 = etkisiz)."""
    try:
        if _OS_NAME != "nt" or _winreg is None:
            return False
        exe = _own_exe_name()
        HKEYS = (_winreg.HKEY_LOCAL_MACHINE, _winreg.HKEY_CURRENT_USER)
        for hive in HKEYS:
            try:
                if _localdumps_armed(hive, _LOCALDUMPS_SUB, root_container=True):
                    return True
            except Exception:
                continue
            if exe:
                try:
                    if _localdumps_armed(hive, _LOCALDUMPS_SUB + "\\" + exe):
                        return True
                except Exception:
                    continue
        return False
    except Exception:
        return False


def enforce_wer_excluded() -> bool:
    """WER'den cik: HKCU excluded-app + (Win10+) excluded-mem kaydi dene."""
    try:
        if _OS_NAME != "nt":
            return True
        exe = _own_exe_name()
        if not exe:
            return False
        ok = False
        try:
            wer = _wer_dll()
            if wer is not None:
                wer.WerAddExcludedApplicationW.restype = ctypes.c_long
                wer.WerAddExcludedApplicationW.argtypes = [ctypes.c_wchar_p, ctypes.c_int]
                if int(wer.WerAddExcludedApplicationW(exe, 0)) == 0:
                    ok = True
        except Exception:
            pass
        if not ok:
            # Registry fallback: HKCU ExcludedApplications (WER okur).
            try:
                if _winreg is not None:
                    with _winreg.CreateKey(
                            _winreg.HKEY_CURRENT_USER,
                            r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\ExcludedApplications") as key:
                        _winreg.SetValueEx(key, exe, 0, _winreg.REG_DWORD, 1)
                    ok = True
            except Exception:
                pass
        return ok
    except Exception:
        return False


def exclude_from_wer(address: int, size: int) -> bool:
    """WerRegisterExcludedMemoryBlock: hassas blogu WER dump disinda tut."""
    try:
        if _OS_NAME != "nt":
            return False
        try:
            address = int(address)
            size = int(size)
        except Exception:
            return False
        if not (0 < address < 2 ** 64 and 0 < size < 2 ** 32):
            return False
        wer = None
        try:
            wer = ctypes.windll.kernel32  # type: ignore[attr-defined]
        except Exception:
            return False
        try:
            fn = wer.WerRegisterExcludedMemoryBlock
        except Exception:
            return False
        fn.restype = ctypes.c_long
        fn.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        if int(fn(ctypes.c_void_p(address), ctypes.c_size_t(size))) != 0:
            return False
        try:
            _WER_BLOCKS.append((address, size))
            if len(_WER_BLOCKS) > 64:
                try:
                    _unexclude_one(*_WER_BLOCKS.pop(0))
                except Exception:
                    pass
        except Exception:
            pass
        return True
    except Exception:
        return False


_WER_BLOCKS: List[Tuple[int, int]] = []


def _unexclude_one(address: int, size: int) -> bool:
    try:
        if _OS_NAME != "nt":
            return False
        wer = ctypes.windll.kernel32  # type: ignore[attr-defined]
        try:
            fn = wer.WerUnregisterExcludedMemoryBlock
        except Exception:
            return False
        fn.restype = ctypes.c_long
        fn.argtypes = [ctypes.c_void_p]
        return int(fn(ctypes.c_void_p(int(address)))) == 0
    except Exception:
        return False


def unexclude_from_wer(address: int) -> bool:
    try:
        ok = _unexclude_one(int(address), 0)
        try:
            _WER_BLOCKS[:] = [b for b in _WER_BLOCKS if b[0] != int(address)]
        except Exception:
            pass
        return ok
    except Exception:
        return False


# ---------------------------------------------------------------------------
# [7] secure_zero + SecureBuffer (amiral gemisi)
# ---------------------------------------------------------------------------

def secure_zero(buf) -> bool:
    """Yazilabilir buffer'i ctypes.memset ile sifirla. Basari=True.

    Degistirilemez girdi (bytes/str) TypeError yukseltir (sessiz no-op YOK).
    """
    try:
        n = len(buf)
        if n <= 0:
            return True
    except Exception:
        raise TypeError("secure_zero:-sized buffer required")
    try:
        mv = memoryview(buf)
    except Exception:
        raise TypeError("secure_zero: buffer interface required")
    try:
        if mv.readonly:
            raise TypeError("secure_zero: writable buffer required")
    except TypeError:
        raise
    except Exception:
        raise TypeError("secure_zero: writable buffer required")
    try:
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, n)
        return True
    except Exception:
        raise TypeError("secure_zero: buffer address unreachable")


_MADV_DONTDUMP = int(getattr(mmap, "MADV_DONTDUMP", 16))


class SecureBuffer:
    """Kilitli hassas tampon: mlock + DONTDUMP + (Win) CryptProtectMemory.

    Kullanim (guvenli):
        buf = SecureBuffer(32)
        buf.write(key_bytes)   # bytes girdi silinemez; mumkunse bytearray ver
        buf.use(lambda mv: hmac_compare(mv, expect))  # kopyasiz erisim
        buf.close()            # sifirla + kilidi ac
    read() geriye uyumluluk icin durur ama plaintext bytes dondurur;
    mumkun olan her yerde use() tercih edilmeli.

    HIGH-2 duzeltmesi: `__slots__` + name-mangled `__buf` — `buf._buf`
    AttributeError verir (dogrudan okuma kapali); erisim yalnizca
    write()/read()/use() uzerinden. `__reduce__`/`__copy__` blokeli,
    `__repr__` redakte.
    """

    __slots__ = ("__buf", "_size", "_capacity", "_closed", "_addr",
                 "_locked", "_nodump", "_protected")

    def __reduce__(self):
        raise TypeError("SecureBuffer picklable degil (sizinti yuzeyi)")

    def __getstate__(self):
        raise TypeError("SecureBuffer picklable degil (sizinti yuzeyi)")

    def __setstate__(self, _state):
        raise TypeError("SecureBuffer picklable degil (sizinti yuzeyi)")

    def __deepcopy__(self, _memo):
        raise TypeError("SecureBuffer kopyalanamaz (sizinti yuzeyi)")

    def __copy__(self):
        raise TypeError("SecureBuffer kopyalanamaz (sizinti yuzeyi)")

    def __repr__(self):
        return "<SecureBuffer:%d locked=%s closed=%s>" % (
            int(getattr(self, "_size", 0)),
            bool(getattr(self, "_locked", False)),
            bool(getattr(self, "_closed", True)))

    __str__ = __repr__

    def __init__(self, size: int):
        if size <= 0:
            raise ValueError("size>0")
        padded = ((int(size) + 15) // 16) * 16
        self.__buf = bytearray(padded)
        self._size = padded
        self._capacity = int(size)
        self._closed = False
        self._addr = ctypes.addressof(ctypes.c_char.from_buffer(self.__buf))
        self._locked = False
        self._nodump = False
        self._protected = False
        self._lock()

    # -- kilitler (best-effort, basarisizlik sessiz) --
    def _lock(self) -> None:
        try:
            if _OS_NAME == "nt":
                k32 = _win_k32()
                if k32 is not None:
                    try:
                        k32.VirtualLock.restype = ctypes.c_int
                        k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                        if int(k32.VirtualLock(ctypes.c_void_p(self._addr),
                                               ctypes.c_void_p(self._size))):
                            self._locked = True
                    except Exception:
                        pass
            else:
                try:
                    libc = ctypes.CDLL(None)
                    libc.mlock.restype = ctypes.c_int
                    libc.mlock.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                    if int(libc.mlock(ctypes.c_void_p(self._addr),
                                      ctypes.c_void_p(self._size))) == 0:
                        self._locked = True
                except Exception:
                    pass
                try:
                    libc = ctypes.CDLL(None)
                    libc.madvise.restype = ctypes.c_int
                    libc.madvise.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
                    if int(libc.madvise(ctypes.c_void_p(self._addr),
                                        ctypes.c_void_p(self._size),
                                        _MADV_DONTDUMP)) == 0:
                        self._nodump = True
                except Exception:
                    pass
                try:
                    # MADV_DONTFORK=10: child process gizli tamponu miras almasin
                    libc.madvise(ctypes.c_void_p(self._addr),
                                 ctypes.c_void_p(self._size), 10)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            exclude_from_wer(self._addr, self._size)
        except Exception:
            pass

    def _unlock(self) -> None:
        try:
            if self._locked:
                if _OS_NAME == "nt":
                    try:
                        k32 = _win_k32()
                        if k32 is not None:
                            k32.VirtualUnlock.restype = ctypes.c_int
                            k32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                            k32.VirtualUnlock(ctypes.c_void_p(self._addr),
                                              ctypes.c_void_p(self._size))
                    except Exception:
                        pass
                else:
                    try:
                        libc = ctypes.CDLL(None)
                        libc.munlock.restype = ctypes.c_int
                        libc.munlock.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
                        libc.munlock(ctypes.c_void_p(self._addr),
                                     ctypes.c_void_p(self._size))
                    except Exception:
                        pass
                self._locked = False
        except Exception:
            pass

    # -- DPAPI bellek sifreleme (Win, 16-byte blok) --
    def protect(self) -> bool:
        try:
            if _OS_NAME != "nt" or self._protected or self._closed:
                return False
            if self._size % 16 != 0:
                return False
            try:
                crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
            except Exception:
                return False
            crypt32.CryptProtectMemory.restype = ctypes.c_int
            crypt32.CryptProtectMemory.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
            if int(crypt32.CryptProtectMemory(ctypes.c_void_p(self._addr),
                                              ctypes.c_ulong(self._size), 0)):
                self._protected = True
                return True
            return False
        except Exception:
            return False

    def unprotect(self) -> bool:
        try:
            if not self._protected:
                return True
            try:
                crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
            except Exception:
                return False
            crypt32.CryptUnprotectMemory.restype = ctypes.c_int
            crypt32.CryptUnprotectMemory.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
            ok = bool(crypt32.CryptUnprotectMemory(ctypes.c_void_p(self._addr),
                                                   ctypes.c_ulong(self._size), 0))
            if ok:
                self._protected = False
            return ok
        except Exception:
            return False

    # -- veri --
    def write(self, data: bytes) -> None:
        if self._closed:
            raise ValueError("closed")
        if len(data) > self._capacity:
            raise ValueError("data buyuklugu tamponu asiyor (sessiz kirpma YOK)")
        n = len(data)
        was = self._protected
        if was and not self.unprotect():
            raise RuntimeError("cozme basarisiz (yazma iptal, veri korunuyor)")
        try:
            self.__buf[:n] = data[:n]
        finally:
            if was:
                self.protect()

    def read(self) -> bytes:
        """Icerigin degismez kopyasini dondurur (cagiran taraf plaintext tutar)."""
        if self._closed:
            raise ValueError("closed")
        was = self._protected
        if was and not self.unprotect():
            raise RuntimeError("cozme basarisiz (sifreli bayt DISARI verilmiyor)")
        try:
            return bytes(self.__buf)
        finally:
            if was:
                self.protect()

    def use(self, fn):
        """Kopyasiz erisim: fn(memoryview) cagir, sonucu dondur.

        fn'e verilen memoryview disari SIZDIRILMAMALIDIR (bytes(mv)/mv.tobytes
        kopya olusturur). Korumaaciliysa islem suresince cozulur, finally'de
        yeniden korunur.
        """
        if self._closed:
            raise ValueError("closed")
        if not callable(fn):
            raise TypeError("callable required")
        was = self._protected
        if was and not self.unprotect():
            raise RuntimeError("cozme basarisiz")
        try:
            return fn(memoryview(self.__buf))
        finally:
            if was:
                try:
                    self.protect()
                except Exception:
                    pass

    def status(self) -> Dict[str, bool]:
        return {"locked": self._locked, "nodump": self._nodump,
                "protected": self._protected, "closed": self._closed}

    def close(self) -> None:
        try:
            if self._protected:
                self.unprotect()
        except Exception:
            pass
        try:
            secure_zero(self.__buf)
        except Exception:
            pass
        try:
            unexclude_from_wer(self._addr)
        except Exception:
            pass
        try:
            self._unlock()
        except Exception:
            pass
        self._closed = True

    def __enter__(self) -> "SecureBuffer":
        return self

    def __exit__(self, *exc) -> bool:
        try:
            self.close()
        except Exception:
            pass
        return False

    def __del__(self):  # noqa: D105
        try:
            if not self._closed:
                try:
                    if self._protected:
                        self.unprotect()
                except Exception:
                    pass
                try:
                    secure_zero(self.__buf)
                except Exception:
                    pass
                try:
                    self._unlock()
                except Exception:
                    pass
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Toplu API (kardes konvansiyon)
# ---------------------------------------------------------------------------

def check_all(paranoid: bool = False) -> Dict[str, bool]:
    out: Dict[str, bool] = {}
    for name, fn in (
        ("pinned_mismatch", _check_pinned_mismatch),
        ("core_posture", _check_core_posture),
        ("faulthandler", _check_faulthandler),
        ("gc_retention", _check_gc_retention),
        ("tracemalloc", _check_tracemalloc),
        ("crash_signals", _check_crash_signals),
        ("dumper_process", lambda: _check_dumper_process(paranoid=paranoid)),
        ("mem_fd_watch", _check_mem_fd_watch),
        ("wer_armed", _check_wer_armed),
        ("wer_localdumps", _check_wer_localdumps),
    ):
        try:
            out[name] = bool(fn())
        except Exception:
            out[name] = True  # fail-closed
    return out


def is_dumped(paranoid: bool = False) -> bool:
    try:
        return any(check_all(paranoid=paranoid).values())
    except Exception:
        return True


def assert_no_dump(paranoid: bool = False) -> None:
    if is_dumped(paranoid=paranoid):
        raise DumpDetected("protected")


def harden() -> Dict[str, bool]:
    """Tum guclendirmeleri uygula (best-effort). Donus: {ad: basari}."""
    out: Dict[str, bool] = {}
    out["no_core"] = enforce_no_core()
    out["faulthandler_off"] = enforce_faulthandler_off()
    out["wer_excluded"] = enforce_wer_excluded()
    out["dumper_scan_ok"] = dumper_scan_health()
    out["admin_authorized"] = len(_ADMIN_MODULES)
    out["admin_locked"] = _ADMIN_LOCKED
    out["admin_denied"] = _ADMIN_DENIED
    return out


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _WD_LOCK:
                _ADMIN_DENIED += 1
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
        with _WD_LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _WD_LOCK:
            allowed = dict(_ADMIN_MODULES)
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


def _deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _WD_LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise DumpDetected("protected")


def _own_suite_hook(fn) -> bool:
    """INFO-1: HyperCipherAnti kardes-modul hook'u mu (dost-atesi yok)?"""
    try:
        mod = getattr(fn, "__module__", "") or ""
        return mod == "HyperCipherAnti" or mod.startswith("HyperCipherAnti.")
    except Exception:
        return False


def break_dumps() -> Dict[str, bool]:
    """Degistirilmis dump-yuzeylerini baseline'a dondur (acik mudahale).

    YONETIM: kayitli operator sart (hook-sokum saldiri-primitifi olmasin).
    Kardes-suit hook'larina DOKUNULMAZ (INFO-1 dost-atesi kapali).
    Sinyal handler'lari, faulthandler kayitlari, gc SAVEALL, tracemalloc ve
    suit-disi sys.excepthook import-anindaki degere dondurulur.
    Donus: {alan: restore-edildi-mi}."""
    if not _check_admin():
        _deny_admin("break_dumps")
    out: Dict[str, bool] = {}
    try:
        fixed = False
        for name, baseline in _SIG_BASELINE.items():
            try:
                signum = getattr(signal, name, None)
                if signum is None:
                    continue
                if _SIG_GETSIGNAL(signum) != baseline:
                    _SIG_SIGNAL(signum, baseline)
                    fixed = True
            except Exception:
                continue
        out["crash_signals"] = fixed
    except Exception:
        out["crash_signals"] = False
    try:
        before = _check_faulthandler()
        enforce_faulthandler_off()
        out["faulthandler"] = bool(before)
    except Exception:
        out["faulthandler"] = False
    try:
        fixed = False
        try:
            if int(gc.get_debug()) & int(getattr(gc, "DEBUG_SAVEALL", 32)):
                gc.set_debug(0)
                fixed = True
        except Exception:
            pass
        try:
            if getattr(gc, "garbage", None):
                gc.garbage.clear()
                fixed = True
        except Exception:
            pass
        try:
            gc.collect()
        except Exception:
            pass
        out["gc_retention"] = fixed
    except Exception:
        out["gc_retention"] = False
    try:
        fixed = False
        try:
            if _TRACEMALLOC_IS_TRACING():
                try:
                    tracemalloc.clear_traces()
                except Exception:
                    pass
                tracemalloc.stop()
                fixed = True
        except Exception:
            pass
        out["tracemalloc"] = fixed
    except Exception:
        out["tracemalloc"] = False
    try:
        fixed = False
        try:
            if sys.excepthook is not _SYS_EXCEPTHOOK and not _own_suite_hook(sys.excepthook):
                sys.excepthook = _SYS_EXCEPTHOOK
                fixed = True
        except Exception:
            pass
        try:
            if sys.__excepthook__ is not _SYS_D_EXCEPTHOOK and not _own_suite_hook(sys.__excepthook__):
                sys.__excepthook__ = _SYS_D_EXCEPTHOOK
                fixed = True
        except Exception:
            pass
        try:
            cur_te = getattr(threading, "excepthook", None)
            if _THREADING_EXCEPTHOOK is not None and cur_te is not _THREADING_EXCEPTHOOK and not _own_suite_hook(cur_te):
                try:
                    threading.excepthook = _THREADING_EXCEPTHOOK
                    fixed = True
                except Exception:
                    pass
        except Exception:
            pass
        try:
            cur_un = getattr(sys, "unraisablehook", None)
            if _SYS_UNRAISABLEHOOK is not None and cur_un is not _SYS_UNRAISABLEHOOK and not _own_suite_hook(cur_un):
                try:
                    sys.unraisablehook = _SYS_UNRAISABLEHOOK
                    fixed = True
                except Exception:
                    pass
        except Exception:
            pass
        out["excepthook"] = fixed
    except Exception:
        out["excepthook"] = False
    return out


def guard(paranoid: bool = False):
    """with anti_dump.guard(): -> harden + assert giris+CIKIS (restore YOK, tek yonlu)."""
    class _G:
        def __enter__(self) -> Dict[str, bool]:
            h = harden()
            assert_no_dump(paranoid=paranoid)
            return h

        def __exit__(self, *exc) -> bool:
            try:
                assert_no_dump(paranoid=paranoid)
            except Exception:
                raise
            return False
    return _G()


def _watch_loop(stop: threading.Event, interval: float, paranoid: bool,
                on_detect: Optional[Callable[[], None]]) -> None:
    try:
        action = on_detect
        if action is None:
            def _default_exit() -> None:
                try:
                    os._exit(1)
                except Exception:
                    pass
            action = _default_exit
        while not stop.wait(interval):
            try:
                if is_dumped(paranoid=paranoid):
                    try:
                        action()
                    except Exception:
                        pass
                    return
            except Exception:
                continue
    except Exception:
        pass


def start_watchdog(interval: float = 1.0, paranoid: bool = False,
                   on_detect: Optional[Callable[[], None]] = None):
    """Arka plan izleme. Donus: stop() callable. Fail-closed: hata=izlemeye devam."""
    global _ADMIN_LOCKED
    try:
        with _WD_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
    except Exception:
        iv = 1.0
    if not (0.1 <= iv <= 3600.0):
        iv = 1.0
    stop = threading.Event()
    thr = threading.Thread(target=_watch_loop, args=(stop, iv, paranoid, on_detect),
                           daemon=True, name="anti-dump-watch")
    try:
        thr.start()
    except Exception:
        def _noop() -> None:
            return None
        return _noop
    with _WD_LOCK:
        _WATCHDOGS.append((thr, stop))

    def _stop() -> None:
        try:
            stop.set()
        except Exception:
            pass
        try:
            with _WD_LOCK:
                _WATCHDOGS[:] = [item for item in _WATCHDOGS if item[1] is not stop]
        except Exception:
            pass
    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    with _WD_LOCK:
        items = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    n = 0
    for _, stop in items:
        try:
            stop.set()
            n += 1
        except Exception:
            continue
    return n
