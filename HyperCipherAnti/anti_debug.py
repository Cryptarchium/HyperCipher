# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiDebug (Stage 4)
=====================================
Entegre cok katmanli debugger tespiti. Stdlib-only, cross-platform,
fail-closed, sessiz (oracle vermez).

Arastirma sentezi (5 guclu arac/teknik):
  [1] Python trace-hook tespiti: sys.gettrace() + sys.getprofile() + sys.monitoring (3.12+)
      -> pdb, pydevd, coverage, sitecustomize enjeksiyonunu yakalar.
      (pyobfus P2-15, Dragon launcher, SANS diary, PyOuro ile dogrulandi)
  [2] Native OS debugger tespiti: Windows IsDebuggerPresent + CheckRemoteDebuggerPresent
      + NtQueryInformationProcess(DebugPort/Flags/ObjectHandle); Linux TracerPid;
      macOS ptrace denemesi. -> gdb/strace/x64dbg/WinDbg gibi sys.gettrace()'in
      goremedigi OS-seviyesi ptrace'leri yakalar.
  [3] Timing-skew anomalisi: sik dongu suresi olcumu -> single-step / breakpoint
      degerlendirme overhead'ini yakalar (platform bagimsiz). Esik bilerek
      comert tutulur (CPU throttle'da false-positive oldurmez).
  [4] Ortam/artifact taramasi: supheli env var'lar (PYCHARM_HOSTED, VSCODE_PID,
      PYDEVD_*, DEBUGPY_*, etc.) + Frida/Sandboxie DLL varligi (GetModuleHandleW).
      -> IDE debugger + enjeksiyon framework izlerini yakalar.
  [5] API-hook capraz dogrulama: IsDebuggerPresent vs CheckRemoteDebuggerPresent
      vs NtQueryInformationProcess(DebugPort) ucgeni tutarsizsa HOOK/BYPASS
      suphesi -> fail-closed. (0xE9 trampoline + ScyllaHide tarzı patch'lere karsi)

Entegrasyon prensibi: HICBIR tek kontrole guvenme. Hepsi best-effort kosar,
hata -> bilinmiyor (False) doner, ASLA crash vermez. BIR tanesi bile True
donerse sonuc True. Hata mesaji OP AKTIR (hangi katman tetiklendi soylenmez).

Kullanim:
    from HyperCipherAnti import anti_debug
    anti_debug.assert_no_debugger()          # varsa DebuggerDetected
    if anti_debug.is_debugged(): ...        # sessiz kontrol
    stop = anti_debug.start_watchdog(interval=0.5)  # arka plan izleme
    stop()                                   # izlemeyi durdur
"""

from __future__ import annotations

import ctypes
import gc
import os
import platform
import sys
import threading
import time
import types as _types
from typing import Callable, Dict, Optional

__all__ = [
    "DebuggerDetected",
    "is_debugged",
    "check_all",
    "assert_no_debugger",
    "start_watchdog",
    "stop_all_watchdogs",
    "enforce_macos_ptrace_deny",
    "enforce_linux_no_dump",
    "enforce_windows_protect",
    "guard",
]


class DebuggerDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# B1 FIX: import aninda orijinal referanslari sabitle. Saldirgan sonradan
# sys.gettrace = lambda: None derse CANLI lookup kor olur; sabit referans
# + canli deger caprazlanir, tutarsizlik = hook suphesi -> True.
_SYS_GETTRACE = sys.gettrace
_SYS_GETPROFILE = getattr(sys, "getprofile", None)
try:
    _SYS_BREAKPOINTHOOK = sys.breakpointhook
except Exception:
    _SYS_BREAKPOINTHOOK = None
_GC_GET_OBJECTS = gc.get_objects
_OS_EXIT = os._exit
_MON_MONITORING = getattr(sys, "monitoring", None)
try:
    _MON_GET_EVENTS = getattr(_MON_MONITORING, "get_events", None)
except Exception:
    _MON_GET_EVENTS = None
_PERF_COUNTER = time.perf_counter
_MONOTONIC = time.monotonic
_PLATFORM_SYS = platform.system().lower()
_OS_ENVIRON = os.environ
_SYS_MODULES = sys.modules
_ADMIN_MODULES: dict = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0
_WIN_LOCK = threading.Lock()
_WIN_PROTO_INIT = False
_K32 = None
_NTDLL = None
try:
    _K32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    _NTDLL = ctypes.windll.ntdll  # type: ignore[attr-defined]
except Exception:
    _K32 = None
    _NTDLL = None


def _win_handles() -> tuple:
    if _K32 is not None:
        return (_K32, _NTDLL)
    try:
        return (ctypes.windll.kernel32, ctypes.windll.ntdll)  # type: ignore[attr-defined]
    except Exception:
        return (None, None)


def _check_pinned_mismatch() -> bool:
    try:
        if time.perf_counter is not _PERF_COUNTER:
            return True
    except Exception:
        pass
    try:
        if time.monotonic is not _MONOTONIC:
            return True
    except Exception:
        pass
    try:
        if platform.system().lower() != _PLATFORM_SYS:
            return True
    except Exception:
        pass
    try:
        if os.environ is not _OS_ENVIRON:
            return True
    except Exception:
        pass
    try:
        if gc.get_objects is not _GC_GET_OBJECTS:
            return True
    except Exception:
        pass
    try:
        if os._exit is not _OS_EXIT:
            return True
    except Exception:
        pass
    try:
        if sys.modules is not _SYS_MODULES:
            return True
    except Exception:
        pass
    try:
        if sys.gettrace is not _SYS_GETTRACE:
            return True
    except Exception:
        pass
    try:
        gt = sys.gettrace
        if type(gt) is not _types.BuiltinFunctionType or getattr(gt, "__self__", None) is not sys:
            return True
    except Exception:
        pass
    try:
        live_gp = getattr(sys, "getprofile", None)
        if live_gp is not _SYS_GETPROFILE:
            return True
    except Exception:
        pass
    try:
        gp = sys.getprofile
        if type(gp) is not _types.BuiltinFunctionType or getattr(gp, "__self__", None) is not sys:
            return True
    except Exception:
        pass
    try:
        live_bh = getattr(sys, "breakpointhook", None)
        if _SYS_BREAKPOINTHOOK is not None and live_bh is not _SYS_BREAKPOINTHOOK:
            return True
    except Exception:
        pass
    try:
        bh = sys.breakpointhook
        if type(bh) is not _types.BuiltinFunctionType or getattr(bh, "__self__", None) is not sys:
            return True
    except Exception:
        pass
    try:
        live_mon = getattr(sys, "monitoring", None)
        if live_mon is not _MON_MONITORING:
            return True
    except Exception:
        pass
    try:
        mon = _MON_MONITORING
        live_ge = getattr(mon, "get_events", None) if mon is not None else None
        if live_ge is not _MON_GET_EVENTS:
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# [1] Python trace-hook katmani
# ---------------------------------------------------------------------------

def _check_trace_hooks() -> bool:
    try:
        pinned = None
        try:
            pinned = _SYS_GETTRACE()
        except Exception:
            pinned = None
        live = None
        try:
            live = sys.gettrace()
        except Exception:
            live = None
        if pinned is not None or live is not None:
            return True
        if pinned is not live:
            return True
        try:
            thr_gettrace = getattr(threading, "gettrace", None)
            if callable(thr_gettrace) and thr_gettrace() is not None:
                return True
        except Exception:
            pass
    except Exception:
        pass
    try:
        gp = _SYS_GETPROFILE
        if callable(gp):
            try:
                if gp() is not None:
                    return True
            except Exception:
                pass
        live_gp = getattr(sys, "getprofile", None)
        if live_gp is not gp:
            return True
        if callable(live_gp):
            try:
                if live_gp() is not None:
                    return True
            except Exception:
                pass
    except Exception:
        pass
    try:
        # breakpointhook degisimi: PyCharm/pydev gettrace bos birakip
        # breakpointhook'u swap eder (research: PyCharm 2023.3 vakasi).
        pinned_bh = _SYS_BREAKPOINTHOOK
        try:
            live_bh = sys.breakpointhook
        except Exception:
            live_bh = None
        if pinned_bh is not None and live_bh is not pinned_bh:
            return True
        try:
            if getattr(live_bh, "__module__", "sys") != "sys":
                return True
        except Exception:
            pass
    except Exception:
        pass
    try:
        mon = _MON_MONITORING
        live_mon = getattr(sys, "monitoring", None)
        if (mon is None) != (live_mon is None):
            return True
        if live_mon is not None and live_mon is not mon:
            return True
        get_events = _MON_GET_EVENTS
        try:
            live_ge = getattr(live_mon, "get_events", None) if live_mon is not None else None
        except Exception:
            live_ge = None
        if (get_events is None) != (live_ge is None):
            return True
        if live_ge is not None and live_ge is not get_events:
            return True
        if mon is not None and callable(get_events):
                tool_ids: list[int] = []
                for attr in ("DEBUGGER_ID", "COVERAGE_ID", "PROFILER_ID", "OPTIMIZER_ID"):
                    try:
                        tool_ids.append(int(getattr(mon, attr)))
                    except Exception:
                        continue
                if not tool_ids:
                    tool_ids = [0, 1, 2, 5]
                for tid in tool_ids:
                    try:
                        if get_events(tid):
                            return True
                    except Exception:
                        continue
                try:
                    get_tool = getattr(mon, "get_tool", None)
                except Exception:
                    get_tool = None
                if callable(get_tool):
                    for tid in tool_ids:
                        try:
                            if get_tool(tid) is not None:
                                return True
                        except Exception:
                            continue
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# [2] Native OS katmani
# ---------------------------------------------------------------------------

def _init_win_prototypes() -> bool:
    global _WIN_PROTO_INIT
    kernel32, ntdll = _win_handles()
    if kernel32 is None:
        return False
    with _WIN_LOCK:
        if _WIN_PROTO_INIT:
            return True
        try:
            kernel32.IsDebuggerPresent.restype = ctypes.c_bool
            kernel32.IsDebuggerPresent.argtypes = []
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            kernel32.GetCurrentProcess.argtypes = []
            kernel32.CheckRemoteDebuggerPresent.restype = ctypes.c_bool
            kernel32.CheckRemoteDebuggerPresent.argtypes = [
                ctypes.c_void_p, ctypes.POINTER(ctypes.c_bool)]
            kernel32.GetModuleHandleW.restype = ctypes.c_void_p
            kernel32.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            try:
                if ntdll is not None:
                    ntdll.NtQueryInformationProcess.restype = ctypes.c_long
                    ntdll.NtQueryInformationProcess.argtypes = [
                        ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p,
                        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
            except Exception:
                pass
            _WIN_PROTO_INIT = True
            return True
        except Exception:
            return False


def _check_windows_native() -> bool:
    kernel32, ntdll = _win_handles()
    if kernel32 is None:
        return False
    _init_win_prototypes()
    try:
        if kernel32.IsDebuggerPresent():
            return True
    except Exception:
        pass
    try:
        flag = ctypes.c_bool(False)
        h = kernel32.GetCurrentProcess()
        if kernel32.CheckRemoteDebuggerPresent(h, ctypes.byref(flag)) and flag.value:
            return True
    except Exception:
        pass
    # 2c. NtQueryInformationProcess(DebugPort=7, DebugObjectHandle=30,
    #     DebugFlags=31). IsDebuggerPresent hook'lanmissa bile kernel yapisi
    #     ele verir. NOT: 9=ProcessAccessToken'dir (DebugFlags DEGIL).
    try:
        NtQIP = ntdll.NtQueryInformationProcess
        h = kernel32.GetCurrentProcess()
        # DebugPort: debugged ise sifir-disi handle doner
        port = ctypes.c_void_p(0)
        retlen = ctypes.c_ulong(0)
        try:
            status = NtQIP(h, 7, ctypes.byref(port), ctypes.sizeof(port), ctypes.byref(retlen))
            if status == 0 and port.value not in (None, 0):
                return True
        except Exception:
            pass
        # DebugObjectHandle: debug objesi varsa handle doner (ScyllaHide'in
        # PEB-yamasi bunu gizleyemez; en guclu sinif)
        try:
            dbgobj = ctypes.c_void_p(0)
            status = NtQIP(h, 30, ctypes.byref(dbgobj), ctypes.sizeof(dbgobj), ctypes.byref(retlen))
            if status == 0 and dbgobj.value not in (None, 0):
                return True
        except Exception:
            pass
        # DebugFlags: debugged degilse 1, debugged ise 0 (ters-mantik)
        flags = ctypes.c_ulong(0)
        try:
            status = NtQIP(h, 31, ctypes.byref(flags), ctypes.sizeof(flags), ctypes.byref(retlen))
            if status == 0 and flags.value == 0:
                return True
        except Exception:
            pass
        # 2d. PEB-direkt okuma (API-hook'larin otesinde):
        #     NtGlobalFlag@0xBC & 0x70 (debugger'da olusan process) ve
        #     ProcessHeap Flags@0x70==2 / ForceFlags@0x74==0.
        #     PEB adresi NtQueryInformationProcess(BasicInformation=0)'dan.
        try:
            import struct as _st
            pbi = ctypes.create_string_buffer(48)
            status = NtQIP(h, 0, pbi, 48, ctypes.byref(retlen))
            if status == 0:
                peb = _st.unpack_from("<Q", pbi, 8)[0]
                if peb:
                    import ctypes as _ct
                    try:
                        ngf = _ct.c_uint32.from_address(peb + 0xBC).value
                        if ngf & 0x70:
                            return True
                    except Exception:
                        pass
                    try:
                        heap = _st.unpack_from("<Q", _ct.string_at(peb + 0x30, 8))[0]
                        if heap:
                            fl = _ct.c_uint32.from_address(heap + 0x70).value
                            ff = _ct.c_uint32.from_address(heap + 0x74).value
                            if fl != 2 or ff != 0:
                                return True
                    except Exception:
                        pass
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_linux_tracerpid() -> bool:
    # /proc/self/status -> TracerPid: 0 degilse gdb/strace/ptrace var.
    # Linux'ta dosya okunamiyor/parse edilemiyorsa fail-closed True.
    try:
        with open("/proc/self/status", "r", encoding="utf-8", errors="strict") as fh:
            for line in fh:
                if line.startswith("TracerPid:"):
                    try:
                        pid = int(line.split(":", 1)[1].strip().split()[0])
                    except Exception:
                        if _PLATFORM_SYS == "linux":
                            return True
                        return False
                    return pid != 0
        if _PLATFORM_SYS == "linux":
            return True
    except Exception:
        if _PLATFORM_SYS == "linux":
            return True
        pass
    return False


def _check_macos_ptrace() -> bool:
    # sysctl kern.proc.pid.<pid> -> kinfo_proc.kp_proc.p_flag & P_TRACED.
    # En guclu stdlib-only macOS tespiti (Apple TechNote desen). Best-effort:
    # herhangi bir hata/belirsizlik -> False (yanlis alarm uretme).
    # P_TRACED = 0x00000800; p_flag kinfo_proc icinde 32. offset'te.
    try:
        if _PLATFORM_SYS != "darwin":
            return False
        import ctypes.util as _util
        name = _util.find_library("c")
        if not name:
            return False
        libc = ctypes.CDLL(name, use_errno=True)
        try:
            libc.sysctl.restype = ctypes.c_int
            libc.sysctl.argtypes = [ctypes.POINTER(ctypes.c_int), ctypes.c_uint,
                                    ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t),
                                    ctypes.c_void_p, ctypes.c_size_t]
            libc.getpid.restype = ctypes.c_int
            libc.getpid.argtypes = []
        except Exception:
            return False
        try:
            pid = int(libc.getpid())
        except Exception:
            return False
        try:
            mib = (ctypes.c_int * 4)(1, 14, 1, pid)  # CTL_KERN, KERN_PROC, KERN_PROC_PID
            buf = ctypes.create_string_buffer(648)
            size = ctypes.c_size_t(648)
            ret = libc.sysctl(mib, 4, buf, ctypes.byref(size), None, 0)
            if int(ret) != 0:
                return False
            if int(size.value) < 36:
                return False
            import struct as _struct
            (p_flag,) = _struct.unpack_from("<I", bytes(buf.raw), 32)
            return bool(p_flag & 0x00000800)
        except Exception:
            return False
    except Exception:
        return False


_DEBUGGER_MODULES = frozenset({
    "pdb", "ipdb", "rpdb", "pudb", "bdb",
    "pydevd", "pydevd_frame_eval_cython", "pydevd_frame_evaluator",
    "_pydevd_bundle", "debugpy", "ptvsd",
    "coverage", "trace", "profile", "cprofile",
    "yappi", "scalene", "viztracer", "hunter", "pyinstrument",
    "lsprof", "_lsprof",
})

# gc taramasi pahali (100k+ nesne) -> kisa TTL cache. Tracer moduller
# saniyeler icinde belirip kaybolmaz; watchdog tick'i hafifler.
_GC_TTL = 0.5
_GC_CACHE = {"at": 0.0, "hit": False}


def _check_gc_tracers() -> bool:
    try:
        try:
            now = _MONOTONIC()
        except Exception:
            now = 0.0
        try:
            with _WATCHDOGS_LOCK:
                cached = (_GC_CACHE["at"], _GC_CACHE["hit"])
            if now and (now - cached[0]) < _GC_TTL:
                return cached[1]
        except Exception:
            pass
        hit = False
        try:
            objs = _GC_GET_OBJECTS()
        except Exception:
            return False
        for ob in objs:
            try:
                mod = getattr(ob, "__module__", "") or ""
            except Exception:
                continue
            try:
                ml = str(mod).lower()
            except Exception:
                continue
            if ml.startswith("coverage") or ml in (
                    "trace", "profile", "cprofile", "yappi", "scalene",
                    "viztracer", "hunter", "pyinstrument", "debugpy",
                    "pydevd", "_pydevd_bundle"):
                hit = True
                break
            try:
                tname = type(ob).__name__ or ""
            except Exception:
                continue
            if tname in ("Coverage", "CTracer", "PyTracer",
                         "YappiStat", "KernelTracer"):
                hit = True
                break
    except Exception:
        pass
    try:
        with _WATCHDOGS_LOCK:
            _GC_CACHE["at"] = now
            _GC_CACHE["hit"] = hit
    except Exception:
        pass
    return hit


def _check_debugger_modules() -> bool:
    try:
        mods = getattr(sys, "modules", None)
        if not mods:
            return False
        for name in _DEBUGGER_MODULES:
            try:
                if name in mods:
                    return True
            except Exception:
                continue
        # Prefiks supurme: pydevd._pydevd_bundle, debugpy.common gibi altlar
        try:
            keys = list(mods.keys())
        except Exception:
            keys = []
        for key in keys:
            try:
                top = key.split(".", 1)[0].lower()
            except Exception:
                continue
            if top in _DEBUGGER_MODULES:
                return True
    except Exception:
        pass
    return False


_LINUX_MAP_MARKS = ("frida", "gum-js", "gadget", "linjector")


def _check_linux_maps() -> bool:
    # /proc/self/maps'te enjeksiyon araci izi (Frida/Gadget). Ucuz tek-dosya
    # okuma; mesru FP uretmez (bu isimler normalde map'te gecmez).
    try:
        if _PLATFORM_SYS != "linux":
            return False
        with open("/proc/self/maps", "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                try:
                    low = line.lower()
                except Exception:
                    continue
                for mark in _LINUX_MAP_MARKS:
                    try:
                        if mark in low:
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    return False


def enforce_macos_ptrace_deny() -> bool:
    try:
        import ctypes.util as _util
        name = _util.find_library("c")
        if not name:
            return False
        libc = ctypes.CDLL(name, use_errno=True)
        libc.ptrace.restype = ctypes.c_int
        libc.ptrace.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
        return int(libc.ptrace(31, 0, None, 0)) == 0
    except Exception:
        return False


def enforce_linux_no_dump() -> bool:
    try:
        import ctypes.util as _util
        name = _util.find_library("c")
        if not name:
            return False
        libc = ctypes.CDLL(name, use_errno=True)
        libc.prctl.restype = ctypes.c_int
        libc.prctl.argtypes = [ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong,
                               ctypes.c_ulong, ctypes.c_ulong]
        return int(libc.prctl(4, 0, 0, 0, 0)) == 0
    except Exception:
        return False


def enforce_windows_protect() -> bool:
    if _PLATFORM_SYS != "windows":
        return False
    ok = False
    try:
        kernel32, _ = _win_handles()
        if kernel32 is None:
            return False
        _init_win_prototypes()
        try:
            if kernel32.SetHandleInformation(kernel32.GetCurrentProcess(), 2, 2):
                ok = True
        except Exception:
            pass
        try:
            class _Mitigation(ctypes.Structure):
                _fields_ = [("Flags", ctypes.c_ulong)]
            pol = _Mitigation()
            pol.Flags = 0x1
            if kernel32.SetProcessMitigationPolicy(2, ctypes.byref(pol), ctypes.sizeof(pol)):
                ok = True
        except Exception:
            pass
    except Exception:
        pass
    return ok


def _check_native() -> bool:
    try:
        sysname = _PLATFORM_SYS
        if sysname == "windows":
            return _check_windows_native()
        if sysname == "linux":
            return _check_linux_tracerpid()
        if sysname == "darwin":
            return _check_macos_ptrace()
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# [3] Timing-skew katmani (single-step / breakpoint overhead)
# ---------------------------------------------------------------------------

_TIMING_ITERS = 200_000
# Normal makinede bu dongu ms mertebesinde biter; single-step altinda
# saniyelere siser. Esik bilerek COMERT (false-positive oldurmez).
_TIMING_THRESHOLD_SEC = 1.5


def _check_timing(threshold: float = _TIMING_THRESHOLD_SEC) -> bool:
    try:
        acc = 0
        t0 = _PERF_COUNTER()
        m0 = _MONOTONIC()
        for i in range(_TIMING_ITERS):
            acc += (i ^ 0x5BD1E995) & 0xFFFF
        dt = _PERF_COUNTER() - t0
        dm = _MONOTONIC() - m0
        if acc == -1:
            time.sleep(0)
        if dt > threshold or dm > threshold:
            return True
        try:
            if abs(dt - dm) > 1.0:
                return True
        except Exception:
            pass
    except Exception:
        return False
    return False


# ---------------------------------------------------------------------------
# [4] Ortam/artifact katmani
# ---------------------------------------------------------------------------

_DEBUG_ENV_VARS = frozenset({
    "PYCHARM_HOSTED",
    "PYCHARM_MATPLOTLIB_INTERACTIVE",
    "VSCODE_PID",
    "VSCODE_CWD",
    "PYDEVD_LOAD_VALUES_ASYNC",
    "PYDEV_CONSOLE_ENCODING",
    "PYTHONBREAKPOINT",  # degeri degil, varligi + debug degeri kontrol edilir
    "DEBUGPY_RUNNING",
    "DEBUGPY_LAUNCHER_PORT",
    "DEBUGPY_ADAPTER_ENDPOINT",
    "PTVSD_LAUNCHER_PORT",
    "PYDEVD_USE_CYTHON",
    "PYDEVD_USE_FRAME_EVAL",
    "JETBRAINS_DEBUGGER",
    "INTELLIJ_DEBUGGER",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
})

_DEBUG_ENV_PREFIXES = ("PYDEVD_", "DEBUGPY_", "_PYDEVD_", "VSCODE_INJECTION=")

try:
    _ENV_SEAL = {k: v for k, v in os.environ.items()
                 if k in _DEBUG_ENV_VARS or k.startswith(_DEBUG_ENV_PREFIXES)}
except Exception:
    _ENV_SEAL = {}

_FRIDA_DLL_NAMES = ("frida-agent.dll", "frida-gadget.dll", "frida-core.dll",
                    "frida-helper.dll", "gum-js.dll", "gadget.dll",)
_SANDBOX_DLL_NAMES = ("sbiedll.dll", "api_log.dll", "dir_watch.dll", "pstorec.dll",)


def _check_env_vars() -> bool:
    try:
        env = _OS_ENVIRON
        for key in _DEBUG_ENV_VARS:
            if key == "PYTHONBREAKPOINT":
                continue  # asagida deger bazli bakilir
            if key in env:
                return True
        # PYTHONBREAKPOINT pdb/ide'ye yonlendirilmisse supheli
        try:
            bp_val = env.get("PYTHONBREAKPOINT", "")
            if bp_val and bp_val != "0":
                low = bp_val.lower()
                if any(t in low for t in ("pdb", "debugpy", "pydevd", "ipdb", "pudb")):
                    return True
        except Exception:
            pass
        try:
            for key in list(env):
                try:
                    ku = str(key).upper()
                except Exception:
                    continue
                for pre in _DEBUG_ENV_PREFIXES:
                    try:
                        if ku.startswith(pre):
                            return True
                    except Exception:
                        continue
        except Exception:
            pass
        try:
            malloc_val = env.get("PYTHONMALLOC", "")
            if malloc_val and "debug" in malloc_val.lower():
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_env_seal() -> bool:
    """F31 duzeltmesi: import-aninda kayitli debug env'den silinen/degisen var mi?

    In-place `del os.environ[...]` kimlik-pinini geciyordu; muhur-karsilastirma
    silerken yakalar. Yeni eklenen debug var'lari _check_env_vars gorur.
    """
    try:
        if not _ENV_SEAL:
            return False
        try:
            env = _OS_ENVIRON
        except Exception:
            return True
        for k, v in _ENV_SEAL.items():
            try:
                if k not in env:
                    return True
                if env.get(k) != v:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return True


def _check_suspicious_modules() -> bool:
    if _PLATFORM_SYS != "windows":
        return False
    try:
        kernel32, _ = _win_handles()
        if kernel32 is None:
            return False
        _init_win_prototypes()
        for dll in _FRIDA_DLL_NAMES + _SANDBOX_DLL_NAMES:
            try:
                if kernel32.GetModuleHandleW(dll):
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# [5] Capraz-dogrulama (anti-hook) katmani
# ---------------------------------------------------------------------------

def _check_cross_validation() -> bool:
    if _PLATFORM_SYS != "windows":
        return False
    try:
        a = _check_windows_native()
    except Exception:
        a = False
    try:
        kernel32, ntdll = _win_handles()
        if kernel32 is None:
            return True
        _init_win_prototypes()
        idp = bool(kernel32.IsDebuggerPresent())
    except Exception:
        return True
    try:
        if a is True and idp is False:
            # Native (NtQIP/CRDP) "var" diyor, resmi API "yok" diyor -> hook
            return True
    except Exception:
        pass
    try:
        if ntdll is not None:
            h = kernel32.GetCurrentProcess()
            dbg_obj = ctypes.c_void_p(0)
            retlen = ctypes.c_ulong(0)
            try:
                status = ntdll.NtQueryInformationProcess(
                    h, 30, ctypes.byref(dbg_obj), ctypes.sizeof(dbg_obj),
                    ctypes.byref(retlen))
                if status == 0 and dbg_obj.value not in (None, 0):
                    return True
            except Exception:
                pass
    except Exception:
        pass
    return False


def _check_remote_debug_open() -> bool:
    """3.14+ uzaktan-debug protokolu posture kontrolu.

    _PyRemoteDebuggerSupport bellekten betik calistirmaya izin verir;
    OS izni olan saldirgan ptrace'siz kod enjekte eder. Savunma:
    PYTHON_DISABLE_REMOTE_DEBUG=1 / -X disable_remote_debug.
    3.14 oncesi vektor YOK -> False. Bayrak yoksa True (acik yuzey).
    """
    try:
        if sys.version_info < (3, 14):
            return False
        try:
            if _OS_ENVIRON.get("PYTHON_DISABLE_REMOTE_DEBUG") == "1":
                return False
        except Exception:
            pass
        try:
            if bool(getattr(sys.flags, "disable_remote_debug", False)):
                return False
        except Exception:
            pass
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_all() -> Dict[str, bool]:
    """Tum katmanlari calistir, detayli (debug amacli) sozluk doner.

    URETIMDE check_all() sonucunu loglama/yansitma (oracle olur).
    Uretim karari icin is_debugged() kullan.
    """
    results: Dict[str, bool] = {}
    for name, fn in (
        ("trace_hooks", _check_trace_hooks),
        ("pinned_mismatch", _check_pinned_mismatch),
        ("native", _check_native),
        ("timing", _check_timing),
        ("env", _check_env_vars),
        ("env_seal", _check_env_seal),
        ("debugger_modules", _check_debugger_modules),
        ("suspicious_modules", _check_suspicious_modules),
        ("cross_validation", _check_cross_validation),
        ("gc_tracers", _check_gc_tracers),
        ("linux_maps", _check_linux_maps),
        ("remote_debug_open", _check_remote_debug_open),
    ):
        try:
            results[name] = bool(fn())
        except Exception:
            results[name] = True  # fail-closed
    return results


def is_debugged(include_timing: bool = True) -> bool:
    try:
        if _check_trace_hooks():
            return True
        if _check_pinned_mismatch():
            return True
        if _check_native():
            return True
        if _check_env_vars():
            return True
        if _check_env_seal():
            return True
        if _check_debugger_modules():
            return True
        if _check_suspicious_modules():
            return True
        if _check_gc_tracers():
            return True
        if _check_linux_maps():
            return True
        if _check_remote_debug_open():
            return True
        if _check_cross_validation():
            return True
        if include_timing and _check_timing():
            return True
    except Exception:
        return True  # fail-closed
    return False


def assert_no_debugger() -> None:
    """Debugger suphesi varsa opak DebuggerDetected firlatir."""
    if is_debugged():
        raise DebuggerDetected("protected")


_WATCHDOGS: list[threading.Event] = []
_WATCHDOGS_LOCK = threading.Lock()


def start_watchdog(
    interval: float = 0.5,
    on_detect: Optional[Callable[[], None]] = None,
    daemon: bool = True,
) -> Callable[[], None]:
    """Arka planda periyodik kontrol. Tespitte varsayilan: sessiz os._exit(1).

    on_detect verilirse o cagrilir (ornek: state wipe + exit).
    Donen stop() fonksiyonu izlemeyi durdurur.
    """
    if interval < 0.1:
        interval = 0.1
    if interval > 10.0:
        interval = 10.0
    global _ADMIN_LOCKED
    try:
        with _WATCHDOGS_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    stop_event = threading.Event()
    with _WATCHDOGS_LOCK:
        _WATCHDOGS.append(stop_event)

    def _default_action() -> None:
        try:
            _OS_EXIT(1)  # sessiz, traceback yok, oracle yok
        except Exception:
            pass

    action = on_detect if callable(on_detect) else _default_action

    def _loop() -> None:
        tick = 0
        try:
            last = _MONOTONIC()
        except Exception:
            last = 0.0
        suspend_limit = min(max(3.0 * interval, 2.0), 8.0)
        while not stop_event.is_set():
            try:
                try:
                    now = _MONOTONIC()
                    if last and (now - last) > suspend_limit:
                        try:
                            action()
                        except Exception:
                            pass
                        return
                    last = now
                except Exception:
                    pass
                hit = (
                    _check_trace_hooks()
                    or _check_pinned_mismatch()
                    or _check_native()
                    or _check_env_vars()
                    or _check_debugger_modules()
                    or _check_gc_tracers()
                    or _check_linux_maps()
                    or _check_suspicious_modules()
                    or _check_cross_validation()
                    or _check_remote_debug_open()
                )
                tick += 1
                if not hit and tick % 2 == 0:
                    hit = _check_timing()
                if hit:
                    try:
                        action()
                    except Exception:
                        pass
                    return
            except Exception:
                pass
            stop_event.wait(interval)

    th = threading.Thread(target=_loop, name="hyper-antidebug", daemon=daemon)
    th.start()

    def _stop() -> None:
        stop_event.set()
        with _WATCHDOGS_LOCK:
            try:
                _WATCHDOGS.remove(stop_event)
            except ValueError:
                pass

    return _stop


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _WATCHDOGS_LOCK:
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
        with _WATCHDOGS_LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _WATCHDOGS_LOCK:
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
        with _WATCHDOGS_LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise DebuggerDetected("protected")


def stop_all_watchdogs() -> None:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    with _WATCHDOGS_LOCK:
        events = list(_WATCHDOGS)
    for ev in events:
        try:
            ev.set()
        except Exception:
            continue


class _Guard:
    def __enter__(self) -> "_Guard":
        assert_no_debugger()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is None:
            assert_no_debugger()
            return False
        if is_debugged():
            raise DebuggerDetected("protected") from exc  # type: ignore[misc]
        return False


def guard() -> _Guard:
    return _Guard()
