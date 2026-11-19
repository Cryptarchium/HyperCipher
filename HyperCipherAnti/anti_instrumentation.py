"""HyperCipherAnti anti_instrumentation — DBI / agent-in-process detector.

Defensive posture module: detects live dynamic-binary-instrumentation
runtimes (Frida agent, Intel Pin, DynamoRIO) from inside the observed
process. stdlib-only, cross-platform, silent by default, fail-closed
(sensor error -> no accusation, health counter records it).

Scope vs siblings (no duplication):
  anti_hook covers module/blocklists (frida/easyhook/detours names),
  import-system, native prologues, EAT ranges, hidden images, HW
  breakpoints, hook env vars. anti_debug covers debuggers/tracers.
  This module covers ONLY what those do not: runtime THREADS of the
  agent, DBI PARENTAGE, code-cache-style ANON-RWX regions, Frida IPC
  PORTS, and JIT compile-BURST timing. ntdll disk-vs-memory compare
  is intentionally left to anti_hook.native_prologue.

Research base (strongest patterns synthesized):
  R1 OWASP MASTG-KNOW-0030 + PTKD 2026: Frida presence checks —
     maps/library strings, TCP 27042/27043 daemon ports, thread
     names (gum-js-loop/gmain/gdbus), Unix sockets (frida-zymbiote-*),
     LIBFRIDA string, Gadget load. Presence checks are fragile alone;
     combine signals, never single-artifact verdicts.
  R2 MDPI Electronics 13(5):871 — 24 Windows DBI techniques in five
     families: Time Overhead (QPC execution/loading/compiling/CPU
     time), Code Cache Artifact (predefined/cache signatures),
     Memory Fingerprints (DBI DLL strings/sections in parent+self),
     JIT Compiler (syscall hooks, DEP events), Environment Artifact
     (parent process, handles, exceptions). Pin: 24/24; DynamoRIO:
     19/24; Frida: 7/24 (in-process injector, no code cache).
  R3 D'Elia et al. (ACM 2022) Pin 3.17 / DynamoRIO 8 field note:
     PEB module lists hide 3.x runtimes — use mapped-file names;
     pinvm strings ("Intel(R) X86 Encoder", PinCommitHashC/PinWinMain,
     .pinclie/.pinvers sections, argv copies); DynamoRIO strings
     ("Copyright @ DynamoRIO", dr_main_client, dr_* exports);
     HW-breakpoint suppression (Pin unaware of DR0-3 single-step);
     NtQueryVirtualMemory hiding (blind-probe DLL bases).
  R4 Kirsch/Arancino (BlackHat EU-17): parent detection
     (NtQuerySystemInformation), memory-fingerprinting allow-lists,
     KUSER_SHARED_DATA + NtQueryPerformanceCounter hooking to hide
     overhead; mitigation = cross-clock / indirect timing.
  R5 RedFoxSec 2025 + Medium rootkit notes: inline-hook forensics —
     prologue JMP (E9/FF25), trampolines in non-module RWX, ETW-TI
     telemetry; disk-vs-memory compare as ground truth. (Prologue
     ground truth lives in anti_hook; here only the RWX-trampoline
     census, which no sibling performs.)
  R6 Assessed gaps, deliberately NOT implemented (no speculative
     code): HW-breakpoint suppression test (needs self
     GetThreadContext + suspend — flaky from usermode Python);
     Frida D-Bus handshake probe (version-fragile fixed
     Sec-WebSocket-Accept); memfd/JIT-heap census (Linux-only
     /proc/self/maps covers the equivalent signal instead).
  R7 Sun et al. (BH Asia-16) + Unizar 2020: Pin code caches are RWX
     + 0xFEEDBEAF header + 0x40000 default size; PinVMShield-style
     runtimes hide them from VirtualQuery. Sig is version-fragile,
     so the generic anon-RWX census (no magic constant) carries this
     family instead — no hardcoded FEEDBEAF scan.
  R8 frida-core source (gadget.vala) + docs 2026: Gadget default is
     listen on 127.0.0.1:27042 with on_load=WAIT, D-Bus server,
     overridable via <lib>.config (port/address/behavior all
     changeable) — port probe stays WEAK + corroborated, correctly.
  R9 Live calibration (this box, bare metal): jit max/med 8.8 on one
     run (single scheduling hitch inflates max: 4.8x vs 1.7x
     second-max, top3-mean 2.6x). Estimator uses SECOND-MAX/median
     (kills single-hitch FPs; DBI compile bursts hit many samples so
     sensitivity survives); threshold 15 (bare 1.7, margin ~9x).
     anon_rwx baseline 0 vs threshold 3; parent powershell.exe.
  R10 frida-tools 14.8.2 / frida 17.9.10 pip-installable (Windows x64
     wheels); attach API = frida.attach(pid).create_script().load().
  R11 TP-THREADS (live, real Frida 17): target looping
     _check_frida_threads — False x5 baseline, True x6 during
     attach+load window, False after detach. Two-sided PASS.
     Debug find: GetThreadDescription needs THREAD_QUERY_INFORMATION
     (0x40); LIMITED (0x400) returns 0xD0000022 — fixed.
  R12 TP-PORT (live): dummy listener on 27042 -> _check_frida_port
     True; closed -> False. Two-sided PASS (mechanics; Frida Gadget
     default 127.0.0.1:27042 per R8 source).
  R13 DynamoRIO: drrun.exe/drinject.exe launchers, dr_client_main
     clients; dynamorio.dll loads via PRIVATE loader (invisible to
     PEB lists — D'Elia blind-probe NtReadProcessMemory). Lesson:
     module-name scans are insufficient; thread/timing/parent
     signals carry DynamoRIO instead (by design here).
  R14 QBDI issue #330: libQBDI.so visible in /proc/self/maps by
     default (no hiding hook); QBDIPreload injection; return-addr
     patching on EXEC_TRANSFER. Windows DLL is QBDI.dll, so maps
     marker is the broader "qbdi" substring (Linux branch).
  R15 MDPI duplicate-execution: code/data found twice under DBI (PE
     image + code cache) — covered behaviorally by anon_rwx + jit
     signals, no extra scan needed.
  R16 Stalker API (frida.re docs + gum source): Stalker.follow([tid],
     {events/transform/onReceive}); follow_me for self; default
     transformer keep-all; unfollow to stop. Self-attach
     (frida.attach(own-pid)) is supported — enables single-process TP.
  R17 TP-STALKER (live, Frida 17 Gum Stalker, call events):
     baseline jit 1.3/rwx 0/verdict False; stalked frida_threads
     True + anon_rwx True (exactly 3 regions) + verdict True.
     Two-sided PASS for threads + rwx census.
  R18 TP-STALKER negative lesson: jit_burst stayed False (3.9/3.3)
     under steady-state Stalker — uniform slowdown lifts median with
     max, so self-relative ratio only fires on FIRST-COMPILE burst
     engines (Pin/DynamoRIO cold cache), not steady Stalker. Honest
     scope: verdict carried by threads+rwx there, as designed.
  R19 TP-PARENT (live): cmd.exe copied to pin.exe, target launched
     through it -> parent='pin.exe', dbi_parent=True. Two-sided PASS
     (mechanics; real Pin untested — no installer here).
  R20 Hamida patches 4/5/7 + frida-gum source (gumscriptscheduler.c):
     "gum-js-loop" is hardcoded GumJS-only (UNIQUE — no framework
     uses it) -> stays STRONG. "gmain"/"gdbus" are GENERIC GLib
     names (any GLib/D-Bus app may carry them; high-confidence only
     combined with gum-js-loop) -> demoted to new WEAK signal
     frida_aux_threads (needs corroboration). Bonus STRONG markers
     from agent.vala/frida-glue.c: "frida-main-loop",
     "frida-eternal-agent" (covered by the "frida-" prefix).
  R21 QBDI docs: Windows launcher is QBDIWinPreloader.exe, tracer
     DLLs libqbdi_*.dll (valgrind/strace/ltrace are Linux-only, so
     their extensionless tuple entries only ever match on Linux) ->
     added qbdiwinpreloader.exe (closes the Windows parent gap).
  R22 Hamida lesson (cat-and-mouse): patched builds rename ALL
     thread markers — thread scan alone is evadable, which is why
     this module keeps six independent families (threads/parent/
     rwx/ports/timing/maps); renamed threads still trip anon_rwx
     (code cache) and need ports/timing corroboration.
  R23 Pin docs (PIN_SpawnInternalThread): Pin 4.0+ "makes an effort
     to hide internal threads from the application" — there are NO
     stable Pin thread names to scan. Consequence: frida_threads is
     Frida-family-specific by design; Pin coverage rests on
     dbi_parent + anon_rwx + jit_burst (honest split, no fake).
  R24 DynamoRIO source (dynamo.c): "tries not to create permanent
     extra threads... Thread Transparency" (nudges preferred) — same
     conclusion as R23: no DR thread-name signal exists to add.
  R25 ACM evasive survey: pinvm.dll exports (PinWinMain/
     CharmVersionC) + pintool sections (.pinclie/.charmve) are the
     module-scan ground truth — owned by anti_hook (module scans),
     deliberately not duplicated here; Linux dbi_maps keeps the
     substring variants for the platform without that sibling
     coverage.
  R26 Pin docs: the launcher is ALWAYS pin.exe (IA-32 + intel64 kits,
     `pin.exe -t tool -- app`) — no versioned variants, so exact
     "pin.exe" suffices; the old "pin." substring fallback was pure
     FP surface, now removed.
  R27 DynamoRIO ships drrun.exe AND drinject.exe (launcher+injector)
     -> both exact-listed (drinject was missing).
  R28 Real "pin." collisions (substring fallback FP-PROVEN): spin.exe
     (Spin model checker, common on dev machines), syspin.exe (Pin
     To Taskbar), Positivo pin.exe bloatware (exact "pin.exe" —
     documented residual, Brazil-OEM only). Fix: stem-anchored match
     (stem=="pin" or pin[-_0-9] prefixes); spin/syspin now silent.
  R29 Gadget asset: frida-gadget-17.x-windows-x86_64.dll.xz (~7MB,
     GitHub releases; .xz = stdlib lzma).
  R30 gadget-glue.c: Windows DllMain -> frida_gadget_load on
     PROCESS_ATTACH; can_block_at_load_time() is FALSE on Windows
     (no WAIT hang) — plain ctypes.WinDLL load is a safe TP.
  R31 TP-GADGET (live, real Gadget 17.9.10 DLL via LoadLibrary, no
     session/attach): pre all-False; post frida_threads True +
     frida_port True (27042 D-Bus) + frida_aux_threads True
     (gmain) -> verdict True. Three-signal corroboration incl. the
     demoted aux family — R20 design validated end-to-end.
  R32 DynamoRIO Windows package is free (GitHub releases, ~463MB
     zip); TP recipe: bin64\drrun.exe -c samples\bin64\bbsize.dll
     -- target (no admin needed for configure-and-run).
  R33 Pin kits need Intel-EULA click-through (no direct scriptable
     URL) -> real-Pin TP infeasible here; documented residual.
  R34 TP-DR (live, real DynamoRIO 11.91 + bbsize over CPython,
     bbsize popup proof: 68049 BBs, max 86, avg 4.2): dbi_parent
     True (parent='drrun.exe') + anon_rwx True (66 RWX regions vs
     0 native, threshold 3) + jit_burst True on cold run ->
     verdict True. WARMUP EFFECT observed: score()'s re-run in the
     same process showed jit_burst False (traces already compiled)
     -> first-compile-burst theory (R18) confirmed live; estimator
     is intentionally cold-sensitive.

Scoring (mirrors sibling contract):
  STRONG = 100, WEAK = 30.
  Trip iff >=1 strong OR >=2 weak.
"""

from __future__ import annotations

import ctypes
import os
import socket
import statistics
import sys
import threading
import time

__all__ = [
    "InstrumentationDetected",
    "is_instrumented",
    "check_all",
    "evidence",
    "score",
    "assert_no_instrumentation",
    "authorize_admin",
    "set_verbose",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
    "status",
]

_SYS_PLATFORM = sys.platform
_IS_WIN = _SYS_PLATFORM == "win32"
_IS_LINUX = _SYS_PLATFORM.startswith("linux")

_VERBOSE = False
_VERBOSE_ENV = "HYPERCIPHER_ANTIINSTRUMENTATION_VERBOSE"


def _verbose() -> bool:
    if _VERBOSE:
        return True
    try:
        return os.environ.get(_VERBOSE_ENV, "") == "1"
    except Exception:
        return False


def set_verbose(on: bool) -> bool:
    global _VERBOSE
    _VERBOSE = bool(on)
    return _VERBOSE


def _log(msg: str) -> None:
    if _verbose():
        try:
            sys.stderr.write("[anti_instrumentation] %s\n" % msg)
        except Exception:
            pass


_HEALTH = {"sensor_fail": 0}


def _health_bump(key: str) -> None:
    try:
        _HEALTH[key] = int(_HEALTH.get(key, 0)) + 1
    except Exception:
        pass


# ---------------------------------------------------------------------------
# R1: Frida runtime threads — gum-js-loop / gmain / gdbus.
# Win: Toolhelp32 thread list + GetThreadDescription (1607+).
# Linux: /proc/self/task/*/comm.
# ---------------------------------------------------------------------------

_FRIDA_THREAD_MARKERS = ("gum-js-loop", "frida-")
_FRIDA_AUX_MARKERS = ("gmain", "gdbus")
_FRIDA_GADGET_MARKERS = ("frida-gadget-tcp-", "frida-gadget-unix")


def _win_thread_marker_hit(markers: tuple) -> bool:
    try:
        k32 = ctypes.windll.kernel32
        try:
            ntdll = ctypes.windll.ntdll
        except Exception:
            return False
        try:
            k32.GetCurrentProcess.argtypes = []
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
            k32.CloseHandle.restype = ctypes.c_bool
            k32.GetThreadDescription.restype = ctypes.HRESULT
            k32.GetThreadDescription.argtypes = (ctypes.c_void_p,
                                                 ctypes.POINTER(ctypes.c_wchar_p))
            try:
                k32.LocalFree.argtypes = [ctypes.c_void_p]
                k32.LocalFree.restype = ctypes.c_void_p
            except Exception:
                pass
            ntdll.NtGetNextThread.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_ulong, ctypes.c_ulong,
                                              ctypes.c_ulong,
                                              ctypes.POINTER(ctypes.c_void_p)]
            ntdll.NtGetNextThread.restype = ctypes.c_ulong
        except Exception:
            return False
        try:
            hp = k32.GetCurrentProcess()
        except Exception:
            return False
        try:
            seen = 0
            prev = ctypes.c_void_p(0)
            found = False
            while seen < 1024:
                seen += 1
                hth = ctypes.c_void_p(0)
                try:
                    st = ntdll.NtGetNextThread(hp, prev, 0x0040, 0, 0,
                                              ctypes.byref(hth))
                except Exception:
                    break
                try:
                    code = int(st) & 0xFFFFFFFF
                except Exception:
                    break
                if code == 0x8000001A:
                    break
                try:
                    old_prev = int(prev.value or 0)
                except Exception:
                    old_prev = 0
                if old_prev:
                    try:
                        k32.CloseHandle(old_prev)
                    except Exception:
                        pass
                if code >= 0x80000000:
                    prev = ctypes.c_void_p(0)
                    continue
                try:
                    hiv = int(hth.value or 0)
                except Exception:
                    hiv = 0
                if not hiv:
                    prev = ctypes.c_void_p(0)
                    continue
                prev = ctypes.c_void_p(hiv)
                try:
                    name = ctypes.c_wchar_p()
                    if k32.GetThreadDescription(hiv, ctypes.byref(name)) >= 0 and name.value:
                        try:
                            low = str(name.value).lower()
                        except Exception:
                            low = ""
                        for marker in markers:
                            try:
                                if marker in low:
                                    found = True
                                    break
                            except Exception:
                                continue
                        try:
                            k32.LocalFree(name)
                        except Exception:
                            pass
                        if found:
                            break
                except Exception:
                    pass
            try:
                last = int(prev.value or 0)
            except Exception:
                last = 0
            if last:
                try:
                    k32.CloseHandle(last)
                except Exception:
                    pass
            return found
        except Exception as exc:
            _log("win threads failed: %r" % (exc,))
            _health_bump("sensor_fail")
            return False
    except Exception as exc:
        _log("win threads failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return False


def _linux_thread_marker_hit(markers: tuple) -> bool:
    try:
        task = "/proc/self/task"
        for tid in os.listdir(task):
            try:
                with open(os.path.join(task, tid, "comm"), "r",
                          errors="ignore") as fh:
                    low = fh.read(256).strip().lower()
            except Exception:
                continue
            for marker in markers:
                if marker in low:
                    return True
        return False
    except Exception as exc:
        _log("linux threads failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return False


def _check_frida_threads() -> bool:
    markers = _FRIDA_THREAD_MARKERS
    if _IS_WIN:
        return _win_thread_marker_hit(markers)
    if _IS_LINUX:
        return _linux_thread_marker_hit(markers)
    return False


def _check_frida_gadget_threads() -> bool:
    """N1b-WEAK: Gadget'in kendi koydugu thread adlari (gadget.vala: set_thread_name).

    Default-build Gadget listen-mode'da "frida-gadget-tcp-<port>" (pick-next
    portu ADIYLA tasinir — port degisikligi thread adina yansir),
    unix-socket'te "frida-gadget-unix" adini koyar. Hamida-tipi rename
    build'lerde gorunmez (dokumante); threads+rwx tasiyicidir.
    """
    markers = _FRIDA_GADGET_MARKERS
    if _IS_WIN:
        return _win_thread_marker_hit(markers)
    if _IS_LINUX:
        return _linux_thread_marker_hit(markers)
    return False


def _check_frida_unix_socket() -> bool:
    """N1c-WEAK (Linux): Gadget/unix-transport abstract-socket izi.

    /proc/net/unix satirlarinda frida/gadget isareti aranir (stdlib-okunur).
    """
    if not _IS_LINUX:
        return False
    try:
        with open("/proc/net/unix", "r", errors="ignore") as fh:
            for _i in range(4096):
                try:
                    line = fh.readline(4096)
                except Exception:
                    break
                if not line:
                    break
                try:
                    low = line.lower()
                except Exception:
                    continue
                if "frida" in low or "gadget" in low:
                    return True
        return False
    except Exception as exc:
        _log("unix socket scan failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return False


def _check_frida_aux_threads() -> bool:
    """WEAK (R20): generic GLib names (gmain/gdbus) — corroboration only."""
    markers = _FRIDA_AUX_MARKERS
    if _IS_WIN:
        return _win_thread_marker_hit(markers)
    if _IS_LINUX:
        return _linux_thread_marker_hit(markers)
    return False


# ---------------------------------------------------------------------------
# R2/R4: DBI parentage — pin.exe / drrun.exe / frida-tools launchers.
# Frida attach-mode has no such parent (covered by thread/port signals).
# ---------------------------------------------------------------------------

_DBI_PARENTS = ("pin.exe", "drrun.exe", "drrun32.exe", "drrun64.exe",
                "drinject.exe", "frida.exe", "frida-server.exe",
                "frida-trace.exe", "qbdiwinpreloader.exe", "qbdi",
                "valgrind", "strace", "ltrace")


def _win_parent_image_path() -> str:
    """Parent tam image yolu (isim degil — rename'e dayanikli zemin)."""
    try:
        k32 = ctypes.windll.kernel32
        TH32CS_SNAPPROCESS = 0x2
        INVALID = ctypes.c_void_p(-1).value
        k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        k32.CreateToolhelp32Snapshot.argtypes = (ctypes.c_ulong, ctypes.c_ulong)
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap in (None, 0, INVALID):
            return ""
        try:
            class PE(ctypes.Structure):
                _fields_ = [("dwSize", ctypes.c_ulong),
                            ("cntUsage", ctypes.c_ulong),
                            ("th32ProcessID", ctypes.c_ulong),
                            ("th32DefaultHeapID", ctypes.c_void_p),
                            ("th32ModuleID", ctypes.c_ulong),
                            ("cntThreads", ctypes.c_ulong),
                            ("th32ParentProcessID", ctypes.c_ulong),
                            ("pcPriClassBase", ctypes.c_long),
                            ("dwFlags", ctypes.c_ulong),
                            ("szExeFile", ctypes.c_wchar * 260)]

            mypid = os.getpid()
            ppid = 0
            k32.Process32FirstW.restype = ctypes.c_bool
            k32.Process32NextW.restype = ctypes.c_bool
            pe = PE()
            pe.dwSize = ctypes.sizeof(PE)
            ok = k32.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                if int(pe.th32ProcessID) == int(mypid):
                    ppid = int(pe.th32ParentProcessID)
                    break
                ok = k32.Process32NextW(snap, ctypes.byref(pe))
            if not ppid:
                return ""
            PROCESS_QUERY_LIMITED = 0x1000
            k32.OpenProcess.restype = ctypes.c_void_p
            k32.OpenProcess.argtypes = (ctypes.c_ulong, ctypes.c_bool, ctypes.c_ulong)
            h = k32.OpenProcess(PROCESS_QUERY_LIMITED, False, ppid)
            if not h:
                return ""
            try:
                buf = ctypes.create_unicode_buffer(1024)
                size = ctypes.c_ulong(1024)
                k32.QueryFullProcessImageNameW.restype = ctypes.c_bool
                k32.QueryFullProcessImageNameW.argtypes = (
                    ctypes.c_void_p, ctypes.c_ulong,
                    ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong))
                if not k32.QueryFullProcessImageNameW(h, 0, buf,
                                                      ctypes.byref(size)):
                    return ""
                return str(buf.value or "")
            finally:
                k32.CloseHandle(h)
        finally:
            k32.CloseHandle(snap)
    except Exception as exc:
        _log("win parent path failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return ""


def _win_verinfo_strings(path: str) -> dict:
    """N2: version-resource string'leri (rename-proof: exe adi degisir, icerik degismez).

    GetFileVersionInfoW/VerQueryValueW (version.dll): CompanyName,
    FileDescription, ProductName, OriginalFilename. OriginalFilename
    kopyalamada AYNI kalir — en guclu rename-delili.
    """
    out: dict = {}
    try:
        if not path:
            return out
        try:
            ver = ctypes.windll.version
        except Exception:
            return out
        try:
            ver.GetFileVersionInfoSizeW.restype = ctypes.c_ulong
            ver.GetFileVersionInfoSizeW.argtypes = (ctypes.c_wchar_p,
                                                    ctypes.POINTER(ctypes.c_ulong))
            ver.GetFileVersionInfoW.restype = ctypes.c_bool
            ver.GetFileVersionInfoW.argtypes = (ctypes.c_wchar_p, ctypes.c_ulong,
                                                ctypes.c_ulong, ctypes.c_void_p)
            ver.VerQueryValueW.restype = ctypes.c_bool
            ver.VerQueryValueW.argtypes = (ctypes.c_void_p, ctypes.c_wchar_p,
                                           ctypes.POINTER(ctypes.c_void_p),
                                           ctypes.POINTER(ctypes.c_uint))
        except Exception:
            return out
        try:
            dummy = ctypes.c_ulong(0)
            size = ver.GetFileVersionInfoSizeW(path, ctypes.byref(dummy))
        except Exception:
            return out
        if not size or size > (1 << 20):
            return out
        try:
            buf = ctypes.create_string_buffer(int(size))
            if not ver.GetFileVersionInfoW(path, 0, int(size), buf):
                return out
        except Exception:
            return out
        try:
            tptr = ctypes.c_void_p()
            tln = ctypes.c_uint(0)
            blocks = ["040904B0"]
            if ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation",
                                  ctypes.byref(tptr), ctypes.byref(tln)) and tptr.value:
                try:
                    n = int(tln.value) // 4
                    raw = ctypes.string_at(tptr.value, int(tln.value))
                    cand = []
                    for i in range(min(n, 8)):
                        try:
                            lang = int.from_bytes(raw[i*4:i*4+2], "little")
                            cp = int.from_bytes(raw[i*4+2:i*4+4], "little")
                            cand.append("%04X%04X" % (lang, cp))
                        except Exception:
                            continue
                    if cand:
                        blocks = cand
                except Exception:
                    pass
        except Exception:
            blocks = ["040904B0"]
        for key in ("CompanyName", "FileDescription", "ProductName",
                    "OriginalFilename"):
            for blk in blocks:
                try:
                    ptr = ctypes.c_void_p()
                    ln = ctypes.c_uint(0)
                    sub = "\\StringFileInfo\\" + blk + "\\" + key
                    if ver.VerQueryValueW(buf, sub, ctypes.byref(ptr),
                                          ctypes.byref(ln)) and ptr.value:
                        try:
                            out[key] = ctypes.wstring_at(ptr.value)
                            break
                        except Exception:
                            continue
                except Exception:
                    continue
        return out
    except Exception as exc:
        _log("verinfo failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return {}


_DBI_VERINFO_COMPANIES = ("intel corporation", "dynamorio", "frida", "qbdi")
_DBI_VERINFO_PRODUCTS = ("pin", "dynamorio", "frida", "qbdi", "pintool")
_DBI_VERINFO_ORIGINALS = ("pin.exe", "drrun.exe", "drrun32.exe", "drrun64.exe",
                          "drinject.exe", "frida.exe", "frida-server.exe",
                          "qbdiwinpreloader.exe")


def _check_dbi_parent_verinfo() -> bool:
    """N2-STRONG: parent version-resource kimligi (rename ile atlatilamaz).

    copy pin.exe myrun.exe: dosya adi degisir ama Version resource
    (CompanyName=Intel Corporation, OriginalFilename=pin.exe) AYNI kalir.
    Resource'suz parent -> suphe DEGIL (sessiz False; isim sinyali ayri).
    """
    try:
        if not _IS_WIN:
            return False
        path = _win_parent_image_path()
        if not path:
            return False
        info = _win_verinfo_strings(path)
        if not info:
            return False
        try:
            orig = str(info.get("OriginalFilename", "") or "").lower()
            if orig in _DBI_VERINFO_ORIGINALS:
                return True
            blob = " ".join(str(info.get(k, "") or "") for k in
                            ("CompanyName", "FileDescription", "ProductName")).lower()
            for mark in _DBI_VERINFO_COMPANIES:
                if mark and mark in blob:
                    return True
            for mark in _DBI_VERINFO_PRODUCTS:
                if mark and mark in blob:
                    return True
        except Exception:
            return False
        return False
    except Exception as exc:
        _log("parent verinfo check failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return False


def _win_parent_name() -> str:
    try:
        return os.path.basename(_win_parent_image_path() or "").lower()
    except Exception as exc:
        _log("win parent failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return ""


def _linux_parent_name() -> str:
    try:
        with open("/proc/self/stat", "r", errors="ignore") as fh:
            parts = fh.read().rsplit(")", 1)
            ppid = int(parts[1].split()[1]) if len(parts) > 1 else 0
        if not ppid:
            return ""
        try:
            with open("/proc/%d/cmdline" % ppid, "rb") as fh:
                raw = fh.read(4096).split(b"\x00")[0].decode("utf-8", "ignore")
        except Exception:
            return ""
        return os.path.basename(raw or "").lower()
    except Exception as exc:
        _log("linux parent failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return ""


def _check_dbi_parent() -> bool:
    name = _win_parent_name() if _IS_WIN else (
        _linux_parent_name() if _IS_LINUX else "")
    if not name:
        return False
    if name in _DBI_PARENTS:
        return True
    stem = name[:-4] if name.endswith(".exe") else name
    if stem in _DBI_PARENTS:
        return True
    if stem == "pin" or stem.startswith(("pin-", "pin_", "pin32",
                                         "pin64")):
        return True
    if "dynamorio" in stem or stem.startswith("frida"):
        return True
    return False


# ---------------------------------------------------------------------------
# R5: anonymous-RWX census — trampolines + JIT code caches live in
# non-module executable memory. No sibling performs this census.
# Win: VirtualQuery walk. Linux: /proc/self/maps anon rwxp count.
# ---------------------------------------------------------------------------

_ANON_RWX_MIN = 3


def _win_anon_rwx() -> int:
    count = 0
    try:
        k32 = ctypes.windll.kernel32
        GetCurrentProcess = k32.GetCurrentProcess
        GetCurrentProcess.restype = ctypes.c_void_p
        proc = GetCurrentProcess()

        class MBI(ctypes.Structure):
            _fields_ = [("BaseAddress", ctypes.c_void_p),
                        ("AllocationBase", ctypes.c_void_p),
                        ("AllocationProtect", ctypes.c_ulong),
                        ("RegionSize", ctypes.c_size_t),
                        ("State", ctypes.c_ulong),
                        ("Protect", ctypes.c_ulong),
                        ("Type", ctypes.c_ulong)]

        k32.VirtualQueryEx.restype = ctypes.c_size_t
        k32.VirtualQueryEx.argtypes = (ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_void_p, ctypes.c_size_t)
        MEM_COMMIT = 0x1000
        MEM_PRIVATE = 0x20000
        RWX = (0x40, 0x80, 0xC0)
        addr = 0
        mbi = MBI()
        size = ctypes.sizeof(MBI)
        while True:
            ret = k32.VirtualQueryEx(proc, ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), size)
            if not ret:
                break
            try:
                if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                        and mbi.Protect in RWX):
                    count += 1
            except Exception:
                pass
            addr = (mbi.BaseAddress or 0) + (mbi.RegionSize or 0x1000)
            if addr >= (1 << 47):
                break
        return count
    except Exception as exc:
        _log("win rwx failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return 0


def _linux_anon_rwx() -> int:
    count = 0
    try:
        with open("/proc/self/maps", "r", errors="ignore") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) != 5:
                    continue
                if parts[1] != "rwxp" or parts[4] != "0":
                    continue
                count += 1
        return count
    except Exception as exc:
        _log("linux rwx failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return 0


def _check_anon_rwx() -> bool:
    n = _win_anon_rwx() if _IS_WIN else (
        _linux_anon_rwx() if _IS_LINUX else 0)
    _log("anon rwx regions: %d" % n)
    return n >= _ANON_RWX_MIN


# ---------------------------------------------------------------------------
# R1: Frida default IPC ports 27042/27043 (short-timeout connect probe).
# ---------------------------------------------------------------------------

_FRIDA_PORTS = (27042, 27043, 27052)
_FRIDA_PORT_TIMEOUT = 0.15


def _check_frida_port() -> bool:
    """N1a: Gadget-listen (27042/43) + portal-connect (27052) + pick-next penceresi.

    Research (frida.re Gadget docs + gadget.vala): default listen 27042
    (on_port_conflict=pick-next → 27043+ da dinlenebilir), connect-mode
    portal default 27052. Unix-socket transport (non-Windows) port probuna
    HIC gorunmez → _check_frida_unix_socket tasiyicidir. script-mode'da
    ag YOKTUR (thread+DLL sinyalleri kapsar) — dokumante sinir.
    """
    for port in _FRIDA_PORTS:
        try:
            s = socket.create_connection(("127.0.0.1", port),
                                         timeout=_FRIDA_PORT_TIMEOUT)
            try:
                s.close()
            except Exception:
                pass
            return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# R2: JIT compile-burst timing — fresh-trace compile costs dominate under
# DBI (first-compile spike), while warm traces run near-native. Metric:
# max/median over fresh code objects; self-relative, no absolute baseline.
# NOT: exec(compile()) denetim `compile`/`exec` olaylarini atesler; kardes
# anti_bytecode_analysis hook'u kuruluysa onun audit_event sinyalini
# tetikler (capraz-modul etkilesimi, tasarim-disi degil: iki sensor de
# kendi olcusunu dogru raporlar).
# ---------------------------------------------------------------------------

_BURST_ITERS = 120
_BURST_RATIO_MIN = 15.0
_BURST_TOP3_MIN = 8.0


def _qpc_ns() -> int | None:
    try:
        if _IS_WIN:
            k32 = ctypes.windll.kernel32
            freq = ctypes.c_int64()
            cur = ctypes.c_int64()
            k32.QueryPerformanceFrequency(ctypes.byref(freq))
            k32.QueryPerformanceCounter(ctypes.byref(cur))
            if not freq.value:
                return None
            return (int(cur.value) * 1_000_000_000) // int(freq.value)
        return time.perf_counter_ns()
    except Exception:
        return None


def _check_jit_burst() -> bool:
    try:
        samples = []
        for i in range(_BURST_ITERS):
            src = "def __f%d():\n return (%d*%d)+(%d^%d)\n" % (i, i + 3,
                                                               i + 7, i, i + 1)
            ns: dict = {}
            t0 = _qpc_ns()
            if t0 is None:
                return False
            try:
                exec(compile(src, "<jit%d>" % i, "exec"), ns)  # noqa: S102
                ns["__f%d" % i]()
            except Exception:
                continue
            t1 = _qpc_ns()
            if t1 is None:
                return False
            samples.append(t1 - t0)
        if len(samples) < 24:
            return False
        med = float(statistics.median(samples))
        if med <= 0:
            return False
        ordered = sorted(samples)
        second_max = float(ordered[-2])
        ratio = second_max / med
        _log("jit burst 2nd-max/med %.1f" % ratio)
        if ratio >= _BURST_RATIO_MIN:
            return True
        # N3: cok-ornekli derleme patlamasi (tek-hitch degil, soguk-cache
        # patlamasi): top3-ortalama/medyan. Temiz kutu top3 ~2.6x (R9);
        # esik 8.0 = ~3x marj. Steady-state Stalker (uniform yavaslama)
        # ratio'yu da top3'u da kaldirmaz — orada threads+rwx tasiyicidir (R18).
        try:
            top3 = float(sum(ordered[-3:])) / 3.0
            ratio3 = top3 / med
        except Exception:
            return False
        _log("jit burst top3/med %.1f" % ratio3)
        return ratio3 >= _BURST_TOP3_MIN
    except Exception as exc:
        _log("jit burst failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return False


# ---------------------------------------------------------------------------
# Linux-only: maps string scan (frida/gum/pinvm/dynamorio/qbdi). Windows
# module-name ground truth lives in anti_hook — not duplicated here.
# ---------------------------------------------------------------------------

_DBI_MAP_MARKERS = ("frida", "gum-js", "pinvm", "pintool", "dynamorio",
                    "qbdi", "drclient")


def _check_dbi_maps() -> bool:
    if not _IS_LINUX:
        return False
    try:
        with open("/proc/self/maps", "r", errors="ignore") as fh:
            for line in fh:
                low = line.lower()
                for marker in _DBI_MAP_MARKERS:
                    if marker in low:
                        return True
        return False
    except Exception as exc:
        _log("maps failed: %r" % (exc,))
        _health_bump("sensor_fail")
        return False


# ---------------------------------------------------------------------------
# Verdict (sibling contract)
# ---------------------------------------------------------------------------

def _raw_results() -> dict[str, bool]:
    return {
        "frida_threads": _check_frida_threads(),
        "dbi_parent": _check_dbi_parent(),
        "dbi_parent_verinfo": _check_dbi_parent_verinfo(),
        "anon_rwx": _check_anon_rwx(),
        "frida_port": _check_frida_port(),
        "frida_gadget_threads": _check_frida_gadget_threads(),
        "frida_unix_socket": _check_frida_unix_socket(),
        "jit_burst": _check_jit_burst(),
        "dbi_maps": _check_dbi_maps(),
        "frida_aux_threads": _check_frida_aux_threads(),
    }


_STRONG = frozenset({"frida_threads", "dbi_parent", "dbi_parent_verinfo"})
_WEAK = frozenset({"anon_rwx", "frida_port", "frida_gadget_threads",
                   "frida_unix_socket", "jit_burst", "dbi_maps",
                   "frida_aux_threads"})


_RESULT_TTL = 5.0
_RESULT_CACHE: dict = {"t": 0.0, "res": None}


def _raw_results_cached() -> dict[str, bool]:
    """N4: paylasimli TTL-onbellek — score/status/evidence/is_instrumented
    TEK suite-calismayi paylasir (3x calisma + TOCTOU dagilmasi + kardes
    self-incrimination biter). TTL 5sn: tazelik/k throughput dengesi."""
    try:
        now = time.monotonic()
    except Exception:
        now = 0.0
    try:
        cached = _RESULT_CACHE.get("res")
        if cached is not None and (now - float(_RESULT_CACHE.get("t", 0.0))) < _RESULT_TTL:
            return dict(cached)
    except Exception:
        pass
    try:
        res = _raw_results()
    except Exception:
        return {"frida_threads": True, "dbi_parent": False,
                "dbi_parent_verinfo": False, "anon_rwx": False,
                "frida_port": False, "frida_gadget_threads": False,
                "frida_unix_socket": False, "jit_burst": False,
                "dbi_maps": False, "frida_aux_threads": False}
    try:
        _RESULT_CACHE["res"] = dict(res)
        _RESULT_CACHE["t"] = now
    except Exception:
        pass
    return res


def check_all() -> dict[str, bool]:
    """{'instrumented': bool} — gradient-descent oracle yok."""
    try:
        return {"instrumented": bool(is_instrumented())}
    except Exception:
        return {"instrumented": True}


def evidence() -> dict[str, bool]:
    res = _collect_results()
    out = dict(res)
    try:
        out["instrumented"] = bool(_verdict_from(res))
    except Exception:
        out["instrumented"] = True
    return out


def score() -> tuple[int, int, int]:
    """(strong_hits, weak_hits, total_score)."""
    try:
        res = _raw_results_cached()
    except Exception:
        return (1, 0, 100)  # fail-closed
    s = sum(1 for k in _STRONG if res.get(k))
    w = sum(1 for k in _WEAK if res.get(k))
    return (s, w, s * 100 + w * 30)


def _verdict_from(res: dict[str, bool]) -> bool:
    if any(res.get(k) for k in _STRONG):
        return True
    weak = [k for k in _WEAK if res.get(k)]
    return len(weak) >= 2


def _collect_results() -> dict[str, bool]:
    try:
        return _raw_results_cached()
    except Exception:
        return {"frida_threads": False, "dbi_parent": False,
                "dbi_parent_verinfo": False, "anon_rwx": False,
                "frida_port": False, "frida_gadget_threads": False,
                "frida_unix_socket": False, "jit_burst": False,
                "dbi_maps": False, "frida_aux_threads": False}


def is_instrumented() -> bool:
    try:
        return bool(_verdict_from(_collect_results()))
    except Exception:
        return True  # fail-closed


class InstrumentationDetected(RuntimeError):
    """Opak hata: hangi sinyal tetiklendi DISARIYA soylenmez (oracle kapali)."""


def assert_no_instrumentation() -> None:
    """Enstrumantasyon suphesi varsa opak hata yukselt."""
    if is_instrumented():
        raise InstrumentationDetected("protected")


# ---------------------------------------------------------------------------
# Watchdog / guard / status (sibling-compatible surface)
# ---------------------------------------------------------------------------

_WATCHDOGS: list = []  # (thread, stop_event) ciftleri
_ADMIN_MODULES: dict = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
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
        _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
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
        _ADMIN_DENIED += 1
    except Exception:
        pass
    raise InstrumentationDetected("protected")


def _default_action() -> None:
    try:
        os._exit(1)
    except Exception:
        pass


def _watchdog_loop(stop, interval: float, action=None) -> None:
    """N5: trip'te action tetiklenir (default: fail-closed cikis).

    on_detect verilmemisse eski sessiz davranis + process-cikisi (gozlemle-ol
    degil: varsayilan action prosesi oldurur; operator callback ile ezer).
    """
    try:
        act = action if callable(action) else _default_action
        wait = stop.wait
    except Exception:
        return
    while not wait(interval):
        try:
            if is_instrumented():
                _log("watchdog: instrumentation trip")
                try:
                    act()
                except Exception:
                    pass
                break
        except Exception:
            pass


def start_watchdog(interval: float = 30.0, on_detect=None) -> threading.Thread:
    global _ADMIN_LOCKED
    try:
        _ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
    except Exception:
        iv = 30.0
    if iv < 1.0:
        iv = 1.0
    if iv > 600.0:
        iv = 600.0
    stop = threading.Event()
    th = threading.Thread(target=_watchdog_loop, args=(stop, iv, on_detect),
                          daemon=True, name="anti-instrumentation-watchdog")
    _WATCHDOGS.append((th, stop))
    th.start()
    return th


def stop_all_watchdogs() -> None:
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    try:
        items = list(_WATCHDOGS)
        _WATCHDOGS.clear()
        for _th, stop in items:
            try:
                stop.set()
            except Exception:
                continue
    except Exception:
        pass


class _Guard:
    def __enter__(self) -> "_Guard":
        assert_no_instrumentation()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is None:
            assert_no_instrumentation()
            return False
        if is_instrumented():
            raise InstrumentationDetected("protected") from exc
        return False


def guard() -> _Guard:
    return _Guard()


def status() -> dict[str, object]:
    try:
        res = _collect_results()
    except Exception:
        res = {}
    try:
        s, w, total = score()
    except Exception:
        s, w, total = (0, 0, 0)
    return {"signals": res, "strong": s, "weak": w, "score": total,
            "health": dict(_HEALTH), "admin_authorized": len(_ADMIN_MODULES),
            "admin_locked": _ADMIN_LOCKED, "admin_denied": _ADMIN_DENIED}
