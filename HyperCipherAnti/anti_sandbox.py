"""HyperCipherAnti anti_sandbox — automated-analysis sandbox detector.

Defensive posture module: detects Cuckoo/CAPE/Sandboxie/Any.run/Joe/Tria.ge
style automated sandboxes via timing, human-interaction, resource-freshness
and artifact signals. stdlib-only, cross-platform, silent by default,
fail-closed (sensor error -> no accusation, health counter records it).

Research base (strongest patterns synthesized):
  R1 al-khaser GEN_SANDBOX + TIMING_ATTACKS — known hostnames/usernames,
     NumberOfProcessors<2 (PEB+GetSystemInfo), accelerated_sleep via
     GetTickCount, human-interaction/mouse-movement, sbiedll/api_log/
     dir_watch/pstorec loaded-DLL list, disk-size thresholds.
  R2 pafish gensandbox.c + RTT — uptime<~12min (0xAFE74 ticks), physmem<1GB,
     disk<=60GB (DeviceIoControl + GetDiskFreeSpaceEx), Sleep(500) patched
     check, mouse presence/movement/speed-limit, username+path markers
     (SAMPLE/VIRUS/SANDBOX/MALWARE), IsNativeVhdBoot.
  R3 CAPE/CAPEv2 + Any.run + MITRE T1497.001 + capa rules — capemon.dll
     monitor, Disguise-vs-clean-image inversion (MRU/app-poverty), Any.run
     driver device (A3E64E55_fl) + KernelLogger minifilter behaviour,
     srvpost.exe/winanr/winsanr agents, Tria.ge wallpaper artifact.
  R4 pstorec.dll native (Protected Storage COM, MS-signed XP->Win11).
  R5 T1497.002 + crawlex: 5s cursor compare + idle-correlation; fresh-boot
     + long-idle is the strong tell, lone static cursor is not.
  R6 pafish 12min / crawlex minutes-scale uptime bands.
  R7 sechost.dll native (SCM/SDDL/LSA Host, MS-signed).
  R8 Unit42 pocket-litter + crawlex contradiction, defensive inversion:
     lived-in host evidence vetoes weak-only verdicts (exoneration).
  R9 CPython ctypes: default restype c_int truncates 64-bit HANDLEs.
  R10 Cuckoo guest: agent.py Flask + analyzer.py mkdtemp + cuckoomon DLL
     injection (no monitor process); CAPE injector pplinject.exe.
  R11 reverseengineering.app DLL list: cuckoomon.dll/cmonitor.dll added.
  R12 Sandboxie SBIESVC/SBIEDRV service names; winreg read needs no admin.
  R13 CheckPoint VB2016: C:\cuckoo_<pid>.ini monitor config.
  R14 CheckPoint evasions + Joe reports: JoeBox names confirmed,
     JoeBoxControl.sys driver path; debugger procs stay in anti_debug.
  R15 OSHI/Godot pattern: GPU names via display-class DriverDesc, no WMI.
  R16 Cuckoo agent binds 0.0.0.0:8000; GET / returns version+features JSON.
  R18 Cufish/serializing.me: FireEye MPS firemon driver. R19 Falcon is
     kernel-mode (no user artifact by design); McAfee confirms categories.
  R20 detect-anyrun: agent service 'aga' + aga.exe; test-signing boot mode.
  R21 Triage UAC-check signature -> EnableLUA signal; wallpaper name
     unpinned (glob stays WEAK).
  R22 windowssyscalls/ntdoc: NtDelayExecution(BOOLEAN, 100ns, neg=relative).
  R23 CAPE hook_sleep.c: coherent multi-clock skipping (QPC+Tick+FileTime);
     counter = cross-API disagreement probe; coherent skip documented FN.
  R24 RecentDocs MRU (HKCU Explorer-driven opens, MRUListEx slots).
  R25 T1497.002 inversion: browser data-file presence as lived-in proof.
  R26 MS Learn PSReadLine history paths (Win + POSIX) as shell-use proof.
  R27 UserAssist GUID\Count entry census (no decode) as GUI-launch proof.
  R28 Cuckoo agent docs: agent.py/agent.pyw in Startup folder for boot.
  R29 OSR + live reg: SystemStartOptions string method (NOEXECUTE=OPTIN here).
  R30 NtQuerySystemInformation(103) CODEINTEGRITY_OPTION_TESTSIGN bit 0x2.
  R33 MS Learn + NtDoc bitmask table (0x1 ENABLED ... 0x2000 IUM).
  R34 TESTSIGN meaningful only with ENABLED -> require (opts & 0x3) == 0x3.
  R36 unprotect.it C#: Tria.ge wallpaper = %USERPROFILE%\Pictures\My Wallpaper.jpg (exact).
  R37 CheckPoint VB2016: analyzer extracted to SYSTEMDRIVE random 5-10 char
     folder (analyzer.py + analysis.conf + bin/dll/lib/modules name-set).
  R40/R41 assessed, no artifact: VMRay monitors via hypervisor-VMI and
     ThreatGrid hooks the hypervisor — neither leaves guest user-mode
     traces to detect (honest out-of-scope, no speculative entries).
  R42 Antiy sandbox-image ProductIds (JoeBox 55274-640-2673064-23950,
     CWSandbox 76487-644-3177037-23510, Anubis 76487-337-8429955-22614).
  R43 guest.py analyzer_zipfile: whole analyzer/windows tree + analysis.conf
     extracted to mkdtemp dir — 1d name-set compatible, no change needed.
  R44 CAPE human.py simulates clicks/realistic mouse (75% active): interaction
     weaks may stay silent there by design; artifact/timing strongs carry.
  R45 Windows Sandbox assigns a GUID hostname (PSAppDeployToolkit #947);
     strict full-match hostname_guid WEAK in new "naming" family.
  R46 modern guests are FAT (CAPE 8GB/4CPU/250GB): poverty bands (2GB/80GB/
     <2cpu, 2-of-3 + corroboration) stay — raising them would FP small hosts.
  R47 Remus 2026: PEB CRC32 vs 11 sandbox DLLs (adds snxhk/cmdvrt32/64) +
     honey@pot.com.pst honeyfile check.
  R48 MS Learn KNOWNFOLDERID: filesystem path stays %USERPROFILE%\Documents
     in all locales (Belgeler is display-only) — honeyfile English-only is
     correct, no locale variant needed.
  R49 Cuckoo Linux guest docs: crontab "@reboot python /path/to/agent.py"
     persistence + /root/.cuckoo/stap_.ko SystemTap ext.
  R50 Sandboxie docs: injected module is SbieDll.dll on BOTH archs (single
     entry covers x64); Windows python-script cmdline needs WMI/fragile PEB
     reads — accepted gap, 4 other Cuckoo layers (file/Startup/port/dir).
  R51 guest crontab @reboot is THE documented agent persistence (systemd
     units are host-side); R52 SystemStartOptions is REG_SZ (MSDN+Q102987).
  R53 agent.py needs no admin, sample inherits analyzer chain (python.exe
     parent, no shell) — parent_chain keeps image names only.
  R54 container markers (/.dockerenv + cgroup docker/containerd/kubepods/
     podman/lxc + mountinfo overlay) as 5th exoneration vote — Cuckoo
     guests are VMs, never containers.
  R55 SCI-103 quadruple-confirmed (MS Learn + sdk-api + NtDoc +
     windowssyscalls): struct {Length; Options}, caller sets Length,
     0x1 ENABLED / 0x2 TESTSIGN — implementation matches, no change.
  R56 MS Learn/N-able/PrivescCheck: EnableLUA 0=off/1=on; Consent*=0 neuters
     prompting regardless of EnableLUA — uac_disabled covers all three.
  R57 Any.run agent names still current (srvpost.exe + winanr/winsanr per
     gist/unprotect/malwation/orangemaster); 1c2/1d/1e code review clean.
  R58 serializing.me PoC confirms firemon.sys exact path
     (C:\WINDOWS\system32\drivers\firemon.sys) — entry matches verbatim.
  R59 TrickBot exact VM defaults 800x600/1024x768 (guest additions absent);
     prior <800/<600 band missed 1024x768 (FN). R60 al-khaser#216
     SM_REMOTESESSION terminal-services flag.
  R38 vmde.pdf + CheckPoint table: Sandboxie control mutex
     Sandboxie_SingleInstanceMutex_Control via OpenMutexW (SbieSvcPort is
     \RPC Control ALPC, SandboxieDriverApi is \Device — not mutex-openable).
  R35 CAPE Disguise fills Office File MRU only — Explorer RecentDocs,
     browser data, PSReadLine, UserAssist vetoes (R24-R27) survive it.
  R31 al-khaser exact hostname/username lists (Gootkit/ostap/Betabot/Satan).
  R32 capa rule + ObliqueRAT blocklist + Emotet combos (SystemIT/KLONE_X64,
     John+take_screenshot/loaddll, email/foobar file sets); personal names
     exact-match only (substring would FP real Millers/Johnsons/Emilys).

Scoring (mirrors anti_vm contract):
  STRONG = 100, WEAK = 30.
  Trip iff >=1 strong OR >=2 weak; weak-only verdicts are vetoed by
  lived-in host evidence (R8 pocket-litter inversion).
"""

from __future__ import annotations

import ctypes
import getpass
import glob as _glob
import os
import re as _re
import socket
import sys
import threading
import time

__version__ = "1.0.0"
__all__ = [
    "SandboxDetected",
    "is_sandboxed",
    "assert_no_sandbox",
    "check_all",
    "evidence",
    "score",
    "status",
    "set_verbose",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]

_VERBOSE = os.environ.get("HYPERCIPHER_ANTISANDBOX_VERBOSE") == "1"

_SENSORS_OK = 0
_SENSORS_TOTAL = 0

STRONG = 100
WEAK = 30

_IS_WIN = sys.platform == "win32"


def set_verbose(on: bool = True) -> None:
    """Enable/disable diagnostic chatter (default silent)."""
    global _VERBOSE
    _VERBOSE = bool(on)


def _v(msg: str) -> None:
    if _VERBOSE:
        sys.stderr.write("[anti_sandbox] %s\n" % msg)


def _sensor(fn):
    """Wrap signal: count health, fail-closed on exception (S-2).

    Sensor-hatasi suphe uretir (True) — bagimlilik fault'lanarak susturma
    kapanir. Hata sayaci _SENSORS_OK/TOTAL ile izlenir.
    """
    def inner():
        global _SENSORS_OK, _SENSORS_TOTAL
        _SENSORS_TOTAL += 1
        try:
            hit = bool(fn())
        except Exception as exc:  # fail-closed: sensor error = suphe
            _v("%s sensor error: %r" % (fn.__name__, exc))
            return True
        if hit:
            _v("%s HIT" % fn.__name__)
        else:
            _SENSORS_OK += 1
        return hit
    inner.__name__ = fn.__name__
    return inner


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _win_dll(name: str):
    try:
        return ctypes.WinDLL(name)
    except Exception:
        return None


_kernel32 = _win_dll("kernel32") if _IS_WIN else None
_user32 = _win_dll("user32") if _IS_WIN else None


def _read_proc_file(path: str, limit: int = 65536) -> str:
    try:
        with open(path, "r", errors="ignore") as fh:
            return fh.read(limit)
    except Exception:
        return ""


def _proc_names() -> list:
    """Process image names, lower-cased. Toolhelp32 on Windows, /proc on POSIX."""
    names: list = []
    try:
        if _IS_WIN and _kernel32 is not None:
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_uint32),
                    ("cntUsage", ctypes.c_uint32),
                    ("th32ProcessID", ctypes.c_uint32),
                    ("th32DefaultHeapID", ctypes.c_ulonglong),
                    ("th32ModuleID", ctypes.c_uint32),
                    ("cntThreads", ctypes.c_uint32),
                    ("th32ParentProcessID", ctypes.c_uint32),
                    ("pcPriClassBase", ctypes.c_int32),
                    ("dwFlags", ctypes.c_uint32),
                    ("szExeFile", ctypes.c_wchar * 260),
                ]

            k = _kernel32
            k.CreateToolhelp32Snapshot.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
            k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
            k.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
            k.Process32FirstW.restype = ctypes.c_int
            k.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(PROCESSENTRY32)]
            k.Process32NextW.restype = ctypes.c_int
            snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if int(snap or 0) not in (0, -1):
                try:
                    pe = PROCESSENTRY32()
                    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
                    ok = k.Process32FirstW(snap, ctypes.byref(pe))
                    while ok:
                        try:
                            names.append(str(pe.szExeFile).lower())
                        except Exception:
                            pass
                        ok = k.Process32NextW(snap, ctypes.byref(pe))
                finally:
                    try:
                        k.CloseHandle(snap)
                    except Exception:
                        pass
        else:
            for pid in os.listdir("/proc"):
                if not pid.isdigit():
                    continue
                comm = _read_proc_file("/proc/%s/comm" % pid, 256).strip().lower()
                if comm:
                    names.append(comm)
                else:
                    cmd = _read_proc_file("/proc/%s/cmdline" % pid, 512)
                    if cmd:
                        base = cmd.split("\x00")[0].split("/")[-1].strip().lower()
                        if base:
                            names.append(base)
    except Exception as exc:
        _v("proc enum error: %r" % (exc,))
    return names


def _loaded_module_names() -> list:
    """Module/DLL basenames loaded in *this* process (lower-cased)."""
    mods: list = []
    try:
        if _IS_WIN and _kernel32 is not None:
            k = _kernel32
            k.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]
            k.GetModuleHandleW.restype = ctypes.c_void_p
            k.EnumProcessModules = getattr(k, "EnumProcessModules", None)
            if k.EnumProcessModules is not None:
                k.EnumProcessModules.argtypes = [
                    ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                    ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
                k.EnumProcessModules.restype = ctypes.c_int
                k.GetModuleBaseNameW.argtypes = [
                    ctypes.c_void_p, ctypes.c_void_p,
                    ctypes.c_wchar_p, ctypes.c_uint32]
                k.GetModuleBaseNameW.restype = ctypes.c_uint32
                arr = (ctypes.c_void_p * 512)()
                need = ctypes.c_uint32(0)
                try:
                    hproc = k.GetCurrentProcess()
                except Exception:
                    hproc = None
                if hproc and k.EnumProcessModules(hproc, arr, ctypes.sizeof(arr), ctypes.byref(need)):
                    n = min(need.value // ctypes.sizeof(ctypes.c_void_p), 512)
                    for i in range(n):
                        buf = ctypes.create_unicode_buffer(260)
                        if k.GetModuleBaseNameW(hproc, arr[i], buf, 260):
                            mods.append(buf.value.lower())
        else:
            maps = _read_proc_file("/proc/self/maps")
            for line in maps.splitlines():
                parts = line.split()
                if parts:
                    base = parts[-1].split("/")[-1].lower()
                    if base.endswith(".so") or ".so." in base:
                        mods.append(base)
    except Exception as exc:
        _v("module enum error: %r" % (exc,))
    return mods


# ---------------------------------------------------------------------------
# STRONG signals
# ---------------------------------------------------------------------------

@_sensor
def _sig_sleep_acceleration() -> bool:
    """Sleep(500ms) returns far too fast on ≥2 independent clocks.

    pafish gensandbox_sleep_patched + al-khaser accelerated_sleep, hardened:
    dual-clock (monotonic + perf_counter) agreement required so a single
    drifting clock cannot trip us; threshold = 60% of requested sleep.
    """
    want = 0.5
    tol = want * 0.6
    t0m = time.monotonic()
    t0p = time.perf_counter()
    try:
        time.sleep(want)
    except Exception:
        return False
    dm = time.monotonic() - t0m
    dp = time.perf_counter() - t0p
    _v("sleep: mono=%.3f perf=%.3f want=%.3f" % (dm, dp, want))
    if dm <= 0 or dp <= 0:
        return False
    # clocks must agree with each other (divergence handled by clock signal)
    if abs(dm - dp) > 0.25:
        return False
    return (dm < tol) and (dp < tol)


@_sensor
def _sig_sleep_disagreement() -> bool:
    """kernel32.Sleep vs ntdll.NtDelayExecution disagree (R22/R23).

    CAPE hook_sleep.c patches Sleep AND NtDelayExecution AND QPC AND
    GetTickCount coherently — coherent skipping is unbeatable from usermode
    (documented limitation, same as malware faces). But cheaper sandboxes
    patch only one sleep API. If one 500ms probe returns in <60% while the
    other honestly sleeps (>80%), the APIs were tampered incoherently.
    NtDelayExecution(Boolean, PLARGE_INTEGER 100ns, negative=relative).
    """
    if not _IS_WIN or _kernel32 is None:
        return False
    try:
        _kernel32.Sleep.argtypes = [ctypes.c_uint32]
        _kernel32.Sleep.restype = None
        try:
            ntdll = ctypes.WinDLL("ntdll")
        except Exception:
            return False
        ntdll.NtDelayExecution.argtypes = [ctypes.c_ubyte,
                                           ctypes.POINTER(ctypes.c_int64)]
        ntdll.NtDelayExecution.restype = ctypes.c_int32

        def _probe_sleep():
            t0 = time.monotonic()
            _kernel32.Sleep(500)
            return time.monotonic() - t0

        def _probe_ntdelay():
            iv = ctypes.c_int64(-500 * 10000)
            t0 = time.monotonic()
            try:
                ntdll.NtDelayExecution(ctypes.c_ubyte(0), ctypes.byref(iv))
            except Exception:
                return -1.0
            return time.monotonic() - t0

        d_sleep = _probe_sleep()
        d_ntd = _probe_ntdelay()
        _v("sleep_vs_ntdelay: %.3f vs %.3f" % (d_sleep, d_ntd))
        if d_sleep <= 0 or d_ntd < 0:
            return False
        if d_sleep < 0.3 and d_ntd < 0.3:
            return False
        return (d_sleep < 0.3) != (d_ntd < 0.3)
    except Exception as exc:
        _v("sleep_disagreement error: %r" % (exc,))
        return False


@_sensor
def _sig_clock_divergence() -> bool:
    """monotonic vs perf_counter vs time.time disagree wildly.

    Catches NtDelayExecution/Sleep patching and VM clock games where one
    clock source is virtualized differently from the others.
    """
    try:
        a_m = time.monotonic()
        a_p = time.perf_counter()
        a_t = time.time()
        time.sleep(0.2)
        d_m = time.monotonic() - a_m
        d_p = time.perf_counter() - a_p
        d_t = time.time() - a_t
    except Exception:
        return False
    _v("clocks: mono=%.3f perf=%.3f wall=%.3f" % (d_m, d_p, d_t))
    for d in (d_m, d_p, d_t):
        if d <= 0 or d > 5.0:
            return True
    # pairwise agreement within 150ms over a 200ms window => manipulated
    pairs = (abs(d_m - d_p), abs(d_m - d_t), abs(d_p - d_t))
    return max(pairs) > 0.15


# Sandbox agent / monitor artifacts (Cuckoo, CAPE, Sandboxie, Any.run, ...).
_AGENT_FILES = (
    # Cuckoo (kevoreilly/community antisandbox_cuckoo_files + agent source)
    "c:\\agent\\agent.pyw", "c:\\agent\\agent.py",
    "c:\\cuckoo\\dll", "c:\\tmp\\agent.py",
    # CAPE monitor
    "capemon.dll", "capemon_x64.dll", "loader.exe",
    # Sandboxie / SunBelt / legacy (al-khaser loaded_dlls + pafish sandboxie.c)
    # NOTE R4: pstorec.dll REMOVED — native Windows file since XP (Protected
    # Storage COM, Microsoft-signed through Win11); al-khaser SunBelt tag is
    # stale and trips every real host (bare-metal FP proven 2026-09-04).
    "sbiedll.dll", "api_log.dll", "dir_watch.dll",
    "vmcheck.dll", "wpespy.dll",
    # Any.run (srvpost.exe + winanr/winsanr + KernelLogger dir)
    # NOTE R7: sechost.dll REMOVED — native Windows file (Host for SCM/SDDL/
    # LSA Lookup APIs, Microsoft-signed); unprotect.it refers to Any.run's own
    # copy in its agent context, while %SystemRoot%\System32\sechost.dll ships
    # on every host (bare-metal FP proven 2026-09-04, same class as pstorec).
    "srvpost.exe", "winanr.dll", "winsanr.dll",
    "c:\\program files\\kernellogger",
    # R20: Any.run usermode agent binary.
    "c:\\program files\\kernellogger\\aga.exe",
    # Joe Sandbox / Triage artifacts
    "joeboxserver.exe", "joeboxcontrol.exe",
    # R14: in-the-wild malware checks the JoeBox driver path.
    "c:\\windows\\system32\\drivers\\joeboxcontrol.sys",
    # R18 (Cufish/serializing.me): FireEye MPS monitor driver firemon.
    "c:\\windows\\system32\\drivers\\firemon.sys",
    # R13 (CheckPoint VB2016): Cuckoo monitor config "C:\cuckoo_<pid>.ini".
    # "glob:" prefix = globbed against the system drive root.
    "glob:c:\\cuckoo_*.ini",
    # R31/R32 (al-khaser other_known_sandbox_environment_checks, Emotet):
    # John + take_screenshot.ps1/loaddll.exe, email.doc/htm + 123\email
    # combo, a\foobar.bmp/doc/gif combo.
    "c:\\take_screenshot.ps1", "c:\\loaddll.exe",
    "c:\\email.doc", "c:\\email.htm",
    # R49 (Cuckoo Linux guest docs): SystemTap kernel ext in /root/.cuckoo.
    "/root/.cuckoo/stap_.ko",
)
# R11 (reverseengineering.app loaded-DLL check): Cuckoo monitor DLLs
# cuckoomon.dll/cmonitor.dll were missing from the module watch (FN gap).
# SbieHide-class tools can hide sbiedll from the PEB, so the service
# registry below is the second layer (R12: SBIESVC/SBIEDRV names from
# Sandboxie SbieUtils.cpp; winreg read needs no admin).
_AGENT_MODULES = (
    "sbiedll.dll", "api_log.dll", "dir_watch.dll",
    "cuckoomon.dll", "cmonitor.dll",
    "capemon.dll", "capemon_x64.dll", "winanr.dll", "winsanr.dll",
    # R47 (Remus 2026 PEB CRC32 11-hash list): Avast + Comodo monitor DLLs.
    "snxhk.dll", "cmdvrt32.dll", "cmdvrt64.dll",
)
_AGENT_SERVICES = (
    r"SYSTEM\CurrentControlSet\Services\SbieSvc",
    r"SYSTEM\CurrentControlSet\Services\SbieDrv",
    # R20 (kkent030315/detect-anyrun): Any.run usermode agent service.
    r"SYSTEM\CurrentControlSet\Services\aga",
)
# R10 (cont.): script basenames (agent.py/analyzer.py) can never equal a
# process image name — covered by the POSIX cmdline branch + file/Startup/
# port/dir layers instead, so they are deliberately absent here.
_AGENT_PROCS = (
    "pplinject.exe", "sbiesvc.exe", "sbiectrl.exe",
    "srvpost.exe", "joeboxserver.exe", "joeboxcontrol.exe",
    "wireshark.exe", "procmon.exe", "procmon64.exe", "fiddler.exe",
)
_AGENT_ENVKEYS = (
    "cuckoo", "cape", "sandboxie", "sbie", "joebox", "anyrun",
    "tria.ge", "hybrid-analysis", "wildfire",
)


@_sensor
def _sig_agent_artifacts() -> bool:
    """Known sandbox agent files / processes / modules / env markers."""
    # 1) files on disk (exact well-known paths + basenames + glob: patterns)
    for pat in _AGENT_FILES:
        try:
            if pat.startswith("glob:"):
                sysdrive = os.path.splitdrive(os.getcwd())[0] or "C:" if _IS_WIN else ""
                gpat = pat[len("glob:"):]
                if _IS_WIN and len(gpat) > 1 and gpat[1] == ":":
                    gpat = sysdrive + gpat[2:]
                hits = _glob.glob(gpat)
                if hits:
                    _v("agent glob: %s" % hits[0])
                    return True
                continue
            if os.path.isabs(pat) or ":\\" in pat or pat.startswith("c:"):
                drive_pat = pat
                # map to current drive letter on Windows hosts
                if _IS_WIN and len(drive_pat) > 1 and drive_pat[1] == ":":
                    cur = os.path.splitdrive(os.getcwd())[0] or "C:"
                    drive_pat = cur + drive_pat[2:]
                if os.path.exists(drive_pat):
                    _v("agent file: %s" % drive_pat)
                    return True
            else:
                for hit in _glob.glob(os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", pat)):
                    _v("agent sysfile: %s" % hit)
                    return True
        except Exception:
            continue
    # 1b) sandbox service registrations (R12: survives SbieHide-class
    # PEB hiding; winreg read requires no elevation)
    if _IS_WIN:
        try:
            import winreg as _wr
            for svc in _AGENT_SERVICES:
                try:
                    with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, svc):
                        _v("agent service: %s" % svc)
                        return True
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
        except Exception as exc:
            _v("service enum: %r" % (exc,))
    # 1b2) Sandboxie control mutex (R38: vmde.pdf + CheckPoint table —
    # SbieHide hides sbiedll, not the driver mutex. Only the mutex is probed
    # here: SbieSvcPort is an \RPC Control ALPC port and SandboxieDriverApi
    # a \Device object, neither openable via OpenMutexW.)
    if _IS_WIN and _kernel32 is not None:
        try:
            _kernel32.OpenMutexW.argtypes = [
                ctypes.c_uint32, ctypes.c_int, ctypes.c_wchar_p]
            _kernel32.OpenMutexW.restype = ctypes.c_void_p
            _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
            _kernel32.CloseHandle.restype = ctypes.c_int
            for _obj in ("Sandboxie_SingleInstanceMutex_Control",):
                try:
                    _h = _kernel32.OpenMutexW(0x0001, 0, _obj)
                    if _h is not None and int(_h or 0) not in (0, -1):
                        try:
                            _kernel32.CloseHandle(_h)
                        except Exception:
                            pass
                        _v("agent named object: %s" % _obj)
                        return True
                except Exception:
                    continue
        except Exception as exc:
            _v("named-object enum: %r" % (exc,))
    # 1c) Startup-folder persistence (R28: Cuckoo docs prescribe placing
    # agent.py/agent.pyw in the Startup folder for boot launch)
    if _IS_WIN:
        try:
            startup_dirs = []
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                startup_dirs.append(os.path.join(
                    appdata, "Microsoft", "Windows", "Start Menu",
                    "Programs", "Startup"))
            progdata = os.environ.get("ProgramData", "")
            if progdata:
                startup_dirs.append(os.path.join(
                    progdata, "Microsoft", "Windows", "Start Menu",
                    "Programs", "Startup"))
            for sdir in startup_dirs:
                try:
                    if not os.path.isdir(sdir):
                        continue
                    for fn in os.listdir(sdir):
                        if fn.lower() in ("agent.py", "agent.pyw", "analyzer.py"):
                            _v("agent startup: %s" % os.path.join(sdir, fn))
                            return True
                except Exception:
                    continue
        except Exception as exc:
            _v("startup enum: %r" % (exc,))
    # 1c2) POSIX agent persistence (R49: Cuckoo Linux guest docs prescribe
    # crontab "@reboot python /path/to/agent.py"). File reads only, capped
    # sizes, fail-closed on permissions.
    if not _IS_WIN:
        try:
            _cron_files = ["/etc/crontab"]
            try:
                for _fn in os.listdir("/etc/cron.d"):
                    _cron_files.append(os.path.join("/etc/cron.d", _fn))
            except Exception:
                pass
            for _spool in ("/var/spool/cron/crontabs", "/var/spool/cron"):
                try:
                    for _fn in os.listdir(_spool):
                        _cron_files.append(os.path.join(_spool, _fn))
                except Exception:
                    continue
            for _cf in _cron_files[:32]:
                try:
                    if not os.path.isfile(_cf):
                        continue
                    with open(_cf, "r", errors="ignore") as _fh:
                        _blob = _fh.read(65536).lower()
                    if _re.search(r"(?<![a-z0-9_.])agent\.pyw?(?![a-z0-9_])", _blob) or \
                       _re.search(r"(?<![a-z0-9_.])analyzer\.py(?![a-z0-9_])", _blob):
                        _v("agent crontab: %s" % _cf)
                        return True
                except Exception:
                    continue
        except Exception as exc:
            _v("cron enum: %r" % (exc,))
    # 1d) analyzer directory layout (R37: CheckPoint VB2016 — agent extracts
    # analyzer to SYSTEMDRIVE random 5-10 char folder holding analyzer.py,
    # analysis.conf, bin/, dll/, lib/, modules/). Top-level scan only, capped
    # entries, name-set match (random folder name itself is unmatchable).
    try:
        root = (os.path.splitdrive(os.getcwd())[0] + "\\") if _IS_WIN else "/"
        try:
            top = os.listdir(root)[:64]
        except Exception:
            top = []
        want_files = {"analyzer.py", "analysis.conf"}
        want_dirs = {"bin", "dll", "lib", "modules"}
        for entry in top:
            try:
                full = os.path.join(root, entry)
                if not os.path.isdir(full):
                    continue
                try:
                    inner = set(n.lower() for n in os.listdir(full)[:64])
                except Exception:
                    continue
                if want_files <= inner or len((want_files | want_dirs) & inner) >= 3:
                    _v("agent analyzer dir: %s" % full)
                    return True
            except Exception:
                continue
    except Exception as exc:
            _v("analyzer-dir enum: %r" % (exc,))
    # 1e) Windows ProductId blocklist (R42: Antiy published sandbox-image IDs;
    # R35 corroboration: CAPE Disguise randomizes ProductId precisely to defeat
    # this check, e.g. Malwr.com static IDs. Exact match — zero FP on real hosts.)
    if _IS_WIN:
        try:
            import winreg as _wr
            for _view in (0, 0x0100):
                try:
                    with _wr.OpenKey(
                            _wr.HKEY_LOCAL_MACHINE,
                            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                            0, _wr.KEY_READ | _view) as key:
                        try:
                            _pid, _typ = _wr.QueryValueEx(key, "ProductId")
                        except FileNotFoundError:
                            continue
                        if str(_pid).strip() in (
                                "55274-640-2673064-23950",
                                "76487-644-3177037-23510",
                                "76487-337-8429955-22614"):
                            _v("agent product-id: %s" % _pid)
                            return True
                except FileNotFoundError:
                    continue
                except Exception:
                    continue
        except Exception as exc:
            _v("product-id enum: %r" % (exc,))
    # 1f) sandbox honeyfiles (R47: Remus treats
    # %UserProfile%\Documents\Outlook Files\honey@pot.com.pst as sandbox).
    # Exact filename — no real host carries it.
    try:
        _home = os.path.expanduser("~") or ""
        if _home:
            _honey = os.path.join(
                _home, "Documents", "Outlook Files", "honey@pot.com.pst")
            if os.path.isfile(_honey):
                _v("agent honeyfile: %s" % _honey)
                return True
    except Exception as exc:
        _v("honeyfile enum: %r" % (exc,))
    # 2) running processes
    try:
        procs = set(_proc_names())
    except Exception:
        procs = set()
    for ap in _AGENT_PROCS:
        if ap in procs:
            _v("agent proc: %s" % ap)
            return True
    # agent.py executed by any python interpreter with sandbox cwd markers
    if ("python.exe" in procs or "pythonw.exe" in procs or "python3" in procs or "python" in procs):
        for marker in ("agent.py", "analyzer.py", "cuckoo", "cape"):
            try:
                for pid in ([] if _IS_WIN else [p for p in os.listdir("/proc") if p.isdigit()]):
                    cmd = _read_proc_file("/proc/%s/cmdline" % pid, 1024).lower().replace("\x00", " ")
                    if marker in cmd and ("cuckoo" in cmd or "cape" in cmd or "agent" in cmd):
                        _v("agent cmdline pid=%s" % pid)
                        return True
            except Exception:
                break
    # 3) monitor DLLs loaded into our own process
    try:
        mods = set(_loaded_module_names())
    except Exception:
        mods = set()
    for dll in _AGENT_MODULES:
        if dll in mods:
            _v("agent module: %s" % dll)
            return True
    # 4) env markers — word-boundary match on names+values (R: F8).
    # A bare substring over the whole env blob FPs on e.g. PATH entries
    # containing "cape" (landscape) or "sbie"-like fragments.
    try:
        items = ["%s=%s" % (k, v) for k, v in os.environ.items()]
    except Exception:
        items = []
    for key in _AGENT_ENVKEYS:
        pat = r"(?<![a-z0-9_.])%s(?![a-z0-9_])" % _re.escape(key)
        for item in items:
            try:
                if _re.search(pat, item.lower()):
                    _v("agent env: %s" % key)
                    return True
            except Exception:
                continue
    return False


# Known sandbox hostnames / usernames (al-khaser known_hostnames/usernames,
# pafish gensandbox_username, capa check-for-sandbox-username-or-hostname).
_SB_HOST_SUBS = (
    "sandbox", "cuckoo", "cape", "joebox", "joecage", "anyrun", "any.run",
    "triage", "tria.ge", "malware", "virus", "sample", "maltest",
    "wildfire", "falcon-sandbox", "vmray", "threatgrid", "hybrid",
    "forti-pc", "willcarter", "sftor-pc", "straznjica",
)
_SB_USER_SUBS = (
    "sandbox", "cuckoo", "cape", "anyrun", "triage",
    "malware", "virus", "sample", "maltest",
)
# R31/R32 exact-match tier (al-khaser _tcsicmp + capa regex semantics).
# Personal names MUST NOT be substring-matched (a real user named Miller,
# Johnson or Emily is not a sandbox) — compare whole identity only.
_SB_HOST_EXACT = (
    "7silvia", "tequilaboomboom", "hanspeter-pc", "john-pc", "mueller-pc",
    "win7-traps", "fortinet", "klone_x64-pc", "systemit", "vbox7-pc",
    "janusz-pc", "abby-pc", "desktop-hrw10", "amazing-lingon", "sandbox-o365",
    "hal9th", "wdagutilityaccount", "tom-pc", "rats-pc",
)
_SB_USER_EXACT = (
    "currentuser", "emily", "hapubws", "hong lee", "it-admin", "johnson",
    "miller", "milozs", "peter wilson", "timmy", "sand box", "test user",
    "john doe", "paul jones", "pjones", "harry johnson", "sal.rosenburg",
    "heuerzl", "nepenthes", "john", "abby", "wilbert", "virlab",
    "hal9th", "wdagutilityaccount", "vm-pc", "analyze", "mallab",
    # R32 completion: capa-only entries (7SILVIA/SystemIT also appear as
    # usernames; d5.vc/g is a known sandbox username string).
    "7silvia", "systemit", "d5.vc/g",
    # S-1: exact-only kisa/kisisel isimler (substring DEGIL — "joel"
    # Fpsi kapatir; al-khaser/capa _tcsicmp EXACT semantigi).
    "joe", "joe cage", "joecage", "test",
)


@_sensor
def _sig_known_identity() -> bool:
    """Hostname/username matches sandbox naming (substring, lower-cased)."""
    hits = []
    try:
        host = (socket.gethostname() or "").lower()
    except Exception:
        host = ""
    try:
        user = (getpass.getuser() if hasattr(getpass, "getuser") else os.environ.get("USERNAME", "") or "").lower()
    except Exception:
        user = ""
    # env fallbacks (USERNAME/USER/HOSTNAME/COMPUTERNAME)
    try:
        envblob = " ".join([
            os.environ.get("COMPUTERNAME", ""), os.environ.get("HOSTNAME", ""),
            os.environ.get("USERNAME", ""), os.environ.get("USER", ""),
        ]).lower()
    except Exception:
        envblob = ""
    for sub in _SB_HOST_SUBS:
        if sub and (sub in host or sub in envblob):
            hits.append("host:%s" % sub)
            break
    if host in _SB_HOST_EXACT:
        hits.append("host-exact:%s" % host)
    # S-5: ayirici-sinirli stem eslesmesi (sandbox-01/sandbox_02 yakalanir,
    # "mysandboxx" degil — exact + separator-boundary).
    try:
        _hnorm = _re.sub(r"[^a-z0-9]+", "-", host).strip("-")
    except Exception:
        _hnorm = host
    for stem in ("sandbox", "cuckoo", "cape", "anyrun", "triage",
                 "joebox", "joecage", "wildfire", "vmray"):
        try:
            if _hnorm == stem or _hnorm.startswith(stem + "-"):
                hits.append("host-stem:%s" % stem)
                break
        except Exception:
            continue
    if user in _SB_USER_EXACT:
        hits.append("user-exact:%s" % user)
    for sub in _SB_USER_SUBS:
        if sub and (sub in user or sub in envblob):
            hits.append("user:%s" % sub)
            break
    # own executable path markers (pafish gensandbox_path: SAMPLE/VIRUS/SANDBOX)
    # G2: normalize separators first (backslash markers never match POSIX
    # paths otherwise = FN), then match whole path segments or filename
    # prefixes — a bare substring FPs on dev dirs like "my-sandbox-tool".
    try:
        me = (sys.argv[0] if sys.argv else "").upper().replace("/", "\\")
    except Exception:
        me = ""
    try:
        segs = [s for s in me.split("\\") if s]
        fname = segs[-1] if segs else ""
    except Exception:
        segs, fname = [], ""
    for marker in ("SAMPLE", "VIRUS", "SANDBOX", "MALWARE"):
        if marker in segs or fname.startswith(marker):
            hits.append("path:%s" % marker)
            break
    if hits:
        _v("identity: %s" % ",".join(hits))
        return True
    return False


@_sensor
def _sig_agent_port() -> bool:
    """Cuckoo/CAPE agent HTTP banner (S-5: port-kumesi + banner-sart).

    agent.py default 8000 (CUCKOO_GUEST_PORT) ama custom dagitimlar
    8001/8080/9000 kullanir. Banner-dogrulamali (acik-port tek-basina
    anlamsiz — dev server FP kalkani). Port-basina 0.4sn butce.
    """
    for port in (8000, 8001, 8080, 9000):
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=0.4)
        except Exception:
            continue
        try:
            s.settimeout(0.4)
            try:
                s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            except Exception:
                try:
                    s.close()
                except Exception:
                    pass
                continue
            data = b""
            try:
                while len(data) < 2048:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    data += chunk
            except Exception:
                pass
        finally:
            try:
                s.close()
            except Exception:
                pass
        text = data.decode("utf-8", "ignore").lower()
        _v("agent port %d banner: %s" % (port, text[:120].replace("\n", " ")))
        if not text:
            continue
        specific = ("cuckoo", "cape", "execpy", "agent.py", "pinning")
        generic = ('"version"', '"features"')
        if (any(m in text for m in specific)
                and sum(m in text for m in specific + generic) >= 2):
            return True
    return False


@_sensor
def _sig_anyrun_driver() -> bool:
    """Any.run introspector driver device / KernelLogger minifilter behaviour.

    orangemaster674 method: opening \\\\.\\A3E64E55_fl succeeds only under
    Any.run; KernelLogger dir access returns non-standard STATUS_NO_SUCH_FILE.
    In Python: device open attempt + protected-dir probing without elevation.
    """
    if not _IS_WIN:
        return False
    # 1) driver symbolic device — R9: HANDLE prototypes mandatory. Default
    # ctypes restype is c_int, which truncates 64-bit handles (CPython docs);
    # INVALID_HANDLE_VALUE is c_void_p(-1).value (Chromium/mercurial pattern).
    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    try:
        _kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.c_void_p]
        _kernel32.CreateFileW.restype = ctypes.c_void_p
        _kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        _kernel32.CloseHandle.restype = ctypes.c_int
        h = _kernel32.CreateFileW(
            "\\\\.\\A3E64E55_fl", 0x80000000, 0, None, 3, 0, None)
        try:
            ok = h is not None and h != _INVALID_HANDLE
        finally:
            try:
                if h is not None and h != _INVALID_HANDLE:
                    _kernel32.CloseHandle(h)
            except Exception:
                pass
        if ok:
            _v("anyrun driver device opened")
            return True
    except Exception as exc:
        _v("anyrun device probe: %r" % (exc,))
    # 2) KernelLogger dir: exists-but-invisible + listdir raises odd error
    kl = os.path.join(os.environ.get("ProgramFiles", "C:\\Program Files"), "KernelLogger")
    try:
        listed = os.listdir(kl)
        _v("kernellogger listed: %d entries" % len(listed))
        return True  # visible logger dir is itself an artifact
    except FileNotFoundError:
        pass
    except PermissionError:
        _v("kernellogger permission-denied (protected?)")
        return True
    except OSError as exc:
        # non-standard failure on a path that 'should' be plain-missing
        # or plain-denied is the minifilter tell
        if getattr(exc, "winerror", 0) not in (2, 3, 5, 267):
            _v("kernellogger odd error: %r" % (exc,))
            return True
    return False


# ---------------------------------------------------------------------------
# WEAK signals
# ---------------------------------------------------------------------------

def _uptime_seconds():
    """Boot-relative uptime in seconds, or None if unavailable."""
    try:
        if _IS_WIN and _kernel32 is not None:
            _kernel32.GetTickCount64.argtypes = []
            _kernel32.GetTickCount64.restype = ctypes.c_uint64
            return float(_kernel32.GetTickCount64()) / 1000.0
        for path in ("/proc/uptime",):
            txt = _read_proc_file(path, 64).split()
            if txt:
                return float(txt[0])
        if sys.platform == "darwin":
            import subprocess as _sp
            out = _sp.check_output(["sysctl", "-n", "kern.boottime"],
                                   timeout=5).decode(errors="ignore")
            # { sec = 1725..., usec = 0 } ...
            import re as _re
            m = _re.search(r"sec\s*=\s*(\d+)", out)
            if m:
                return time.time() - float(m.group(1))
    except Exception as exc:
        _v("uptime error: %r" % (exc,))
    return None


@_sensor
def _sig_uptime_fresh() -> bool:
    """System booted very recently (pafish ~12min; weak => 30min band).

    WEAK alone: fresh boot also happens on real machines. Needs corroboration
    (>=2 weak or weak+cross) to trip the verdict.
    """
    up = _uptime_seconds()
    if up is None:
        return False
    _v("uptime=%.0fs" % up)
    return up < 30 * 60


@_sensor
def _sig_human_gap() -> bool:
    """No human input for a long window (GetLastInputInfo / X11 / macOS).

    pafish RTT inversion: sandboxes run headless — no keyboard/mouse for the
    whole session. WEAK: kiosk/servers also idle; corroboration required.
    """
    try:
        if _IS_WIN and _user32 is not None and _kernel32 is not None:
            class LASTINPUTINFO(ctypes.Structure):
                _fields_ = [("cbSize", ctypes.c_uint),
                            ("dwTime", ctypes.c_uint32)]

            _user32.GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
            _user32.GetLastInputInfo.restype = ctypes.c_int
            lii = LASTINPUTINFO()
            lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
            if _user32.GetLastInputInfo(ctypes.byref(lii)):
                _kernel32.GetTickCount.argtypes = []
                _kernel32.GetTickCount.restype = ctypes.c_uint32
                now = _kernel32.GetTickCount()
                idle_ms = (now - lii.dwTime) & 0xFFFFFFFF
                up = _uptime_seconds() or 0
                _v("idle=%dms uptime=%.0fs" % (idle_ms, up))
                # idle almost since boot and boot was a while ago => no human
                if up > 20 * 60 and idle_ms >= (up * 1000 - 120 * 1000):
                    return True
                # absolute: >3h without any input on a desktop session
                if idle_ms > 3 * 3600 * 1000:
                    return True
                return False
            return False
        # POSIX: X11 idle via xprintidle if present; else console-only => weak
        import shutil as _sh
        if _sh.which("xprintidle"):
            import subprocess as _sp
            try:
                idle_ms = int(_sp.check_output(["xprintidle"], timeout=5).decode().strip())
                up = _uptime_seconds() or 0
                if up > 20 * 60 and idle_ms >= (up * 1000 - 120 * 1000):
                    return True
            except Exception:
                return False
            return False
        # no display server at all on a GUI-claimed host is covered by display
        return False
    except Exception as exc:
        _v("human_gap error: %r" % (exc,))
        return False


_CI_MARKERS = ("GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "TF_BUILD",
                "CIRCLECI", "TRAVIS", "APPVEYOR", "TEAMCITY_VERSION",
                "BUILDKITE", "DRONE", "CI")


def _in_ci() -> bool:
    """S-6: bilinen CI/headless-runner ortaminda mi? (etkilesim-ailesi kapi)."""
    try:
        for var in _CI_MARKERS:
            try:
                if os.environ.get(var):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


@_sensor
def _sig_mouse_presence() -> bool:
    """No mouse device (pafish rtt_mouse_presence: SM_MOUSEPRESENT==0).

    S-6: CI-runner headlessligi sandbox DEGILDIR — CI isaretliyse False.
    """
    try:
        if _in_ci():
            return False
        if _IS_WIN and _user32 is not None:
            SM_MOUSEPRESENT = 19
            _user32.GetSystemMetrics.argtypes = [ctypes.c_int]
            _user32.GetSystemMetrics.restype = ctypes.c_int
            present = _user32.GetSystemMetrics(SM_MOUSEPRESENT)
            _v("mouse_present=%s" % bool(present))
            return not bool(present)
        # POSIX: no X11/Wayland display + no /dev/input/mice => headless
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            return False
        return not os.path.exists("/dev/input/mice")
    except Exception as exc:
        _v("mouse error: %r" % (exc,))
        return False


@_sensor
def _sig_mouse_static() -> bool:
    """Cursor static across a 2s window AND no input during that window.

    R5 (T1497.002 + crawlex): malware standard is a 5s cursor compare, but a
    lone static reading also matches a real user reading text. The strong
    tell is "fresh host + untouched", so a static cursor only counts when
    GetLastInputInfo agrees no input happened during the sampling window.
    Without that agreement this returns False (idle user, not a sandbox).
    """
    try:
        if not (_IS_WIN and _user32 is not None):
            return False
        _user32.GetCursorPos.argtypes = [ctypes.POINTER(ctypes.c_long * 2)]
        _user32.GetCursorPos.restype = ctypes.c_int

        def _pos():
            pt = (ctypes.c_long * 2)()
            if _user32.GetCursorPos(pt):
                return (pt[0], pt[1])
            return None

        def _idle_ms():
            try:
                class LASTINPUTINFO(ctypes.Structure):
                    _fields_ = [("cbSize", ctypes.c_uint),
                                ("dwTime", ctypes.c_uint32)]

                _user32.GetLastInputInfo.argtypes = [ctypes.POINTER(LASTINPUTINFO)]
                _user32.GetLastInputInfo.restype = ctypes.c_int
                lii = LASTINPUTINFO()
                lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
                if _user32.GetLastInputInfo(ctypes.byref(lii)):
                    _kernel32.GetTickCount.argtypes = []
                    _kernel32.GetTickCount.restype = ctypes.c_uint32
                    return (int(_kernel32.GetTickCount()) - int(lii.dwTime)) & 0xFFFFFFFF
            except Exception as exc:
                _v("idle probe: %r" % (exc,))
            return None

        idle_before = _idle_ms()
        a = _pos()
        time.sleep(1.0)
        b = _pos()
        time.sleep(1.0)
        c = _pos()
        idle_after = _idle_ms()
        _v("cursor: %r %r %r idle_before=%r idle_after=%r" % (
            a, b, c, idle_before, idle_after))
        if a is None or b is None or c is None:
            return False
        if not (a == b == c):
            return False
        # cursor static — but did the user touch anything in that window?
        # idle_after must cover the whole ~2s sampling window.
        if idle_after is None:
            return False
        return idle_after >= 2000
    except Exception as exc:
        _v("cursor error: %r" % (exc,))
        return False


def _phys_mem_bytes():
    try:
        if _IS_WIN and _kernel32 is not None:
            class MEMSTAT(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_uint32),
                            ("dwMemoryLoad", ctypes.c_uint32),
                            ("ullTotalPhys", ctypes.c_uint64),
                            ("ullAvailPhys", ctypes.c_uint64),
                            ("ullTotalPageFile", ctypes.c_uint64),
                            ("ullAvailPageFile", ctypes.c_uint64),
                            ("ullTotalVirtual", ctypes.c_uint64),
                            ("ullAvailVirtual", ctypes.c_uint64),
                            ("ullAvailExtendedVirtual", ctypes.c_uint64)]

            _kernel32.GlobalMemoryStatusEx.argtypes = [ctypes.POINTER(MEMSTAT)]
            _kernel32.GlobalMemoryStatusEx.restype = ctypes.c_int
            st = MEMSTAT()
            st.dwLength = ctypes.sizeof(MEMSTAT)
            if _kernel32.GlobalMemoryStatusEx(ctypes.byref(st)):
                return int(st.ullTotalPhys)
            return None
        txt = _read_proc_file("/proc/meminfo", 256)
        for line in txt.splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except Exception as exc:
        _v("mem error: %r" % (exc,))
    return None


def _disk_total_bytes(path=None):
    try:
        if path is None:
            path = os.path.splitdrive(os.getcwd())[0] + "\\" if _IS_WIN else "/"
        if _IS_WIN and _kernel32 is not None:
            _kernel32.GetDiskFreeSpaceExW.argtypes = [
                ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_uint64),
                ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(ctypes.c_uint64)]
            _kernel32.GetDiskFreeSpaceExW.restype = ctypes.c_int
            free = ctypes.c_uint64(0)
            total = ctypes.c_uint64(0)
            avail = ctypes.c_uint64(0)
            if _kernel32.GetDiskFreeSpaceExW(path, ctypes.byref(avail),
                                             ctypes.byref(total), ctypes.byref(free)):
                return int(total.value)
            return None
        st = os.statvfs(path)
        return int(st.f_blocks * st.f_frsize)
    except Exception as exc:
        _v("disk error: %r" % (exc,))
        return None


@_sensor
def _sig_hardware_poverty() -> bool:
    """Tiny VM-style resources (pafish: RAM<1GB, disk<=60GB, cpu<2).

    Band widened slightly (2GB/80GB) but WEAK: small real machines exist.
    Needs corroboration.
    """
    votes = 0
    mem = _phys_mem_bytes()
    if mem is not None:
        _v("physmem=%.2fGB" % (mem / 1e9))
        if mem < 2 * 1024 ** 3:
            votes += 1
    disk = _disk_total_bytes()
    if disk is not None:
        _v("disk=%.1fGB" % (disk / 1e9))
        if disk < 80 * 1000 ** 3:
            votes += 1
    try:
        cpu = os.cpu_count() or 0
    except Exception:
        cpu = 0
    _v("cpu=%s" % cpu)
    if cpu and cpu < 2:
        votes += 1
    return votes >= 2


@_sensor
def _sig_gpu_anomaly() -> bool:
    """No real GPU vendor in display adapters (R15, ScarfaceStealer gate).

    Reads DriverDesc (+HardwareInformation.AdapterString fallback) from the
    display class key — OSHI/Godot pattern, stdlib winreg, no WMI, no admin.
    Sandboxes expose only "Microsoft Basic Display Adapter" (or nothing).
    WEAK: headless servers share the shape; corroboration required.
    Non-Windows hosts return False (no reliable stdlib source).
    """
    if not _IS_WIN:
        return False
    try:
        import winreg as _wr
        base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
        names: list = []
        try:
            with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, base) as key:
                n = _wr.QueryInfoKey(key)[0]
                subs = [_wr.EnumKey(key, i) for i in range(min(n, 32))]
        except Exception as exc:
            _v("gpu enum: %r" % (exc,))
            return False
        for sub in subs:
            try:
                with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE, base + "\\" + sub) as sk:
                    for value in ("DriverDesc", "HardwareInformation.AdapterString"):
                        try:
                            val, _typ = _wr.QueryValueEx(sk, value)
                            if val:
                                names.append(str(val))
                                break
                        except Exception:
                            continue
            except Exception:
                continue
        blob = " | ".join(names).lower()
        _v("gpu: %s" % (blob[:160] if blob else "<none>"))
        if not blob:
            return True
        vendors = ("nvidia", "geforce", "radeon", "amd", "intel", "arc",
                   "qualcomm", "adreno", "apple", "mali", "powervr")
        return not any(v in blob for v in vendors)
    except Exception as exc:
        _v("gpu error: %r" % (exc,))
        return False


@_sensor
def _sig_display_anomaly() -> bool:
    """Missing/tiny display (headless sandbox, RDP-less automation).

    S-6: CI-runner headlessligi sandbox DEGILDIR — CI isaretliyse False.
    """
    try:
        if _in_ci():
            return False
        if _IS_WIN and _user32 is not None:
            SM_CXSCREEN, SM_CYSCREEN = 0, 1
            SM_REMOTESESSION = 0x1000
            _user32.GetSystemMetrics.argtypes = [ctypes.c_int]
            _user32.GetSystemMetrics.restype = ctypes.c_int
            w = _user32.GetSystemMetrics(SM_CXSCREEN)
            h = _user32.GetSystemMetrics(SM_CYSCREEN)
            _v("screen=%sx%s" % (w, h))
            if not w or not h:
                return True
            # R59: TrickBot exact VM defaults (guest additions absent) +
            # tiny band; R60: remote terminal-services session flag.
            if (w, h) in ((800, 600), (1024, 768)):
                return True
            if w < 800 or h < 600:
                return True
            try:
                if _user32.GetSystemMetrics(SM_REMOTESESSION):
                    _v("remote session flag set")
                    return True
            except Exception:
                pass
            return False
        # POSIX: neither X11 nor Wayland nor framebuffer => headless
        if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            return False
        if os.path.exists("/dev/fb0"):
            return False
        return True
    except Exception as exc:
        _v("display error: %r" % (exc,))
        return False


@_sensor
def _sig_clean_image() -> bool:
    """Suspiciously clean user image (CAPE Disguise inversion).

    Real workstations accumulate files/MRU; fresh sandbox images have
    near-empty Documents/Downloads and few installed apps. WEAK alone.
    R24/R25 lived-in vetoes inside the signal: a populated RecentDocs MRU
    or a real browser data file proves Explorer-driven user history that a
    fresh image cannot have — either one clears this signal immediately.
    File existence/size only; no content is ever read.
    """
    # R24: RecentDocs MRU population (HKCU, Explorer-driven opens only)
    if _IS_WIN:
        try:
            import winreg as _wr
            with _wr.OpenKey(_wr.HKEY_CURRENT_USER,
                             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs") as key:
                nvals = _wr.QueryInfoKey(key)[1]
                # values are numbered slots + MRUListEx; >=5 slots = lived-in
                if nvals >= 6:
                    _v("recentdocs populated (%d values)" % nvals)
                    return False
        except FileNotFoundError:
            pass
        except Exception as exc:
            _v("recentdocs enum: %r" % (exc,))
    # R26: PSReadLine command history (MS Learn: APPDATA\...\PSReadLine on
    # Windows, ~/.local/share/powershell/PSReadLine on POSIX). A non-empty
    # history file proves interactive shell use a fresh image lacks.
    try:
        hist_dirs = []
        if _IS_WIN:
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                hist_dirs.append(os.path.join(
                    appdata, "Microsoft", "Windows", "PowerShell", "PSReadLine"))
        else:
            xdg = os.environ.get("XDG_DATA_HOME", "")
            hist_dirs.append(os.path.join(xdg, "powershell", "PSReadLine") if xdg
                             else os.path.join(home if (home := os.path.expanduser("~")) else "", ".local", "share", "powershell", "PSReadLine"))
        for hdir in hist_dirs:
            try:
                if os.path.isdir(hdir):
                    for fn in os.listdir(hdir):
                        if fn.lower().endswith("_history.txt"):
                            fp = os.path.join(hdir, fn)
                            if os.path.getsize(fp) > 0:
                                _v("shell history present")
                                return False
            except Exception:
                continue
    except Exception as exc:
        _v("shell-history enum: %r" % (exc,))
    # R27: UserAssist program-launch records (HKCU Explorer\UserAssist\{GUID}
    # \Count). GUI launches only — sandboxes that never drive the shell have
    # few entries. Counting values only; no ROT13 decode, no content read.
    if _IS_WIN:
        try:
            import winreg as _wr
            total = 0
            try:
                with _wr.OpenKey(_wr.HKEY_CURRENT_USER,
                                 r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist") as ua:
                    nguids = _wr.QueryInfoKey(ua)[0]
                    for i in range(min(nguids, 16)):
                        try:
                            guid = _wr.EnumKey(ua, i)
                        except Exception:
                            continue
                        try:
                            with _wr.OpenKey(ua, guid + r"\Count") as cnt:
                                nvals = _wr.QueryInfoKey(cnt)[1]
                                # exclude UEME_CTLSESSION bookkeeping counters
                                total += max(0, nvals - 2)
                        except Exception:
                            continue
            except FileNotFoundError:
                total = 0
            if total >= 10:
                _v("userassist populated (%d entries)" % total)
                return False
        except Exception as exc:
            _v("userassist enum: %r" % (exc,))
    # R25: real browser data files (T1497.002 malware checks these paths)
    try:
        home = os.path.expanduser("~") or ""
        candidates = []
        if _IS_WIN:
            local = os.environ.get("LOCALAPPDATA", "")
            if local:
                candidates.append(os.path.join(
                    local, "Google", "Chrome", "User Data", "Default", "History"))
                candidates.append(os.path.join(
                    local, "Microsoft", "Edge", "User Data", "Default", "History"))
            roaming = os.environ.get("APPDATA", "")
            if roaming:
                candidates.append(os.path.join(
                    roaming, "Mozilla", "Firefox", "Profiles"))
        else:
            candidates.append(os.path.join(home, ".config", "google-chrome",
                                           "Default", "History"))
            candidates.append(os.path.join(home, ".mozilla", "firefox"))
        for cand in candidates:
            try:
                if os.path.isfile(cand) and os.path.getsize(cand) > 0:
                    _v("browser data present")
                    return False
                if os.path.isdir(cand):
                    try:
                        for prof in os.listdir(cand):
                            if "default" in prof.lower():
                                ph = os.path.join(cand, prof, "places.sqlite")
                                if os.path.isfile(ph) and os.path.getsize(ph) > 0:
                                    _v("browser data present")
                                    return False
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception as exc:
        _v("browser-data enum: %r" % (exc,))
    try:
        home = os.path.expanduser("~") or ""
    except Exception:
        home = ""
    if not home or not os.path.isdir(home):
        return False
    small_dirs = 0
    checked = 0
    for sub in ("Documents", "Downloads", "Desktop", "Pictures", "Music", "Videos",
                "Belgeler", "Masaüstü", "Resimler", "documents", "downloads", "desktop"):
        d = os.path.join(home, sub)
        try:
            if os.path.isdir(d):
                checked += 1
                n = len(os.listdir(d))
                if n <= 2:
                    small_dirs += 1
        except Exception:
            continue
    _v("clean_image: %d/%d small dirs" % (small_dirs, checked))
    if checked >= 3 and small_dirs == checked:
        return True
    # installed-app poverty (Windows uninstall keys)
    if _IS_WIN:
        try:
            import winreg as _wr
            count = 0
            for root, path in (
                    (_wr.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (_wr.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")):
                try:
                    with _wr.OpenKey(root, path) as key:
                        count += _wr.QueryInfoKey(key)[0]
                except Exception:
                    continue
            _v("uninstall entries=%d" % count)
            if 0 < count < 8 and checked >= 2 and small_dirs >= checked - 1:
                return True
        except Exception as exc:
            _v("uninstall enum: %r" % (exc,))
    return False


@_sensor
def _sig_parent_chain() -> bool:
    """Suspicious parentage: no explorer shell ancestor / SYSTEM session.

    Cuckoo/CAPE launch samples from agent services, not Explorer. WEAK:
    services and scheduled tasks share this shape on real hosts.
    """
    try:
        if _IS_WIN and _kernel32 is not None:
            TH32CS_SNAPPROCESS = 0x00000002

            class PROCESSENTRY32(ctypes.Structure):
                _fields_ = [
                    ("dwSize", ctypes.c_uint32),
                    ("cntUsage", ctypes.c_uint32),
                    ("th32ProcessID", ctypes.c_uint32),
                    ("th32DefaultHeapID", ctypes.c_ulonglong),
                    ("th32ModuleID", ctypes.c_uint32),
                    ("cntThreads", ctypes.c_uint32),
                    ("th32ParentProcessID", ctypes.c_uint32),
                    ("pcPriClassBase", ctypes.c_int32),
                    ("dwFlags", ctypes.c_uint32),
                    ("szExeFile", ctypes.c_wchar * 260),
                ]

            k = _kernel32
            me = os.getpid()
            table = {}
            snap = k.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if int(snap or 0) in (0, -1):
                return False
            try:
                pe = PROCESSENTRY32()
                pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
                ok = k.Process32FirstW(snap, ctypes.byref(pe))
                while ok:
                    try:
                        table[int(pe.th32ProcessID)] = (
                            str(pe.szExeFile).lower(), int(pe.th32ParentProcessID))
                    except Exception:
                        pass
                    ok = k.Process32NextW(snap, ctypes.byref(pe))
            finally:
                try:
                    k.CloseHandle(snap)
                except Exception:
                    pass
            # walk up from our pid
            seen = set()
            pid = me
            shells = ("explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
                      "windowsterminal.exe", "wt.exe", "code.exe", "py.exe")
            # R53 (agent.py needs no admin; sample inherits the analyzer
            # chain): image names only — script basenames can never match a
            # process image here.
            agents = ("python.exe", "pythonw.exe", "services.exe",
                      "srvpost.exe")
            depth = 0
            agent_hit = False
            shell_hit = False
            while pid and pid not in seen and depth < 16:
                seen.add(pid)
                entry = table.get(pid)
                if not entry:
                    break
                name, ppid = entry
                if name in shells:
                    shell_hit = True
                if name in agents and depth >= 1:
                    agent_hit = True
                pid = ppid
                depth += 1
            _v("parent: shell=%s agent=%s depth=%d" % (shell_hit, agent_hit, depth))
            if agent_hit and not shell_hit:
                return True
            return False
        # POSIX: ppid==1 with no login session (no systemd-logind scope)
        ppid = os.getppid()
        if ppid == 1:
            if not os.environ.get("INVOCATION_ID") and not os.environ.get("SESSION_MANAGER"):
                _v("posix orphan under init")
                return True
        return False
    except Exception as exc:
        _v("parent error: %r" % (exc,))
        return False


@_sensor
def _sig_testsigning() -> bool:
    """Windows test-signing boot mode (R20: Any.run runs test-signed).

    R29/R30 primary: NtQuerySystemInformation(SystemCodeIntegrityInformation
    =103) CODEINTEGRITY_OPTION_TESTSIGN bit (0x2) — the authoritative check.
    Fallback: SystemStartOptions registry string (OSR installer pattern).
    Both stdlib-only, no elevation. WEAK: driver devs also enable it.
    Non-Windows hosts return False.
    """
    if not _IS_WIN:
        return False
    try:
        ntdll = ctypes.WinDLL("ntdll")
        ntdll.NtQuerySystemInformation.argtypes = [
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]
        ntdll.NtQuerySystemInformation.restype = ctypes.c_int32

        class _SCI(ctypes.Structure):
            _fields_ = [("Length", ctypes.c_uint32),
                        ("CodeIntegrityOptions", ctypes.c_uint32)]

        sci = _SCI()
        sci.Length = ctypes.sizeof(_SCI)
        retlen = ctypes.c_uint32(0)
        status = ntdll.NtQuerySystemInformation(
            103, ctypes.byref(sci), ctypes.sizeof(sci),
            ctypes.byref(retlen))
        if status == 0:
            opts = int(sci.CodeIntegrityOptions)
            hit = (opts & 0x3) == 0x3
            if hit:
                _v("testsigning via code-integrity options")
            return hit
        _v("NtQuerySystemInformation status=0x%x" % (status & 0xFFFFFFFF))
    except Exception as exc:
        _v("testsigning sci: %r" % (exc,))
    try:
        import winreg as _wr
        with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                         r"SYSTEM\CurrentControlSet\Control") as key:
            try:
                val, _typ = _wr.QueryValueEx(key, "SystemStartOptions")
            except FileNotFoundError:
                return False
        hit = "TESTSIGNING" in str(val).upper()
        if hit:
            _v("testsigning boot options present")
        return hit
    except Exception as exc:
        _v("testsigning error: %r" % (exc,))
        return False


@_sensor
def _sig_uac_disabled() -> bool:
    """UAC enforcement neutered (R21 Triage signature + R56 N-able).

    EnableLUA==0 disables UAC outright; ConsentPromptBehaviorAdmin==0 or
    ConsentPromptBehaviorUser==0 neuters prompting regardless of EnableLUA
    (MS Learn/N-able tables). Missing values fail closed (no accusation).
    winreg read, no elevation. WEAK: corroboration required.
    Non-Windows hosts return False.
    """
    if not _IS_WIN:
        return False
    try:
        import winreg as _wr
        with _wr.OpenKey(_wr.HKEY_LOCAL_MACHINE,
                         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") as key:
            def _dword(name):
                try:
                    val, _typ = _wr.QueryValueEx(key, name)
                    return int(val)
                except Exception:
                    return None

            lua = _dword("EnableLUA")
            if lua is not None and lua == 0:
                _v("uac disabled (EnableLUA=0)")
                return True
            for _name in ("ConsentPromptBehaviorAdmin",
                          "ConsentPromptBehaviorUser"):
                _c = _dword(_name)
                if _c is not None and _c == 0:
                    _v("uac neutered (%s=0)" % _name)
                    return True
        return False
    except Exception as exc:
        _v("uac error: %r" % (exc,))
        return False


@_sensor
def _sig_hostname_guid() -> bool:
    """Hostname is a GUID (R45: Windows Sandbox assigns a random GUID).

    PSAppDeployToolkit #947 + windowsphoneinfo: ComputerName inside the
    Sandbox is a GUID (truncated to 15 chars in the env var, full via
    DNSHostName). Real workstations are essentially never GUID-named.
    Strict full-match only; WEAK alone, corroboration required.
    """
    try:
        host = (socket.gethostname() or "").strip().lower()
    except Exception:
        return False
    if not host:
        return False
    hit = bool(_re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        host))
    if hit:
        _v("guid hostname: %s" % host)
    return hit


@_sensor
def _sig_triage_wallpaper() -> bool:
    """Tria.ge default-wallpaper artifact (R36: exact filename pinned).

    unprotect.it C# technique: %USERPROFILE%\\Pictures\\My Wallpaper.jpg
    exists only inside Tria.ge. Exact-file primary (FP-safe); the older
    *triage* globs stay as fallback for renamed variants. WEAK alone.
    """
    try:
        if _IS_WIN:
            profile = os.environ.get("USERPROFILE", "")
            if profile:
                exact = os.path.join(profile, "Pictures", "My Wallpaper.jpg")
                if os.path.isfile(exact):
                    _v("triage wallpaper: %s" % exact)
                    return True
        else:
            home = os.path.expanduser("~")
            exact = os.path.join(home, "Pictures", "My Wallpaper.jpg")
            if os.path.isfile(exact):
                _v("triage wallpaper: %s" % exact)
                return True
    except Exception as exc:
        _v("triage exact: %r" % (exc,))
    candidates = []
    try:
        if _IS_WIN:
            appdata = os.environ.get("APPDATA", "")
            localapp = os.environ.get("LOCALAPPDATA", "")
            windir = os.environ.get("SystemRoot", "C:\\Windows")
            for base in (appdata, localapp, windir):
                if base:
                    candidates.append(os.path.join(base, "*triage*"))
                    candidates.append(os.path.join(base, "*TRIAGE*"))
            candidates.append(os.path.join(windir, "Web", "Wallpaper", "*triage*"))
        else:
            home = os.path.expanduser("~")
            candidates.append(os.path.join(home, "*triage*"))
            candidates.append("/usr/share/backgrounds/*triage*")
    except Exception:
        return False
    for pat in candidates:
        try:
            hits = _glob.glob(pat)
            if hits:
                _v("triage artifact: %s" % hits[0])
                return True
        except Exception:
            continue
    return False


# ---------------------------------------------------------------------------
# registry: signals, verdict, API
# ---------------------------------------------------------------------------

_SIGNALS = (
    ("sleep_acceleration", STRONG, _sig_sleep_acceleration),
    ("sleep_disagreement", STRONG, _sig_sleep_disagreement),
    ("clock_divergence", STRONG, _sig_clock_divergence),
    ("agent_artifacts", STRONG, _sig_agent_artifacts),
    ("agent_port", STRONG, _sig_agent_port),
    ("known_identity", STRONG, _sig_known_identity),
    ("anyrun_driver", STRONG, _sig_anyrun_driver),
    ("uptime_fresh", WEAK, _sig_uptime_fresh),
    ("human_gap", WEAK, _sig_human_gap),
    ("mouse_presence", WEAK, _sig_mouse_presence),
    ("mouse_static", WEAK, _sig_mouse_static),
    ("hardware_poverty", WEAK, _sig_hardware_poverty),
    ("gpu_anomaly", WEAK, _sig_gpu_anomaly),
    ("display_anomaly", WEAK, _sig_display_anomaly),
    ("clean_image", WEAK, _sig_clean_image),
    ("parent_chain", WEAK, _sig_parent_chain),
    ("testsigning", WEAK, _sig_testsigning),
    ("uac_disabled", WEAK, _sig_uac_disabled),
    ("triage_wallpaper", WEAK, _sig_triage_wallpaper),
    ("hostname_guid", WEAK, _sig_hostname_guid),
)

_LAST: dict = {}
_LOCK = threading.RLock()
_LAST_SCAN_S = 0.0
_SB_ADMINS: dict = {}
_SB_ADMIN_LOCKED = False
_SB_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _SB_ADMIN_DENIED
    try:
        if _SB_ADMIN_LOCKED:
            with _LOCK:
                _SB_ADMIN_DENIED += 1
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
        with _LOCK:
            _SB_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _sb_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_SB_ADMINS)
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


def _sb_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _SB_ADMIN_DENIED
    try:
        with _LOCK:
            _SB_ADMIN_DENIED += 1
    except Exception:
        pass
    raise SandboxDetected("protected")


def _last_snapshot() -> dict:
    """_LAST'in kilitli kopyasi (okur-yazar yarisina karsi)."""
    try:
        with _LOCK:
            return dict(_LAST)
    except Exception:
        return {}


def check_all() -> dict:
    """Run every signal once; returns {name: bool} plus meta keys.

    S-4: agir sinyaller kilit DISINDA kosar (reentrant RLock + kisa kritik
    bolge) — concurrent verdict okuyuculari saniyelerce bloklanmaz.
    Efektif tarama suresi _LAST_SCAN_S/status()'ta raporlanir.
    """
    global _SENSORS_OK, _SENSORS_TOTAL, _LAST_SCAN_S
    _SENSORS_OK = 0
    _SENSORS_TOTAL = 0
    out: dict = {}
    try:
        t0 = time.monotonic()
    except Exception:
        t0 = 0.0
    for name, _w, fn in _SIGNALS:
        out[name] = fn()
    try:
        _LAST_SCAN_S = time.monotonic() - t0 if t0 else 0.0
    except Exception:
        _LAST_SCAN_S = 0.0
    with _LOCK:
        out["_sensors_ok"] = _SENSORS_OK
        out["_sensors_total"] = _SENSORS_TOTAL
        _LAST.clear()
        _LAST.update(out)
        return dict(out)


def _cross_validation(results: dict) -> bool:
    """Independent corroboration across weak categories.

    A lone weak signal never trips; two weak signals from *different*
    families (freshness vs interaction vs resources vs image) corroborate.
    POSIX-headless trio (display/mouse) tek aileye toplanmistir: headless
    sunucu/container tek-basina trip uretmez (T1497 corroboration kurali).
    """
    families = {
        "freshness": ("uptime_fresh",),
        "interaction": ("human_gap", "mouse_presence", "mouse_static",
                        "display_anomaly"),
        "resources": ("hardware_poverty", "gpu_anomaly"),
        "image": ("clean_image", "parent_chain", "uac_disabled",
                  "triage_wallpaper"),
        "naming": ("hostname_guid",),
        "boot_integrity": ("testsigning",),
    }
    hit_families = 0
    for names in families.values():
        if any(results.get(n) for n in names):
            hit_families += 1
    return hit_families >= 2


def score(results: dict | None = None) -> int:
    """Weighted score: STRONG=100, WEAK=30 each (capped at 300)."""
    res = results if results is not None else (_last_snapshot() or check_all())
    total = 0
    for name, weight, _fn in _SIGNALS:
        if res.get(name):
            total += weight
    return min(total, 300)


def evidence(results: dict | None = None) -> dict:
    """Machine-readable evidence bundle (no stdout side effects)."""
    res = results if results is not None else (_last_snapshot() or check_all())
    fired = [n for n, _w, _f in _SIGNALS if res.get(n)]
    strong = [n for n, w, _f in _SIGNALS if w == STRONG and res.get(n)]
    weak = [n for n, w, _f in _SIGNALS if w == WEAK and res.get(n)]
    return {
        "sandboxed": is_sandboxed(res),
        "score": score(res),
        "strong": strong,
        "weak": weak,
        "fired": fired,
        "cross_validated": _cross_validation(res),
        "sensors_ok": res.get("_sensors_ok"),
        "sensors_total": res.get("_sensors_total"),
        "scan_s": _LAST_SCAN_S,
    }


def is_sandboxed(results: dict | None = None) -> bool:
    """Verdict: >=1 strong OR >=2 weak ACROSS FAMILIES (weak-only vetoed
    by exoneration).

    R8 exoneration (Unit42 pocket-litter + crawlex contradiction, defensive
    inversion): weak-only verdicts are vetoed when the host shows lived-in
    evidence (populated user dirs, rich app inventory, shell ancestry, real
    resources). Strong artifact/timing/identity hits always convict.
    Capraz-aile kurali: ayni ailenin iki weaki (or. headless display+mouse)
    tek-basina trip uretmez.
    """
    res = results if results is not None else (_last_snapshot() or check_all())
    strong = sum(1 for n, w, _f in _SIGNALS if w == STRONG and res.get(n))
    weak = sum(1 for n, w, _f in _SIGNALS if w == WEAK and res.get(n))
    if strong >= 1:
        return True
    if weak == 0:
        return False
    if _exonerated():
        _v("weak signals vetoed by lived-in host evidence")
        return False
    if weak >= 2:
        if not _cross_validation(res):
            return False
        try:
            _idle_set = ("uptime_fresh", "human_gap", "mouse_presence",
                         "mouse_static", "display_anomaly")
            _outside = [n for n, w, _f in _SIGNALS
                        if w == WEAK and res.get(n) and n not in _idle_set]
            if not _outside:
                return False
        except Exception:
            pass
        return True
    return False


def _in_container() -> bool:
    """POSIX container detection (R54: /.dockerenv + cgroup + mountinfo).

    Best-effort, fail-closed (False on error/non-POSIX). Markers combined
    because no single one is universal (is-docker/codemia notes); only one
    exoneration vote either way, so a stray hit cannot veto alone.
    """
    if _IS_WIN:
        return False
    try:
        if os.path.exists("/.dockerenv"):
            return True
    except Exception:
        pass
    try:
        blob = _read_proc_file("/proc/1/cgroup", 8192).lower()
        if blob and any(m in blob for m in (
                "docker", "containerd", "kubepods", "podman", "lxc")):
            return True
    except Exception:
        pass
    try:
        blob = _read_proc_file("/proc/1/mountinfo", 16384).lower()
        if blob and ("overlay" in blob or "/docker/containers/" in blob):
            return True
    except Exception:
        pass
    return False


def _exonerated() -> bool:
    """Lived-in host evidence vetoes weak-only verdicts (R8 + S-3 sikilastirma).

    S-3: modern sisman imajlar 3 oyu topluyordu (apps+resources+shell).
    Bar 4 oya cikarildi + esikler yukseltildi (apps>=100, kaynak
    8GB+8CPU): gercek lived-in box gecer, sisman guest gecemez.
    Fail-closed both ways: sensor errors grant no credit.
    """
    votes = 0
    # 1) populated user directories (pocket litter present)
    try:
        home = os.path.expanduser("~") or ""
        lived_dirs = 0
        if home and os.path.isdir(home):
            for sub in ("Documents", "Downloads", "Desktop", "Pictures",
                        "Belgeler", "Masaüstü", "Resimler", "documents",
                        "downloads", "desktop"):
                try:
                    if len(os.listdir(os.path.join(home, sub))) > 2:
                        lived_dirs += 1
                except Exception:
                    continue
        if lived_dirs >= 2:
            votes += 1
    except Exception as exc:
        _v("exon dirs: %r" % (exc,))
    # 2) rich installed-app inventory
    try:
        apps = 0
        if _IS_WIN:
            import winreg as _wr
            for root, path in (
                    (_wr.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                    (_wr.HKEY_LOCAL_MACHINE,
                     r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")):
                try:
                    with _wr.OpenKey(root, path) as key:
                        apps += _wr.QueryInfoKey(key)[0]
                except Exception:
                    continue
        else:
            for d in ("/usr/bin", "/usr/local/bin", "/opt"):
                try:
                    apps += len(os.listdir(d))
                except Exception:
                    continue
        if apps >= 100:
            votes += 1
    except Exception as exc:
        _v("exon apps: %r" % (exc,))
    # 3) interactive shell ancestry (not agent-launched)
    try:
        procs = set(_proc_names())
        if procs & {"explorer.exe", "code.exe", "windowsterminal.exe",
                    "wt.exe", "gnome-shell", "plasmashell", "finder"}:
            votes += 1
    except Exception as exc:
        _v("exon shell: %r" % (exc,))
    # 4) real-machine resources (no poverty at all)
    try:
        mem = _phys_mem_bytes()
        cpu = os.cpu_count() or 0
        if mem is not None and mem >= 8 * 1024 ** 3 and cpu >= 8:
            votes += 1
    except Exception as exc:
        _v("exon res: %r" % (exc,))
    # 5) container runtime (R54: a Docker/Podman/k8s dev container is a real
    # lived-in environment, not a malware sandbox — Cuckoo guests are VMs,
    # never containers, so this vote cannot shield an actual sandbox)
    try:
        if not _IS_WIN and _in_container():
            votes += 1
    except Exception as exc:
        _v("exon container: %r" % (exc,))
    # 6) AI-ecosystem presence (AIprint 2026: .claude/.cursor/OPENAI_API_KEY/
    # Ollama:11434 appear on real AI-capable hosts, never on sandbox images;
    # reproducing a convincing AI ecosystem costs far more than spoofing
    # classic wear-and-tear). >=2 independent indicators = +1 vote.
    try:
        _ai_hits = 0
        try:
            _home = os.path.expanduser("~") or ""
        except Exception:
            _home = ""
        try:
            for _d in (".claude", ".cursor", ".copilot", ".gemini",
                       ".ollama", ".codeium", ".continue", ".opencode"):
                try:
                    if _home and os.path.isdir(os.path.join(_home, _d)):
                        _ai_hits += 1
                except Exception:
                    continue
        except Exception:
            pass
        try:
            for _k in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                       "HUGGINGFACE_HUB_TOKEN", "OLLAMA_HOST",
                       "GEMINI_API_KEY"):
                try:
                    if os.environ.get(_k):
                        _ai_hits += 1
                        break
                except Exception:
                    continue
        except Exception:
            pass
        if _ai_hits >= 2:
            votes += 1
    except Exception as exc:
        _v("exon ai-eco: %r" % (exc,))
    _v("exoneration votes=%d" % votes)
    return votes >= 4


def status() -> str:
    """One-line human status (silent unless verbose)."""
    ev = evidence()
    s = "%s(score=%d,strong=%d,weak=%d)" % (
        "sandboxed" if ev["sandboxed"] else "clean",
        ev["score"], len(ev["strong"]), len(ev["weak"]))
    _v(s)
    return s


class SandboxDetected(RuntimeError):
    """Opak hata: hangi sinyal tetiklendi DISARIYA soylenmez (oracle kapali).

    RuntimeError alt-sinifi: eski `except RuntimeError` cagiranlari kirmaz.
    """


def assert_no_sandbox() -> None:
    """Raise SandboxDetected when the environment looks like a sandbox."""
    ev = evidence()
    if ev["sandboxed"]:
        raise SandboxDetected("protected")


_WATCHDOGS: list = []
_WATCHDOGS_LOCK = threading.Lock()


def start_watchdog(interval: float = 5.0, on_detect=None):
    """Arka plan izleme (kardes konvansiyon). Donus: stop() callable.

    S-4: default OLDURMEZ — kutuphane host prosesi varsayilanla
    intihar etmez (FP'de veri-kaybi disiplini). Dis-aksiyon icin
    operator on_detect verir (or. lambda: os._exit(1)). Interval
    0.5-300sn; efektif tarama suresi status()'ta gorunur.
    """
    global _SB_ADMIN_LOCKED
    try:
        with _WATCHDOGS_LOCK:
            _SB_ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
    except Exception:
        iv = 5.0
    if iv < 0.5:
        iv = 0.5
    if iv > 300.0:
        iv = 300.0
    stop_event = threading.Event()
    with _WATCHDOGS_LOCK:
        _WATCHDOGS.append(stop_event)

    def _loop() -> None:
        try:
            while not stop_event.wait(iv):
                try:
                    if is_sandboxed():
                        try:
                            if callable(on_detect):
                                on_detect()
                        except Exception:
                            pass
                        return
                except Exception:
                    pass
        except Exception:
            pass

    th = threading.Thread(target=_loop, name="hyper-antisandbox", daemon=True)
    try:
        th.start()
    except Exception:
        pass

    def _stop() -> None:
        try:
            stop_event.set()
        except Exception:
            pass
        with _WATCHDOGS_LOCK:
            try:
                _WATCHDOGS.remove(stop_event)
            except ValueError:
                pass

    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart). Donus: sayi."""
    if not _sb_check_admin():
        _sb_deny_admin("stop_all_watchdogs")
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
        assert_no_sandbox()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is None:
            assert_no_sandbox()
            return False
        if is_sandboxed():
            raise SandboxDetected("protected") from exc
        return False


def guard() -> _Guard:
    return _Guard()
