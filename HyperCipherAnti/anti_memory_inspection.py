# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiMemoryInspection (Stage 4)
=================================================
Entegre cok katmanli canli-memory inspection tespiti + korunakli-hucre API'si.
Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi:
  R1 Linux canli-okuma (man7 memfd_secret, cloudtaser attack-surface,
     systemshardening YAMA, securityscientist T1003.007/T1055.008, netacoding
     ptrace+prctl, DFRWS Volatility-Python): saldirgan (a) /proc/<pid>/mem
     dogrudan read, (b) ptrace ATTACH + PEEKDATA, (c) process_vm_readv,
     (d) /proc/<pid>/{maps,environ} kesif, (e) core-dump ile okur.
     Savunma katmani: PR_SET_DUMPABLE=0 (core yok + mem/maps/environ non-root'a
     kapanir + ATTACH reddi, YAMA'dan bagimsiz; OpenSSH 8.2+ ayni), YAMA
     ptrace_scope>=1, seccomp'ta ptrace/process_vm_readv blogu, MADV_DONTDUMP
     (core disi), MADV_DONTFORK (cocuk miras keser), mlock (swap disi),
     memfd_secret (5.14+, kernel-direct-map disi; bu hostta yoksa fallback).
     NOT: ptrace_scope=2 /proc/mem'i KAPATMAZ (dosya-izni yolu ayri);
     root CAP_SYS_PTRACE YAMA'yi bypaslar. Dokumante rezidu.
  R2 Windows canli-okuma (MS Learn NtQueryInformationProcess/MiniDumpWriteDump/
     VirtualQuery, checkpoint process-memory, secnews anti-debug, aquia PEB,
     bugcheck NtMapViewOfSection): saldirgan (a) OpenProcess+ReadProcessMemory,
     (b) MiniDumpWriteDump (PROCESS_QUERY_INFORMATION|PROCESS_VM_READ),
     (c) PEB BeingDebugged/NtGlobalFlag/heap bayraklari, (d) Dr0-3 hardware
     breakpoint, (e) PAGE_GUARD one-shot alarm, (f) IsDebuggerPresent yamasi
     ile okur. Savunma: BeingDebugged/DebugPort yoklamasi (tespit), Dr0-3
     taramasi (RtlCaptureContext/GetThreadContext), RWX private-anon taramasi
     (VirtualQuery; staged shellcode RW->RX iki-adimli izin degisimi yuksek
     fidelite), writable-IMAGE taramasi (yazilabilir kod = yama/enjeksiyon),
     guard'li hassas hucre (PAGE_GUARD degil; hassas hucre mprotect/VirtualLock
     + kullanim-disi NOACCESS penceresi). Saldirgan karsiligi: ScyllaHide PEB
     sifirlama + GetThreadContext hook + kernel hook (ring-0'da userspace
     kor). Dokumante rezidu.
  R3 Python ici gozetim (bpo-43439 gc audit, cyber.wtf py-spy/GC-walk, DFRWS
     PyGC_Head/GC-generations, PyMemoryExplorer _gc_head scan, tracemalloc
     docs, pithysecurity ctypes-shellcode): yorumlayici-ici saldirgan
     (a) gc.get_objects/get_referrers ile tum nesneleri gezer (bytes/str
     immutable KOPYA birakir; gc container-disi izlemez), (b) ctypes
     memmove/cast ile ham RAM okur, (c) tracemalloc/audit-hook ile tahsis
     izler, (d) py-spy ile disaridan frame/locals doker (GC-walk + interpreter
     state), (e) RWX ayirip PyCapsule/cast ile ayni-process calistirir
     (WriteProcessMemory YOK; sinyal RW->RX izidir). Savunma: hassas veri
     SADECE bytearray SecureCell'de (mlock + DONTDUMP + DONTFORK + kullanim-
     disi sifreli/kilitli pencere + scoped-view + anti-leak repr), gc-traversal
     denetimi (supheli tutamac sayisi), sys.gettrace/audit-hook denetimi,
     RWX taramasi, introspection-araci taramasi (/proc maps'te frida-agent,
     calisan surecte py-spy/strace ismi). Saldirgan karsiligi: ayni-UID
     GC-walk engellenemez (yorumlayici ozelligi); cozum maruziyeti kucultmektir
     (kisa-omur + wipe + kilit). Dokumante.

Entegrasyon prensibi: anti_dump crash-dump + dumper-process + swap-hijyeni,
anti_key_extraction erisim-hijyeni, anti_instrumentation DBI/thread,
BU modul canli-inspection (tracer + HW-BP + RWX + maps-posture + hucre).
HICBIR tek kontrole guvenme; best-effort; hata -> bilinmiyor (None);
True = risk, False = temiz. Mesaj OP AKTIR (hangi katman soylenmez).

DURUST SINIR (rezidu): root/CAP_SYS_PTRACE, kernel-modul taramasi, DMA/PCIe,
hypervisor fiziki gorunum, hibernation imaji, ayni-ayricalik tam-sahtecilik
(LD_PRELOAD open/read filtresi, ScyllaHide PEB/DR sifirlama, Frida hook),
setuid-disi YAMA=0 policy, memfd_secret yoklugu bu hostta. RX-split staging
(RW ayir + VirtualProtect->RX; hicbir-anda RWX yok) RWX-sinyaline gorunmez;
INT3/HW-BP'siz VEH+DR-kombosu sessiz kalabilir. Bu modul
firsatci + ayni-UID canli-okuma + yorumlayici-ici gozetimi kapsar.
  R4 QueryWorkingSetEx Shared-bit INT3 tespiti (waliedassar ShareCount trick,
     Midi12 ornegi, 0xPat malware-dev-3, NCC d-cow/Moneta): yazilamaz kod
     sayfalari tum process'lerde AYNI fiziki sayfayi paylasir; INT3 yazimi
     copy-on-write'i tetikler -> sayfa ozel kopyaya doner (Shared=0).
     Cozum: calistirilabilir committed bolgelerden ornek sayfalar al,
     QueryWorkingSetEx ile Shared bitini oku (Valid=1 sarti). HW-BP ve
     RX-split'i YAKALAMAZ (kod degismez) -> hw/rwx sinyalleri tamamlar.
     Saldirgan karsiligi: HW-BP/VEH kullanimi (paylasim bozulmaz); rezidu.
  R5 memfd_secret capability (man7 memfd_secret, LWN 865256, arkey.fr JVM
     rehberi): syscall 447 (x86_64/aarch64), glibc wrapper YOK -> libc.syscall
     ile; ENOSYS = cekirdek desteksiz ya da secretmem.enable=0 (5.14-6.4 boot
     flag; 6.5+ default-acik, CONFIG_SECRETMEM sart). Bu modul capability'yi
     SADECE raporlar (status()['memfd_secret']); hucre tasiyici degil
     (SecureCell mlock+DONTDUMP hattinda; tasiyici degisimi ayri is).
  R6 Ham-PEB caprazi (checkpoint debug-flags, exchangetuts PEB-ctypes,
     winappdbg _PEB_NT, NCC VEH arastirmasi): IsDebuggerPresent IAT-hook'u
     API donusunu sifirlayabilir; NtQueryInformationProcess(BasicInformation)
     + self ReadProcessMemory ile ham-okuma farkli yoldur (BeingDebugged +2,
     NtGlobalFlag +0xBC [0x70 maskesi], CrossProcessFlags +0x50 [0x4 = VEH]).
     Offsetler Win10/11-x64; surum-kirilganlik best-effort None ile karsilanir.
     VEH mesru-kullanimda da kurulur (CLR/slack/edge; NCC ornekleri) -> WEAK
     sinyal veh_flag (tek-basina tripsiz). ScyllaHide PEB-sifirlamaya karsi
     kor degildir (dokumante rezidu); bu yol API-hook katmanini kapatir.
  R7 ntdll-kapsamli CoW (NCC d-cow/Moneta, winsider LdrpCheckPagesForTampering,
     CAIN per-boot DLL paylasimi, MS Learn QueryWorkingSetEx): Windows ASLR
     DLL tabanlarini boot-basina bir kez secer (ntdll tum sureclerde AYNI
     fiziki sayfa); loader'in kendisi ayni biti okur (SharedOriginal, bit 30;
     Shared bit 15, Valid bit 0). KONTROL-A3: battaniye-ornekleme ASLR sonrasi
     ozel-sayfalari bayrakliyordu -> SADECE ntdll imaji (GetModuleHandleW +
     AllocationBase eslesmesi) + MEM_IMAGE + calistirilabilir + Valid=1;
     ates sarti Shared=0 VEYA SharedOriginal=0. NtGlobalFlag'de TAM 0x70 sarti
     (reverseengineering.app/aldeid/cocomelonc; tek-bit gflags/app-verifier
     mesru-kullanim olabilir). W4'te tasklist-subprocess kaldirildi (hizli +
     cocuk-surec yok); yerine Toolhelp32 snapshot + 5sn TTL cache (MS Learn +
     ActiveState/carcigenicate/synodriver ctypes desenleri).

Kullanim:
    from HyperCipherAnti import anti_memory_inspection as ami
    ami.harden()
    ami.assert_no_inspection()
    if ami.is_inspected(): ...
    with ami.SecureCell(secret) as view:
        use(bytes(view))
    stop = ami.start_watchdog(interval=1.0)
    stop()
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

__all__ = [
    "MemoryInspectionDetected",
    "is_inspected",
    "check_all",
    "assert_no_inspection",
    "harden",
    "secure_zero",
    "protect_bytes",
    "SecureCell",
    "enforce_undumpable",
    "enforce_no_core",
    "status",
    "score",
    "guard",
    "start_watchdog",
    "stop_all_watchdogs",
    "set_verbose",
    "health",
    "memfd_secret_available",
]


class MemoryInspectionDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


_VERBOSE = False


def set_verbose(on: bool = True) -> None:
    global _VERBOSE
    _VERBOSE = bool(on)


def _log(msg: str) -> None:
    if _VERBOSE:
        try:
            sys.stderr.write("[anti_memory_inspection] %s\n" % msg)
        except Exception:
            pass


def _fail() -> MemoryInspectionDetected:
    return MemoryInspectionDetected("protected")


_OS_NAME = os.name
_PLATFORM = sys.platform
_PID = os.getpid()
_TIME_MONO = time.monotonic

# ---------------------------------------------------------------------------
# Import-aninda pin'ler (sabit + canli capraz; TOCTOU degil, baseline)
# ---------------------------------------------------------------------------

_PIN_GETTRACE = sys.gettrace


def _live_pid() -> int:
    try:
        return os.getpid()
    except Exception:
        return _PID


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------

def _read_file(path: str, limit: int = 65536) -> Optional[bytes]:
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Native kilit (R22-mimari: tek recursive kilit; fork-cocuk kilit almaz)
# ---------------------------------------------------------------------------

_NATIVE_LOCK = threading.RLock()


def _with_native_lock(fn: Callable[[], object]) -> object:
    with _NATIVE_LOCK:
        return fn()


_LIBC = None
_K32 = None


def _libc():
    global _LIBC
    if _LIBC is not None:
        return _LIBC
    if _OS_NAME != "posix":
        return None
    for name in ("libc.so.6", "libc.so", "libSystem.dylib"):
        try:
            lib = ctypes.CDLL(name, use_errno=True)
            _LIBC = lib
            return lib
        except Exception:
            continue
    return None


def _k32():
    global _K32
    if _K32 is not None:
        return _K32
    if _OS_NAME != "nt":
        return None
    try:
        _K32 = ctypes.WinDLL("kernel32", use_last_error=True)
        return _K32
    except Exception:
        return None


def _mlock_bytes(buf: bytearray) -> bool:
    def _do():
        try:
            if _OS_NAME == "posix":
                lib = _libc()
                if lib is None:
                    return False
                cbuf = (ctypes.c_char * len(buf)).from_buffer(buf)
                addr = ctypes.addressof(cbuf)
                lib.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                lib.mlock.restype = ctypes.c_int
                return int(lib.mlock(ctypes.c_void_p(addr), len(buf))) == 0
            elif _OS_NAME == "nt":
                k32 = _k32()
                if k32 is None or not buf:
                    return False
                cbuf = (ctypes.c_char * len(buf)).from_buffer(buf)
                addr = ctypes.addressof(cbuf)
                try:
                    k32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    k32.VirtualLock.restype = ctypes.c_bool
                    return bool(k32.VirtualLock(ctypes.c_void_p(addr), len(buf)))
                except Exception:
                    return False
            return False
        except Exception:
            return False
    try:
        return bool(_with_native_lock(_do))
    except Exception:
        return False


def _munlock_bytes(buf: bytearray) -> None:
    def _do():
        try:
            if _OS_NAME == "posix":
                lib = _libc()
                if lib is None:
                    return
                cbuf = (ctypes.c_char * len(buf)).from_buffer(buf)
                addr = ctypes.addressof(cbuf)
                try:
                    lib.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    lib.munlock.restype = ctypes.c_int
                    lib.munlock(ctypes.c_void_p(addr), len(buf))
                except Exception:
                    pass
            elif _OS_NAME == "nt":
                k32 = _k32()
                if k32 is None or not buf:
                    return
                cbuf = (ctypes.c_char * len(buf)).from_buffer(buf)
                addr = ctypes.addressof(cbuf)
                try:
                    k32.VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                    k32.VirtualUnlock.restype = ctypes.c_bool
                    k32.VirtualUnlock(ctypes.c_void_p(addr), len(buf))
                except Exception:
                    pass
        except Exception:
            pass
    try:
        _with_native_lock(_do)
    except Exception:
        pass


def _madvise_no_dump_fork(buf: bytearray) -> None:
    """Linux: DONTDUMP + DONTFORK (best-effort; cikti sessiz)."""
    def _do():
        try:
            if _PLATFORM.startswith("linux") and buf:
                lib = _libc()
                if lib is None:
                    return
                cbuf = (ctypes.c_char * len(buf)).from_buffer(buf)
                addr = ctypes.addressof(cbuf)
                try:
                    lib.madvise.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
                    lib.madvise.restype = ctypes.c_int
                    lib.madvise(ctypes.c_void_p(addr), len(buf), 16)  # MADV_DONTDUMP
                    lib.madvise(ctypes.c_void_p(addr), len(buf), 10)  # MADV_DONTFORK
                except Exception:
                    pass
        except Exception:
            pass
    try:
        _with_native_lock(_do)
    except Exception:
        pass


def _secure_zero(buf: bytearray) -> None:
    def _do():
        try:
            if not buf:
                return
            cbuf = (ctypes.c_char * len(buf)).from_buffer(buf)
            addr = ctypes.addressof(cbuf)
            try:
                if _OS_NAME == "posix":
                    lib = _libc()
                    if lib is not None:
                        lib.memset.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]
                        lib.memset.restype = ctypes.c_void_p
                        lib.memset(ctypes.c_void_p(addr), 0, len(buf))
                elif _OS_NAME == "nt":
                    k32 = _k32()
                    if k32 is not None:
                        try:
                            k32.RtlZeroMemory.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
                            k32.RtlZeroMemory.restype = None
                            k32.RtlZeroMemory(ctypes.c_void_p(addr), len(buf))
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                for i in range(len(buf)):
                    buf[i] = 0
            except Exception:
                pass
        except Exception:
            pass
    try:
        _with_native_lock(_do)
    except Exception:
        pass


def secure_zero(buf: bytearray) -> None:
    """Herkese-acik sifirlama (bytearray-only; bytes/str SIFIRLANAMAZ)."""
    try:
        if isinstance(buf, bytearray):
            _secure_zero(buf)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# S1 STRONG: tracer_attached — canli izleyici bagli mi?
# ---------------------------------------------------------------------------

def _linux_tracer_pid() -> Optional[int]:
    try:
        data = _read_file("/proc/self/status", 16384)
        if not data:
            return None
        for line in data.split(b"\n"):
            if line.startswith(b"TracerPid:"):
                try:
                    return int(line.split(b":", 1)[1].strip())
                except Exception:
                    return None
        return None
    except Exception:
        return None


def _win_being_debugged() -> Optional[bool]:
    try:
        k32 = _k32()
        if k32 is None:
            return None
        try:
            k32.IsDebuggerPresent.argtypes = []
            k32.IsDebuggerPresent.restype = ctypes.c_bool
            return bool(k32.IsDebuggerPresent())
        except Exception:
            return None
    except Exception:
        return None


def _win_peb_direct() -> Optional[Dict[str, object]]:
    """Kendi PEB'ini API-donusu DEGIL ham-memory olarak oku (R6).

    IsDebuggerPresent IAT-hook'u API donusunu sifirlayabilir; ham-okuma
    farkli yoldur (NtQueryInformationProcess(BasicInformation) + self
    ReadProcessMemory). Okunanlar: BeingDebugged (+2, 1B), NtGlobalFlag
    (+0xBC x64, DWORD; 0x70 = debugger-uretimi heap bayraklari),
    CrossProcessFlags (+0x50 x64, DWORD; 0x4 = VEH kullanimda).
    Offsetler surum-kirilgan (Win10/11 x64 dogrulandi; NCC VEH arastirmasi +
    winappdbg _PEB_NT) -> okuma basarisizsa None (bilinmiyor). Saldirgan
    karsiligi: ScyllaHide PEB'i de sifirlar (ayni-ayricalik sahtecilik);
    bu yol SADECE API-hook katmanini yakalar."""
    try:
        if _OS_NAME != "nt":
            return None
        # KONTROL-A12: offsetler x64'e ozgu (PEB +0xBC/+0x50, CONTEXT Dr).
        # 32-bit/WOW64'te yanlis okuma = STRONG false-positive sinifi ->
        # gate'le, None don (bilinmiyor).
        try:
            if ctypes.sizeof(ctypes.c_void_p) != 8:
                return None
        except Exception:
            return None
        try:
            ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        except Exception:
            return None
        k32 = _k32()
        if k32 is None:
            return None
        try:
            qip = ntdll.NtQueryInformationProcess
            qip.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                            ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
            qip.restype = ctypes.c_long
            k32.GetCurrentProcess.argtypes = []
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            k32.ReadProcessMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                              ctypes.c_void_p, ctypes.c_size_t,
                                              ctypes.POINTER(ctypes.c_size_t)]
            k32.ReadProcessMemory.restype = ctypes.c_bool
            hp = k32.GetCurrentProcess()
        except Exception:
            return None

        class _PBI(ctypes.Structure):
            _fields_ = [("ExitStatus", ctypes.c_long),
                        ("PebBaseAddress", ctypes.c_void_p),
                        ("AffinityMask", ctypes.c_void_p),
                        ("BasePriority", ctypes.c_long),
                        ("UniqueProcessId", ctypes.c_void_p),
                        ("ParentId", ctypes.c_void_p)]

        try:
            pbi = _PBI()
            rlen = ctypes.c_ulong(0)
            st = qip(hp, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(rlen))
            if int(st) != 0 or not pbi.PebBaseAddress:
                return None
            peb = int(pbi.PebBaseAddress)
        except Exception:
            return None

        def _read_u8(off: int) -> Optional[int]:
            try:
                v = ctypes.c_ubyte(0)
                n = ctypes.c_size_t(0)
                ok = k32.ReadProcessMemory(hp, ctypes.c_void_p(peb + off),
                                           ctypes.byref(v), 1, ctypes.byref(n))
                if not ok or int(n.value) != 1:
                    return None
                return int(v.value)
            except Exception:
                return None

        def _read_u32(off: int) -> Optional[int]:
            try:
                v = ctypes.c_uint32(0)
                n = ctypes.c_size_t(0)
                ok = k32.ReadProcessMemory(hp, ctypes.c_void_p(peb + off),
                                           ctypes.byref(v), 4, ctypes.byref(n))
                if not ok or int(n.value) != 4:
                    return None
                return int(v.value)
            except Exception:
                return None

        bd = _read_u8(0x02)
        ng = _read_u32(0xBC)
        cp = _read_u32(0x50)
        if bd is None and ng is None and cp is None:
            return None
        return {"being_debugged": bd, "ntglobal": ng, "cross": cp}
    except Exception:
        return None


def _win_debug_port() -> Optional[bool]:
    """NtQueryInformationProcess(ProcessDebugPort=7) nonzero -> debugger."""
    try:
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
    except Exception:
        return None
    try:
        qip = ntdll.NtQueryInformationProcess
        qip.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p,
                        ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
        qip.restype = ctypes.c_long
        k32 = _k32()
        if k32 is None:
            return None
        try:
            k32.GetCurrentProcess.argtypes = []
            k32.GetCurrentProcess.restype = ctypes.c_void_p
            hp = k32.GetCurrentProcess()
        except Exception:
            return None
        port = ctypes.c_void_p(0)
        rlen = ctypes.c_ulong(0)
        try:
            st = qip(hp, 7, ctypes.byref(port), ctypes.sizeof(port), ctypes.byref(rlen))
        except Exception:
            return None
        if int(st) != 0:
            return None
        return bool(port.value not in (None, 0))
    except Exception:
        return None


def _sig_tracer_attached() -> Optional[bool]:
    """STRONG: tracer/debugger canli-bagli. Saldirgan karsiligi: TracerPid
    LD_PRELOAD filtresi / ScyllaHide PEB sifirlama (ayni-ayricalik sahtecilik
    bu katmanda gorunmez; DURUST SINIR)."""
    try:
        if _PLATFORM.startswith("linux"):
            tp = _linux_tracer_pid()
            if tp is None:
                return None
            return tp != 0
        if _OS_NAME == "nt":
            b = _win_being_debugged()
            p = _win_debug_port()
            vals = [v for v in (b, p) if v is not None]
            # R6 ham-PEB caprazi: API-hook arkasina saklanan debugger izi.
            try:
                peb = _win_peb_direct()
                if peb is not None:
                    bd = peb.get("being_debugged")
                    if isinstance(bd, int):
                        vals.append(bd != 0)
                    ng = peb.get("ntglobal")
                    # KONTROL-A2: TAM 0x70 sarti (debugger-uretimi imza).
                    # Tek-bit (gflags/app-verifier mesru-kullanim) sayilmaz.
                    if isinstance(ng, int) and ng != 0:
                        vals.append((ng & 0x70) == 0x70)
            except Exception:
                pass
            if not vals:
                return None
            return any(vals)
        tp = _linux_tracer_pid()
        if tp is None:
            return None
        return tp != 0
    except Exception:
        return None


# ---------------------------------------------------------------------------
# S2 STRONG: hw_breakpoints_armed — Dr0-3 dolu mu? (Windows; Linux'ta None)
# ---------------------------------------------------------------------------

def _sig_hw_breakpoints() -> Optional[bool]:
    """M2-STRONG (Win x64): debug-register'lerde GERCEK HW breakpoint.

    Research (reverseengineering.app + LingSec + mabj/anti AD013):
    kanonik tespit GetThreadContext(CONTEXT_DEBUG_REGISTERS) + Dr0-3
    nonzero (+ Dr7 enable-mask). RtlCaptureContext Dr'leri doldurmaz
    (olu-sinyaldi) -> KALDIRILDI. Kapsam: once current-thread (suspend'suz,
    guvenli), sonra diger thread'ler Suspend+GetThreadContext+Resume
    best-effort (basarisiz thread atlanir). Dr7 dusuk-byte enable-mask
    bos + adresler kanonik-kullanici-aralikta degilse sayilmaz.
    Saldirgan karsiligi: GetThreadContext-hook ile DR sifirlama
    (ScyllaHide) -> gorunmez (dokumante rezidu).
    """
    try:
        if _OS_NAME != "nt":
            return None
        try:
            if ctypes.sizeof(ctypes.c_void_p) != 8:
                return None
        except Exception:
            return None
        k32 = _k32()
        if k32 is None:
            return None
        import struct as _st
        try:
            k32.GetCurrentThread.restype = ctypes.c_void_p
            k32.GetCurrentThread.argtypes = []
            k32.GetThreadContext.restype = ctypes.c_bool
            k32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            k32.SuspendThread.restype = ctypes.c_ulong
            k32.SuspendThread.argtypes = [ctypes.c_void_p]
            k32.ResumeThread.restype = ctypes.c_ulong
            k32.ResumeThread.argtypes = [ctypes.c_void_p]
            k32.CloseHandle.restype = ctypes.c_bool
            k32.CloseHandle.argtypes = [ctypes.c_void_p]
        except Exception:
            return None

        def _dr_hit(buf) -> bool:
            try:
                raw = bytes(buf.raw)
                try:
                    dr7 = _st.unpack_from("<I", raw, 0x68)[0]
                except Exception:
                    dr7 = 0
                if (dr7 & 0xFF) == 0:
                    return False
                for off in (0x48, 0x50, 0x58, 0x60):
                    try:
                        v = _st.unpack_from("<Q", raw, off)[0]
                    except Exception:
                        continue
                    if v != 0 and 0x10000 <= v <= 0x00007FFFFFFFFFFF:
                        return True
                return False
            except Exception:
                return False

        def _read_ctx(h, suspend: bool) -> Optional[bool]:
            try:
                if suspend:
                    try:
                        if k32.SuspendThread(h) == 0xFFFFFFFF:
                            return None
                    except Exception:
                        return None
                try:
                    buf = ctypes.create_string_buffer(0x4D0)
                    _st.pack_into("<I", buf, 48, 0x10)
                    ok = k32.GetThreadContext(h, buf)
                    if not ok:
                        return None
                    return _dr_hit(buf)
                finally:
                    if suspend:
                        try:
                            k32.ResumeThread(h)
                        except Exception:
                            pass
            except Exception:
                return None

        try:
            cur = k32.GetCurrentThread()
            if cur:
                r = _read_ctx(cur, False)
                if r is True:
                    return True
        except Exception:
            pass
        try:
            import ctypes as _ct
            import os as _os2
            try:
                k32.GetCurrentThreadId.restype = _ct.c_ulong
                k32.GetCurrentThreadId.argtypes = []
                my_tid = int(k32.GetCurrentThreadId())
            except Exception:
                return False
            try:
                mypid = int(_os2.getpid())
            except Exception:
                return False
            try:
                k32.CreateToolhelp32Snapshot.restype = _ct.c_void_p
                k32.CreateToolhelp32Snapshot.argtypes = [_ct.c_ulong, _ct.c_ulong]
                k32.Thread32First.restype = _ct.c_bool
                k32.Thread32First.argtypes = [_ct.c_void_p, _ct.c_void_p]
                k32.Thread32Next.restype = _ct.c_bool
                k32.Thread32Next.argtypes = [_ct.c_void_p, _ct.c_void_p]
                k32.OpenThread.restype = _ct.c_void_p
                k32.OpenThread.argtypes = [_ct.c_ulong, _ct.c_bool, _ct.c_ulong]
            except Exception:
                return False
            try:
                snap = k32.CreateToolhelp32Snapshot(0x4, 0)
            except Exception:
                return False
            try:
                iv = int(snap or 0)
            except Exception:
                return False
            if iv == 0 or iv == 0xFFFFFFFFFFFFFFFF or iv == 0xFFFFFFFF:
                return False
            try:
                te = _ct.create_string_buffer(28)
                _st.pack_into("<I", te, 0, 28)
                try:
                    more = bool(k32.Thread32First(snap, te))
                except Exception:
                    return False
                checked = 0
                while more and checked < 256:
                    try:
                        tid, owner = _st.unpack_from("<II", te, 8)
                    except Exception:
                        tid, owner = 0, 0
                    try:
                        more = bool(k32.Thread32Next(snap, te))
                    except Exception:
                        more = False
                    if not tid or int(owner) != mypid or int(tid) == my_tid:
                        continue
                    checked += 1
                    h = None
                    try:
                        h = k32.OpenThread(0x0A, False, int(tid))
                    except Exception:
                        continue
                    if not h:
                        continue
                    try:
                        if _read_ctx(h, True) is True:
                            return True
                    except Exception:
                        pass
                    finally:
                        try:
                            k32.CloseHandle(h)
                        except Exception:
                            pass
                return False
            finally:
                try:
                    k32.CloseHandle(snap)
                except Exception:
                    pass
        except Exception:
            return False
    except Exception:
        return None


# ---------------------------------------------------------------------------
# S3 STRONG: rwx_private_anon — sahsi RWX sayfa (staged shellcode izi)
# ---------------------------------------------------------------------------

def _linux_maps_text() -> Optional[bytes]:
    return _read_file("/proc/self/maps", 1 << 20)


def _sig_rwx_private_anon() -> Optional[bool]:
    """STRONG: calisma-aninda ozel RWX bolge (pithysecurity RW->RX iki-adim
    izi; EDR'larin yuksek-fidelite sinyali). MeSHRU JIT'ler (V8/CLR) RWX
    acabilir -> tek-basina trip STRONG sayilir ama status() baglami gosterir;
    supheliyse harden + yeniden-olcum onerilir. Saldirgan karsiligi: RX-ayri
    staging (RW ayir + RX'e cevir, RWX hicbir-anda yok) -> bu sinyal goremez;
    writable-code sinyali tamamlar."""
    try:
        if _PLATFORM.startswith("linux"):
            data = _linux_maps_text()
            if not data:
                return None
            for line in data.split(b"\n"):
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                # maps formati: adres perms offset dev inode [pathname];
                # KONTROL-3: parts[0] ADRES'tir, perms parts[1]'dir. [0]'i
                # okumak Linux'ta olu-sinyal veriyordu (adres rwx ile
                # baslamaz). Fix: perms = parts[1].
                perms = parts[1]
                if len(perms) < 4:
                    continue
                # rwx + private (p) + anon (inode 0 / path yok)
                if perms[:3] == b"rwx" and perms[3:4] == b"p":
                    pathname = parts[5] if len(parts) >= 6 else b""
                    if not pathname or pathname.startswith(b"["):
                        # [heap]/[stack] RWX suphelidir; dosyasiz anon RWX supheli
                        return True
            return False
        if _OS_NAME == "nt":
            k32 = _k32()
            if k32 is None:
                return None
            try:
                k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
                k32.VirtualQuery.restype = ctypes.c_size_t
            except Exception:
                return None
            PAGE_EXECUTE_READWRITE = 0x40
            MEM_PRIVATE = 0x20000
            MEM_COMMIT = 0x1000
            class _MBI(ctypes.Structure):
                _fields_ = [("BaseAddress", ctypes.c_void_p),
                            ("AllocationBase", ctypes.c_void_p),
                            ("AllocationProtect", ctypes.c_ulong),
                            ("RegionSize", ctypes.c_size_t),
                            ("State", ctypes.c_ulong),
                            ("Protect", ctypes.c_ulong),
                            ("Type", ctypes.c_ulong)]
            try:
                addr = 0x10000
                hits = 0
                for _ in range(512):
                    mbi = _MBI()
                    try:
                        r = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
                    except Exception:
                        break
                    if not r:
                        nxt = (addr + 0x10000) & ~0xFFFF
                        if nxt <= addr:
                            break
                        addr = nxt
                        continue
                    try:
                        if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                                and (mbi.Protect & 0xFF) == PAGE_EXECUTE_READWRITE):
                            # Kendi imaj disi kucuk RWX staging suphelidir.
                            # Buyuk CLR/JIT rezervleri false-positive vermesin
                            # diye SADECE committed-kucuk (<16MB) sayilir.
                            if int(mbi.RegionSize) <= (16 << 20):
                                hits += 1
                                if hits >= 1:
                                    return True
                    except Exception:
                        pass
                    try:
                        nxt = int(mbi.BaseAddress or addr) + int(mbi.RegionSize or 0x10000)
                    except Exception:
                        break
                    if nxt <= addr or nxt > 0x00007FFFFFFFFFFF:
                        break
                    addr = nxt
                return False
            except Exception:
                return None
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# S4 STRONG (Win): sw_breakpoint_shared — calistirilabilir sayfada Shared=0
# ---------------------------------------------------------------------------

def _sig_sw_breakpoint_shared(max_samples: int = 32) -> Optional[bool]:
    """STRONG (Win): ntdll .text sayfasinda CoW-ozel kopya (INT3/hook yazimi).
    R7 deseni (NCC d-cow/Moneta, winsider LdrpCheckPagesForTampering, CAIN):
    sistem DLL'leri boot-basina tek adrestedir (ntdll tum sureclerde AYNI
    fiziki sayfayi paylasir); yazim CoW'i tetikler -> Shared=0 / SharedOriginal=0.
    KONTROL-A3: battaniye-ornekleme ASLR-relocasyonu sonrasi ozel sayfalari da
    bayrakliyordu (STRONG false-positive sinifi). Fix: SADECE ntdll imaji
    (rebasesiz) + MEM_IMAGE + calistirilabilir sayfalar; Valid=1 sarti.
    ntdll bulunamazsa None (bilinmiyor; eski battaniye-moda DONULMEZ).
    Saldirgan karsiligi: HW-BP/VEH (paylasim bozulmaz) -> hw-sinyali tamamlar."""
    try:
        if _OS_NAME != "nt":
            return None
        k32 = _k32()
        if k32 is None:
            return None
        try:
            import ctypes as _ct
            try:
                psapi = _ct.WinDLL("psapi", use_last_error=True)
            except Exception:
                return None
            try:
                k32.GetModuleHandleW.argtypes = [_ct.c_wchar_p]
                k32.GetModuleHandleW.restype = _ct.c_void_p
                k32.VirtualQuery.argtypes = [_ct.c_void_p, _ct.c_void_p, _ct.c_size_t]
                k32.VirtualQuery.restype = _ct.c_size_t
                k32.GetCurrentProcess.argtypes = []
                k32.GetCurrentProcess.restype = _ct.c_void_p
            except Exception:
                return None

            class _MBI(_ct.Structure):
                _fields_ = [("BaseAddress", _ct.c_void_p),
                            ("AllocationBase", _ct.c_void_p),
                            ("AllocationProtect", _ct.c_ulong),
                            ("RegionSize", _ct.c_size_t),
                            ("State", _ct.c_ulong),
                            ("Protect", _ct.c_ulong),
                            ("Type", _ct.c_ulong)]

            class _WSEX(_ct.Structure):
                _fields_ = [("VirtualAddress", _ct.c_void_p),
                            ("VirtualAttributes", _ct.c_void_p)]

            try:
                psapi.QueryWorkingSetEx.argtypes = [_ct.c_void_p, _ct.c_void_p, _ct.c_ulong]
                psapi.QueryWorkingSetEx.restype = _ct.c_bool
            except Exception:
                return None
            try:
                ntdll = int(k32.GetModuleHandleW("ntdll.dll") or 0)
            except Exception:
                return None
            if not ntdll:
                return None
            hp = k32.GetCurrentProcess()
            MEM_COMMIT = 0x1000
            MEM_IMAGE = 0x1000000
            EXEC = (0x10, 0x20, 0x40, 0x80)
            # ntdll imaj-araligindaki calistirilabilir sayfalari topla
            pages = []
            try:
                addr = ntdll
                for _ in range(128):
                    mbi = _MBI()
                    try:
                        r = k32.VirtualQuery(_ct.c_void_p(addr), _ct.byref(mbi), _ct.sizeof(mbi))
                    except Exception:
                        break
                    if not r:
                        break
                    try:
                        base = int(mbi.BaseAddress or addr)
                        size = int(mbi.RegionSize or 0)
                        alloc = int(mbi.AllocationBase or 0)
                        is_image = mbi.Type == MEM_IMAGE and alloc == ntdll
                    except Exception:
                        break
                    if not is_image or size <= 0:
                        break
                    try:
                        prot = int(mbi.Protect & 0xFF)
                        if mbi.State == MEM_COMMIT and prot in EXEC:
                            off = 0
                            while off < size:
                                pages.append(base + off)
                                off += 0x1000
                    except Exception:
                        pass
                    nxt = base + size
                    if nxt <= addr or nxt > 0x00007FFFFFFFFFFF:
                        break
                    addr = nxt
            except Exception:
                return None
            if not pages:
                return None
            # Araliga yayilmis ornekleme (INT3 tek-sayfada da yakalanir)
            try:
                step = max(1, len(pages) // max(1, int(max_samples)))
            except Exception:
                step = 1
            try:
                for va in pages[::step][:max_samples]:
                    try:
                        info = _WSEX()
                        info.VirtualAddress = _ct.c_void_p(va)
                        info.VirtualAttributes = _ct.c_void_p(0)
                        ok = psapi.QueryWorkingSetEx(hp, _ct.byref(info), _ct.sizeof(info))
                        if not ok:
                            continue
                        attrs = int(info.VirtualAttributes or 0)
                        if (attrs & 0x1) != 1:
                            continue  # resident degil -> hukum yok
                        shared = (attrs >> 15) & 0x1
                        shared_orig = (attrs >> 30) & 0x1
                        if shared == 0 or shared_orig == 0:
                            return True
                    except Exception:
                        continue
                return False
            except Exception:
                return None
        except Exception:
            return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# W1 WEAK: writable_code — yazilabilir kod sayfasi (yama/enjeksiyon zemini)
# ---------------------------------------------------------------------------

def _own_exe_path() -> str:
    try:
        return os.path.abspath(sys.executable or "")
    except Exception:
        return ""


def _sig_writable_code() -> Optional[bool]:
    """WEAK: calisan kod goruntusu yazilabilir (IMAGE+w ya da exe-mapping w).
    checkpoint [2.2] function-patch + [2.x] INT3-taramasi zemini. MeSHRU:
    lazy-reloc/profiling kisa-pencerede w olabilir -> WEAK (tek-basina trip
    YOK). Saldirgan karsiligi: HW-BP kullanimi (kod degismez) -> hw sinyali
    tamamlar."""
    try:
        if _PLATFORM.startswith("linux"):
            data = _linux_maps_text()
            if not data:
                return None
            exe = _own_exe_path()
            for line in data.split(b"\n"):
                if not line:
                    continue
                parts = line.split()
                if len(parts) < 2:
                    continue
                # KONTROL-3 fix: perms parts[1]'dir (parts[0] adres).
                perms = parts[1]
                if len(perms) < 3 or perms[2:3] != b"x" or perms[1:2] != b"w":
                    continue
                pathname = parts[5] if len(parts) >= 6 else b""
                if pathname.endswith(b".so") or pathname.endswith(b".pyd") or pathname.endswith(b".dll"):
                    return True
                if exe and pathname.decode("utf-8", "ignore") == exe:
                    return True
            return False
        if _OS_NAME == "nt":
            k32 = _k32()
            if k32 is None:
                return None
            try:
                k32.VirtualQuery.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
                k32.VirtualQuery.restype = ctypes.c_size_t
            except Exception:
                return None
            MEM_IMAGE = 0x1000000
            MEM_COMMIT = 0x1000
            # KONTROL-2: DLL .data/.rdata bolumleri MEM_IMAGE + RW'dir (NORMAL);
            # RW'yi bayraklamak her Windows makinede surekli-WEAK verirdi.
            # Fix: IMAGE'da SADECE calistirilabilir+yazilabilir (RWX 0x40,
            # EXEC_WRITECOPY 0x80) suphelidir. Salt-RW IMAGE normal sayilir.
            WRX = (0x40, 0x80)
            class _MBI(ctypes.Structure):
                _fields_ = [("BaseAddress", ctypes.c_void_p),
                            ("AllocationBase", ctypes.c_void_p),
                            ("AllocationProtect", ctypes.c_ulong),
                            ("RegionSize", ctypes.c_size_t),
                            ("State", ctypes.c_ulong),
                            ("Protect", ctypes.c_ulong),
                            ("Type", ctypes.c_ulong)]
            try:
                addr = 0x10000
                for _ in range(256):
                    mbi = _MBI()
                    try:
                        r = k32.VirtualQuery(ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
                    except Exception:
                        break
                    if not r:
                        break
                    try:
                        if mbi.State == MEM_COMMIT and mbi.Type == MEM_IMAGE and (mbi.Protect & 0xFF) in WRX:
                            return True
                    except Exception:
                        pass
                    try:
                        nxt = int(mbi.BaseAddress or addr) + int(mbi.RegionSize or 0x10000)
                    except Exception:
                        break
                    if nxt <= addr:
                        break
                    addr = nxt
                return False
            except Exception:
                return None
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# W2 WEAK: maps_posture — kesif dosyasi baskasina acik mi? (dumpable+yama)
# ---------------------------------------------------------------------------

def _yama_scope() -> Optional[int]:
    try:
        data = _read_file("/sys/kernel/yama/ptrace_scope", 32)
        if not data:
            data = _read_file("/proc/sys/kernel/yama/ptrace_scope", 32)
        if not data:
            return None
        return int(data.strip())
    except Exception:
        return None


def _prctl_get_dumpable() -> Optional[int]:
    try:
        lib = _libc()
        if lib is None:
            return None
        lib.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                              ctypes.c_ulong, ctypes.c_ulong]
        lib.prctl.restype = ctypes.c_int
        return int(lib.prctl(3, 0, 0, 0, 0))
    except Exception:
        return None


def _sig_maps_posture() -> Optional[bool]:
    """WEAK: kesif-posturu acik (dumpable=1 VE yama-scope=0). T1003.007 notu:
    ptrace_scope=2 /proc/mem'i KAPATMAZ; bu sinyal iki-kosulu birlikte arar
    (tek-kosul yetersiz). Saldirgan karsiligi: root okur (rezidu)."""
    try:
        if not _PLATFORM.startswith("linux"):
            return None
        d = _prctl_get_dumpable()
        y = _yama_scope()
        if d is None and y is None:
            return None
        if d == 1 and (y is None or y == 0):
            return True
        if d is None:
            return None
        return False
    except Exception:
        return None


def _sig_dumpable_process() -> Optional[bool]:
    """WEAK: PR_SET_DUMPABLE=1 (core + mem/maps/attach yuzeyi acik). R1/R5
    karsiligi; harden() 0'lar."""
    try:
        d = _prctl_get_dumpable()
        if d is None:
            return None
        return d != 0
    except Exception:
        return None


# ---------------------------------------------------------------------------
# W3 WEAK: core_exposed — core'a dusebilir mi? (RLIMIT + pattern pipe)
# ---------------------------------------------------------------------------

def _sig_core_posture() -> Optional[bool]:
    """M6-WEAK: core-dump HAM-dosya yazabilir (alarm-yorgunlugu duzeltmeli).

    Stok-sistem FP'si kapanir: RLIMIT acik olmasi YETMEZ; pattern ham-dosya
    yaziyorsa True. Boru-handler'a (apport/systemd-coredump) yonlendirme
    tek-basina trip DEGIL (CVE-2025-4598 sinifi handler-zaaflari ayri
    katmanin isi); handler calistirilamaz/kirik ise kernel ham-dosyaya
    duser -> True. |/bin/false veya bos pattern = dokum kapali -> False.
    anti_dump [1]/[2] karsiligi; burada SADECE gozlem.
    """
    try:
        try:
            import resource as _res
            soft, _hard = _res.getrlimit(_res.RLIMIT_CORE)
            if int(soft) == 0:
                return False
        except Exception:
            pass
        try:
            data = _read_file("/proc/sys/kernel/core_pattern", 4096)
        except Exception:
            return None
        if data is None:
            return None
        try:
            pat = data.strip()
        except Exception:
            return None
        if not pat:
            return False
        if pat.startswith(b"|"):
            try:
                parts = pat[1:].split(b" ", 1)
                handler = parts[0].decode("utf-8", "ignore") if parts else ""
            except Exception:
                handler = ""
            if handler in ("", "/bin/false", "/bin/true"):
                return False
            try:
                if handler and os.path.isfile(handler) and os.access(handler, os.X_OK):
                    return False
            except Exception:
                pass
            return True
        return True
    except Exception:
        return None


# ---------------------------------------------------------------------------
# W4 WEAK: introspection_tools — disaridan/disaridan-ici gozetim araci izi
# ---------------------------------------------------------------------------

_TOOL_NAMES = (b"frida", b"gadget", b"py-spy", b"py_spy", b"strace",
               b"ltrace", b"gdb", b"windbg", b"x64dbg", b"ollydbg",
               b"volatility", b"mimipenguin", b"gcore", b"procdump")

_TOOL_CACHE = {"at": 0.0, "hit": False, "ok": False}


def _win_tool_scan_cached(ttl: float = 2.0) -> Optional[bool]:
    """Toolhelp32 snapshot + kisa TTL cache (R7). tasklist-subprocess YOK:
    hizli, cocuk-surec yok, konsol-penceresi yok. Cache en fazla `ttl` sn
    geciktirir (WEAK sinyal icin kabul; dokumante)."""
    try:
        now = _TIME_MONO()
        if _TOOL_CACHE.get("ok") and (now - float(_TOOL_CACHE.get("at", 0.0))) < ttl:
            return bool(_TOOL_CACHE.get("hit"))
    except Exception:
        pass
    hit: Optional[bool] = None
    try:
        k32 = _k32()
        if k32 is None:
            return None
        import ctypes as _ct

        class _PE(_ct.Structure):
            _fields_ = [("dwSize", _ct.c_ulong),
                        ("cntUsage", _ct.c_ulong),
                        ("th32ProcessID", _ct.c_ulong),
                        ("th32DefaultHeapID", _ct.c_void_p),
                        ("th32ModuleID", _ct.c_ulong),
                        ("cntThreads", _ct.c_ulong),
                        ("th32ParentProcessID", _ct.c_ulong),
                        ("pcPriClassBase", _ct.c_long),
                        ("dwFlags", _ct.c_ulong),
                        ("szExeFile", _ct.c_char * 260)]

        try:
            k32.CreateToolhelp32Snapshot.argtypes = [_ct.c_ulong, _ct.c_ulong]
            k32.CreateToolhelp32Snapshot.restype = _ct.c_void_p
            k32.Process32First.argtypes = [_ct.c_void_p, _ct.POINTER(_PE)]
            k32.Process32First.restype = _ct.c_bool
            k32.Process32Next.argtypes = [_ct.c_void_p, _ct.POINTER(_PE)]
            k32.Process32Next.restype = _ct.c_bool
            k32.CloseHandle.argtypes = [_ct.c_void_p]
            k32.CloseHandle.restype = _ct.c_bool
        except Exception:
            return None
        try:
            snap = k32.CreateToolhelp32Snapshot(0x2, 0)
        except Exception:
            return None
        # KONTROL-A13: c_void_p int() isaretsizdir; INVALID_HANDLE_VALUE
        # (-1) 0xFFFF...F olarak gelir. `== -1` karsilastirmasi olu-dal
        # olurdu (gecersiz handle ile devam). Fix: her iki genislikte de yakala.
        try:
            iv = int(snap or 0)
        except Exception:
            return None
        if iv == 0 or iv == 0xFFFFFFFFFFFFFFFF or iv == 0xFFFFFFFF:
            return None
        try:
            pe = _PE()
            pe.dwSize = _ct.sizeof(_PE)
            try:
                more = bool(k32.Process32First(snap, _ct.byref(pe)))
            except Exception:
                return None
            names = (b"frida", b"procdump", b"windbg", b"x64dbg", b"ollydbg",
                     b"cheat", b"process hacker", b"pyspy", b" cheatengine",
                     b"dbvm", b"scylla")
            seen = 0
            while more and seen < 1024:
                seen += 1
                try:
                    exe = bytes(pe.szExeFile).split(b"\x00", 1)[0].lower()
                    for t in names:
                        if t in exe:
                            hit = True
                            break
                    if hit is True:
                        break
                except Exception:
                    pass
                try:
                    more = bool(k32.Process32Next(snap, _ct.byref(pe)))
                except Exception:
                    break
            if hit is None:
                hit = False
        finally:
            try:
                k32.CloseHandle(snap)
            except Exception:
                pass
    except Exception:
        return None
    try:
        _TOOL_CACHE["at"] = _TIME_MONO()
        _TOOL_CACHE["hit"] = bool(hit)
        _TOOL_CACHE["ok"] = hit is not None
    except Exception:
        pass
    return hit


def _sig_introspection_tools() -> Optional[bool]:
    """WEAK: bilinen introspection/dump araci kalintisi (kendi maps'te
    frida-agent ya da komsu surecte py-spy/strace adi). Saldirgan karsiligi:
    ad-degistirmis binary (gorunmez); bu yuzden WEAK + tek-basina tripsiz."""
    try:
        if _PLATFORM.startswith("linux"):
            data = _linux_maps_text()
            if data is not None:
                low = data.lower()
                for t in _TOOL_NAMES[:6]:
                    if t in low:
                        return True
            # komsu-surec adi taramasi (best-effort, /proc)
            try:
                procs = os.listdir("/proc")
            except Exception:
                return False if data is not None else None
            hits = 0
            seen = 0
            for pid in procs:
                if not pid.isdigit() or int(pid) == _live_pid():
                    continue
                seen += 1
                if seen > 1024:
                    break
                try:
                    with open("/proc/%s/comm" % pid, "rb") as f:
                        comm = f.read(64).lower().strip()
                    for t in _TOOL_NAMES:
                        if t in comm:
                            hits += 1
                            break
                    if hits:
                        break
                except Exception:
                    continue
            return hits > 0
        if _OS_NAME == "nt":
            return _win_tool_scan_cached()
        return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# W5 WEAK: python_introspection — yorumlayici-ici kanca (gettrace/audit/gc)
# ---------------------------------------------------------------------------

def _sig_python_hooks() -> Optional[bool]:
    """WEAK: yorumlayici-ici gozetim kancasi (sys.gettrace pin-sapmasi veya
    tracemalloc izleme aktif). KONTROL-A4: sys.audit_hooks diye API YOK
    (olu-dal kaldirildi); addaudithook kancalari numaralandirilamaz (rezidu).
    Profiler/debugger mesru-kullanim olabilir -> WEAK.
    Saldirgan karsiligi: gc/C-API ile kancasiz gezinti (gorunmez); hucre
    disiplini (kisa-omur+wipe) tamamlar."""
    try:
        hooked = False
        try:
            gt = sys.gettrace()
            if gt is not None and gt is not _PIN_GETTRACE:
                hooked = True
        except Exception:
            pass
        try:
            import tracemalloc as _tm
            if _tm.is_tracing():
                hooked = True
        except Exception:
            pass
        return hooked
    except Exception:
        return None


def _sig_veh_flag() -> Optional[bool]:
    """WEAK (Win): surecte VEH kurulu (CrossProcessFlags&4). NCC: VEH mesru
    kullanimda da gorulur (CLR/tarayici) -> WEAK, tek-basina tripsiz. Beklen-
    medik VEH + ikinci sinyal = trip. Okunamazsa None."""
    try:
        if _OS_NAME != "nt":
            return None
        try:
            peb = _win_peb_direct()
        except Exception:
            return None
        if not peb:
            return None
        cp = peb.get("cross")
        if not isinstance(cp, int):
            return None
        return bool(cp & 0x4)
    except Exception:
        return None


def _sig_injected_threads() -> Optional[bool]:
    """STRONG (Win): baslangic-adresi unbacked-executable bolgede thread
    (CreateRemoteThread/shellcode isareti; Elastic Get-InjectedThreads
    teknigi). Mesru thread'ler imaj-kodunda baslar; MEM_PRIVATE+X baslangic
    enjeksiyondur. Numaralandirma NtGetNextThread ile (Toolhelp kancalarina
    dayanikli). Saldirgan karsiligi: imaj-ici ROP-baslangic (gorunmez);
    RWX taramasi + hw-sinyalleri tamamlar."""
    try:
        import ctypes as _ct
    except Exception:
        return None
    try:
        if _OS_NAME != "nt":
            return None
        try:
            k32 = _k32()
            ntdll = _ct.windll.ntdll
        except Exception:
            return None
        if k32 is None:
            return None

        class _MBI(_ct.Structure):
            _fields_ = [("BaseAddress", _ct.c_void_p),
                        ("AllocationBase", _ct.c_void_p),
                        ("AllocationProtect", _ct.c_ulong),
                        ("RegionSize", _ct.c_size_t),
                        ("State", _ct.c_ulong),
                        ("Protect", _ct.c_ulong),
                        ("Type", _ct.c_ulong)]
        try:
            k32.GetCurrentProcess.argtypes = []
            k32.GetCurrentProcess.restype = _ct.c_void_p
            k32.CloseHandle.argtypes = [_ct.c_void_p]
            k32.CloseHandle.restype = _ct.c_bool
            k32.VirtualQuery.argtypes = [_ct.c_void_p, _ct.c_void_p, _ct.c_size_t]
            k32.VirtualQuery.restype = _ct.c_size_t
            ntdll.NtGetNextThread.argtypes = [_ct.c_void_p, _ct.c_void_p,
                                             _ct.c_ulong, _ct.c_ulong,
                                             _ct.c_ulong,
                                             _ct.POINTER(_ct.c_void_p)]
            ntdll.NtGetNextThread.restype = _ct.c_ulong
            ntdll.NtQueryInformationThread.argtypes = [_ct.c_void_p, _ct.c_ulong,
                                                      _ct.c_void_p, _ct.c_ulong,
                                                      _ct.POINTER(_ct.c_ulong)]
            ntdll.NtQueryInformationThread.restype = _ct.c_ulong
        except Exception:
            return None
        try:
            hp = k32.GetCurrentProcess()
        except Exception:
            return None
        try:
            seen = 0
            prev = _ct.c_void_p(0)
            found = False
            while seen < 1024:
                seen += 1
                hth = _ct.c_void_p(0)
                try:
                    st = ntdll.NtGetNextThread(hp, prev, 0x0040, 0, 0,
                                              _ct.byref(hth))
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
                    prev = _ct.c_void_p(0)
                    continue
                try:
                    hiv = int(hth.value or 0)
                except Exception:
                    hiv = 0
                if not hiv:
                    prev = _ct.c_void_p(0)
                    continue
                prev = _ct.c_void_p(hiv)
                try:
                    start = _ct.c_void_p(0)
                    retlen = _ct.c_ulong(0)
                    st2 = ntdll.NtQueryInformationThread(
                        hiv, 9, _ct.byref(start),
                        _ct.sizeof(start), _ct.byref(retlen))
                    try:
                        ok = (int(st2) & 0xFFFFFFFF) < 0x80000000
                    except Exception:
                        ok = False
                    if ok:
                        saddr = int(start.value or 0)
                        if saddr:
                            mbi = _MBI()
                            r = k32.VirtualQuery(
                                _ct.c_void_p(saddr),
                                _ct.byref(mbi), _ct.sizeof(mbi))
                            if r:
                                prot = int(mbi.Protect or 0)
                                if (int(mbi.State or 0) == 0x1000
                                        and int(mbi.Type or 0) == 0x20000
                                        and (prot & 0xF0) != 0):
                                    found = True
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
        except Exception:
            return None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Skor / toplu API (fail-closed: STRONG=100, WEAK=30; >=1S veya >=2W trip)
# ---------------------------------------------------------------------------

def _raw_results() -> Dict[str, Optional[bool]]:
    out: Dict[str, Optional[bool]] = {}
    for name, fn in (
        ("tracer_attached", _sig_tracer_attached),
        ("hw_breakpoints", _sig_hw_breakpoints),
        ("rwx_private_anon", _sig_rwx_private_anon),
        ("sw_breakpoint_shared", _sig_sw_breakpoint_shared),
        ("writable_code", _sig_writable_code),
        ("maps_posture", _sig_maps_posture),
        ("dumpable_process", _sig_dumpable_process),
        ("core_posture", _sig_core_posture),
        ("introspection_tools", _sig_introspection_tools),
        ("python_hooks", _sig_python_hooks),
        ("veh_flag", _sig_veh_flag),
        ("injected_threads", _sig_injected_threads),
    ):
        try:
            out[name] = fn()
        except Exception:
            out[name] = None
    return out


_STRONG = ("tracer_attached", "hw_breakpoints", "rwx_private_anon",
            "sw_breakpoint_shared", "injected_threads")
_WEAK = ("writable_code", "maps_posture", "dumpable_process", "core_posture",
         "introspection_tools", "python_hooks", "veh_flag")


def _score_from_raw(raw: Dict[str, Optional[bool]]) -> Tuple[int, int, int]:
    """Donus SIRASI: (strong_sayisi, weak_sayisi, toplam_puan) — M3 kardes-kontrat.

    M3: tarihsel (toplam, s, w) sirasi paylasilan caller kodunda sessiz
    yanlis-unpack uretiyordu. Kardes-kontrat (s, w, toplam)'a gecildi
    (BREAKING: eski siraya bagli cagiranlar guncellenmeli).
    """
    s = sum(1 for k in _STRONG if raw.get(k) is True)
    w = sum(1 for k in _WEAK if raw.get(k) is True)
    return s, w, s * 100 + w * 30


def check_all() -> Dict[str, Optional[bool]]:
    return _raw_results()


def score() -> Tuple[int, int, int]:
    """(strong_sayisi, weak_sayisi, toplam_puan) — kardes-kontrat (M3)."""
    raw = _raw_results()
    return _score_from_raw(raw)


def is_inspected() -> bool:
    try:
        s, w, total = _score_from_raw(_raw_results())
        _ = total
        return s >= 1 or w >= 2
    except Exception:
        return True


def assert_no_inspection() -> None:
    if is_inspected():
        raise _fail()


def status() -> Dict[str, object]:
    """Tek-pas durum (agir gc-walk YOK; hucre sayisi dahili)."""
    try:
        raw = _raw_results()
        s, w, total = _score_from_raw(raw)
        try:
            memfd = memfd_secret_available()
        except Exception:
            memfd = None
        return {
            "tripped": bool(s >= 1 or w >= 2),
            "score": total,
            "strong": s,
            "weak": w,
            "signals": raw,
            "pid": _live_pid(),
            "cells_live": SecureCell.live_count(),
            "memfd_secret": memfd,
        }
    except Exception:
        return {"tripped": True, "score": -1, "strong": -1, "weak": -1,
                "signals": {}, "pid": _live_pid(), "cells_live": -1}


def health() -> Dict[str, object]:
    return status()


# ---------------------------------------------------------------------------
# Capability: memfd_secret (R5) — SADECE rapor, sinyal degil
# ---------------------------------------------------------------------------

def memfd_secret_available() -> Optional[bool]:
    """Linux memfd_secret syscall-447 destegi var mi? True/False; non-Linux
    veya olculemezse None. Olcum: libc.syscall(447, 0) + fd> =0 ise kapat.
    ENOSYS (cekirdek yok / secretmem.enable=0) -> False. Best-effort."""
    try:
        if not _PLATFORM.startswith("linux"):
            return None
        lib = _libc()
        if lib is None:
            return None
        try:
            lib.syscall.argtypes = [ctypes.c_long, ctypes.c_int]
            lib.syscall.restype = ctypes.c_long
            fd = int(lib.syscall(447, 0))
        except Exception:
            return None
        if fd is None or fd < 0:
            return False
        try:
            os.close(fd)
        except Exception:
            pass
        return True
    except Exception:
        return None


# ---------------------------------------------------------------------------
# SecureCell — kilitli + dump-disi + scoped-view hucre (bytearray-only)
# ---------------------------------------------------------------------------

_live_cells = None


def _live_set():
    global _live_cells
    try:
        import weakref as _wr
        if _live_cells is None:
            _live_cells = _wr.WeakSet()
        return _live_cells
    except Exception:
        return None


class _CellView:
    """Scoped-view: with-bloku disi erisim ValueError (cypher_cell deseni)."""

    def __init__(self, cell: "SecureCell"):
        self._cell = cell
        self._dead = False

    def __enter__(self) -> "_CellView":
        self._check()
        return self

    def __exit__(self, *exc) -> bool:
        try:
            self.invalidate()
        except Exception:
            pass
        return False

    def _check(self) -> "SecureCell":
        if self._dead:
            raise ValueError("View expired")
        c = self._cell
        if c is None or getattr(c, "_dead", True):
            raise ValueError("View expired")
        return c

    def __bytes__(self) -> bytes:
        c = self._check()
        return c._plain_bytes()

    def __str__(self) -> str:
        c = self._check()
        raw = c._plain_bytes()
        try:
            return raw.decode("utf-8")
        except Exception:
            raise ValueError("not utf-8")

    def verify(self, candidate: bytes) -> bool:
        """Sabit-zamanli karsilastirma (timing-oracle karsiti)."""
        c = self._check()
        return c._verify_bytes(candidate)

    def readinto(self, target: bytearray) -> int:
        """M5: view uzerinden sifir-kopya okuma."""
        c = self._check()
        return c.readinto(target)

    def invalidate(self) -> None:
        self._dead = True


def _mi_internal_caller() -> bool:
    """M1: dogrudan cagiran bu modul-ici mi? (hucre-muhur gecidi)."""
    try:
        fr = sys._getframe(2)
    except Exception:
        return False
    try:
        fn = str(getattr(fr.f_code, "co_filename", "") or "")
        return bool(fn) and fn == __file__
    except Exception:
        return False


class SecureCell:
    """Hassas baytlar icin korunakli hucre.

    - bytearray-only (immutable bytes/str SIFIRLANAMAZ; ctor TEK kopya alir,
      bytearray girdide cagiran kopya sifirlanir; str YASAK).
    - mlock/VirtualLock + MADV_DONTDUMP/DONTFORK (best-effort).
    - Kullanim-disi NOACCESS penceresi YOK (saf-Python mprotect yok); bunun
      yerine kullanim SADECE with-view icinde + cikista wipe disiplini.
    - anti-leak repr (icerik ASLA yazilmaz).
    - W5 karsiligi: gc-traversal hucreyi bulabilir; cozum kisa-omur + wipe.
    - M1 MUHUR (KeyVault-parite): __slots__ (__dict__ YOK — flag-flip ve
      buf-swap icin sozluk kaldirildi) + __getattribute__/__setattr__
      gecidi: _buf/_dead SADECE modul-ici cagirana acilir. Dogrudan
      bytes(cell._buf) + cell._buf[:] sessiz-tamper kapanir. DURUST rezidu:
      object.__getattribute__ bilerek-bypass mumkundur (Python-seviyesi
      kontrollerin ortak siniri); anti_hook/anti_tamper ile katmanli savunur.
    """

    __slots__ = ("_buf", "_dead", "_volatile", "_born", "_ttl",
                 "_open_views", "__weakref__")

    _SENSITIVE = frozenset({"_buf", "_dead"})

    def __getattribute__(self, name):
        try:
            if name in SecureCell._SENSITIVE and not _mi_internal_caller():
                raise AttributeError("SecureCell: protected")
        except AttributeError:
            raise
        except Exception:
            raise AttributeError("SecureCell: protected")
        return object.__getattribute__(self, name)

    def __setattr__(self, name, value):
        try:
            if name in SecureCell._SENSITIVE and not _mi_internal_caller():
                raise AttributeError("SecureCell: protected")
        except AttributeError:
            raise
        except Exception:
            raise AttributeError("SecureCell: protected")
        object.__setattr__(self, name, value)

    def __init__(self, data: bytes | bytearray, *, volatile: bool = False,
                 ttl: float = 0.0):
        if isinstance(data, str):
            raise TypeError("str verilemez (immutable); bytes/bytearray kullan")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError("bytes/bytearray gerekli")
        # KONTROL-A9: tek-kopya ctor (ara bytes() kaldirildi; heap'te 1
        # gecici kopya kalir, once 2'ydi; bytearray girdide cagiran sifirlanir).
        self._buf = bytearray(data)
        if isinstance(data, bytearray):
            try:
                _secure_zero(data)
            except Exception:
                pass
        self._dead = False
        self._volatile = bool(volatile)
        self._born = _TIME_MONO()
        self._ttl = float(ttl or 0.0)
        # DERIN-5: WeakSet (hucre->view->hucre guclu-cevriminden kacinma;
        # normal yolda _kill_views zaten bosaltir, bu ek garanti).
        try:
            import weakref as _wr
            self._open_views = _wr.WeakSet()
        except Exception:
            self._open_views = []
        try:
            _mlock_bytes(self._buf)
        except Exception:
            pass
        try:
            _madvise_no_dump_fork(self._buf)
        except Exception:
            pass
        try:
            ls = _live_set()
            if ls is not None:
                ls.add(self)
        except Exception:
            pass

    @staticmethod
    def live_count() -> int:
        try:
            ls = _live_set()
            if ls is None:
                return -1
            return len(ls)
        except Exception:
            return -1

    @classmethod
    def from_env(cls, name: str, *, scrub: bool = True,
                 volatile: bool = False, ttl: float = 0.0) -> "SecureCell":
        """Environ'dan direkt-yukleme (heap'e degmeden; cypher_cell from_env
        deseni). DURUSTLUK: env str immutable -> scrub=True ayni-uzunlukta
        dummy ile degistirir (orijinal GC'ye duser; sifirlanamaz)."""
        try:
            val = os.environ.get(name, "")
        except Exception:
            val = ""
        cell = cls(val.encode("utf-8"), volatile=volatile, ttl=ttl)
        if scrub:
            try:
                os.environ[name] = "x" * len(val)
            except Exception:
                pass
        return cell

    def _check_live(self) -> None:
        if self._dead:
            raise ValueError("cell dead")
        if self._ttl > 0:
            try:
                if _TIME_MONO() - self._born > self._ttl:
                    self.wipe()
                    raise ValueError("cell expired")
            except ValueError:
                raise
            except Exception:
                pass

    def _plain_bytes(self) -> bytes:
        self._check_live()
        return bytes(self._buf)

    def readinto(self, target: bytearray) -> int:
        """M5: sifir-kopya okuma — bytes uretilmez, hedef tampona yazilir."""
        self._check_live()
        try:
            n = len(self._buf)
            if len(target) < n:
                raise ValueError("readinto: hedef kucuk")
            try:
                target[:n] = self._buf
            except Exception:
                raise ValueError("readinto: yazma basarisiz")
            return n
        except ValueError:
            raise
        except Exception:
            raise ValueError("readinto basarisiz")

    def _verify_bytes(self, candidate: bytes) -> bool:
        """M5: memoryview-karsilastirma (plaintext bytes kopyasiz)."""
        self._check_live()
        try:
            import hmac as _hmac
            if not isinstance(candidate, (bytes, bytearray, memoryview)):
                return False
            try:
                return bool(_hmac.compare_digest(memoryview(self._buf),
                                                 memoryview(candidate)))
            except Exception:
                return False
        except Exception:
            return False

    def __enter__(self) -> _CellView:
        self._check_live()
        v = _CellView(self)
        try:
            add = getattr(self._open_views, "add", None)
            if callable(add):
                add(v)
            else:
                self._open_views.append(v)
        except Exception:
            pass
        return v

    def _kill_views(self) -> None:
        try:
            views, self._open_views = list(self._open_views), []
        except Exception:
            return
        for v in views:
            try:
                v.invalidate()
            except Exception:
                pass

    def __exit__(self, *exc) -> bool:
        # DERIN-4: blok-cikista gorunumler oldurulur (scoped-view garantisi;
        # blok-disi erisim ValueError). Once view'ler, sonra volatile-wipe.
        try:
            self._kill_views()
        except Exception:
            pass
        try:
            if self._volatile:
                self.wipe()
        except Exception:
            pass
        return False

    def wipe(self) -> None:
        try:
            self._kill_views()
        except Exception:
            pass
        try:
            _secure_zero(self._buf)
        except Exception:
            pass
        try:
            _munlock_bytes(self._buf)
        except Exception:
            pass
        self._dead = True

    def close(self) -> None:
        self.wipe()

    def __del__(self):  # noqa: D105
        try:
            self.wipe()
        except Exception:
            pass

    def __repr__(self) -> str:  # noqa: D105
        return "SecureCell([REDACTED])"

    def __reduce__(self):
        raise TypeError("SecureCell pickling yasak")

    def __getstate__(self):
        raise TypeError("SecureCell pickling yasak")

    def __deepcopy__(self, memo):
        raise TypeError("SecureCell kopyalama yasak")

    def __copy__(self):
        raise TypeError("SecureCell kopyalama yasak")


def protect_bytes(data: bytes | bytearray, **kw) -> SecureCell:
    """Kisa-omurlu koruma (with ile kullan; blok disi erismez)."""
    return SecureCell(data, **kw)


# ---------------------------------------------------------------------------
# Harden / enforce (best-effort; hepsi sessiz)
# ---------------------------------------------------------------------------

def enforce_undumpable() -> bool:
    """PR_SET_DUMPABLE=0 (Linux). Basariliysa True."""
    try:
        if not _PLATFORM.startswith("linux"):
            return False
        lib = _libc()
        if lib is None:
            return False
        lib.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                              ctypes.c_ulong, ctypes.c_ulong]
        lib.prctl.restype = ctypes.c_int
        rc = lib.prctl(4, 0, 0, 0, 0)
        if int(rc) != 0:
            return False
        try:
            return int(lib.prctl(3, 0, 0, 0, 0)) == 0
        except Exception:
            return True
    except Exception:
        return False


def enforce_no_core() -> bool:
    """RLIMIT_CORE soft=0 (reversible; hard korunur)."""
    try:
        import resource as _res
        try:
            _soft, hard = _res.getrlimit(_res.RLIMIT_CORE)
            _res.setrlimit(_res.RLIMIT_CORE, (0, hard))
            return True
        except Exception:
            return False
    except Exception:
        return False


def harden() -> Dict[str, object]:
    """Tum guclendirmeler (best-effort) + dogrulama raporu."""
    out: Dict[str, object] = {}
    try:
        out["undumpable"] = enforce_undumpable()
    except Exception:
        out["undumpable"] = False
    try:
        out["no_core"] = enforce_no_core()
    except Exception:
        out["no_core"] = False
    try:
        import faulthandler as _fh
        try:
            _fh.disable()
            out["faulthandler_off"] = not bool(_fh.is_enabled())
        except Exception:
            out["faulthandler_off"] = None
    except Exception:
        out["faulthandler_off"] = None
    try:
        d = _prctl_get_dumpable()
        out["dumpable_now"] = d
    except Exception:
        out["dumpable_now"] = None
    return out


# ---------------------------------------------------------------------------
# guard + watchdog
# ---------------------------------------------------------------------------

_WATCHDOGS: List[Tuple[threading.Thread, threading.Event]] = []
_WD_LOCK = threading.Lock()
_MI_ADMIN_MODULES: Dict[str, str] = {}
_MI_ADMIN_LOCKED = False
_MI_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _MI_ADMIN_DENIED
    try:
        if _MI_ADMIN_LOCKED:
            with _WD_LOCK:
                _MI_ADMIN_DENIED += 1
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
            _MI_ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _mi_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _WD_LOCK:
            allowed = dict(_MI_ADMIN_MODULES)
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


def _mi_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _MI_ADMIN_DENIED
    try:
        with _WD_LOCK:
            _MI_ADMIN_DENIED += 1
    except Exception:
        pass
    raise MemoryInspectionDetected("protected")


def _default_trip_action(st: Dict[str, object]) -> None:
    """M4: varsayilan trip-tepkisi — hucreleri wipe'la + cik (fail-closed).

    Operator cb vererek ezer (gozlem-only isteyen). cb=None artik sessiz
    gozlem DEGIL korumali-cikistir.
    """
    try:
        ls = _live_set()
        if ls is not None:
            for c in list(ls):
                try:
                    c.wipe()
                except Exception:
                    pass
    except Exception:
        pass
    try:
        os._exit(1)
    except Exception:
        pass


def _watch_loop(stop: threading.Event, interval: float,
                cb: Optional[Callable[[Dict[str, object]], None]]) -> None:
    try:
        while not stop.wait(interval):
            try:
                st = status()
                if st.get("tripped"):
                    try:
                        (cb if callable(cb) else _default_trip_action)(st)
                    except Exception:
                        pass
                    if not callable(cb):
                        return
            except Exception:
                continue
    except Exception:
        pass


def start_watchdog(interval: float = 1.0,
                   cb: Optional[Callable[[Dict[str, object]], None]] = None):
    global _MI_ADMIN_LOCKED
    try:
        with _WD_LOCK:
            _MI_ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = max(0.2, float(interval))
    except Exception:
        iv = 1.0
    stop = threading.Event()
    th = threading.Thread(target=_watch_loop, args=(stop, iv, cb), daemon=True)
    try:
        with _WD_LOCK:
            _WATCHDOGS.append((th, stop))
    except Exception:
        pass
    try:
        th.start()
    except Exception:
        pass

    def _stop() -> None:
        if not _mi_check_admin():
            _mi_deny_admin("_stop")
        try:
            stop.set()
        except Exception:
            pass

    return _stop


def stop_all_watchdogs() -> int:
    if not _mi_check_admin():
        _mi_deny_admin("stop_all_watchdogs")
    n = 0
    try:
        with _WD_LOCK:
            pairs = list(_WATCHDOGS)
            _WATCHDOGS.clear()
    except Exception:
        pairs = []
    for _th, stop in pairs:
        try:
            stop.set()
            n += 1
        except Exception:
            pass
    return n


def guard(fn: Callable[[], object]) -> object:
    """Cagir-oncesi + sonrasi cift-kontrol (oracle vermez; trip -> raise)."""
    assert_no_inspection()
    try:
        return fn()
    finally:
        assert_no_inspection()
