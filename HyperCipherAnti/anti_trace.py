# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiTrace (Stage 4)
=====================================
Entegre cok katmanli trace/profiler/coverage tespiti + aktif kor kirma.
Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi (5 kaynak):
  [1] Trace-hook notralizasyonu: sys.settrace(None) == PyEval_SetTrace(NULL,NULL)
      (Ned Batchelder trace-func analizi, CPython profiling.rst). Per-frame
      f_trace=None o cerceveyi kor eder; ama saldirgan yeniden kurabilir ->
      tek cozum watchdog ile surekli kirma. Lokal trace'in None donmesi SADECE
      ilk cagrida etkilidir (bpo-56201) -> frame taramasi sart.
  [2] sys.monitoring (3.12+, PEP 669): 6 tool ID (0-5). DEBUGGER=0, COVERAGE=1,
      PROFILER=2, OPTIMIZER=5; 3-4 bosta. get_tool/get_events = tespit,
      clear_tool_id = kor etme (event+callback'leri sokup ID'yi kilitli tutar).
      3.14'te coverage.py + pdb monitoring tabanli -> bu katman sart.
      (docs.python.org/3/library/sys.monitoring, JetBrains PEP669 blog,
      pythoncodecrack 2026-03, pytest-timeout#182)
  [3] Audit-hook REDDEDILDI: PEP 578 + bpo-43438 + D^3CTF writeup -> Python
      hook'lari listede tutulur (gc/ctypes ile silinir), listeleme API'si yok,
      "sandbox icin degil". Bu modul audit-hook KULLANMAZ.
  [4] En guclu port edilebilir mekanizmalar: settrace/setprofile kirma +
      watchdog (coverage CTracer de PyEval_SetTrace kullanir), monitoring
      clear (scalene PROFILER_ID+3/4 fallback kullanir), frame scrub,
      parmak-izi taramasi (coveragepy/coveragepy, microsoft/debugpy kaynakli).
  [5] Coverage parmak izleri: sys.modules['coverage'], COVERAGE_PROCESS_START /
      COVERAGE_PROCESS_CONFIG / COVERAGE_* env, *cov*.pth + sitecustomize
      enjeksiyonu. py-spy HARIC (external sampler, in-process gorunmez).
  [6] FIX-TURU (3 research): threading.settrace/_trace_hook (yeni thread'lere
      bulasir, Lib/threading.py _bootstrap_inner) -> pinli kontrol + kirma;
      C-seviyesi tracer gettrace()'e None dondurur (tespit-kor, Ned Batchelder
      c_traceobj analizi) -> enforcement + paranoid supurme; .coverage dosyasi
      run SONRASI da kalir (false positive) -> kaldirildi, yerine canli
      Coverage.current()/_instances/process_startup.coverage kontrolu.
  [7] MAX-GUC TURU: gc taramasi (sys.modules temizlense bile yasayan
      Coverage/CTracer/PyTracer nesnelerini yakalar, ~4ms); builtins.breakpoint
      pini (pdb yonlendirme sabote edilirse trip); SANS 0xE9 trampoline
      kontrolu anti_hook.py'ye not edildi (bu modulun kapsami degil).
  [8] LATCH-FIX + SQUAT TURU: clear_tool_id ismi birakir -> get_tool latch'i
      free_tool_id ile cozultu (clear yoksa set_events(tid,0) fallback);
      claim_monitoring_ids() 6 ID'yi eventsiz sahiplenir (debugpy/bdb
      use_tool_id'de ValueError yer, baslayamaz); pin'lere threading
      getter'lari + gc.get_objects eklendi.
  [9] PIN-TAMAMLAMA TURU (cynapse arastirmasi): os._exit + monitoring
      func'lari pinlendi, _mon_func pin-canli capraz dogrular (stub=korluk
      yerine trip); _default_action pinli exit kullanir.

Bilinen rezidu (tasinabilir cozum yok, dokumante): dogrudan C ile kurulan ve
c_traceobj=NULL birakan tracer tespit-kordur; break_trace + paranoid watchdog
onu da oldurur (PyEval_SetTrace(NULL,NULL) kaynaga bakmaz).

Entegrasyon prensibi: HICBIR tek kontrole guvenme. Hepsi best-effort kosar,
hata -> bilinmiyor (False) doner, ASLA crash vermez. BIR tanesi bile True
donerse sonuc True. Tespit + aktif kirma (break_trace) + watchdog.
Hata mesaji OP AKTIR (hangi katman tetiklendi soylenmez).

Kullanim:
    from HyperCipherAnti import anti_trace
    anti_trace.assert_no_trace()          # varsa TraceDetected
    if anti_trace.is_traced(): ...        # sessiz kontrol
    anti_trace.break_trace()              # tum korleri kir (opt-in enforce)
    stop = anti_trace.start_watchdog()    # arka plan: tespit->kir->exit
    stop()                                # izlemeyi durdur
"""

from __future__ import annotations

import builtins
import gc
import os
import sys
import threading
import time
from typing import Any, Callable, Dict, Optional

__all__ = [
    "TraceDetected",
    "is_traced",
    "check_all",
    "assert_no_trace",
    "break_trace",
    "claim_monitoring_ids",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]


class TraceDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# Import aninda orijinal referanslari sabitle. Saldirgan sonradan
# sys.settrace = lambda *a, **k: None derse CANLI lookup kor olur
# (break_trace sessizce etkisiz kalir); sabit referans + canli deger
# caprazlanir, tutarsizlik = hook suphesi -> True.
_SYS_SETTRACE = sys.settrace
_SYS_GETTRACE = sys.gettrace
_SYS_SETPROFILE = getattr(sys, "setprofile", None)
_SYS_GETPROFILE = getattr(sys, "getprofile", None)
_SYS_CURRENT_FRAMES = getattr(sys, "_current_frames", None)
_SYS_MONITORING = getattr(sys, "monitoring", None)
_SYS_SETTRACE_ALL = getattr(sys, "_settraceallthreads", None)
_SYS_SETPROFILE_ALL = getattr(sys, "_setprofileallthreads", None)
# threading hook'ları: yeni baslayan her thread'e trace bulastirir
# (Lib/threading.py _bootstrap_inner). Public getter + privat global.
_THREADING_SETTRACE = threading.settrace
_THREADING_GETTRACE = getattr(threading, "gettrace", None)
_THREADING_SETPROFILE = getattr(threading, "setprofile", None)
_THREADING_GETPROFILE = getattr(threading, "getprofile", None)
_MONOTONIC = time.monotonic
_OS_ENVIRON = os.environ
_OS_EXIT = os._exit
_BUILTIN_BREAKPOINT = builtins.breakpoint
_GC_GET_OBJECTS = gc.get_objects


def _check_pinned_mismatch() -> bool:
    """Kritik API'ler monkey-patch'lenmis mi (kor kirma stub'landi mi)?"""
    try:
        if sys.settrace is not _SYS_SETTRACE:
            return True
    except Exception:
        pass
    try:
        if sys.gettrace is not _SYS_GETTRACE:
            return True
    except Exception:
        pass
    try:
        if _SYS_SETPROFILE is not None and sys.setprofile is not _SYS_SETPROFILE:
            return True
    except Exception:
        pass
    try:
        if _SYS_GETPROFILE is not None and sys.getprofile is not _SYS_GETPROFILE:
            return True
    except Exception:
        pass
    try:
        if _SYS_CURRENT_FRAMES is not None and sys._current_frames is not _SYS_CURRENT_FRAMES:
            return True
    except Exception:
        pass
    try:
        if _SYS_MONITORING is not None and sys.monitoring is not _SYS_MONITORING:
            return True
    except Exception:
        pass
    try:
        if threading.settrace is not _THREADING_SETTRACE:
            return True
    except Exception:
        pass
    try:
        if _THREADING_SETPROFILE is not None and threading.setprofile is not _THREADING_SETPROFILE:
            return True
    except Exception:
        pass
    try:
        if os.environ is not _OS_ENVIRON:
            return True
    except Exception:
        pass
    try:
        if builtins.breakpoint is not _BUILTIN_BREAKPOINT:
            return True
    except Exception:
        pass
    try:
        if threading.gettrace is not _THREADING_GETTRACE:
            return True
    except Exception:
        pass
    try:
        if _THREADING_GETPROFILE is not None and threading.getprofile is not _THREADING_GETPROFILE:
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
        mon = _SYS_MONITORING
        if mon is not None:
            if getattr(mon, "get_events", None) is not _MON_GET_EVENTS:
                return True
    except Exception:
        pass
    try:
        mon = _SYS_MONITORING
        if mon is not None:
            if getattr(mon, "use_tool_id", None) is not _MON_USE_TOOL:
                return True
    except Exception:
        pass
    return False


def _is_genuine_builtin(ref, home_modname: str) -> bool:
    """HIGH-kosulu: pin'li ref GERCEK mi? (pre-import korluk-kapagi).

    Research (inspect.isbuiltin + CPython test_funcattrs): C-builtin'ler
    (a) types.BuiltinFunctionType ornegi, (b) __code__ YOK, (c) __self__
    ev-modulu, (d) __module__ ev-modul adi. Ayrica dogal-istisnalar:
    os.* C-fonksiyonlari nt/posix modulunden gelir (__self__/__module__
    'nt'/'posix' mesrudur); threading.settrace KANONIK OLARAK saf-Python'dur
    (Lib/threading.py) — onun icin stdlib-dosya + modul-adi capraz kontrolu.
    Python-seviyesi notrleyici (baska modulden lambda/def) tum dallarda
    duser. C-seviyesi yama gorunmez (dokumante rezidu).
    """
    try:
        import types as _t
        try:
            home_variants = {"os": ("os", "nt", "posix"),
                             "sys": ("sys",),
                             "builtins": ("builtins",),
                             "threading": ("threading",)}.get(
                                 home_modname, (home_modname,))
        except Exception:
            home_variants = (home_modname,)
        if isinstance(ref, _t.BuiltinFunctionType):
            try:
                if hasattr(ref, "__code__"):
                    return False
            except Exception:
                return False
            try:
                selfmod = getattr(getattr(ref, "__self__", None), "__name__", None)
                if selfmod is not None and selfmod not in home_variants:
                    return False
            except Exception:
                pass
            try:
                if getattr(ref, "__module__", None) not in (home_variants + (None,)):
                    return False
            except Exception:
                return False
            return True
        if isinstance(ref, _t.FunctionType):
            try:
                if getattr(ref, "__module__", None) != home_modname:
                    return False
                code = getattr(ref, "__code__", None)
                fn = getattr(code, "co_filename", "") if code is not None else ""
                if not fn:
                    return False
                try:
                    import sysconfig as _sc
                    std = _sc.get_path("stdlib")
                except Exception:
                    std = ""
                if not std:
                    return False
                try:
                    import os as _o
                    if not _o.path.abspath(fn).startswith(_o.path.abspath(std)):
                        return False
                except Exception:
                    return False
                return True
            except Exception:
                return False
        return False
    except Exception:
        return False


def _check_pin_provenance() -> bool:
    """HIGH: pin'ler import-aninda zehirli mi? (pre-import notrleme).

    Pin kimlik-esitligi malicious==malicious karsilastirir — kaynagi
    dogrulanmamis pin kor gorur. Davranis + tip + ev-modul capraz
    kontrolu sahte pin'i yakalar. Boot-sirasi kontrati (bu modul ILK
    import edilmeli) + bu check birlikte savunur.
    """
    try:
        probes = (
            (_SYS_SETTRACE, "sys"),
            (_SYS_GETTRACE, "sys"),
            (_OS_EXIT, "os"),
            (_BUILTIN_BREAKPOINT, "builtins"),
            (_THREADING_SETTRACE, "threading"),
        )
        for ref, home in probes:
            try:
                if ref is None:
                    continue
                if not _is_genuine_builtin(ref, home):
                    return True
            except Exception:
                continue
        try:
            if _SYS_MONITORING is not None and not isinstance(
                    _SYS_MONITORING, type(sys)):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return True


def _check_threading_hooks() -> bool:
    try:
        gt = _THREADING_GETTRACE
        if callable(gt):
            try:
                if gt() is not None:
                    return True
            except Exception:
                pass
        try:
            if getattr(threading, "_trace_hook", None) is not None:
                return True
        except Exception:
            pass
        gp = _THREADING_GETPROFILE
        if callable(gp):
            try:
                if gp() is not None:
                    return True
            except Exception:
                pass
        try:
            if getattr(threading, "_profile_hook", None) is not None:
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# [1] Trace/profile-hook katmani (settrace + setprofile, pinli+canli)
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
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# [2] Frame-duzeyi kor taramasi (f_trace kalintisi)
# ---------------------------------------------------------------------------

def _iter_all_frames() -> Any:
    seen = set()
    try:
        if _SYS_CURRENT_FRAMES is not None:
            try:
                for fr in list(_SYS_CURRENT_FRAMES().values()):
                    try:
                        if id(fr) not in seen:
                            seen.add(id(fr))
                            yield fr
                    except Exception:
                        continue
            except Exception:
                pass
    except Exception:
        pass
    try:
        import types as _t
        count = 0
        for ob in _GC_GET_OBJECTS():
            try:
                count += 1
                if count > 30000:
                    break
                if isinstance(ob, _t.FrameType):
                    if id(ob) not in seen:
                        seen.add(id(ob))
                        yield ob
            except Exception:
                continue
    except Exception:
        pass


def _check_frame_trace() -> bool:
    """Canli + gc-erisilebilir frame'lerde f_trace kalmis mi?"""
    try:
        for fr in _iter_all_frames():
            try:
                f = fr
                while f is not None:
                    try:
                        if getattr(f, "f_trace", None) is not None:
                            return True
                    except Exception:
                        pass
                    try:
                        f = f.f_back
                    except Exception:
                        break
            except Exception:
                continue
    except Exception:
        pass
    return False


def _scrub_frames() -> int:
    """Tum erisilebilir frame'lerden f_trace'i sok. Donus: temizlenen sayisi."""
    cleaned = 0
    try:
        for fr in _iter_all_frames():
            try:
                f = fr
                while f is not None:
                    try:
                        if getattr(f, "f_trace", None) is not None:
                            try:
                                f.f_trace = None
                            except Exception:
                                pass
                            cleaned += 1
                    except Exception:
                        pass
                    try:
                        f.f_trace_lines = False
                    except Exception:
                        pass
                    try:
                        f.f_trace_opcodes = False
                    except Exception:
                        pass
                    try:
                        f = f.f_back
                    except Exception:
                        break
            except Exception:
                continue
    except Exception:
        pass
    return cleaned


def _verify_clean() -> bool:
    try:
        try:
            if _SYS_GETTRACE() is not None:
                return False
        except Exception:
            pass
        try:
            gp = _SYS_GETPROFILE
            if callable(gp) and gp() is not None:
                return False
        except Exception:
            pass
        try:
            if _THREADING_GETTRACE is not None:
                try:
                    if _THREADING_GETTRACE() is not None:
                        return False
                except Exception:
                    pass
        except Exception:
            pass
        try:
            tgp = _THREADING_GETPROFILE
            if callable(tgp) and tgp() is not None:
                return False
        except Exception:
            pass
        if _check_frame_trace():
            return False
        if _check_monitoring():
            return False
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# [3] sys.monitoring katmani (3.12+; debugpy/coverage/pdb backend'i)
# ---------------------------------------------------------------------------

_MON_TOOL_IDS = (0, 1, 2, 3, 4, 5)
# Squatter adi bilerek siradan bir tool adi: get_tool() ciktisini okuyan
# saldirgana "coverage" gorunur, koruma modulu ele verilmez (oracle kapali).
_MON_SQUAT_NAME = "coverage"


def _mon_ref(name: str):
    try:
        mon = _SYS_MONITORING
        if mon is None:
            return None
        fn = getattr(mon, name, None)
        return fn if callable(fn) else None
    except Exception:
        return None


_MON_GET_EVENTS = _mon_ref("get_events")
_MON_GET_TOOL = _mon_ref("get_tool")
_MON_USE_TOOL = _mon_ref("use_tool_id")
_MON_CLEAR_TOOL = _mon_ref("clear_tool_id")
_MON_FREE_TOOL = _mon_ref("free_tool_id")
_MON_SET_EVENTS = _mon_ref("set_events")


def _mon_func(name: str):
    try:
        mon = _SYS_MONITORING
        if mon is None:
            return None
        live = getattr(mon, name, None)
        pinned = {
            "get_events": _MON_GET_EVENTS,
            "get_tool": _MON_GET_TOOL,
            "use_tool_id": _MON_USE_TOOL,
            "clear_tool_id": _MON_CLEAR_TOOL,
            "free_tool_id": _MON_FREE_TOOL,
            "set_events": _MON_SET_EVENTS,
        }.get(name)
        if pinned is None or live is not pinned:
            return None
        return pinned
    except Exception:
        return None


def _check_monitoring() -> bool:
    try:
        mon = _SYS_MONITORING
        if mon is None:
            return False
        get_events = _mon_func("get_events")
        get_tool = _mon_func("get_tool")
        if get_events is None:
            return False
        for tid in _MON_TOOL_IDS:
            try:
                if int(get_events(tid)) != 0:
                    return True
            except Exception:
                continue
            try:
                if get_tool is not None and get_tool(tid) not in (None, _MON_SQUAT_NAME):
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _clear_monitoring() -> int:
    try:
        mon = _SYS_MONITORING
        if mon is None:
            return 0
        get_events = _mon_func("get_events")
        get_tool = _mon_func("get_tool")
        clear_tool = _mon_func("clear_tool_id")
        free_tool = _mon_func("free_tool_id")
        set_events = _mon_func("set_events")
        use_tool = _mon_func("use_tool_id")
        if get_events is None:
            return 0
        cleared = 0
        for tid in _MON_TOOL_IDS:
            try:
                try:
                    ev = int(get_events(tid))
                except Exception:
                    ev = 0
                try:
                    nm = get_tool(tid) if get_tool is not None else None
                except Exception:
                    nm = None
                if ev == 0 and nm in (None, _MON_SQUAT_NAME):
                    continue
                if clear_tool is not None:
                    try:
                        clear_tool(tid)
                    except Exception:
                        pass
                elif set_events is not None:
                    try:
                        set_events(tid, 0)
                    except Exception:
                        pass
                if nm != _MON_SQUAT_NAME and free_tool is not None:
                    try:
                        free_tool(tid)
                    except Exception:
                        pass
                if use_tool is not None:
                    try:
                        use_tool(tid, _MON_SQUAT_NAME)
                        cleared += 1
                        continue
                    except Exception:
                        pass
                cleared += 1
            except Exception:
                continue
        return cleared
    except Exception:
        pass
    return 0


def claim_monitoring_ids() -> None:
    """Bos + yabanci-tutan ID'leri tahliye edip squat'la (oracle sessiz)."""
    try:
        mon = _SYS_MONITORING
        if mon is None:
            return None
        use_tool = _mon_func("use_tool_id")
        get_tool = _mon_func("get_tool")
        clear_tool = _mon_func("clear_tool_id")
        free_tool = _mon_func("free_tool_id")
        if use_tool is None:
            return None
        for tid in _MON_TOOL_IDS:
            try:
                try:
                    cur = get_tool(tid) if get_tool is not None else None
                except Exception:
                    cur = None
                if cur == _MON_SQUAT_NAME:
                    continue
                if cur is not None:
                    try:
                        if clear_tool is not None:
                            clear_tool(tid)
                    except Exception:
                        pass
                    try:
                        if free_tool is not None:
                            free_tool(tid)
                    except Exception:
                        pass
                try:
                    use_tool(tid, _MON_SQUAT_NAME)
                except Exception:
                    continue
            except Exception:
                continue
    except Exception:
        pass
    return None


# [4] Profiler/coverage parmak-izi katmani (sys.modules + canli instance + env)
# ---------------------------------------------------------------------------

_TRACER_MODULES = frozenset({
    # coverage olcum
    "coverage", "coverage.control", "coverage.collector", "coverage.ctracer",
    # stdlib trace/profile
    "trace", "profile", "cProfile", "pstats",
    # harici profiler'lar (in-process calisanlar)
    "line_profiler", "kernprof",
    "pyinstrument", "yappi", "pprofile", "vprof", "pycallgraph",
    "scalene", "hunter", "viztracer", "py_spy",
    # coverage-rehberli fuzzer'lar (in-process bytecode enstrumantasyonu:
    # atheris instrument_imports/instrument_all, hypothesis fuzz_one_input)
    "atheris", "hypothesis", "hypofuzz",
    # debugger-tracer'lar (trace altyapisi paylasir)
    "pdb", "ipdb", "rpdb", "pudb", "bdb",
    "pydevd", "pydevd_frame_eval_cython", "debugpy", "ptvsd",
})


def _check_tracer_instances() -> bool:
    """MED-alias-kapagi: modul ADI ne olursa olsun tracer SINIF/obje taramasi.

    Alias-import ayni code-object'i tasir: Coverage/CTracer/PyTracer/
    LineProfiler/YappiStat tipleri + started bayraklari isimden bagimsiz
    aranir. sys.modules'taki HER modulun attr'leri yoklanir (cap'li).
    """
    try:
        mods = getattr(sys, "modules", None)
        if not mods:
            return False
        try:
            items = list(mods.items())[:4096]
        except Exception:
            return False
        _type_names = ("Coverage", "CTracer", "PyTracer", "LineProfiler",
                       "KernelTracer", "StatCollector", "VizTracer",
                       "DebugClient", "PyDB", "ThreadTracer", "YappiStat")
        for _mn, mod in items:
            try:
                d = getattr(mod, "__dict__", None)
                if not isinstance(d, dict):
                    continue
                try:
                    vals = list(d.values())[:512]
                except Exception:
                    continue
                for v in vals:
                    try:
                        t = type(v)
                        tn = getattr(t, "__name__", "") or ""
                        tm = getattr(t, "__module__", "") or ""
                        # Sinif/fonksiyon NESNESI icin kendi adi da yoklanir
                        # (Coverage SINIFI: type(v)='type', v.__name__='Coverage').
                        try:
                            own = getattr(v, "__name__", "") or ""
                        except Exception:
                            own = ""
                    except Exception:
                        continue
                    try:
                        low = (tm + "." + tn).lower()
                    except Exception:
                        continue
                    if (tn in _type_names or own in _type_names
                            or "coverage" in tm.lower() or "tracer" in low
                            or "trace" in tn.lower() or "coverage" in own.lower()):
                        try:
                            if getattr(v, "_started", False) or getattr(v, "started", False):
                                return True
                        except Exception:
                            pass
                        try:
                            if own in ("Coverage", "CTracer", "PyTracer", "LineProfiler", "VizTracer"):
                                return True
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception:
        pass
    return False


def _check_tracer_modules() -> bool:
    try:
        mods = getattr(sys, "modules", None)
        if not mods:
            return False
        for name in _TRACER_MODULES:
            try:
                if name in mods:
                    return True
            except Exception:
                continue
        # Prefiks supurme: debugpy.common, pydevd._pydevd_bundle,
        # viztracer.*, scalene.* gibi alt moduller (tam-eslesme kor).
        try:
            tops = set()
            for entry in _TRACER_MODULES:
                try:
                    tops.add(entry.split(".", 1)[0].lower())
                except Exception:
                    continue
            for key in mods:
                try:
                    if key.split(".", 1)[0].lower() in tops:
                        return True
                except Exception:
                    continue
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_coverage_live() -> bool:
    try:
        mods = getattr(sys, "modules", None)
        if not mods:
            return False
        try:
            covmod = mods.get("coverage")
        except Exception:
            covmod = None
        if covmod is None:
            return False
        try:
            covcls = getattr(covmod, "Coverage", None)
            if covcls is not None:
                try:
                    cur = covcls.current()
                    if cur is not None:
                        return True
                except Exception:
                    pass
                try:
                    if getattr(covcls, "_instances", None):
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        try:
            psu = getattr(covmod, "process_startup", None)
            if psu is not None and getattr(psu, "coverage", None) is not None:
                return True
        except Exception:
            pass
    except Exception:
        pass
    return False


_GC_TTL = 1.0
_GC_CACHE = [0.0, False]


def _check_gc_tracers() -> bool:
    # Tam gc taramasi pahali -> kisa TTL cache (watchdog tick'i hafifler).
    try:
        try:
            now = _MONOTONIC()
        except Exception:
            now = 0.0
        try:
            cached = _GC_CACHE
            if now and (now - cached[0]) < _GC_TTL:
                return cached[1]
        except Exception:
            pass
        hit = _scan_gc_tracers()
        try:
            _GC_CACHE[0] = now
            _GC_CACHE[1] = hit
        except Exception:
            pass
        return hit
    except Exception:
        return False


def _scan_gc_tracers() -> bool:
    try:
        try:
            objs = _GC_GET_OBJECTS()
        except Exception:
            return False
        for ob in objs:
            try:
                t = type(ob)
            except Exception:
                continue
            try:
                mod = getattr(t, "__module__", "") or ""
                name = getattr(t, "__name__", "") or ""
            except Exception:
                continue
            if mod.startswith("coverage") and name in ("Coverage", "CTracer", "PyTracer"):
                try:
                    if name == "Coverage":
                        if getattr(ob, "_started", False):
                            return True
                    else:
                        if getattr(ob, "started", False):
                            return True
                except Exception:
                    continue
            try:
                ml = mod.lower()
            except Exception:
                continue
            if ml in ("yappi", "scalene", "viztracer", "hunter",
                      "pyinstrument", "debugpy", "pydevd",
                      "_pydevd_bundle", "line_profiler", "kernprof"):
                try:
                    if getattr(ob, "started", False) or getattr(ob, "_started", False):
                        return True
                except Exception:
                    pass
                try:
                    if name in ("YappiStat", "KernelTracer", "StatCollector",
                                "LineProfiler", "VizTracer", "DebugClient",
                                "PyDB", "ThreadTracer"):
                        return True
                except Exception:
                    pass
    except Exception:
        pass
    return False


_COVERAGE_ENV_VARS = frozenset({
    "COVERAGE_PROCESS_START",
    "COVERAGE_PROCESS_CONFIG",
    "COVERAGE_COVERAGE",
    "COVERAGE_TESTING",
    "COV_CORE_SOURCE",
    "COV_CORE_DATAFILE",
    "PYTEST_COV",
    "PYDEVD_LOAD_VALUES_ASYNC",
    "PYDEV_CONSOLE_ENCODING",
    "DEBUGPY_RUNNING",
    "DEBUGPY_LAUNCHER_PORT",
    "DEBUGPY_ADAPTER_ENDPOINT",
    "PTVSD_LAUNCHER_PORT",
})

# MED-split: IDE/ortam-baglami isaretleri tracer DEGILDIR (dev self-trip
# kalkani). Ayri bilgi-sinyali; verdict/watchdog'a GIRMEZ.
_IDE_CONTEXT_ENV_VARS = frozenset({
    "VSCODE_PID",
    "PYCHARM_HOSTED",
    "LD_PRELOAD",
    "DYLD_INSERT_LIBRARIES",
})


def _check_coverage_env() -> bool:
    try:
        env = _OS_ENVIRON
        for key in _COVERAGE_ENV_VARS:
            try:
                if key in env:
                    return True
            except Exception:
                continue
        try:
            for key in env:
                try:
                    ku = str(key).upper()
                except Exception:
                    continue
                if ku.startswith("COVERAGE_") or ku.startswith("COV_"):
                    return True
        except Exception:
            pass
    except Exception:
        pass
    return False


def _check_ide_context() -> bool:
    """MED-bilgi: IDE/ortam baglami (verdict-disi; check_all'da raporlanır)."""
    try:
        env = _OS_ENVIRON
        for key in _IDE_CONTEXT_ENV_VARS:
            try:
                if key in env:
                    return True
            except Exception:
                continue
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Aktif koruma: break_trace (opt-in enforce)
# ---------------------------------------------------------------------------

def break_trace() -> None:
    """Tum izleme korlerini kir (oracle sessiz, donus yok).

    Opt-in enforce: cagiran, debugger/profiler baglantisini koparmayi
    goze alir. Saldirgan dongude yeniden kurarsa watchdog ile birlestir.
    """
    try:
        _SYS_SETTRACE(None)
    except Exception:
        pass
    try:
        if callable(_SYS_SETPROFILE):
            _SYS_SETPROFILE(None)
    except Exception:
        pass
    try:
        if callable(_SYS_SETTRACE_ALL):
            _SYS_SETTRACE_ALL(None)
    except Exception:
        pass
    try:
        if callable(_SYS_SETPROFILE_ALL):
            _SYS_SETPROFILE_ALL(None)
    except Exception:
        pass
    try:
        _THREADING_SETTRACE(None)
    except Exception:
        pass
    try:
        if callable(_THREADING_SETPROFILE):
            _THREADING_SETPROFILE(None)
    except Exception:
        pass
    try:
        _scrub_frames()
    except Exception:
        pass
    try:
        _clear_monitoring()
    except Exception:
        pass
    try:
        claim_monitoring_ids()
    except Exception:
        pass
    try:
        for _ in range(3):
            try:
                if _verify_clean():
                    break
            except Exception:
                break
            try:
                _SYS_SETTRACE(None)
            except Exception:
                pass
            try:
                _scrub_frames()
            except Exception:
                pass
            try:
                _clear_monitoring()
            except Exception:
                pass
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def check_all() -> Dict[str, bool]:
    """Tum katmanlari calistir, detayli (debug amacli) sozluk doner.

    URETIMDE check_all() sonucunu loglama/yansitma (oracle olur).
    Uretim karari icin is_traced() kullan.
    """
    results: Dict[str, bool] = {}
    for name, fn in (
        ("trace_hooks", _check_trace_hooks),
        ("threading_hooks", _check_threading_hooks),
        ("frame_trace", _check_frame_trace),
        ("monitoring", _check_monitoring),
        ("pinned_mismatch", _check_pinned_mismatch),
        ("pin_provenance", _check_pin_provenance),
        ("tracer_modules", _check_tracer_modules),
        ("tracer_instances", _check_tracer_instances),
        ("coverage_live", _check_coverage_live),
        ("gc_tracers", _check_gc_tracers),
        ("coverage_env", _check_coverage_env),
        ("ide_context", _check_ide_context),
    ):
        try:
            results[name] = bool(fn())
        except Exception:
            results[name] = True
    return results


def is_traced() -> bool:
    try:
        if _check_trace_hooks():
            return True
        if _check_threading_hooks():
            return True
        if _check_frame_trace():
            return True
        if _check_monitoring():
            return True
        if _check_pinned_mismatch():
            return True
        if _check_pin_provenance():
            return True
        if _check_tracer_modules():
            return True
        if _check_tracer_instances():
            return True
        if _check_coverage_live():
            return True
        if _check_gc_tracers():
            return True
        if _check_coverage_env():
            return True
    except Exception:
        return True
    return False


def assert_no_trace() -> None:
    """Iz suphesi varsa opak TraceDetected firlatir."""
    if is_traced():
        raise TraceDetected("protected")


_WATCHDOGS: list[threading.Event] = []
_WATCHDOGS_LOCK = threading.Lock()
_TR_ADMINS: dict = {}
_TR_ADMIN_LOCKED = False
_TR_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _TR_ADMIN_DENIED
    try:
        if _TR_ADMIN_LOCKED:
            with _WATCHDOGS_LOCK:
                _TR_ADMIN_DENIED += 1
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
            _TR_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _tr_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _WATCHDOGS_LOCK:
            allowed = dict(_TR_ADMINS)
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


def _tr_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _TR_ADMIN_DENIED
    try:
        with _WATCHDOGS_LOCK:
            _TR_ADMIN_DENIED += 1
    except Exception:
        pass
    raise TraceDetected("protected")


def start_watchdog(
    interval: float = 0.5,
    on_detect: Optional[Callable[[], None]] = None,
    daemon: bool = True,
    paranoid: bool = True,
) -> Callable[[], None]:
    """Arka planda periyodik kontrol. Tespitte once kor kirilir (break_trace),
    sonra varsayilan: sessiz os._exit(1).

    paranoid=True: her 10 tick'te bir kosulsuz break_trace supurmesi yapar.
    C-seviyesi tracer'lar gettrace()'e None dondurur (tespit-kor); enforcement
    onlari da oldurur, bu yuzden periyodik supurme tek tasinabilir cozumu.

    on_detect verilirse o cagrilir (ornek: state wipe + exit).
    Donen stop() fonksiyonu izlemeyi durdurur.
    """
    global _TR_ADMIN_LOCKED
    try:
        with _WATCHDOGS_LOCK:
            _TR_ADMIN_LOCKED = True
    except Exception:
        pass
    if interval < 0.1:
        interval = 0.1
    if interval > 2.0:
        interval = 2.0
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
        suspend_strikes = 0
        try:
            last = _MONOTONIC()
        except Exception:
            last = 0.0
        suspend_limit = max(10.0 * interval, 10.0)
        while not stop_event.is_set():
            try:
                try:
                    now = _MONOTONIC()
                    if last and (now - last) > suspend_limit:
                        # LOW-fix: tek clock-adimi oldurmez — iki ARDISIK
                        # asim gerekir (NTP/VM guc-durumu FP kalkani).
                        suspend_strikes += 1
                        if suspend_strikes >= 2:
                            try:
                                action()
                            except Exception:
                                pass
                            return
                    else:
                        suspend_strikes = 0
                    last = now
                except Exception:
                    pass
                hit = (
                    _check_trace_hooks()
                    or _check_threading_hooks()
                    or _check_frame_trace()
                    or _check_monitoring()
                    or _check_pinned_mismatch()
                    or _check_pin_provenance()
                    or _check_tracer_modules()
                    or _check_tracer_instances()
                    or _check_coverage_live()
                    or _check_gc_tracers()
                    or _check_coverage_env()
                )
                tick += 1
                if paranoid and not hit and tick % 10 == 0:
                    try:
                        break_trace()
                    except Exception:
                        pass
                    try:
                        claim_monitoring_ids()
                    except Exception:
                        pass
                if hit:
                    try:
                        break_trace()
                    except Exception:
                        pass
                    try:
                        action()
                    except Exception:
                        pass
                    return
            except Exception:
                pass
            stop_event.wait(interval)

    th = threading.Thread(target=_loop, name="hyper-antitrace", daemon=daemon)
    try:
        th.start()
    except Exception:
        try:
            _OS_EXIT(1)
        except Exception:
            pass
        def _noop() -> None:
            return None
        return _noop

    def _stop() -> None:
        if not _tr_check_admin():
            _tr_deny_admin("_stop")
        stop_event.set()
        with _WATCHDOGS_LOCK:
            try:
                _WATCHDOGS.remove(stop_event)
            except ValueError:
                pass

    return _stop


def stop_all_watchdogs() -> None:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart; liste temizlenir)."""
    if not _tr_check_admin():
        _tr_deny_admin("stop_all_watchdogs")
    with _WATCHDOGS_LOCK:
        events = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    for ev in events:
        try:
            ev.set()
        except Exception:
            continue


class _Guard:
    def __enter__(self) -> "_Guard":
        assert_no_trace()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        if exc_type is None:
            assert_no_trace()
            return False
        if is_traced():
            raise TraceDetected("protected") from exc  # type: ignore[misc]
        return False


def guard() -> _Guard:
    return _Guard()
