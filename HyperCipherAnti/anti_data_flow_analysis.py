# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiDataFlowAnalysis (Stage 4)
================================================
Calisma-aninda veri-akisi / taint-takibi tespiti + taint-yuzey olcumu.
Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi (3 guclu arastirma + en guclu teknikler):
  [1] CodeQL Python dataflow/taint: local (hizli, kesin) vs global
      (yavas, genis) akis; taint = deger-korumayan adimlarla genisletilmis
      akis; kaynak -> sink iliskisi, sanitizer kirilimi; access-path domain
      (konum + alan/zincir); koleksiyonlar: mutator (append/add) lekeyi
      kaba tasir, accessor (get/pop) geri cikarir. Savunma dersi: kritik
      veri hicbir taint-motorunun gordugu kanaldan (trace/frame/audit)
      gecmemeli; kaynak-sink zinciri tek kontrole birakilmamali.
      (CodeQL analyzing-data-flow-in-python + TaintTracking.qll)
  [2] IFDS/SVF tarzi statik veri-akisi: Andersen points-to -> MemSSA ->
      seyrek value-flow grafigi; kenarlar: direct (SSA yereli), memory
      (heap (nesne,alan) yukle/sakla), call (arg->param, return->cagri);
      kritik kural: arg ASLA dogrudan cagri-sonucuna akmaz -> sanitizer
      taint'i saglam kirar. k-object duyarliligi alicilari ayirir.
      Soundy bosluklar: getattr/setattr dinamik ad, eval/exec, generator
      protokolu, istisnai akis. Savunma dersi: dinamik-ad + eval/exec
      yuzeyini kucult, taint-kirilgan tek hat birakma.
      (PyFlow IFDS arxiv 2608.07026 + py-svf-analysis README)
  [3] Dinamik taint (taintmode kutuphanesi + DynaPyt): wrapper alt-sinif +
      propagate_taint kancalari, AST enstrumantasyonu, decorator'lerle
      kaynak/sink/sanitizer isaretleme; calisma-aninda izleme
      sys.settrace / sys.monitoring / audit-hook (PEP 578: settrace,
      setprofile, _getframe, _current_frames) + DynaPyt runtime hook'lari
      uzerinden. Savunma dersi: trace/profile/monitoring AC IKSA ve
      cerceve-erisim (frame) izleri taint-motorunun ayak izidir.
      (Chalmers taint-mode + DynaPyt FSE'22 + PEP 578 + sys belgesi)

Entegrasyon prensibi: HICBIR tek kontrole guvenme. Trip kurali: >=1 STRONG
veya >=2 WEAK. Kritik hata -> True (fail-closed). `dataflow_score()` saf
olcudur (koruma dogrulama icin), trip uretmez. Hata mesaji OP AKTIR.

Kullanim:
    from HyperCipherAnti import anti_data_flow_analysis as adf
    print(adf.dataflow_score(my_func))  # taint-yuzey yogunlugu
    if adf.is_dataflow_analyzed(): ...  # sessiz kontrol
    adf.assert_no_dataflow_analysis()   # varsa DataFlowAnalysisDetected
"""

from __future__ import annotations

import gc
import hashlib
import os
import sys
import threading
import time
from types import BuiltinFunctionType, CodeType, FunctionType
from typing import Callable, Dict, List, Optional, Tuple
import importlib.machinery as _mach

__all__ = [
    "DataFlowAnalysisDetected",
    "is_dataflow_analyzed",
    "check_all",
    "score",
    "status",
    "assert_no_dataflow_analysis",
    "dataflow_score",
    "taint_surface_score",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]


class DataFlowAnalysisDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Pin'li referanslar (kardes B1 deseni).
# ---------------------------------------------------------------------------
_SYS_MODULES = sys.modules
_SYS_CURRENT_FRAMES = getattr(sys, "_current_frames", None)
_SYS_GETTRACE = getattr(sys, "gettrace", None)
_SYS_GETPROFILE = getattr(sys, "getprofile", None)
_GC_GET_OBJECTS = gc.get_objects
_OS_EXIT = os._exit
_HASH_SHA256 = hashlib.sha256
_PERF_COUNTER = time.perf_counter
_THREAD_LOCK = threading.Lock()
_WATCHDOGS: List[Tuple[threading.Thread, threading.Event]] = []
_CANONICAL_FINDER_TYPES = frozenset({
    _mach.BuiltinImporter, _mach.FrozenImporter, _mach.PathFinder,
})
_ADMIN_MODULES: Dict[str, str] = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0
_GC_SCAN_CAP = 150000

_STRONG = 100
_WEAK = 30

# Calisma-aninda taint/veri-akisi motorlari (process-ici yuk STRONG).
# DynaPyt: runtime hook'lu dinamik analiz cercevesi.
# taintmode/pytaint/pyt: wrapper-alt-sinif + propagate kancali taint kutuphaneleri.
# pyflow: IFDS/CPG tabanli Python veri-akisi cercevesi (ZJU-PL).
# py_svf/pysvf: SVF-tarzi value-flow (Andersen+MemSSA) denemeleri.
_TAINT_MODULES = frozenset({
    "dynapyt",
    "taintmode",
    "pytaint",
    "pyt",
    "pyflow",
    "taint",
    "taint_tracker",
    "py_svf",
    "pysvf",
    "dytan",
})

# Statik SAST / taint-kural motorlari (tek basina WEAK: mesru CI kullanimi
# yaygin; taint-motoruyla birlesince STRONG sinyaller zaten trip uretir).
_SAST_MODULES = frozenset({
    "bandit",
    "semgrep",
    "dlint",
    "devskim",
    "bearer",
    "snyk",
    "pysa",
})

# Aktif analiz cerceve imzasi. Motor-ozel isaretler (dynapyt, taintmode,
# pytaint, pyflow, memssa, andersen, valueflow) alt-string olarak aranir.
# Jenerik isaretler (tainted, dataflow, data_flow, taint) segment-esitligi
# ister (`/mydataflow/` gibi mesru yollarda FP vermesin). Kendi dosyamiz
# (anti_data_flow_analysis.py) her zaman atlanir (self-FP karsiti).
_FRAME_MARKS_SPECIFIC = ("dynapyt", "taintmode", "pytaint", "pyflow",
                         "memssa", "andersen", "valueflow", "value_flow")
_FRAME_MARKS_GENERIC = ("tainted", "dataflow", "data_flow", "taint")
_FRAME_MARKS_SHORT = ("pyt", "svf", "cpg", "ddg", "pdg", "ifds")
_SELF_BASENAME = "anti_data_flow_analysis.py"
try:
    _SELF_ABS = os.path.normcase(os.path.abspath(__file__))
except Exception:
    _SELF_ABS = ""


def _base_tokens(base_noext: str) -> tuple:
    try:
        cur: list = []
        out: list = []
        for ch in (base_noext or ""):
            try:
                if ch.isalnum():
                    cur.append(ch)
                else:
                    if cur:
                        out.append("".join(cur))
                        cur = []
            except Exception:
                continue
        if cur:
            out.append("".join(cur))
        return tuple(out)
    except Exception:
        return ()


def _pinned_mismatch() -> bool:
    try:
        if sys.modules is not _SYS_MODULES:
            return True
    except Exception:
        pass
    try:
        if gc.get_objects is not _GC_GET_OBJECTS:
            return True
    except Exception:
        pass
    try:
        if hashlib.sha256 is not _HASH_SHA256:
            return True
    except Exception:
        pass
    try:
        if time.perf_counter is not _PERF_COUNTER:
            return True
    except Exception:
        pass
    try:
        _gt = sys.gettrace
        if type(_gt) is not BuiltinFunctionType or getattr(_gt, "__self__", None) is not sys:
            return True
    except Exception:
        pass
    try:
        _gp = sys.getprofile
        if type(_gp) is not BuiltinFunctionType or getattr(_gp, "__self__", None) is not sys:
            return True
    except Exception:
        pass
    return False


def _gc_module_tops():
    """Derin-teyit: gc'deki canli modul nesnelerinin ust-seviye adlari."""
    tops = set()
    try:
        import types as _t
        n = 0
        for ob in gc.get_objects():
            n += 1
            if n > _GC_SCAN_CAP:
                break
            try:
                if type(ob) is _t.ModuleType:
                    nm = getattr(ob, "__name__", "")
                    if isinstance(nm, str) and nm:
                        tops.add(nm.split(".", 1)[0].lower())
            except Exception:
                continue
    except Exception:
        pass
    return tops


def _module_present(names: frozenset) -> bool:
    """Ust-seviye modul varligi: sys.modules + gc-derin-teyit."""
    try:
        live = sys.modules
    except Exception:
        return False
    try:
        for name in names:
            try:
                if name in live:
                    return True
            except Exception:
                continue
        try:
            keys = list(live.keys())
        except Exception:
            keys = []
        for key in keys:
            try:
                top = key.split(".", 1)[0].lower()
            except Exception:
                continue
            if top in names:
                return True
        try:
            tops = _gc_module_tops()
        except Exception:
            tops = set()
        for name in names:
            try:
                if name in tops:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_taint_engines() -> bool:
    """STRONG: taint/veri-akisi motoru yuklu mu."""
    try:
        return _module_present(_TAINT_MODULES)
    except Exception:
        return True


def _check_sast_tools() -> bool:
    """WEAK: SAST/taint-kural araci yuklu mu."""
    try:
        return _module_present(_SAST_MODULES)
    except Exception:
        return False


def _check_active_frames() -> bool:
    """STRONG: veri-akisi motoru cercevesi su an calisiyor mu."""
    get_frames = _SYS_CURRENT_FRAMES
    if get_frames is None:
        return False
    try:
        frames = get_frames()
    except Exception:
        return True
    try:
        for _tid, frame in frames.items():
            f = frame
            depth = 0
            while f is not None and depth < 64:
                depth += 1
                try:
                    path = (f.f_code.co_filename or "").lower().replace("\\", "/")
                except Exception:
                    break
                try:
                    try:
                        own = os.path.normcase(os.path.abspath(path)) == _SELF_ABS if _SELF_ABS else path.endswith(_SELF_BASENAME)
                    except Exception:
                        own = path.endswith(_SELF_BASENAME)
                    if own:
                        try:
                            f = f.f_back
                        except Exception:
                            break
                        continue
                    for mark in _FRAME_MARKS_SPECIFIC:
                        if mark in path:
                            return True
                    try:
                        segs = path.split("/")
                        base = segs[-1] if segs else ""
                    except Exception:
                        segs = ()
                        base = ""
                    try:
                        base_noext = base.rsplit(".", 1)[0] if "." in base else base
                    except Exception:
                        base_noext = base
                    for mark in _FRAME_MARKS_GENERIC:
                        try:
                            if mark == base_noext:
                                return True
                            for seg in segs:
                                if seg == mark:
                                    return True
                        except Exception:
                            continue
                    for mark in _FRAME_MARKS_SHORT:
                        try:
                            if mark == base_noext:
                                return True
                            for tok in _base_tokens(base_noext):
                                if tok == mark:
                                    return True
                            for seg in segs:
                                if seg == mark:
                                    return True
                        except Exception:
                            continue
                except Exception:
                    pass
                try:
                    f = f.f_back
                except Exception:
                    break
        return False
    except Exception:
        return True


def _check_runtime_trace() -> bool:
    """STRONG: dinamik taint izleme kanali acik mi (canli+yapisal).

    F25 duzeltmesi: modul-globali re-pin'e dayanmaz; CANLI sys.gettrace /
    getprofile + builtin-yapi dogrulamasi kullanilir. Alias'lanmis evil
    (None donen) yapi testinde elenir. DynaPyt/taintmode tarzi motorlar
    veri-akisini settrace/monitoring ile gozler.
    """
    try:
        try:
            gt = sys.gettrace
        except Exception:
            return True
        try:
            import types as _t
            if type(gt) is not _t.BuiltinFunctionType or getattr(gt, "__self__", None) is not sys:
                return True
        except Exception:
            return True
        try:
            if gt() is not None:
                return True
        except Exception:
            return True
    except Exception:
        pass
    try:
        try:
            gp = sys.getprofile
        except Exception:
            return True
        try:
            import types as _t2
            if type(gp) is not _t2.BuiltinFunctionType or getattr(gp, "__self__", None) is not sys:
                return True
        except Exception:
            return True
        try:
            if gp() is not None:
                return True
        except Exception:
            return True
    except Exception:
        pass
    # sys.monitoring (3.12+): herhangi bir olay etkinse izleme vardir.
    try:
        mon = getattr(sys, "monitoring", None)
        if mon is not None:
            try:
                get_events = getattr(mon, "get_events", None)
                if get_events is not None:
                    for tool_id in (0, 1, 2, 3, 4, 5):
                        try:
                            if int(get_events(tool_id)) != 0:
                                return True
                        except Exception:
                            continue
            except Exception:
                pass
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# Taint-yuzey skoru (saf olcum):
#   skor = (STORE/SINK-agirlikli veri-akisi op'lari) / toplam-op
# Kaynak->sink zincirini kuran op'lar (STORE_SUBSCR/STORE_ATTR/CALL/BINARY_
# op'lar) agirliklidir; saf olcum oldugu icin trip uretmez. Surum-bagimsiz
# olmasi icin stdlib `dis` LAZY import edilir ve sys.modules'e BIZ eklediysek
# geri kaldirilir (kardes modul WEAK sinyallerini kirletmemek icin).
# ---------------------------------------------------------------------------
_SINK_OPS = frozenset({
    "STORE_SUBSCR", "STORE_ATTR", "STORE_GLOBAL", "STORE_NAME",
    "CALL", "CALL_FUNCTION", "CALL_FUNCTION_EX", "CALL_METHOD",
    "CALL_FINALLY", "SEND",
})
_FLOW_OPS = frozenset({
    "BINARY_ADD", "BINARY_SUBSCR", "BINARY_OP", "BINARY_SLICE",
    "FORMAT_VALUE", "BUILD_STRING", "JOIN", "BUILD_LIST", "BUILD_MAP",
    "BUILD_TUPLE", "BUILD_SET", "LIST_EXTEND", "MAP_ADD", "SET_ADD",
    "DICT_UPDATE", "LOAD_ATTR", "LOAD_METHOD",
})


def dataflow_score(target) -> Optional[float]:
    """Taint-yuzey yogunlugu 0.0-1.0 (saf; trip uretmez).

    hedef: fonksiyon / kod nesnesi. Yuksek skor = veri-akisi analizi icin
    zengin hedef (cok atama/cagri/birlestirme), dusuk skor = seyrek yuzey.
    Olculemeyen durum None doner (0.0 "temiz" degil, "bilinmiyor"dur).
    Asiri buyuk fonksiyonlarda olcum reddedilir (DoS karsiti sinir).
    """
    try:
        if isinstance(target, FunctionType):
            code = target.__code__
        elif isinstance(target, CodeType):
            code = target
        else:
            return None
        try:
            if len(code.co_code) > 60000:
                return None
        except Exception:
            pass
        added_dis = False
        try:
            added_dis = "dis" not in _SYS_MODULES
            import dis as _dis
        except Exception:
            return None
        try:
            try:
                instrs = list(_dis.get_instructions(code))
            except Exception:
                return None
            total = len(instrs)
            if total < 4:
                return None
            weighted = 0.0
            for ins in instrs:
                try:
                    op = ins.opname
                except Exception:
                    continue
                try:
                    if op.startswith("INSTRUMENTED_"):
                        op = op[13:]
                    if op in _SINK_OPS or op.startswith("CALL"):
                        weighted += 1.0
                    elif op in _FLOW_OPS:
                        weighted += 0.5
                    elif op.startswith(("LOAD_", "STORE_", "DELETE_")):
                        weighted += 0.25
                except Exception:
                    continue
            frac = weighted / float(total)
            if frac < 0.0:
                return None
            if frac > 1.0:
                return 1.0
            return frac
        finally:
            try:
                # Kardes WEAK sinyalini kirletmemek icin biz eklediysek kaldir.
                import sys as _s
                if added_dis and "dis" in _s.modules:
                    try:
                        del _s.modules["dis"]
                    except Exception:
                        pass
            except Exception:
                pass
    except Exception:
        return None


def taint_surface_score(target) -> float:
    """`dataflow_score` takma adi (taint-literaturu adlandirmasi)."""
    try:
        return dataflow_score(target)
    except Exception:
        return None


# Bilinen-masum finder'lar: EXACT-TYPE kanonik kume + tam-etiket eslesme.
# `__module__` spoof'lanabilir string'dir; "mock"/"importlib"/"_bootstrap"
# prefix muafiyeti KALDIRILDI; unittest/pytest test-kosucu muafiyeti korunur.
_TRUSTED_FINDERS = frozenset({
    "_distutils_hack.distutilsmetafinder",
    "_pynvml_redirector.pynvmlfinder",
})
_TRUSTED_PREFIXES = ("unittest", "_pytest", "pytest")


def _finder_tag(finder) -> str:
    try:
        cls = finder if isinstance(finder, type) else type(finder)
        mod = getattr(cls, "__module__", "") or ""
        name = getattr(cls, "__name__", "") or ""
        return (mod + "." + name).lower()
    except Exception:
        return "?"


def _check_foreign_finder() -> bool:
    """WEAK: meta-path'te yabanci finder var mi (exact-type + tam-etiket)."""
    try:
        path = sys.meta_path
    except Exception:
        return False
    try:
        for finder in path:
            try:
                if type(finder) in _CANONICAL_FINDER_TYPES:
                    continue
            except Exception:
                pass
            tag = _finder_tag(finder)
            if tag in _TRUSTED_FINDERS:
                continue
            if tag.startswith(_TRUSTED_PREFIXES):
                continue
            if tag.startswith(("_frozen_importlib", "importlib",
                               "_bootstrap", "zipimport")):
                continue
            if "hyper cipher" in tag or "hyperct" in tag:
                continue
            return True  # ilk yabanci yeterli (WEAK)
        return False
    except Exception:
        return False


def check_all() -> Dict[str, bool]:
    """Tum sinyaller (True=risk). Kritik hata -> True (fail-closed)."""
    out: Dict[str, bool] = {}
    try:
        out["pinned_mismatch"] = _pinned_mismatch()
    except Exception:
        out["pinned_mismatch"] = True
    try:
        out["taint_engine"] = _check_taint_engines()
    except Exception:
        out["taint_engine"] = True
    try:
        out["active_dataflow_frame"] = _check_active_frames()
    except Exception:
        out["active_dataflow_frame"] = True
    try:
        out["runtime_trace_active"] = _check_runtime_trace()
    except Exception:
        out["runtime_trace_active"] = True
    try:
        out["sast_tool_present"] = _check_sast_tools()
    except Exception:
        out["sast_tool_present"] = False
    try:
        out["foreign_finder"] = _check_foreign_finder()
    except Exception:
        out["foreign_finder"] = False
    return out


def score() -> Tuple[int, int, int]:
    """(strong_sayisi, weak_sayisi, toplam)."""
    try:
        signals = check_all()
    except Exception:
        return (1, 0, _STRONG)
    strong = 0
    weak = 0
    try:
        for key in ("pinned_mismatch", "taint_engine",
                    "active_dataflow_frame", "runtime_trace_active"):
            if signals.get(key):
                strong += 1
        for key in ("sast_tool_present", "foreign_finder"):
            if signals.get(key):
                weak += 1
    except Exception:
        return (1, 0, _STRONG)
    return (strong, weak, strong * _STRONG + weak * _WEAK)


def is_dataflow_analyzed() -> bool:
    """Trip kurali: >=1 STRONG veya >=2 WEAK. Hata -> True."""
    try:
        strong, weak, _total = score()
        return strong >= 1 or weak >= 2
    except Exception:
        return True


def status() -> Dict[str, object]:
    """Durum ozeti (sinyal isimleri acik, degerler bool)."""
    try:
        signals = check_all()
    except Exception:
        signals = {}
    try:
        strong, weak, total = score()
    except Exception:
        strong, weak, total = (1, 0, _STRONG)
    try:
        verdict = is_dataflow_analyzed()
    except Exception:
        verdict = True
    return {"dataflow_analyzed": verdict, "strong": strong, "weak": weak,
            "score": total, "signals": signals,
            "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
            "admin_denied": _ADMIN_DENIED}


def assert_no_dataflow_analysis() -> None:
    """Trip varsa opak hata yukselt."""
    if is_dataflow_analyzed():
        raise DataFlowAnalysisDetected("protected")


def _watchdog_loop(stop_event: threading.Event, interval: float,
                   on_trip: Optional[Callable[[], None]]) -> None:
    try:
        while not stop_event.wait(interval):
            try:
                tripped = is_dataflow_analyzed()
            except Exception:
                tripped = True
            if tripped:
                try:
                    if on_trip is not None:
                        on_trip()
                except Exception:
                    pass
                try:
                    _OS_EXIT(1)
                except Exception:
                    pass
                return
    except Exception:
        pass


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _THREAD_LOCK:
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
        with _THREAD_LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _THREAD_LOCK:
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
        with _THREAD_LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise DataFlowAnalysisDetected("protected")


def start_watchdog(interval: float = 0.5,
                   on_trip: Optional[Callable[[], None]] = None):
    """Watchdog baslat, durdurma fonksiyonu don (opt-in; uretim profili)."""
    global _ADMIN_LOCKED
    try:
        with _THREAD_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
    except Exception:
        iv = 0.5
    if iv < 0.05:
        iv = 0.05
    if iv > 60.0:
        iv = 60.0
    stop_event = threading.Event()
    thread = threading.Thread(target=_watchdog_loop, args=(stop_event, iv, on_trip), daemon=True)
    with _THREAD_LOCK:
        _WATCHDOGS.append((thread, stop_event))
    try:
        thread.start()
    except Exception:
        pass

    def _stop() -> None:
        try:
            stop_event.set()
        except Exception:
            pass

    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart).

    Donus: durdurulan sayisi.
    """
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    count = 0
    with _THREAD_LOCK:
        items = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    for _thread, stop_event in items:
        try:
            stop_event.set()
            count += 1
        except Exception:
            continue
    return count


def guard(func):
    """Dekorator: cagri oncesi sessiz kontrol, trip varsa opak hata."""
    try:
        if not callable(func):
            return func
    except Exception:
        return func

    def _wrapped(*args, **kwargs):
        if is_dataflow_analyzed():
            raise DataFlowAnalysisDetected("protected")
        return func(*args, **kwargs)

    try:
        _wrapped.__name__ = getattr(func, "__name__", "_wrapped")
        _wrapped.__qualname__ = getattr(func, "__qualname__", "_wrapped")
        _wrapped.__doc__ = getattr(func, "__doc__", None)
        try:
            _wrapped.__dict__.update(getattr(func, "__dict__", {}))
        except Exception:
            pass
        try:
            _wrapped.__annotations__ = dict(getattr(func, "__annotations__", {}))
        except Exception:
            pass
    except Exception:
        pass
    return _wrapped
