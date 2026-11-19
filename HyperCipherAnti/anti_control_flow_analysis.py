# -*- coding: utf-8 -*-
"""
HyperCipherAnti - AntiControlFlowAnalysis (Stage 4)
===================================================
Calisma-aninda CFG-kurtarma / sembolik-yurutme tespiti + dispatcher
skorlama. Stdlib-only, cross-platform, fail-closed, sessiz (oracle vermez).

Arastirma sentezi (3 guclu arastirma + en guclu teknikler):
  [1] Duzenleyici tespiti: duzlestirilmis CFG'de dispatcher donguyu kontrol
      eder ve bloklarin coguna hukumeder (dominator + back-edge). Skor =
      domine-edilen-blok / toplam-blok; >=0.9 duzlestirme suphesi. Ileri
      varyantlar (indirect/call-tabanli dispatch) bu skoru atlatir -> tek
      heuristik yetmez, sinyal coklugu sart.
      (Blazytko flattening-detection + zerotistic CFF-remover analizi)
  [2] Kurtarma hatti: state-degiskeni bul -> durum-gecis grafigini cikar
      (kosullu = cok-cikis, dongu = guclu-baglantili-bilesen) -> CFG'yi
      yeniden kur. Savunma dersi (FlatD): dispatcher etiketlerini tek-yonlu
      hash + gizli salt ile gizle, dongu-yapisini indirect-jump ile yok et,
      salt'i opaque-predicate sorgulariyla uret.
      (FlatD ICSE-SEIP'25 + jadx-deflatten + wowsdeob/unfuck hatti)
  [3] Anti-DSE opaque predicate'ler: tek-yonlu fonksiyon (hash/log) cozucuyu
      cozumsuz birakir; Fermat teoremi (a^(p-1) == 1 mod p) KLEE/Angr'i
      O(p)'de bogar; path-explosion (Fibonacci/Collatz) 3 saati asan
      cozum sureleri uretir. Klasik `x*x >= 0` DSE'de aninda elenir.
      (Cao/Zhou/Zhuang CMC'25 + HD-DBVO honeypot-decoy cercevesi)

Entegrasyon prensibi: HICBIR tek kontrole guvenme. Trip kurali: >=1 STRONG
veya >=2 WEAK. Kritik hata -> True (fail-closed). `flattening_score()` saf
olcumdur (koruma dogrulama icin), trip uretmez. Hata mesaji OP AKTIR.

Kullanim:
    from HyperCipherAnti import anti_control_flow_analysis as acf
    print(acf.flattening_score(my_func))  # duzlestirme olcumu
    if acf.is_flow_analyzed(): ...        # sessiz kontrol
    acf.assert_no_flow_analysis()         # varsa FlowAnalysisDetected
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
    "FlowAnalysisDetected",
    "is_flow_analyzed",
    "check_all",
    "score",
    "status",
    "assert_no_flow_analysis",
    "flattening_score",
    "fermat_true",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]


class FlowAnalysisDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Pin'li referanslar (B1 deseni).
# ---------------------------------------------------------------------------
_SYS_MODULES = sys.modules
_SYS_CURRENT_FRAMES = getattr(sys, "_current_frames", None)
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

# Sembolik-yurutme / CFG-kurtarma motorlari (process-ici yuk STRONG).
# angr+claripy, miasm, manticore, z3: DSE zincirinin cekirdegi.
# NOT: `triton` bilerek BURADA DEGIL (GPU-kernel dili `import triton` ile
# isim-cakisiyor -> WEAK kumede; STRONG'ta dursa ML makinesi hep trip uretir).
_DSE_MODULES = frozenset({
    "angr",
    "claripy",
    "miasm",
    "manticore",
    "manticore_native",
    "z3",
    "z3solver",
    "pysmt",
    "qsym",
})

# Yardimci grafik/kurtarma kutuphaneleri (tek basina WEAK: mesru kullanim
# yaygin; DSE motoruyla birlesince STRONG sinyaller zaten trip uretir).
_GRAPH_MODULES = frozenset({
    "networkx",
    "pygraphviz",
    "pydot",
    "lief",
    "capstone",
    "keystone",
    "unicorn",
    "unfuck",
    "triton",
})

# Aktif analiz cerceve imzasi. Kisa isaretler (<=3 char: "z3", "cff")
# dosya-adi parcasi esitligi ister (`/z3phyr/` gibi yollarda FP vermesin);
# uzun isaretler alt-string olarak aranir. DSE motoru kendi dizininden
# calisir (or. `z3/z3core.py`) -> parca-esitlik yine yakalar.
_FRAME_MARKS_SHORT = ("z3", "cff")
_FRAME_MARKS_LONG = ("angr", "claripy", "miasm", "manticore",
                     "unfuck", "deflatten", "wowsdeob")

# Surum-bagimsiz dallanma siniflandirma: tum CPython surumlerinde kosulsuz
# atlamalar JUMP_* ile baslar, kosullu atlamalar POP_JUMP_* / JUMP_IF_* ile.
_UNCOND_PREFIXES = ("JUMP_ABSOLUTE", "JUMP_FORWARD", "JUMP_BACKWARD", "JUMP_NO_INTERRUPT")


def _is_jump(op: str) -> bool:
    try:
        return op.startswith(("JUMP", "POP_JUMP")) or op in ("FOR_ITER", "SEND")
    except Exception:
        return False


def _is_uncond(op: str) -> bool:
    try:
        return op.startswith(_UNCOND_PREFIXES)
    except Exception:
        return False


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
    """F22 derin-teyit: gc'deki canli modul nesnelerinin ust-seviye adlari.

    sys.modules'tan silinmis ama referansla yasayan motoru yakalar
    (tek bounded tarama; isabette erken cikar).
    """
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
    """Ust-seviye modul varligi: sys.modules + gc-derin-teyit (F22)."""
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


def _check_dse_engines() -> bool:
    """STRONG: sembolik-yurutme motoru yuklu mu."""
    try:
        return _module_present(_DSE_MODULES)
    except Exception:
        return True


def _check_graph_libs() -> bool:
    """WEAK: CFG yardimci kutuphane yuklu mu."""
    try:
        return _module_present(_GRAPH_MODULES)
    except Exception:
        return False


def _check_active_frames() -> bool:
    """STRONG: analiz motoru cercevesi su an calisiyor mu."""
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
                    for mark in _FRAME_MARKS_LONG:
                        if mark in path:
                            return True
                    try:
                        segs = path.split("/")
                        base = segs[-1] if segs else ""
                    except Exception:
                        segs = ()
                        base = ""
                    for mark in _FRAME_MARKS_SHORT:
                        try:
                            if mark in base:
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


# ---------------------------------------------------------------------------
# Dispatcher skoru (Blazytko hevristigi, saf olcum):
#   skor = max_dispatcher(domine_edilen / toplam)
# Dispatcher adayi = geri-kenarli (back-edge) dongu basi. Surum-bagimsiz
# olmasi icin stdlib `dis` LAZY import edilir ve sys.modules'e BIZ eklediysek
# geri kaldirilir (kardes modul WEAK sinyallerini kirletmemek icin).
# ---------------------------------------------------------------------------


def _build_blocks(instrs):
    """Temel bloklara bol: (offset -> blok_id), bloklar, kenarlar."""
    offs = [i.offset for i in instrs]
    idx = {o: n for n, o in enumerate(offs)}
    leaders = set()
    if offs:
        leaders.add(offs[0])
    for ins in instrs:
        try:
            op = ins.opname
            if op in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"):
                nxt = ins.offset + ins.size if hasattr(ins, "size") else ins.offset + 2
                if nxt in idx:
                    leaders.add(nxt)
            if _is_jump(op) and ins.argval is not None:
                try:
                    leaders.add(int(ins.argval))
                except Exception:
                    pass
                nxt = ins.offset + (ins.size if hasattr(ins, "size") else 2)
                if nxt in idx:
                    leaders.add(nxt)
        except Exception:
            continue
    bounds = sorted(leaders)
    owner = {}
    for b, start in enumerate(bounds):
        end = bounds[b + 1] if b + 1 < len(bounds) else None
        for o in offs:
            if o >= start and (end is None or o < end):
                owner[o] = b
    n = len(bounds)
    edges = [set() for _ in range(n)]
    for ins in instrs:
        try:
            op = ins.opname
            if op in ("RETURN_VALUE", "RETURN_CONST", "RAISE_VARARGS", "RERAISE"):
                continue
            src = owner.get(ins.offset)
            if src is None:
                continue
            if _is_jump(op) and ins.argval is not None:
                try:
                    dst = owner.get(int(ins.argval))
                except Exception:
                    dst = None
                if dst is not None:
                    edges[src].add(dst)
                # kosullu dallanma: dusus-kenari
                if not _is_uncond(op):
                    nxt = ins.offset + (ins.size if hasattr(ins, "size") else 2)
                    nxt_b = owner.get(nxt)
                    if nxt_b is not None:
                        edges[src].add(nxt_b)
            else:
                nxt = ins.offset + (ins.size if hasattr(ins, "size") else 2)
                nxt_b = owner.get(nxt)
                if nxt_b is not None and nxt_b != src:
                    edges[src].add(nxt_b)
        except Exception:
            continue
    return n, edges


def _dominators(n: int, edges) -> list:
    """Iteratif dominator kumeleri (kucuk graflar icin yeterli)."""
    try:
        preds = [set() for _ in range(n)]
        for s, dsts in enumerate(edges):
            for d in dsts:
                if 0 <= d < n:
                    preds[d].add(s)
        dom = [set(range(n)) for _ in range(n)]
        if n:
            dom[0] = {0}
        changed = True
        rounds = 0
        while changed and rounds < n + 2:
            changed = False
            rounds += 1
            for b in range(1, n):
                if not preds[b]:
                    new = {b}
                else:
                    it = iter(preds[b])
                    try:
                        new = set(dom[next(it)])
                    except StopIteration:
                        new = set()
                    for p in it:
                        new &= dom[p]
                    new.add(b)
                if new != dom[b]:
                    dom[b] = new
                    changed = True
        return dom
    except Exception:
        return [set() for _ in range(n)]


def flattening_score(target) -> Optional[float]:
    """Dispatcher skoru 0.0-1.0 (saf; trip uretmez).

    hedef: fonksiyon / kod nesnesi. >=0.9 duzlestirme suphesi.
    F26 duzeltmesi: olculemeyen durum None doner (0.0 "temiz" degil,
    "bilinmiyor"dur). Asiri buyuk fonksiyonlarda olcum reddedilir.
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
            if len(instrs) < 8:
                return None
            n, edges = _build_blocks(instrs)
            if n < 4:
                return None
            dom = _dominators(n, edges)
            best = 0.0
            for d in range(n):
                dominated = sum(1 for b in range(n) if d in dom[b])
                # geri-kenar sarti: domine edilenlerden birinden d'ye donus
                back = False
                try:
                    for b in range(n):
                        if b != d and d in dom[b] and d in edges[b]:
                            back = True
                            break
                except Exception:
                    back = False
                if not back:
                    continue
                frac = dominated / n
                if frac > best:
                    best = frac
            return best if 0.0 <= best <= 1.0 else 0.0
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


# ---------------------------------------------------------------------------
# Fermat opaque predicate (arastirma-destekli anti-DSE):
#   p asal, a % p != 0  =>  pow(a, p-1, p) == 1   (daima True)
# KLEE/Angr cozumu O(p)'de bogar; calisma maliyeti O(log p).
# ---------------------------------------------------------------------------
_FERMAT_P = 1000003  # asal


def fermat_true(a: int = 2) -> bool:
    """Fermat kimligi: gecerli (a, p) icin daima True."""
    try:
        p = _FERMAT_P
        x = int(a) % p
        if x == 0:
            x = 1
        return pow(x, p - 1, p) == 1
    except Exception:
        return True


# Bilinen-masum finder'lar: EXACT-TYPE kanonik kume + tam-etiket eslesme.
# F23 duzeltmesi: `__module__` spoof'lanabilir string'dir; guven exact-type
# ve tam-etikete dayanir. "mock"/"importlib"/"_bootstrap" prefix muafiyeti
# KALDIRILDI (spoof kapisiydi); unittest/pytest test-kosucu muafiyeti
# dokumante olarak korunur (acik test altyapisi, gizli degil).
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
        out["dse_engine"] = _check_dse_engines()
    except Exception:
        out["dse_engine"] = True
    try:
        out["active_analysis_frame"] = _check_active_frames()
    except Exception:
        out["active_analysis_frame"] = True
    try:
        out["graph_tool_present"] = _check_graph_libs()
    except Exception:
        out["graph_tool_present"] = False
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
        for key in ("pinned_mismatch", "dse_engine", "active_analysis_frame"):
            if signals.get(key):
                strong += 1
        for key in ("graph_tool_present", "foreign_finder"):
            if signals.get(key):
                weak += 1
    except Exception:
        return (1, 0, _STRONG)
    return (strong, weak, strong * _STRONG + weak * _WEAK)


def is_flow_analyzed() -> bool:
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
        verdict = is_flow_analyzed()
    except Exception:
        verdict = True
    return {"flow_analyzed": verdict, "strong": strong, "weak": weak,
            "score": total, "signals": signals,
            "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
            "admin_denied": _ADMIN_DENIED}


def assert_no_flow_analysis() -> None:
    """Trip varsa opak hata yukselt."""
    if is_flow_analyzed():
        raise FlowAnalysisDetected("protected")


def _watchdog_loop(stop_event: threading.Event, interval: float,
                   on_trip: Optional[Callable[[], None]]) -> None:
    try:
        while not stop_event.wait(interval):
            try:
                tripped = is_flow_analyzed()
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
    raise FlowAnalysisDetected("protected")


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
        if is_flow_analyzed():
            raise FlowAnalysisDetected("protected")
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
