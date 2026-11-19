# -*- coding: utf-8 -*-
"""anti_profiling: deterministik-profiler gozetim tespiti.

Tehdit modeli (arastirma sentezi - 3x ReSearch, TUR8):
  - R1 Deterministik-profiler (CPython profile docs + profiling.tracing.rst +
    C-API profiling): cProfile/profile her CALL/RETURN/EXCEPTION olayinda
    kesin sayim + zamanlama uretir; cagrilar-cagrilanlar grafigi kodun
    cagri-yapisini (hangi fonksiyon kimi cagiriyor) tam ortaya doker;
    "beklenmedik cagrilar" analizi tersine-muhendislik icin birebirdir.
    Savunma: setprofile-kimlik-pin'i + aktif-profiler tespiti.
  - R2 Gorunmezlik-degisimi (CPython issue #130377, 2025): 3.12+ cProfile
    artik _PyEval_SetProfile DEGIL sys.monitoring kullaniyor ->
    sys.getprofile() BOS doner (korluk!). Tespit: monitoring PROFILER_ID
    (2) get_tool ile okunur. Savunma: iki-kanalli kontrol (getprofile +
    monitoring-get_tool); tek kanala guvenme.
  - R3 Harici-ornekleyici siniri (coveragepy howitworks + py-spy): py-spy
    EXTERNAL sampler'dir (in-process gorunmez) -> iddia edilmez, dokumante
    rezidu. In-process calisanlar (cProfile, profile, yappi, scalene,
    hunter, viztracer) pin + modul-varligi + frame ile yakalanir.

Kapsam (kardeslerle cakisma yok):
  - anti_trace: trace/coverage/monitoring GENEL-katmani + aktif-kirma.
    BU modul: deterministik-PROFILER ozeli (setprofile-pin + cProfile
    aktiflik + profiler-harness-frame); kirma YAPMAZ, sadece sinyal uretir
    (kirma anti_trace'in isi).
  - anti_fuzzing: fuzzer-harness. BU modul: profiler-kanali, fuzz
    mekanigine GIRMEZ.
  - anti_instrumentation: DBI/agent-thread. BU modul: saf-Python profiler
    kancalari.

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
Trip >=1 STRONG veya >=2 WEAK.
"""

from __future__ import annotations

import sys as _sys
import threading as _threading

__all__ = [
    "ProfilingDetected",
    "is_profiled",
    "check_all",
    "score",
    "status",
    "assert_no_profiling",
    "authorize_admin",
    "pin",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]

STRONG = 100
WEAK = 30

# sys.monitoring tool ID'leri (PEP 669): 0=DEBUGGER 1=COVERAGE 2=PROFILER
# 3,4 bosta 5=OPTIMIZER. Bu modul SADECE PROFILER_ID'yi okur.
_PROFILER_ID = 2


class ProfilingDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Pin (setprofile kimligi pin() aninda alinir; mismatch = STRONG)
# ---------------------------------------------------------------------------

_LOCK = _threading.RLock()
_PINNED: dict = {}
_PR_ADMINS: dict = {}
_PR_ADMIN_LOCKED = False
_PR_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _PR_ADMIN_DENIED
    try:
        if _PR_ADMIN_LOCKED:
            with _LOCK:
                _PR_ADMIN_DENIED += 1
            return False
        try:
            fr = _sys._getframe(1)
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
            import os as _o
            if not _o.path.isfile(fn):
                return False
        except Exception:
            return False
        with _LOCK:
            _PR_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _prof_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_PR_ADMINS)
        if not allowed:
            return False
        try:
            fr = _sys._getframe(2)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
            want = allowed.get(name)
            if (want is not None and fn == want and not fn.startswith("<")):
                try:
                    import os as _o2
                    if _o2.path.isfile(fn):
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False
    except Exception:
        return False


def _prof_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _PR_ADMIN_DENIED
    try:
        with _LOCK:
            _PR_ADMIN_DENIED += 1
    except Exception:
        pass
    raise ProfilingDetected("operation failed")


def _code_fp(fn):
    """Davranis-parmagi: co_code + consts + names (spoof-proof pin parcasi)."""
    try:
        import hashlib as _h
        code = getattr(fn, "__code__", None)
        if code is None:
            return ""
        h = _h.sha256()
        try:
            h.update(bytes(getattr(code, "co_code", b"") or b""))
        except Exception:
            h.update(b"?")
        try:
            for c in getattr(code, "co_consts", ()) or ():
                try:
                    if isinstance(c, (str, bytes, int, float, bool, type(None))):
                        h.update(repr(c).encode("utf-8", "ignore"))
                except Exception:
                    continue
        except Exception:
            pass
        try:
            h.update(repr(tuple(getattr(code, "co_names", ()) or ())).encode("utf-8", "ignore"))
        except Exception:
            pass
        return h.hexdigest()
    except Exception:
        return ""


def _fn_id(fn):
    """PR-1: spoof-proof kimlik — id + kod-parmak + tip (yazilabilir
    __module__/__qualname__ DEGIL). Ayni-kod farkli-obje (id) ve farkli-kod
    ayni-isim (fp) ikisi de mismatch uretir."""
    try:
        if fn is None:
            return ("none", "", "")
        return (id(fn), _code_fp(fn), getattr(type(fn), "__name__", "?"))
    except Exception:
        return ("?", "?", "?")


try:
    _PINNED = {"setprofile": _fn_id(_sys.getprofile())}
except Exception:
    _PINNED = {}


def pin() -> int:
    """Mevcut setprofile kimligini muhurle. Donus: 1 (ok) / 0 (hata).

    YONETIM: kayitli operator sart (saldirgan pin'leyip evil'i
    mesrulastiramaz) — boot'ta authorize→pin sirasi.
    """
    if not _prof_check_admin():
        _prof_deny_admin("pin")
    global _PINNED
    try:
        cur = _sys.getprofile()
    except Exception:
        return 0
    with _LOCK:
        _PINNED = {"setprofile": _fn_id(cur)}
    return 1


def _pinned_mismatch() -> bool:
    """STRONG: pin sonrasi setprofile kimligi degismis mi."""
    try:
        pinned = dict(_PINNED)
    except Exception:
        return True
    if not pinned:
        return True
    try:
        cur = _sys.getprofile()
    except Exception:
        return True
    try:
        return _fn_id(cur) != pinned.get("setprofile")
    except Exception:
        return True


def _check_profile_tamper() -> bool:
    """STRONG: pin'li setprofile kimligi bozulmus mu."""
    try:
        return _pinned_mismatch()
    except Exception:
        return True


def _check_profiler_active() -> bool:
    """STRONG: deterministik-profiler AKTIF mi (uc kanal).

    Kanal 1: klasik getprofile (<3.12 cProfile + profile + yappi C — hepsi
    sys.setprofile uzerinden gider, research-dogrulamali).
    Kanal 2: sys.monitoring TUM tool-ID'leri (0-5) + aktif event'ler —
    custom/C profiler non-2 ID kullanirsa yakalanir (get_tool dolu VEYA
    get_events!=0). Non-profiler tool (debugger/coverage) mesru-kullanimda
    trip uretebilir (strict-by-design, dokumante).
    DURUST REZIDU: sys.getprofile THREAD-LOCAL'dir — baska thread'in
    kurdugu setprofile-profiler bu thread'den gorunmez (3.11'de
    monitoring yok). Capraz-thread setprofile gozetimi icin sys.monitoring
    (3.12+) kanali veya watchdog'un profillenen thread'de kosulmasi
    gerekir; ayrica yappi-tipi C kancalar threading.setprofile uzerinden
    tum thread'lere yayilir ama okuma yine thread-local'dir. External
    sampler (py-spy) surec-disi oldugu icin gorunmez (R3).
    """
    try:
        if _sys.getprofile() is not None:
            return True
    except Exception:
        return True
    try:
        mon = getattr(_sys, "monitoring", None)
        if mon is not None:
            try:
                get_tool = getattr(mon, "get_tool", None)
                get_events = getattr(mon, "get_events", None)
            except Exception:
                get_tool = None
                get_events = None
            if callable(get_tool) or callable(get_events):
                for tool_id in (0, 1, 2, 3, 4, 5):
                    try:
                        if callable(get_tool) and get_tool(tool_id) is not None:
                            try:
                                if callable(get_events) and int(get_events(tool_id)) == 0:
                                    continue
                            except Exception:
                                pass
                            return True
                    except Exception:
                        continue
                    try:
                        if callable(get_events) and int(get_events(tool_id)) != 0:
                            return True
                    except Exception:
                        continue
    except Exception:
        pass
    return False


_PROFILER_MODULES = frozenset({
    "cprofile",
    "profile",
    "pstats",
    "yappi",
    "scalene",
    "hunter",
    "viztracer",
    "line_profiler",
    "kernprof",
    "pyinstrument",
    "lsprof",
    "_lsprof",
    "austin",
    "py_spy",
    "pyspy",
    "plop",
    "pyflame",
    "vmprof",
    "pprofile",
    "vprof",
    "guppy",
})


def _check_tool_presence() -> bool:
    """WEAK: profiler modul yuklu mu (varlik tek basina suphe degil)."""
    try:
        live = _sys.modules
    except Exception:
        return False
    try:
        for name in _PROFILER_MODULES:
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
            if top in _PROFILER_MODULES:
                return True
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Toplama
# ---------------------------------------------------------------------------

def check_all() -> dict:
    """Tum sinyaller (True=risk). Kritik hata -> True (fail-closed)."""
    out: dict = {}
    try:
        out["profile_tampered"] = _check_profile_tamper()
    except Exception:
        out["profile_tampered"] = True
    try:
        out["profiler_active"] = _check_profiler_active()
    except Exception:
        out["profiler_active"] = True
    try:
        out["tool_present"] = _check_tool_presence()
    except Exception:
        out["tool_present"] = False
    return out


_STRONG_KEYS = ("profile_tampered", "profiler_active")
_WEAK_KEYS = ("tool_present",)


def score() -> tuple:
    """(strong_sayisi, weak_sayisi, toplam)."""
    try:
        signals = check_all()
    except Exception:
        return (1, 0, STRONG)
    try:
        s = sum(1 for k in _STRONG_KEYS if signals.get(k))
        w = sum(1 for k in _WEAK_KEYS if signals.get(k))
        return (s, w, s * STRONG + w * WEAK)
    except Exception:
        return (1, 0, STRONG)


def is_profiled() -> bool:
    """Trip kurali: >=1 STRONG veya >=2 WEAK."""
    try:
        s, w, _ = score()
        return s >= 1 or w >= 2
    except Exception:
        return True


def status() -> dict:
    """Sessiz durum ozeti (watchdog-bayrak dahil — PR-5 gorunurluk)."""
    try:
        s, w, pts = score()
        try:
            with _WD_LOCK:
                wd = [bool(st.get("tripped")) for _, st in list(_WATCHDOGS)]
        except Exception:
            wd = []
        return {"profiled": is_profiled(), "strong": s, "weak": w,
                "score": pts, "signals": check_all(),
                "watchdogs": len(wd), "watchdog_tripped": any(wd),
                "admin_authorized": len(_PR_ADMINS),
                "admin_locked": _PR_ADMIN_LOCKED,
                "admin_denied": _PR_ADMIN_DENIED}
    except Exception:
        return {"profiled": True, "strong": 1, "weak": 0, "score": STRONG,
                "signals": {}}


def assert_no_profiling() -> None:
    """Trip varsa opak hata (oracle kapali)."""
    if is_profiled():
        raise ProfilingDetected("operation failed")


# ---------------------------------------------------------------------------
# Watchdog + guard
# ---------------------------------------------------------------------------

_WATCHDOGS: list = []
_WD_LOCK = _threading.RLock()


def _clamp_interval(v) -> float:
    try:
        f = float(v)
    except Exception:
        return 0.5
    if f < 0.1:
        return 0.1
    if f > 3600.0:
        return 3600.0
    return f


def start_watchdog(interval=0.5, on_detect=None):
    """Periyodik check_all; trip'te bayrak + opsiyonel callback. stop fn doner.

    PR-5: on_detect verilmezse bayrak davranisi korunur (modul
    detect-only'dir, kirma anti_trace'indir); operator callback ile
    dis-aksiyon baglar. status() watchdog durumunu raporlar.
    """
    global _PR_ADMIN_LOCKED
    try:
        with _WD_LOCK:
            _PR_ADMIN_LOCKED = True
    except Exception:
        pass
    iv = _clamp_interval(interval)
    stop_ev = _threading.Event()
    state = {"tripped": False}
    act = on_detect if callable(on_detect) else None

    def _loop():
        try:
            while not stop_ev.wait(iv):
                try:
                    if is_profiled():
                        state["tripped"] = True
                        if act is not None:
                            try:
                                act(dict(state))
                            except Exception:
                                pass
                except Exception:
                    state["tripped"] = True
        except Exception:
            pass

    try:
        t = _threading.Thread(target=_loop, name="prof-wd", daemon=True)
        t.start()
    except Exception:
        return lambda: None

    def _stop():
        try:
            stop_ev.set()
        except Exception:
            pass
        return dict(state)

    with _WD_LOCK:
        _WATCHDOGS.append((_stop, state))
    return _stop


def stop_all_watchdogs() -> int:
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart). Donus: sayi."""
    if not _prof_check_admin():
        _prof_deny_admin("stop_all_watchdogs")
    n = 0
    with _WD_LOCK:
        stops = list(_WATCHDOGS)
        _WATCHDOGS.clear()
    for stop, _state in stops:
        try:
            stop()
            n += 1
        except Exception:
            continue
    return n


class guard:
    """`with guard():` blogunda GIRIS + CIKIS trip kontrolu (fail-closed iki uc).

    PR-4: govde exception'la bitse bile profiling-trip ONCELIKLIDIR
    (yutulmaz; govde-hatasi context'e zincirlenir).
    """

    def __enter__(self):
        try:
            assert_no_profiling()
        except Exception:
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            assert_no_profiling()
        except Exception as trip_e:
            if exc is None:
                raise
            raise trip_e from exc
        return False
