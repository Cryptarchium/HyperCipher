# -*- coding: utf-8 -*-
"""anti_fuzzing: coverage-rehberli fuzzer enstrumantasyon tespiti.

Tehdit modeli (arastirma sentezi - 3x ReSearch, TUR8):
  - R1 Atheris (google/atheris + OSS-Fuzz python_lang + PTD 2026): libFuzzer
    tabanli; instrument_imports()/instrument_func()/instrument_all() ile
    bytecode'a coverage-callback enjekte eder; TestOneInput(bytes) dongusu;
    FuzzedDataProvider; RegEx hook; default oracle "uncaught exception".
    Bulgu siniflari: malformed-input crash, RecursionError DoS, quadratic
    timeout, length-field memory-exhaustion. Savunma: harness-frame + enstrumante
    kod-parmak-izi + modul-varligi (3 katman, tek sinyale guvenme).
  - R2 Hypothesis+HypoFuzz (issue #3912 + v6.124.1 BytestringProvider):
    fuzz_one_input koprusu; dis fuzzer bayt-tampon surer; shrinking +
    minimal-repro. Savunma: hypothesis/hypofuzz modul-varligi + harness-frame.
  - R3 Elit-oracle riski: fuzzer'in crash-oracle'i bizim fail-closed
    patikalari degil, UNCAUGHT exception'dir; surekli malformed-girdi yagmuru
    exception-yogunlugu ve ayni-giris-tekrar-cagri deseni uretir. Savunma:
    enstrumantasyon tespiti (kod-yeniden-yazim) + harness-frame.

Kapsam (kardeslerle cakisma yok):
  - anti_trace: settrace/setprofile/monitoring/coverage genel-katmani
    (atheris/hypothesis parmak-izi TUR8'de EKLENDI). BU modul: fuzzer-OZEL
    harness (TestOneInput/FuzzedDataProvider) + enstrumante-kod tespiti
    (self-probe co_code parmak-izi).
  - anti_profiling: deterministik-profiler (setprofile/cProfile). BU modul:
    fuzzer-harness, profiler mekanigine GIRMEZ.
  - anti_error_leakage: fuzzer'in tetikledigi hatalarin ICERIGI. BU modul:
    fuzzer'in VARLIGI.

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
Trip >=1 STRONG veya >=2 WEAK.
"""

from __future__ import annotations

import hashlib as _hashlib
import os as _os
import sys as _sys
import threading as _threading

__all__ = [
    "FuzzingDetected",
    "is_fuzzed",
    "check_all",
    "score",
    "status",
    "assert_no_fuzzing",
    "watch",
    "unwatch",
    "authorize_admin",
    "start_watchdog",
    "stop_all_watchdogs",
    "guard",
]

STRONG = 100
WEAK = 30


class FuzzingDetected(RuntimeError):
    """Opak hata: hangi katman tetiklendi DISARIYA soylenmez (oracle kapali)."""


# ---------------------------------------------------------------------------
# Self-probe (enstrumante-kod tespiti: atheris instrument_all() tum
# yuklu fonksiyonlarin __code__'unu yeniden yazar -> parmak-izi bozulur)
# ---------------------------------------------------------------------------

def _probe():
    return 0xF12A4B


def _code_fp(fn) -> str:
    try:
        code = fn.__code__
    except Exception:
        return ""
    try:
        h = _hashlib.sha256()
        h.update(bytes(getattr(code, "co_code", b"") or b""))
        h.update(repr(getattr(code, "co_consts", ())).encode("utf-8", "ignore"))
        h.update(repr(getattr(code, "co_names", ())).encode("utf-8", "ignore"))
        return h.hexdigest()
    except Exception:
        return ""


_PROBE_FP = _code_fp(_probe)


def _check_code_rewritten() -> bool:
    """STRONG: self-probe parmak-izi bozulmus (kod yeniden yazilmis)."""
    try:
        if not _PROBE_FP:
            return False
        return _code_fp(_probe) != _PROBE_FP
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Harness-frame (iki katmanli eslesme, FP karsiti)
# ---------------------------------------------------------------------------

_HARNESS_FUNCS_LOOSE = frozenset({
    "TestOneInput",
    "FuzzOneInput",
    "fuzz_one_input",
    "fuzz_with_atheris",
    "LLVMFuzzerTestOneInput",
    "FuzzedDataProvider",
    "instrument_all",
    "instrument_func",
    "instrument_imports",
    "Setup",
    "Fuzz",
    "setup",
    "fuzz",
})
_HARNESS_FUNCS_STRICT = frozenset({
    "Fuzz",
    "Setup",
    "mutate",
    "fuzz",
})
_HARNESS_FILE_MARKS = ("atheris", "hypofuzz", "hypothesis", "libfuzzer",
                       "oss-fuzz", "oss_fuzz")


def _check_harness_frames() -> bool:
    """STRONG: fuzzer-harness cercevesi stack'te aktif mi."""
    get_frames = getattr(_sys, "_current_frames", None)
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
                    code = f.f_code
                    fname = code.co_name
                    fpath = (code.co_filename or "").lower().replace(
                        "\\", "/")
                except Exception:
                    break
                try:
                    if fname in _HARNESS_FUNCS_LOOSE:
                        return True
                    if fname in _HARNESS_FUNCS_STRICT:
                        for mark in _HARNESS_FILE_MARKS:
                            if mark in fpath:
                                return True
                except Exception:
                    pass
                try:
                    f = f.f_back
                except Exception:
                    break
        return False
    except Exception:
        return True


_FUZZ_MODULES = frozenset({
    "atheris",
    "hypothesis",
    "hypofuzz",
})


def _check_tool_presence() -> bool:
    """WEAK: fuzzer modul yuklu mu (varlik tek basina suphe degil)."""
    try:
        live = _sys.modules
    except Exception:
        return True
    try:
        for name in _FUZZ_MODULES:
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
            if top in _FUZZ_MODULES:
                return True
        return False
    except Exception:
        return True


_FUZZ_ENV_MARKS = ("atheris", "libfuzzer", "fuzz", "hypofuzz", "hypothesis")


def _check_fuzz_env() -> bool:
    """WEAK: fuzzer ortam-degiskeni mevcut mu (ANAHTAR + DEGER taramali, F3)."""
    try:
        environ = _os.environ
    except Exception:
        return True
    try:
        try:
            items = list(environ.items())
        except Exception:
            items = []
        for key in environ:
            try:
                low = str(key).lower()
            except Exception:
                continue
            for mark in _FUZZ_ENV_MARKS:
                if mark in low:
                    return True
        for key, val in items:
            try:
                vlow = str(val).lower()
            except Exception:
                continue
            for mark in _FUZZ_ENV_MARKS:
                if mark in vlow:
                    return True
        return False
    except Exception:
        return True


# ---------------------------------------------------------------------------
# Toplama
# ---------------------------------------------------------------------------

def check_all() -> dict:
    """Tum sinyaller (True=risk). Kritik hata -> True (fail-closed)."""
    out: dict = {}
    try:
        out["code_rewritten"] = _check_code_rewritten()
    except Exception:
        out["code_rewritten"] = True
    try:
        out["harness_frame"] = _check_harness_frames()
    except Exception:
        out["harness_frame"] = True
    try:
        out["tool_present"] = _check_tool_presence()
    except Exception:
        out["tool_present"] = True
    try:
        out["fuzz_env"] = _check_fuzz_env()
    except Exception:
        out["fuzz_env"] = True
    try:
        out["watched_rewritten"] = _check_watched_rewritten()
    except Exception:
        out["watched_rewritten"] = True
    return out


_STRONG_KEYS = ("code_rewritten", "harness_frame", "watched_rewritten")
_WEAK_KEYS = ("tool_present", "fuzz_env")


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


def is_fuzzed() -> bool:
    """Trip kurali: >=1 STRONG veya >=2 WEAK."""
    try:
        s, w, _ = score()
        return s >= 1 or w >= 2
    except Exception:
        return True


def status() -> dict:
    """Sessiz durum ozeti."""
    try:
        s, w, pts = score()
        return {"fuzzed": is_fuzzed(), "strong": s, "weak": w,
                "score": pts, "signals": check_all(),
                "admin_authorized": len(_ADMIN_MODULES), "admin_locked": _ADMIN_LOCKED,
                "admin_denied": _ADMIN_DENIED}
    except Exception:
        return {"fuzzed": True, "strong": 1, "weak": 0, "score": STRONG,
                "signals": {}}


def assert_no_fuzzing() -> None:
    """Trip varsa opak hata (oracle kapali)."""
    if is_fuzzed():
        raise FuzzingDetected("operation failed")


# ---------------------------------------------------------------------------
# Watchdog + guard
# ---------------------------------------------------------------------------

_WATCHDOGS: list = []
_WD_LOCK = _threading.RLock()
_WATCH: dict = {}
_WATCH_CAP = 1024
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
            with _WD_LOCK:
                _ADMIN_DENIED += 1
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
            if not _os.path.isfile(fn):
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
            fr = _sys._getframe(2)
        except Exception:
            return False
        try:
            name = str(fr.f_globals.get("__name__", "") or "")
            fn = str(getattr(fr.f_code, "co_filename", "") or "")
            want = allowed.get(name)
            if (want is not None and fn == want and not fn.startswith("<")
                    and _os.path.isfile(fn)):
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
    raise FuzzingDetected("protected")


def watch(fn):
    """Hedefi izlemeye al (F2: izlenen-hedef rewrite-dedektoru).

    Cap doluysa refuse (None). Donus: key veya None.
    """
    try:
        code = getattr(fn, "__code__", None)
        if code is None:
            return None
        fp = _code_fp(fn)
        if not fp:
            return None
        with _WD_LOCK:
            if len(_WATCH) >= _WATCH_CAP and id(fn) not in _WATCH:
                return None
            _WATCH[id(fn)] = (fn, fp)
        return id(fn)
    except Exception:
        return None


def unwatch(fn=None, key=None):
    """Izlemeden cikar (YONETIM: kayitli operator sart — korlestirme kapali)."""
    if not _check_admin():
        _deny_admin("unwatch")
    try:
        with _WD_LOCK:
            if key is not None:
                _WATCH.pop(key, None)
            elif fn is not None:
                _WATCH.pop(id(fn), None)
        return True
    except Exception:
        return False


def _check_watched_rewritten() -> bool:
    """STRONG (F2): izlenen hedefin kodu degismis mi (instrument_func izi)."""
    try:
        with _WD_LOCK:
            items = list(_WATCH.items())
        for _k, (fn, fp) in items:
            try:
                if _code_fp(fn) != fp:
                    return True
            except Exception:
                return True
        return False
    except Exception:
        return True


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


def start_watchdog(interval=0.5):
    """Periyodik check_all; trip'te bayrak kurar. stop fn doner."""
    global _ADMIN_LOCKED
    try:
        with _WD_LOCK:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    iv = _clamp_interval(interval)
    stop_ev = _threading.Event()
    state = {"tripped": False}

    def _loop():
        try:
            while not stop_ev.wait(iv):
                try:
                    if is_fuzzed():
                        state["tripped"] = True
                except Exception:
                    state["tripped"] = True
        except Exception:
            pass

    try:
        t = _threading.Thread(target=_loop, name="fuzz-wd", daemon=True)
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
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart). Donus: durdurulan sayi."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
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

    F4 duzeltmesi: govde exception'la bitse bile fuzz-trip ONCELIKLIDIR
    (yutulmaz; govde-hatasi context'e zincirlenir).
    """

    def __enter__(self):
        try:
            assert_no_fuzzing()
        except Exception:
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            assert_no_fuzzing()
        except Exception as trip_e:
            if exc is None:
                raise
            raise trip_e from exc
        return False
