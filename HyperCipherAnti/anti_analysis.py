# -*- coding: utf-8 -*-
"""anti_analysis: genel analiz-tespit orkestrasyon katmani (semsiye modul).

Tehdit modeli (arastirma sentezi - 3x ReSearch):
  - R1 Calisma-zamani gozlem altyapisi (CPython belgeleri + PEP 669):
    ``sys.settrace``/``sys.setprofile`` global kancalari + ``sys.monitoring``
    (3.12+, tool ID: DEBUGGER=0, COVERAGE=1, PROFILER=2, OPTIMIZER=5) +
    ``sys.addaudithook`` (kalici, proses-omurlu). coverage.py 3 cekirdek:
    ctrace/pytrace (settrace) + sysmon (monitoring, ~65x daha hizli).
    silentguard olcumu: monitoring ~1.6x taban, settrace ~105x taban.
    Savunma: gettrace/getprofile kimligi + monitoring event-mask/get_tool
    okuma + breakpointhook-kimligi + frame f_trace taramasi.
    cuckoo/PyFEX/DynaPyt zorlamali-yurutme sinyali
    timing-skew ile yakalanir.
  - R2 Statik analiz araclari (pydepgate STR001-004/DYN001-007/ENC001-002/
    STDLIB001-003/DENS001-051 + pycdc/uncompyle6/decompile3/PyLingual):
    decode-then-execute zinciri, getattr/globals/__builtins__ uzerinden
    exec-primitive erisimi, chr/concat/slice/join/fromhex obfuscation,
    yuksek-entropi/base64 literal, .pth/setup.py startup vektorleri.
    Savunma: audit_source() ile calistirmadan kismi-cozumleyici tarama
    (payload'a DOKUNMAZ, desifre ETMEZ, sadece sinyal uretir).
  - R3 Anti-debug/anti-tersine-muhendislik sentezi (pyobfuscator whitepaper
    12 katman + pyobfus v0.5.11 4 yontem): gettrace + TracerPid +
    IsDebuggerPresent + timing-skew; debugger modulleri (pydevd/debugpy/
    pdb/ipdb/pudb); analiz Ortam degiskenleri (PYTHONDEBUG/PYCHARM_DEBUG/
    VSCODE_DEBUG); ebeveyn-proses araci (IDA/Ghidra/WinDbg/x64dbg/Frida).
    Savunma: 6 STRONG + 6 WEAK sinyal, trip >=1 STRONG veya >=2 WEAK.

Kapsam (kardeslerle cakisma yok - BU modul ORKESTRATOR):
  - anti_debug: debugger-spesifik (TracerPid/IsDebuggerPresent/breakpoint).
    BU modul sadece genel "debugger modulu yuklu mu" + tracer kimligi tutar.
  - anti_trace/anti_instrumentation: trace-mekanigi derin-analizi. BU modul
    sadece "iz surme AKTIF mi" sorusunu sorar, mekanige GIRMEZ.
  - anti_decompile/anti_bytecode/anti_disassembly-ailesi: statik-form
    derin-analizi. BU modul audit_source() ile yuzeysel sinyal uretir.
  - anti_sandbox/anti_vm/anti_emulation: ortam-derin-analizi. BU modul
    sadece env-flag + parent-surec yuzeyine bakar.
  - anti_hook.import_system: kanca sagligi. BU modul kancalari TAMIR ETMEZ,
    sadece sensor_health ile kendi pin'lerini dogrular.
  - Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
  - Trip >=1 STRONG veya >=2 WEAK (puan esigi 100).

Sinirlar (bilincli tercihler):
  - Audit-hook listesi CPython'da GORUNMEZ (kalici, kaldirilamaz). Yabanci
    audit-hook'un VARLIGI dogrudan okunamaz; sensor_health + davranis
    sinyalleriyle karsilanir, iddia edilmez.
  - sys.monitoring <3.12'de YOKTUR; yokluk TEMIZ sayilir (fail-open degil,
    kapsama-disi). 3.12+ maske okuma en iyi-gayrettir.
  - Ebeveyn-proses adi stdlib'den tam okunamaz (psutil YOK). /proc +
    argv + modul-yolu kanitlari birlesir; tek kanitla STRONG uretilmez.
  - Timing-skew yuksek-yukte YANLIS-POZITIF uretebilir; WEAK degil STRONG
    esigi + eiken 8x carpan ile dengelenir. Supheli-sonuc fail-closed'dur.
    Baseline min(3 ornek) ile alinir; seal() disinda baseline DEGISTIRILMEZ
    (watchdog-heal trip aninda re-baseline YAPMAZ - zehirlenme kapali).
  - audit_source DoS-butcelidir: parantez-derinlik >200 veya 50K dugum
    asimi trip uretir (bpo-32758: ast.parse guvensiz girdide crash).
    Derin-nesting MESRU uretim-kodu da asabilir; sinyal WEAK-esikte
    degerlendirilir (tek basina STRONG degil).
  - scan_module hostile-nesnede kod CALISTIRMAZ: modul/sinif icin
    _raw_dict() ile gercek tp_dict anligi alinir
    (type.__dict__['__dict__'].__get__ cagrisi metaclass data-descriptor
    golgelemesini bypass eder + PEP 562 __getattr__ bypass), diger
    nesnelerde getattr_static. Anlik exact-type'lidir (dict/mappingproxy
    degilse reddedilir). _safe_kind MRO okumasi da _raw_mro() bypass'lidir
    (type.__dict__['__mro__'].__get__; metaclass __mro__ property exec kapali).
  - _PROBE_LOG 2048 giris + 300s TTL ile sinirlidir; id()-reuse
    carpismasi teorik-rezidueldir (prune penceresi disi etki uretmez).
  - dis/ast/inspect VARLIGI benign sayilir (bu modul dis'i import eder);
    hostile KULLANIM scan_function/audit_source ile yakalanir.
  - Self-FP: WEIGHTS/STRONG/esik/sinyal-tablolari/cap'ler import-aninda
    SHA-256 ile muhurleur; sensor_health her check_all'de dogrular
    (folija/cynapse import-time-baseline deseni). Reziduel: FP
    degiskenini de yeniden-hesaplayan 2-nokta mutasyon + tam code-exec
    saldirgan kapsam-disidir (folija da in-memory patch'i kapsam-disi
    sayar); tek-nokta tablo susturma yakalanir.
  - Watchdog'lar WeakSet registry'dedir; stop_all_watchdogs() GERCEKTEN
    durdurur (BaseThread stop-registry deseni).
  - monitoring hem GLOBAL maske hem get_tool hem de LOCAL (hedefli kod-
    nesnesi enstrumantasyonu, set_local_events) okunur; saldirganin
    sadece HyperCipher fonksiyonlarini izlemesi de trip uretir.
    breakpointhook-kimligi + sys.monitoring-kimligi sensor_health'tedir.
  - _WATCH 4096 giris cap'lidir (ceyrek-tahliye); flood bellek-DoS'a
    donusmez, sessiz budanir. self-FP cap degerini de muhurler.
  - Tarama girisleri _safe_kind kapisindadir: egzotik nesne (spoof
    isinstance/metaclass __getattr__/property-descritor tasiyan) scan/
    pin/watch/probe'a giriste reddedilir; modul/sinif icin yalnizca
    __dict__ anligi okunur (PEP 562 bypass). unparse denemesi audit
    basina 200 ile sinirlidir (ic-ice BinOp O(n2) sismesi kapali).
    _bracket_depth triple-quote + comment-bilinclidir.
  - audit_source fail-closed'dur: parse-sonrasi beklenmedik abort
    SCAN-aborted trip uretir (bulgular korunur); parse-oncesi girdi
    hatalari sessiz-gecer (fail-open, girdi-katmani).
  - start_watchdog interval clamp'lidir [0.1, 3600.0]s; negatif/NaN
    busy-loop uretemez. sys.modules okumalari _safe_modules() dict
    kapisindadir (dict degilse fail-closed trip). os.getenv kimligi
    sensor_health'tedir.
  - Bilinen-kabul (statik-tarama): split-string/getattr-obfuscation
    ("set"+"trace") + exec-string yukleri statik taramada gorunmez; ETKI
    runtime-guard'larca (tracer/profiler/monitoring check_all) yakalanir.
    Statik scan tripwire, runtime check enforcement'tir.
  - Proses-disi gozlem mimari-gorunmezdir (F6): ikinci proses bellek
    okuma + kopya .pyc uzerinde offline dis; runtime tripwire bunu
    gormez, iddia etmez (tehdit-modeli disi).
"""
from __future__ import annotations
import builtins as _builtins
import os as _os
import sys as _sys
import threading as _threading
import time as _time
import types as _types
import weakref as _weakref


def _take_dis_pin(attr: str):
    """dis'i lazy yukle + tahliye et (self-FP onler, kardes konvansiyon)."""
    try:
        added = "dis" not in _sys.modules
        import dis as _d
        try:
            return getattr(_d, attr, None)
        finally:
            try:
                if added and "dis" in _sys.modules:
                    del _sys.modules["dis"]
            except Exception:
                pass
    except Exception:
        return None


class AnalysisDetected(RuntimeError):
    pass


def _raise() -> None:
    raise AnalysisDetected("protected")


_PIN_THREAD_RLOCK = _threading.RLock
_PIN_THREAD_THREAD = _threading.Thread
_PIN_THREAD_EVENT = _threading.Event
_PIN_TIME_MONOTONIC = _time.monotonic
_PIN_TIME_PERF = _time.perf_counter
_PIN_GETATTR = getattr
_PIN_HASATTR = hasattr
_PIN_ISINSTANCE = isinstance
_PIN_LEN = len
_PIN_LIST = list
_PIN_FROZENSET = frozenset
_PIN_STR = str
_PIN_ID = id
_PIN_TYPE = type
_PIN_SYS = _sys
_PIN_DIS_GET_INSTRUCTIONS = _take_dis_pin("get_instructions")
_PIN_MODULE_TYPE = _types.ModuleType
_PIN_MAPPINGPROXY_TYPE = _types.MappingProxyType
_PIN_FUNC_TYPE = _PIN_TYPE(lambda: 0)
_PIN_METHOD_TYPE = _types.MethodType
_PIN_BUILTIN_FUNC_TYPE2 = _types.BuiltinFunctionType
_PIN_OS_GETENV = _os.getenv
_PIN_SYS_GETTRACE = _PIN_GETATTR(_sys, "gettrace", None)
_PIN_SYS_GETPROFILE = _PIN_GETATTR(_sys, "getprofile", None)
_PIN_SYS_BREAKPOINTHOOK = _PIN_GETATTR(_sys, "breakpointhook", None)
try:
    _PIN_SYS_DOT_BREAKPOINTHOOK = _PIN_TYPE.__dict__["breakpointhook"]
except Exception:
    _PIN_SYS_DOT_BREAKPOINTHOOK = None
_PIN_SYS_MONITORING = _PIN_GETATTR(_sys, "monitoring", None)
_PIN_BUILTIN_BREAKPOINT = _PIN_GETATTR(_builtins, "breakpoint", None)

_LOCK = _PIN_THREAD_RLOCK()

WEIGHTS = {
    "tracer_active": 100,
    "profiler_active": 100,
    "monitoring_active": 100,
    "debugger_module": 100,
    "timing_skew": 100,
    "sensor_health": 100,
    "coverage_artifact": 30,
    "static_tool_artifact": 30,
    "env_analysis_flag": 30,
    "frame_trace_anomaly": 30,
    "parent_suspicious": 30,
    "analysis_probe_anomaly": 30,
    "watch_flood": 30,
    "dynamic_name_construct": 30,
}
STRONG = _PIN_FROZENSET({
    "tracer_active",
    "profiler_active",
    "monitoring_active",
    "debugger_module",
    "timing_skew",
    "sensor_health",
})
_THRESHOLD_TRIP = 100

_DEBUGGER_MODULES = _PIN_FROZENSET({
    "pydevd", "pydevd_frame_eval_cython", "debugpy", "_debugpy",
    "pdb", "ipdb", "pudb", "wdb", "trepan", "pydb",
    "pydev_ipython", "pydevconsole",
})
_COVERAGE_MODULES = _PIN_FROZENSET({
    "coverage", "trace", "profile", "cProfile", "pstats",
    "profiling", "profiling.tracing", "sysmon", "ctrace", "pytrace",
    "pytest_cov", "cov_core",
})
_STATIC_TOOL_MODULES = _PIN_FROZENSET({
    "uncompyle6", "decompyle3", "pycdc", "pylingual", "pychd",
    "pyobfus", "pyobfuscator", "pyarmor", "pyinstxtractor",
    "frida", "r2pipe", "capstone", "unicorn",
})
_ENV_FLAGS = (
    "PYTHONDEBUG", "PYTHONVERBOSE", "PYTHONPROFILE",
    "PYCHARM_DEBUG", "PYDEVD", "DEBUGPY", "VSCODE_DEBUG",
    "PYDEVD_LOAD_VALUES_ASYNC", "PYDEVD_USE_CYTHON",
)
_PARENT_HINTS = _PIN_FROZENSET({
    "ida", "ghidra", "windbg", "olly", "x64dbg", "x32dbg",
    "cheatengine", "cheat engine", "frida", "wireshark",
    "procmon", "sysmon", "dnspy", "hopper", "binaryninja",
    "cuckoo", "sandbox", "vmtools",
})
_OBFUSCATED_EXEC_PRIMS = _PIN_FROZENSET({
    "exec", "eval", "compile", "__import__",
})

_WATCH: dict = {}
_PINS: dict = {}
_PROBE_LOG: dict = {}
_ALERT_HOOK = None
_WD_STOPS = _weakref.WeakSet()

_TIMING_BASELINE: float = 0.0
_TIMING_BASELINE_N = 200
_TIMING_BASELINE_SANCTIONED: float = 0.0
_WATCH_REFUSED_TIMES: list = []
_ADMIN_MODULES: dict = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def _measure_tick(n: int = 200) -> float:
    try:
        t0 = _PIN_TIME_PERF()
        acc = 0
        for _i in range(n):
            acc += _i
        t1 = _PIN_TIME_PERF()
        if acc < 0:
            return 999.0
        return max(0.0, t1 - t0)
    except Exception:
        return 0.0


def _snapshot_timing_baseline() -> None:
    global _TIMING_BASELINE
    try:
        samples = []
        for _k in range(3):
            try:
                samples.append(_measure_tick(_TIMING_BASELINE_N))
            except Exception:
                continue
        if samples:
            try:
                _TIMING_BASELINE = min(samples)
            except Exception:
                _TIMING_BASELINE = samples[0]
        if _TIMING_BASELINE <= 0.0:
            _TIMING_BASELINE = 0.00005
    except Exception:
        try:
            _TIMING_BASELINE = 0.00005
        except Exception:
            pass


def _get_trace_fn():
    try:
        g = _PIN_GETATTR(_PIN_SYS, "gettrace", None)
        if g is None:
            return None
        try:
            return g()
        except Exception:
            return None
    except Exception:
        return None


def _get_profile_fn():
    try:
        g = _PIN_GETATTR(_PIN_SYS, "getprofile", None)
        if g is None:
            return None
        try:
            return g()
        except Exception:
            return None
    except Exception:
        return None


def _check_tracer() -> bool:
    try:
        fn = _get_trace_fn()
        if fn is not None:
            return True
    except Exception:
        pass
    try:
        cur = _PIN_GETATTR(_PIN_SYS, "_current_frames", None)
        if cur is not None:
            try:
                frames = cur()
                for _tid, _fr in _PIN_LIST(_PIN_GETATTR(frames, "items", lambda: [])()):
                    try:
                        f = _fr
                        d = 0
                        while f is not None and d < 32:
                            try:
                                if _PIN_GETATTR(f, "f_trace", None) is not None:
                                    return True
                            except Exception:
                                pass
                            try:
                                f = _PIN_GETATTR(f, "f_back", None)
                            except Exception:
                                break
                            d += 1
                    except Exception:
                        continue
            except Exception:
                pass
    except Exception:
        pass
    try:
        bh = _PIN_GETATTR(_PIN_SYS, "breakpointhook", None)
        if bh is not None:
            try:
                mod = _PIN_GETATTR(bh, "__module__", "sys")
            except Exception:
                mod = "?"
            if bh is not _PIN_SYS_BREAKPOINTHOOK or mod != "sys":
                return True
            if _PIN_SYS_DOT_BREAKPOINTHOOK is not None:
                try:
                    _raw = _PIN_SYS_DOT_BREAKPOINTHOOK.__get__(_PIN_SYS, _PIN_TYPE(_PIN_SYS))
                    if _raw is not bh:
                        return True
                except Exception:
                    pass
    except Exception:
        pass
    try:
        bp = _PIN_GETATTR(_builtins, "breakpoint", None)
        if bp is not None and bp is not _PIN_BUILTIN_BREAKPOINT:
            return True
    except Exception:
        pass
    if _PIN_OS_GETENV("PYTHONBREAKPOINT", "") == "0":
        try:
            if _PIN_GETATTR(_PIN_SYS, "breakpointhook", None) is not _PIN_SYS_BREAKPOINTHOOK:
                return True
        except Exception:
            pass
    return False


def _check_profiler() -> bool:
    try:
        fn = _get_profile_fn()
        if fn is not None:
            return True
    except Exception:
        pass
    try:
        cur = _PIN_GETATTR(_PIN_SYS, "_current_frames", None)
        if cur is not None:
            try:
                frames = cur()
                for _tid, _fr in _PIN_LIST(_PIN_GETATTR(frames, "items", lambda: [])()):
                    try:
                        f = _fr
                        d = 0
                        while f is not None and d < 32:
                            try:
                                if _PIN_GETATTR(f, "f_trace", None) is not None:
                                    return True
                            except Exception:
                                pass
                            try:
                                f = _PIN_GETATTR(f, "f_back", None)
                            except Exception:
                                break
                            d += 1
                    except Exception:
                        continue
            except Exception:
                pass
    except Exception:
        pass
    return False


def _monitoring_mask_active() -> bool:
    try:
        mon = _PIN_GETATTR(_PIN_SYS, "monitoring", None)
        if mon is None:
            return False
        try:
            get_ev = _PIN_GETATTR(mon, "get_events", None)
            if get_ev is None:
                return False
            ids = []
            for _nm in ("DEBUGGER_ID", "COVERAGE_ID", "PROFILER_ID"):
                try:
                    ids.append(_PIN_GETATTR(mon, _nm))
                except Exception:
                    continue
            try:
                get_tool = _PIN_GETATTR(mon, "get_tool", None)
                if get_tool is not None:
                    for _tid in ids:
                        try:
                            if get_tool(_tid) is not None:
                                return True
                        except Exception:
                            continue
            except Exception:
                pass
            for _tid in ids:
                try:
                    if int(get_ev(_tid)) != 0:
                        return True
                except Exception:
                    continue
            return False
        except Exception:
            return False
    except Exception:
        return False


def _check_monitoring() -> bool:
    try:
        if _monitoring_mask_active():
            return True
    except Exception:
        pass
    try:
        return bool(_check_local_monitoring())
    except Exception:
        return False


def _iter_own_code_objects() -> list:
    codes: list = []
    try:
        targets: list = []
        try:
            _mods = _safe_modules()
            mod = _mods.get(__name__) if _mods is not None else None
            if mod is not None:
                md = _PIN_GETATTR(mod, "__dict__", None) or {}
                targets.extend(_PIN_LIST(md.values()))
        except Exception:
            pass
        try:
            with _LOCK:
                targets.extend(_PIN_LIST(_WATCH.values()))
        except Exception:
            pass
        seen = set()
        for _o in targets[:512]:
            try:
                co = _co_of(_o)
                if co is None:
                    continue
                if _PIN_ID(co) in seen:
                    continue
                seen.add(_PIN_ID(co))
                codes.append(co)
            except Exception:
                continue
    except Exception:
        pass
    return codes


def _check_local_monitoring() -> bool:
    try:
        mon = _PIN_SYS_MONITORING
        if mon is None:
            try:
                mon = _PIN_GETATTR(_PIN_SYS, "monitoring", None)
            except Exception:
                mon = None
            if mon is None:
                return False
        get_local = _PIN_GETATTR(mon, "get_local_events", None)
        if get_local is None:
            return False
        ids = []
        for _nm in ("DEBUGGER_ID", "COVERAGE_ID", "PROFILER_ID"):
            try:
                ids.append(_PIN_GETATTR(mon, _nm))
            except Exception:
                continue
        if not ids:
            return False
        for _co in _iter_own_code_objects():
            for _tid in ids:
                try:
                    if int(get_local(_tid, _co)) != 0:
                        return True
                except Exception:
                    continue
        return False
    except Exception:
        return False


def _safe_modules():
    try:
        _m = _PIN_GETATTR(_PIN_SYS, "modules", None)
    except Exception:
        return None
    try:
        if _PIN_TYPE(_m) is dict:
            return _m
    except Exception:
        pass
    return None


def _check_debugger_module() -> bool:
    try:
        mods = _safe_modules()
        if mods is None:
            return True
        for _name in _DEBUGGER_MODULES:
            try:
                if _name in mods and mods.get(_name) is not None:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_timing_skew() -> bool:
    try:
        try:
            if _TIMING_BASELINE != _TIMING_BASELINE_SANCTIONED:
                return True
        except Exception:
            return True
        base = _TIMING_BASELINE
        if base <= 0.0:
            return False
        try:
            cur = _measure_tick(_TIMING_BASELINE_N)
        except Exception:
            return False
        if cur <= 0.0:
            return False
        try:
            if cur > 0.05 and cur > base * 8.0:
                return True
        except Exception:
            return False
        return False
    except Exception:
        return False


def _check_sensor_health() -> bool:
    try:
        if _PIN_GETATTR is not getattr:
            return True
        if _PIN_HASATTR is not hasattr:
            return True
        if _PIN_ISINSTANCE is not isinstance:
            return True
        if _PIN_LEN is not len:
            return True
        if _PIN_SYS is not _sys:
            return True
        if _PIN_TIME_MONOTONIC is not _time.monotonic:
            return True
        if _PIN_THREAD_RLOCK is not _threading.RLock:
            return True
        try:
            if _PIN_OS_GETENV is not _os.getenv:
                return True
        except Exception:
            return True
        try:
            if _PIN_GETATTR(_PIN_SYS, "gettrace", None) is not _PIN_SYS_GETTRACE:
                return True
            if _PIN_GETATTR(_PIN_SYS, "getprofile", None) is not _PIN_SYS_GETPROFILE:
                return True
            bh_now = _PIN_GETATTR(_PIN_SYS, "breakpointhook", None)
            if bh_now is not _PIN_SYS_BREAKPOINTHOOK:
                return True
            if _PIN_SYS_DOT_BREAKPOINTHOOK is not None:
                try:
                    _raw_bh = _PIN_SYS_DOT_BREAKPOINTHOOK.__get__(_PIN_SYS, _PIN_TYPE(_PIN_SYS))
                    if _raw_bh is not bh_now:
                        return True
                except Exception:
                    return True
            if _PIN_GETATTR(_PIN_SYS, "monitoring", None) is not _PIN_SYS_MONITORING:
                return True
            if _PIN_GETATTR(_builtins, "breakpoint", None) is not _PIN_BUILTIN_BREAKPOINT:
                return True
            if _PIN_GETATTR is not getattr or _PIN_HASATTR is not hasattr:
                return True
        except Exception:
            return True
        try:
            if _verify_self_fp() is False:
                return True
        except Exception:
            return True
        try:
            if _PIN_GETATTR(_builtins, "__import__", None) is None:
                return True
        except Exception:
            return True
        return False
    except Exception:
        return True


def _check_coverage_artifact() -> bool:
    try:
        mods = _safe_modules()
        if mods is None:
            return True
        for _name in _COVERAGE_MODULES:
            try:
                if _name in mods and mods.get(_name) is not None:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_static_tool_artifact() -> bool:
    try:
        mods = _safe_modules()
        if mods is None:
            return True
        hits = 0
        for _name in _STATIC_TOOL_MODULES:
            try:
                if _name in mods and mods.get(_name) is not None:
                    hits += 1
            except Exception:
                continue
        if hits:
            return True
        try:
            argv0 = ""
            try:
                argv = _PIN_GETATTR(_PIN_SYS, "argv", [])
                if argv:
                    argv0 = _PIN_STR(argv[0]).lower()
            except Exception:
                argv0 = ""
            for _h in ("pycdc", "uncompyle", "decompyle", "pylingual",
                       "pyinstxtractor", "frida"):
                try:
                    if _h in argv0:
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False
    except Exception:
        return False


def _check_env_flag() -> bool:
    try:
        for _k in _ENV_FLAGS:
            try:
                v = _PIN_OS_GETENV(_k, "")
                if v not in ("", None):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_frame_anomaly() -> bool:
    try:
        cur_frames = _PIN_GETATTR(_PIN_SYS, "_current_frames", None)
        if cur_frames is None:
            return False
        try:
            frames = cur_frames()
        except Exception:
            return False
        for _tid, _fr in _PIN_LIST(_PIN_GETATTR(frames, "items", lambda: [])()):
            try:
                f = _fr
                depth = 0
                while f is not None and depth < 64:
                    try:
                        if _PIN_GETATTR(f, "f_trace", None) is not None:
                            return True
                    except Exception:
                        pass
                    try:
                        f = _PIN_GETATTR(f, "f_back", None)
                    except Exception:
                        break
                    depth += 1
            except Exception:
                continue
        return False
    except Exception:
        return False


def _parent_cmdline() -> str:
    blob = ""
    try:
        try:
            blob += _PIN_STR(_PIN_GETATTR(_PIN_SYS, "argv", []))
        except Exception:
            pass
        try:
            exe = _PIN_STR(_PIN_GETATTR(_PIN_SYS, "executable", ""))
            blob += " " + exe
        except Exception:
            pass
        try:
            ppid = None
            try:
                ppid = _PIN_GETATTR(_os, "getppid", lambda: None)()
            except Exception:
                ppid = None
            if _PIN_ISINSTANCE(ppid, int) and ppid > 0:
                for _p in ("/proc/%s/comm" % ppid, "/proc/%s/cmdline" % ppid):
                    try:
                        with open(_p, "rb") as _fh:
                            blob += " " + repr(_fh.read(512))
                    except Exception:
                        continue
        except Exception:
            pass
    except Exception:
        pass
    try:
        return blob.lower()
    except Exception:
        return ""


def _check_parent_suspicious() -> bool:
    try:
        blob = _parent_cmdline()
        if not blob:
            return False
        for _h in _PARENT_HINTS:
            try:
                if _h in blob:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _check_probe_anomaly() -> bool:
    try:
        with _LOCK:
            items = _PIN_LIST(_PROBE_LOG.items())
        if not items:
            return False
        try:
            now = _PIN_TIME_MONOTONIC()
        except Exception:
            return False
        recent = 0
        for _k, _t in items:
            try:
                if _t > now + 1.0:
                    return True
                if now - _t < 60.0:
                    recent += 1
            except Exception:
                continue
        return recent > 50
    except Exception:
        return False


def _norm_const(c, depth: int = 0):
    try:
        if depth > 8:
            return ("<depth>",)
        if _PIN_HASATTR(c, "co_consts"):
            try:
                return ("code", _PIN_GETATTR(c, "co_name", "?"))
            except Exception:
                return ("code", "?")
        if _PIN_ISINSTANCE(c, (str, bytes, int, float, complex, bool, type(None))):
            try:
                return ("v", repr(c)[:512])
            except Exception:
                return ("v", "?")
        if _PIN_ISINSTANCE(c, tuple):
            try:
                return ("t", tuple(_norm_const(_x, depth + 1) for _x in c))
            except Exception:
                return ("t", "?")
        return ("o", _PIN_TYPE(c).__name__)
    except Exception:
        return ("?",)


def _code_fp(co) -> str:
    try:
        import hashlib as _h
        parts: list = []
        try:
            raw = _PIN_GETATTR(co, "co_code", b"")
            try:
                code_bytes = bytes(raw)
            except Exception:
                code_bytes = repr(raw).encode("utf-8", "replace")
            parts.append(code_bytes.hex())
        except Exception:
            parts.append("?")
        try:
            consts = _PIN_GETATTR(co, "co_consts", ()) or ()
            parts.append(repr(tuple(_norm_const(_c) for _c in consts)))
        except Exception:
            parts.append("?")
        for _field in ("co_names", "co_varnames", "co_freevars", "co_cellvars"):
            try:
                parts.append(repr(tuple(_PIN_GETATTR(co, _field, ())) or ()))
            except Exception:
                parts.append("?")
        for _field in ("co_flags", "co_argcount", "co_posonlyargcount",
                       "co_kwonlyargcount"):
            try:
                parts.append(_PIN_STR(_PIN_GETATTR(co, _field, 0)))
            except Exception:
                parts.append("0")
        try:
            parts.append(_PIN_STR(_PIN_GETATTR(co, "co_name", "?")))
        except Exception:
            parts.append("?")
        return _h.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()
    except Exception:
        return ""


def _raw_mro(ft):
    try:
        try:
            _td = _PIN_TYPE.__dict__
        except Exception:
            return ()
        try:
            _desc = _td.get("__mro__")
        except Exception:
            return ()
        try:
            _m = _desc.__get__(ft, _PIN_TYPE(ft))
        except Exception:
            return ()
        try:
            if _PIN_TYPE(_m) is tuple:
                return _m
        except Exception:
            pass
        return ()
    except Exception:
        return ()


def _safe_kind(fn) -> str:
    try:
        ft = _PIN_TYPE(fn)
        if ft is _PIN_FUNC_TYPE or ft is _PIN_METHOD_TYPE or \
           ft is _PIN_MODULE_TYPE or ft is _PIN_BUILTIN_FUNC_TYPE2:
            return "func"
        try:
            mro = _raw_mro(ft)
        except Exception:
            return "exotic"
        try:
            if _PIN_TYPE in mro:
                return "classmod"
        except Exception:
            return "exotic"
        return "exotic"
    except Exception:
        return "exotic"


def _co_of(f):
    try:
        if _safe_kind(f) != "func":
            return None
        c = _PIN_GETATTR(f, "__code__", None)
        if c is not None:
            return c
    except Exception:
        pass
    return None


def _raw_dict(fn):
    try:
        if _PIN_TYPE(fn) is _PIN_MODULE_TYPE:
            try:
                return _PIN_GETATTR(fn, "__dict__", None)
            except Exception:
                return None
        try:
            _td = _PIN_TYPE.__dict__
        except Exception:
            return None
        try:
            _desc = _td.get("__dict__")
        except Exception:
            return None
        try:
            return _desc.__get__(fn, _PIN_TYPE(fn))
        except Exception:
            return None
    except Exception:
        return None


def _func_names(fn) -> tuple:
    try:
        kind = _safe_kind(fn)
        if kind == "exotic":
            return ("?",)
        if kind == "classmod":
            try:
                d = _raw_dict(fn)
                if d is not None and (_PIN_TYPE(d) is dict or _PIN_TYPE(d) is _PIN_MAPPINGPROXY_TYPE):
                    try:
                        _get = d.get
                    except Exception:
                        _get = None
                    if _get is not None:
                        names = []
                        for _k in ("__name__", "__qualname__", "__module__"):
                            try:
                                names.append(_PIN_STR(_get(_k, "?")))
                            except Exception:
                                names.append("?")
                        return tuple(names)
            except Exception:
                pass
            return ("?",)
        names = []
        try:
            names.append(_PIN_STR(_PIN_GETATTR(fn, "__name__", "?")))
        except Exception:
            names.append("?")
        try:
            names.append(_PIN_STR(_PIN_GETATTR(fn, "__qualname__", "?")))
        except Exception:
            names.append("?")
        try:
            names.append(_PIN_STR(_PIN_GETATTR(fn, "__module__", "?")))
        except Exception:
            names.append("?")
        return tuple(names)
    except Exception:
        return ("?",)


def _resolve_obfuscated_name(expr: str) -> str:
    try:
        s = expr.strip()
        if _PIN_LEN(s) > 512:
            return ""
        if (s.startswith("'") and s.endswith("'")) or \
           (s.startswith('"') and s.endswith('"')):
            try:
                import ast as _a
                v = _a.literal_eval(s)
                if _PIN_ISINSTANCE(v, str):
                    return v
            except Exception:
                pass
        if "+" in s or ".join" in s or "chr(" in s or "[::-1]" in s or \
           "fromhex" in s or "bytes(" in s:
            try:
                import ast as _a
                tree = _a.parse(s, mode="eval")

                def _ev(_n) -> str | None:
                    try:
                        if _PIN_ISINSTANCE(_n, _a.Constant) and \
                           _PIN_ISINSTANCE(_n.value, str):
                            return _n.value
                        if _PIN_ISINSTANCE(_n, _a.Constant) and \
                           _PIN_ISINSTANCE(_n.value, int):
                            try:
                                if 0 <= _n.value <= 0x10FFFF:
                                    return chr(_n.value)
                            except Exception:
                                return None
                            return None
                        if _PIN_ISINSTANCE(_n, _a.BinOp) and \
                           _PIN_ISINSTANCE(_n.op, _a.Add):
                            a = _ev(_n.left)
                            b = _ev(_n.right)
                            if a is not None and b is not None:
                                return a + b
                            return None
                        if _PIN_ISINSTANCE(_n, _a.Call):
                            try:
                                fn = _n.func
                                if _PIN_ISINSTANCE(fn, _a.Name) and \
                                    fn.id == "chr" and _PIN_LEN(_n.args) == 1:
                                    v = _ev(_n.args[0])
                                    if v is not None and _PIN_LEN(v) == 1:
                                        return v
                                    av = _n.args[0]
                                    if _PIN_ISINSTANCE(av, _a.Constant):
                                        return chr(int(av.value))
                                if _PIN_ISINSTANCE(fn, _a.Attribute) and \
                                    _PIN_LEN(_n.args) == 1:
                                    try:
                                        recv = _ev(fn.value)
                                    except Exception:
                                        recv = None
                                    try:
                                        arg = _ev(_n.args[0])
                                    except Exception:
                                        arg = None
                                    if fn.attr == "join" and recv is not None and arg is None:
                                        try:
                                            parts = []
                                            ag = _n.args[0]
                                            if _PIN_ISINSTANCE(ag, (_a.List, _a.Tuple)):
                                                ok = True
                                                for _e in ag.elts:
                                                    _p = _ev(_e)
                                                    if _p is None:
                                                        ok = False
                                                        break
                                                    parts.append(_p)
                                                if ok:
                                                    return recv.join(parts)
                                        except Exception:
                                            pass
                                    if fn.attr == "fromhex" and arg is not None:
                                        try:
                                            return bytes.fromhex(arg).decode("ascii", "ignore")
                                        except Exception:
                                            pass
                                if _PIN_ISINSTANCE(fn, _a.Name) and \
                                    fn.id == "bytes" and _PIN_LEN(_n.args) == 1:
                                    try:
                                        ag = _n.args[0]
                                        if _PIN_ISINSTANCE(ag, (_a.List, _a.Tuple)):
                                            vals = []
                                            for _e in ag.elts:
                                                if _PIN_ISINSTANCE(_e, _a.Constant) and \
                                                    _PIN_ISINSTANCE(_e.value, int):
                                                    vals.append(int(_e.value) & 0xFF)
                                                else:
                                                    vals = []
                                                    break
                                            if vals:
                                                return bytes(vals).decode("ascii", "ignore")
                                    except Exception:
                                        pass
                                if _PIN_ISINSTANCE(fn, _a.Attribute):
                                    try:
                                        return _ev(fn.value)
                                    except Exception:
                                        pass
                            except Exception:
                                return None
                            return None
                        if _PIN_ISINSTANCE(_n, _a.JoinedStr):
                            try:
                                parts = []
                                for _v in _n.values:
                                    if _PIN_ISINSTANCE(_v, _a.Constant) and \
                                        _PIN_ISINSTANCE(_v.value, str):
                                        parts.append(_v.value)
                                if parts:
                                    return "".join(parts)
                            except Exception:
                                pass
                            return None
                        if _PIN_ISINSTANCE(_n, _a.Subscript):
                            try:
                                base = _ev(_n.value)
                                sl = _n.slice
                                if base is not None and \
                                    _PIN_ISINSTANCE(sl, _a.Slice) and \
                                    sl.lower is None and sl.upper is None:
                                    try:
                                        st = sl.step
                                        if _PIN_ISINSTANCE(st, _a.UnaryOp) and \
                                            _PIN_ISINSTANCE(st.op, _a.USub) and \
                                            _PIN_ISINSTANCE(st.operand, _a.Constant) and \
                                            int(st.operand.value) == 1:
                                            return base[::-1]
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            return None
                        return None
                    except Exception:
                        return None

                r = _ev(tree.body)
                if r is not None:
                    return r[:256]
            except Exception:
                pass
        return ""
    except Exception:
        return ""


def _bracket_depth(text: str) -> int:
    try:
        depth = 0
        peak = 0
        in_str = None
        in_comment = False
        i = 0
        n = _PIN_LEN(text)
        while i < n:
            try:
                ch = text[i]
                if in_comment:
                    if ch == "\n":
                        in_comment = False
                    i += 1
                    continue
                if in_str is not None:
                    if _PIN_LEN(in_str) == 3:
                        if text.startswith(in_str, i):
                            in_str = None
                            i += 3
                            continue
                        i += 1
                        continue
                    if ch == "\\":
                        i += 2
                        continue
                    if ch == in_str:
                        in_str = None
                    i += 1
                    continue
                if ch == "#":
                    in_comment = True
                elif text.startswith("'''", i) or text.startswith('"""', i):
                    in_str = text[i:i + 3]
                    i += 3
                    continue
                elif ch in ("'", '"'):
                    in_str = ch
                elif ch in ("(", "[", "{"):
                    depth += 1
                    if depth > peak:
                        peak = depth
                        if peak > 200:
                            return peak
                elif ch in (")", "]", "}"):
                    depth -= 1
                    if depth < 0:
                        depth = 0
                i += 1
            except Exception:
                try:
                    i += 1
                except Exception:
                    break
                continue
        return peak
    except Exception:
        return 0


def audit_source(text: str) -> dict:
    try:
        if not _PIN_ISINSTANCE(text, str):
            try:
                text = _PIN_STR(text)
            except Exception:
                return {"findings": [], "tripped": False}
        if _PIN_LEN(text) > 1000000:
            text = text[:1000000]
        try:
            if _bracket_depth(text) > 200:
                return {"findings": ["DENS-deep-nesting"], "tripped": True}
        except Exception:
            pass
        findings: list = []
        _parsed = False
        try:
            import ast as _a
            import base64 as _b64
            import re as _re
            try:
                if _PIN_GETATTR(_a, "__name__", "ast") != "ast":
                    return {"findings": ["SENSOR-poisoned-ast"], "tripped": True}
                _spec = _PIN_GETATTR(_a, "__spec__", None)
                if _spec is None:
                    return {"findings": ["SENSOR-poisoned-ast"], "tripped": True}
                _orig = _PIN_GETATTR(_spec, "origin", "")
                if not _orig or "ast" not in _PIN_STR(_orig).lower():
                    return {"findings": ["SENSOR-poisoned-ast"], "tripped": True}
            except Exception:
                return {"findings": ["SENSOR-poisoned-ast"], "tripped": True}
        except Exception:
            return {"findings": ["SENSOR-import-fail"], "tripped": True}
        try:
            tree = _a.parse(text)
            _parsed = True
        except (RecursionError, MemoryError, SyntaxError, ValueError):
            return {"findings": ["DENS-parse-guard"], "tripped": True}
        except Exception:
            return {"findings": ["SCAN-aborted"], "tripped": True}
        _budget = [50000]
        _unparse_budget = [200]
        for _node in _a.walk(tree):
            try:
                _budget[0] -= 1
                if _budget[0] <= 0:
                    findings.append("DENS-node-budget")
                    break
            except Exception:
                break
            try:
                if _PIN_ISINSTANCE(_node, _a.Call):
                    try:
                        fn = _node.func
                        nm = ""
                        if _PIN_ISINSTANCE(fn, _a.Name):
                            nm = fn.id
                        elif _PIN_ISINSTANCE(fn, _a.Attribute):
                            nm = fn.attr
                        if nm in ("settrace", "setprofile", "addaudithook",
                                  "set_local_events", "set_events",
                                  "breakpoint", "breakpointhook"):
                            findings.append("DYN-trace-hook:" + nm)
                        if nm in ("exec", "eval", "compile", "__import__"):
                            findings.append("DYN-exec-prim:" + nm)
                        if nm in ("gettrace", "getprofile", "getmonitoring",
                                  "current_frames", "_current_frames"):
                            findings.append("DYN-introspect:" + nm)
                        if nm == "getattr" and _PIN_LEN(_node.args) >= 2:
                            try:
                                _a2 = _node.args[1]
                                _r = ""
                                if _PIN_ISINSTANCE(_a2, _a.Constant) and _PIN_ISINSTANCE(_a2.value, str):
                                    _r = _a2.value
                                elif _PIN_ISINSTANCE(_a2, (_a.BinOp, _a.Call, _a.Subscript,
                                                           _a.JoinedStr, _a.Attribute)):
                                    try:
                                        if _unparse_budget[0] > 0:
                                            _unparse_budget[0] -= 1
                                            _r = _resolve_obfuscated_name(_a.unparse(_a2))  # type: ignore[attr-defined]
                                    except Exception:
                                        _r = ""
                                if _r in ("settrace", "setprofile", "gettrace", "getprofile",
                                          "breakpoint", "breakpointhook", "exec", "eval"):
                                    findings.append("DYN-getattr-hook:" + _r)
                            except Exception:
                                pass
                    except Exception:
                        pass
                if _PIN_ISINSTANCE(_node, _a.JoinedStr):
                    try:
                        _js = ""
                        try:
                            _js = _a.unparse(_node)  # type: ignore[attr-defined]
                            _jr = _resolve_obfuscated_name(_js)
                            if _jr in ("settrace", "setprofile", "breakpoint", "breakpointhook", "exec", "eval"):
                                findings.append("STR-fstring-prim:" + _jr)
                                _js = _jr
                            else:
                                _js = "".join(_v.value for _v in _node.values if _PIN_ISINSTANCE(_v, _a.Constant) and _PIN_ISINSTANCE(_v.value, str))
                        except Exception:
                            _js = "".join(_v.value for _v in _node.values if _PIN_ISINSTANCE(_v, _a.Constant) and _PIN_ISINSTANCE(_v.value, str))
                        if _js in ("settrace", "setprofile", "breakpoint", "breakpointhook", "exec", "eval"):
                            if "STR-fstring-prim:" + _js not in findings:
                                findings.append("STR-fstring-prim:" + _js)
                    except Exception:
                        pass
                if _PIN_ISINSTANCE(_node, _a.Subscript):
                    try:
                        _sl = _node.slice
                        _sn = ""
                        if _PIN_ISINSTANCE(_sl, _a.Constant) and _PIN_ISINSTANCE(_sl.value, str):
                            _sn = _sl.value
                        elif _PIN_ISINSTANCE(_sl, _a.BinOp):
                            try:
                                _sn = _resolve_obfuscated_name(_a.unparse(_sl))  # type: ignore[attr-defined]
                            except Exception:
                                _sn = ""
                        if _sn in ("settrace", "breakpointhook", "breakpoint", "__dict__", "exec", "eval"):
                            findings.append("DYN-subscript-hook:" + _sn)
                    except Exception:
                        pass
                if _PIN_ISINSTANCE(_node, (_a.Import, _a.ImportFrom)):
                    try:
                        names = []
                        if _PIN_ISINSTANCE(_node, _a.Import):
                            names = [_x.name for _x in _node.names]
                        else:
                            names.append(_PIN_STR(_node.module or ""))
                        blob = " ".join(names).lower()
                        for _bad in ("debugpy", "pydevd", "coverage",
                                     "uncompyle", "decompyle", "frida",
                                     "pycdc"):
                            if _bad in blob:
                                findings.append("STDLIB-analysis-import:" + _bad)
                    except Exception:
                        pass
                if _PIN_ISINSTANCE(_node, _a.Constant) and \
                   _PIN_ISINSTANCE(_node.value, str):
                    try:
                        v = _node.value
                        if v in ("settrace", "setprofile", "breakpoint", "breakpointhook",
                                 "gettrace", "getprofile", "addaudithook", "set_events",
                                 "exec", "eval"):
                            findings.append("STR-plain-hook:" + v)
                        if 64 <= _PIN_LEN(v) <= 200000:
                            try:
                                _b64.b64decode(v, validate=True)
                                if _re.search(r"[A-Za-z0-9+/]{64,}={0,2}", v):
                                    findings.append("ENC-b64-blob")
                            except Exception:
                                pass
                    except Exception:
                        pass
                if _PIN_ISINSTANCE(_node, _a.BinOp) and \
                   _PIN_ISINSTANCE(_node.op, _a.Add):
                    try:
                        if _unparse_budget[0] <= 0:
                            continue
                        _unparse_budget[0] -= 1
                        src = _a.unparse(_node)  # type: ignore[attr-defined]
                        resolved = _resolve_obfuscated_name(src)
                        if resolved in _OBFUSCATED_EXEC_PRIMS or \
                           resolved in ("settrace", "setprofile",
                                        "gettrace", "getprofile"):
                            findings.append("STR-obfuscated-prim:" + resolved)
                    except Exception:
                        pass
            except Exception:
                continue
        tripped = _PIN_LEN(findings) > 0
        return {"findings": findings[:64], "tripped": bool(tripped)}
    except Exception:
        try:
            _aborted = _parsed
        except Exception:
            _aborted = False
        if _aborted:
            try:
                _f = list(findings)
            except Exception:
                _f = []
            try:
                _f.append("SCAN-aborted")
            except Exception:
                _f = ["SCAN-aborted"]
            return {"findings": _f[:64], "tripped": True}
        return {"findings": [], "tripped": False}


def scan_function(fn) -> dict:
    try:
        if _safe_kind(fn) == "exotic":
            return {}
        co = _co_of(fn)
        if co is None:
            return {}
        out: dict = {}
        try:
            names: set = set()
            consts: list = []
            try:
                for _ins in _PIN_DIS_GET_INSTRUCTIONS(co):
                    try:
                        n = _PIN_GETATTR(_ins, "opname", "")
                        a = _PIN_GETATTR(_ins, "argrepr", "")
                        if n in ("LOAD_GLOBAL", "LOAD_NAME", "LOAD_ATTR",
                                 "LOAD_METHOD", "LOAD_DEREF", "LOAD_CLOSURE",
                                 "LOAD_CLASSDEREF", "LOAD_FROM_DICT_OR_DEREF",
                                 "LOAD_FROM_DICT_OR_GLOBALS"):
                            if a:
                                try:
                                    _an = _PIN_STR(a).split(".")[-1]
                                    if "+" in _an:
                                        _an = _an.split("+")[-1].strip()
                                    names.add(_an)
                                except Exception:
                                    pass
                        if n == "LOAD_CONST":
                            try:
                                consts.append(_ins.argval)
                            except Exception:
                                pass
                    except Exception:
                        continue
            except Exception:
                pass
            hook_names = {"settrace", "setprofile", "addaudithook",
                          "set_events", "set_local_events",
                          "register_callback", "gettrace", "getprofile",
                          "current_frames", "_current_frames",
                          "breakpoint", "breakpointhook",
                          "__breakpointhook__"}
            dyn_construct_names = {"chr", "join", "fromhex", "bytes",
                                   "decode", "encode", "format", "getattr"}
            try:
                if names & dyn_construct_names:
                    out["dynamic_name_construct"] = True
            except Exception:
                pass
            try:
                _free = _PIN_GETATTR(co, "co_freevars", ()) or ()
                for _n in _free:
                    if _PIN_STR(_n) in hook_names:
                        out["trace_hook_ref"] = True
                        break
            except Exception:
                pass
            try:
                _clo = _PIN_GETATTR(fn, "__closure__", None)
                if _clo:
                    for _cell in _clo:
                        try:
                            _v = _PIN_GETATTR(_cell, "cell_contents", None)
                        except Exception:
                            continue
                        try:
                            if _v is _PIN_SYS_GETTRACE or _v is _PIN_SYS_GETPROFILE or \
                               _v is _PIN_SYS_BREAKPOINTHOOK or _v is _PIN_BUILTIN_BREAKPOINT:
                                out["trace_hook_ref"] = True
                                break
                            _vn = _PIN_GETATTR(_v, "__name__", "")
                            if _PIN_STR(_vn) in hook_names:
                                out["trace_hook_ref"] = True
                                break
                        except Exception:
                            continue
            except Exception:
                pass
            if names & hook_names:
                out["trace_hook_ref"] = True
            prim_names = {"exec", "eval", "compile", "__import__"}
            if names & prim_names:
                out["exec_prim_ref"] = True
            for _c in consts:
                try:
                    if _PIN_ISINSTANCE(_c, str) and _PIN_LEN(_c) >= 3:
                        if _c in ("settrace", "setprofile", "breakpoint", "breakpointhook",
                                  "gettrace", "getprofile", "exec", "eval", "compile"):
                            out["obfuscated_prim_const"] = True
                            break
                        r = _resolve_obfuscated_name(repr(_c))
                        if r in _OBFUSCATED_EXEC_PRIMS or r in ("settrace", "setprofile", "breakpoint"):
                            out["obfuscated_prim_const"] = True
                            break
                except Exception:
                    continue
        except Exception:
            pass
        return out
    except Exception:
        return {}


def scan_module(mod) -> dict:
    try:
        out: dict = {}
        if _safe_kind(mod) == "exotic":
            return out
        try:
            fns = []
            try:
                if _PIN_ISINSTANCE(mod, (_PIN_MODULE_TYPE, _PIN_TYPE)):
                    try:
                        d = _raw_dict(mod)
                    except Exception:
                        d = None
                    pairs = []
                    try:
                        if d is not None and (_PIN_TYPE(d) is dict or _PIN_TYPE(d) is _PIN_MAPPINGPROXY_TYPE):
                            try:
                                _items = d.items
                            except Exception:
                                _items = None
                            if _items is not None:
                                pairs = _PIN_LIST(_items())
                    except Exception:
                        pairs = []
                    for _n, _o in pairs:
                        try:
                            if _PIN_ISINSTANCE(_o, _PIN_FUNC_TYPE):
                                fns.append(_o)
                        except Exception:
                            continue
                else:
                    try:
                        import inspect as _insp
                        _gstatic = _PIN_GETATTR(_insp, "getattr_static", None)
                    except Exception:
                        _gstatic = None
                    for _n in dir(mod):
                        try:
                            if _gstatic is not None:
                                try:
                                    _o = _gstatic(mod, _n)
                                except Exception:
                                    continue
                            else:
                                _o = _PIN_GETATTR(mod, _n, None)
                            if _PIN_ISINSTANCE(_o, _PIN_FUNC_TYPE):
                                fns.append(_o)
                        except Exception:
                            continue
            except Exception:
                fns = []
            agg: dict = {}
            for _f in fns[:256]:
                try:
                    r = scan_function(_f)
                    for _k, _v in _PIN_LIST(r.items()):
                        if _v:
                            agg[_k] = True
                except Exception:
                    continue
            out.update(agg)
        except Exception:
            pass
        return out
    except Exception:
        return {}


_WATCH_CAP = 4096


def watch(fn, key=None):
    """Izlemeye al. Cap doluysa REDDEDILIR (None) — aktif pin asla
    tahliye edilmez (F2: flood-evict kapali, fail-closed kapasite)."""
    try:
        if _safe_kind(fn) == "exotic":
            return None
        with _LOCK:
            if _PIN_LEN(_WATCH) >= _WATCH_CAP:
                try:
                    _note_watch_refused()
                except Exception:
                    pass
                return None
            _WATCH[key or _PIN_ID(fn)] = fn
        return key or _PIN_ID(fn)
    except Exception:
        return None


def unwatch(fn=None, key=None):
    """Izlemeden cikar (YONETIM: kayitli operator sart — korlestirme kapali)."""
    if not _check_admin():
        _deny_admin("unwatch")
    try:
        with _LOCK:
            if key is not None:
                _WATCH.pop(key, None)
            elif fn is not None:
                _WATCH.pop(_PIN_ID(fn), None)
        return True
    except Exception:
        return False


def pin(fn, key=None):
    try:
        if _safe_kind(fn) == "exotic":
            return None
        co = _co_of(fn)
        if co is None:
            with _LOCK:
                _PINS[key or _PIN_ID(fn)] = (_PIN_ID(fn), _func_names(fn))
            return key or _PIN_ID(fn)
        fp = _code_fp(co)
        if not fp:
            return None
        with _LOCK:
            _PINS[key or _PIN_ID(fn)] = (_PIN_ID(fn), _func_names(fn), fp)
        return key or _PIN_ID(fn)
    except Exception:
        return None


def verify_pins() -> bool:
    try:
        with _LOCK:
            items = _PIN_LIST(_PINS.items())
            watches = dict(_WATCH)
        for key, _rec in items:
            try:
                fn = watches.get(key)
                if fn is None:
                    continue
                if _PIN_LEN(_rec) == 3:
                    fid, names, fp = _rec
                    if _PIN_ID(fn) != fid or _func_names(fn) != names:
                        return False
                    co = _co_of(fn)
                    if co is not None and _code_fp(co) != fp:
                        return False
                else:
                    fid, names = _rec[0], _rec[1]
                    if _PIN_ID(fn) != fid or _func_names(fn) != names:
                        return False
            except Exception:
                return False
        return True
    except Exception:
        return False


def _self_fp() -> str:
    try:
        import hashlib as _h
        parts: list = []
        try:
            parts.append(repr(sorted(WEIGHTS.items())))
        except Exception:
            parts.append("?")
        try:
            parts.append(repr(sorted(STRONG)))
        except Exception:
            parts.append("?")
        for _v in (_THRESHOLD_TRIP, _TIMING_BASELINE_N,
                   _PROBE_CAP, _PROBE_TTL, _WATCH_CAP):
            try:
                parts.append(repr(_v))
            except Exception:
                parts.append("?")
        for _s in (_DEBUGGER_MODULES, _COVERAGE_MODULES,
                   _STATIC_TOOL_MODULES, _PARENT_HINTS,
                   _OBFUSCATED_EXEC_PRIMS):
            try:
                parts.append(repr(sorted(_s)))
            except Exception:
                parts.append("?")
        try:
            parts.append(repr(tuple(_ENV_FLAGS)))
        except Exception:
            parts.append("?")
        return _h.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()
    except Exception:
        return ""


def _verify_self_fp() -> bool:
    try:
        if not _SELF_FP:
            return True
        return _self_fp() == _SELF_FP
    except Exception:
        return False


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk basarili seal() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _LOCK:
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
        with _LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def lock_admin():
    """Yonetim kaydini kilitle (seal() zaten kilitler)."""
    global _ADMIN_LOCKED
    try:
        with _LOCK:
            _ADMIN_LOCKED = True
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
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
    """Yonetim reddi: sayaç + fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()


def _note_watch_refused() -> None:
    """Flood-reddi zaman damgasi (son 60s penceresi, cap'li)."""
    try:
        now = _PIN_TIME_MONOTONIC()
        with _LOCK:
            _WATCH_REFUSED_TIMES.append(now)
            while _PIN_LEN(_WATCH_REFUSED_TIMES) > 128:
                _WATCH_REFUSED_TIMES.pop(0)
    except Exception:
        pass


def _check_watch_flood() -> bool:
    """WEAK: son 60s'de cap-reddi yasandi mi (flood girisimi izi)."""
    try:
        now = _PIN_TIME_MONOTONIC()
        with _LOCK:
            items = _PIN_LIST(_WATCH_REFUSED_TIMES)
        for _t in items:
            try:
                if 0.0 <= now - _t < 60.0:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return True


def seal() -> dict:
    """Operator muhru: timing-baseline yenile + watch'lari pin'le.

    YONETIM: kayitli operator sart (F1: saldirgan kendi zehirli
    baseline'ini mesrulastiramaz). Basarili seal sanctioned-baseline'i
    gunceller + yonetim kaydini kilitler.
    """
    if not _check_admin():
        _deny_admin("seal")
    global _TIMING_BASELINE_SANCTIONED, _ADMIN_LOCKED
    try:
        _snapshot_timing_baseline()
        with _LOCK:
            _TIMING_BASELINE_SANCTIONED = _TIMING_BASELINE
            _ADMIN_LOCKED = True
            for key, fn in _PIN_LIST(_WATCH.items()):
                try:
                    co = _co_of(fn)
                    if co is not None:
                        fp = _code_fp(co)
                        if fp:
                            _PINS[key] = (_PIN_ID(fn), _func_names(fn), fp)
                            continue
                    _PINS[key] = (_PIN_ID(fn), _func_names(fn))
                except Exception:
                    continue
        return {"sealed": True, "pins": _PIN_LEN(_PINS)}
    except Exception:
        return {"sealed": False, "pins": 0}


def harden() -> dict:
    try:
        return seal()
    except Exception:
        return {"sealed": False, "pins": 0}


def guard():
    return check_all()


def _raw_results() -> dict:
    """F5 duzeltmesi: sensor-hatasi fail-closed True'dur (sensor_health dahil
    tum sinyallerde simetrik)."""
    out: dict = {}
    try:
        out["tracer_active"] = bool(_check_tracer())
    except Exception:
        out["tracer_active"] = True
    try:
        out["profiler_active"] = bool(_check_profiler())
    except Exception:
        out["profiler_active"] = True
    try:
        out["monitoring_active"] = bool(_check_monitoring())
    except Exception:
        out["monitoring_active"] = True
    try:
        out["debugger_module"] = bool(_check_debugger_module())
    except Exception:
        out["debugger_module"] = True
    try:
        out["timing_skew"] = bool(_check_timing_skew())
    except Exception:
        out["timing_skew"] = True
    try:
        out["sensor_health"] = bool(_check_sensor_health())
    except Exception:
        out["sensor_health"] = True
    try:
        out["coverage_artifact"] = bool(_check_coverage_artifact())
    except Exception:
        out["coverage_artifact"] = True
    try:
        out["static_tool_artifact"] = bool(_check_static_tool_artifact())
    except Exception:
        out["static_tool_artifact"] = True
    try:
        out["env_analysis_flag"] = bool(_check_env_flag())
    except Exception:
        out["env_analysis_flag"] = True
    try:
        out["frame_trace_anomaly"] = bool(_check_frame_anomaly())
    except Exception:
        out["frame_trace_anomaly"] = True
    try:
        out["parent_suspicious"] = bool(_check_parent_suspicious())
    except Exception:
        out["parent_suspicious"] = True
    try:
        out["analysis_probe_anomaly"] = bool(_check_probe_anomaly())
    except Exception:
        out["analysis_probe_anomaly"] = True
    try:
        out["watch_flood"] = bool(_check_watch_flood())
    except Exception:
        out["watch_flood"] = True
    return out


def _score(results: dict) -> int:
    try:
        total = 0
        for k, v in _PIN_LIST(results.items()):
            try:
                if v:
                    total += WEIGHTS.get(k, 0)
            except Exception:
                continue
        return total
    except Exception:
        return 0


def is_tripped(results: dict | None = None) -> bool:
    try:
        res = results if results is not None else _raw_results()
        strong_hit = any(bool(res.get(k)) for k in STRONG)
        if strong_hit:
            return True
        weak_n = sum(1 for k, v in _PIN_LIST(res.items()) if v and k not in STRONG)
        return weak_n >= 2 or _score(res) >= _THRESHOLD_TRIP
    except Exception:
        return True


def check_all() -> dict:
    try:
        return _raw_results()
    except Exception:
        return {k: True for k in WEIGHTS}


def status() -> dict:
    try:
        res = _raw_results()
        with _LOCK:
            wcount = _PIN_LEN(_WATCH)
            rcount = _PIN_LEN(_WATCH_REFUSED_TIMES)
            admin_n = _PIN_LEN(_ADMIN_MODULES)
        return {"tripped": bool(is_tripped(res)),
                "strong": sum(1 for k in STRONG if res.get(k)),
                "weak": sum(1 for k, v in _PIN_LIST(res.items()) if v and k not in STRONG),
                "points": _score(res), "results": res,
                "watch_count": wcount, "watch_refused_60s": rcount,
                "admin_authorized": admin_n, "admin_locked": _ADMIN_LOCKED,
                "admin_denied": _ADMIN_DENIED}
    except Exception:
        return {"tripped": True, "strong": 0, "weak": 0, "points": 0, "results": {}}


_PROBE_CAP = 2048
_PROBE_TTL = 300.0


def _prune_probe_log(now: float) -> None:
    try:
        with _LOCK:
            if _PIN_LEN(_PROBE_LOG) <= _PROBE_CAP:
                try:
                    for _k in [k for k, t in _PIN_LIST(_PROBE_LOG.items())
                               if now - t > _PROBE_TTL]:
                        _PROBE_LOG.pop(_k, None)
                except Exception:
                    pass
                return
            try:
                ordered = sorted(_PROBE_LOG.items(), key=lambda kv: kv[1])
                for _k, _t in ordered[:_PIN_LEN(ordered) // 2]:
                    _PROBE_LOG.pop(_k, None)
            except Exception:
                try:
                    _PROBE_LOG.clear()
                except Exception:
                    pass
    except Exception:
        pass


def probe(fn) -> dict:
    try:
        res = scan_function(fn)
        try:
            now = _PIN_TIME_MONOTONIC()
            with _LOCK:
                _PROBE_LOG[_PIN_ID(fn)] = now
            _prune_probe_log(now)
        except Exception:
            pass
        cur = check_all()
        return {"tripped": bool(is_tripped(cur)),
                "points": _score(cur), "results": res}
    except Exception:
        return {"tripped": True, "points": 0, "results": {}}


def set_alert_hook(fn) -> bool:
    global _ALERT_HOOK
    try:
        if fn is None:
            _ALERT_HOOK = None
            return True
        if not callable(fn):
            return False
        _ALERT_HOOK = fn
        return True
    except Exception:
        return False


def _watch_loop(stop, interval, heal):
    try:
        while not stop.is_set():
            try:
                res = _raw_results()
                if is_tripped(res):
                    try:
                        if _ALERT_HOOK is not None:
                            _ALERT_HOOK(status())
                    except Exception:
                        pass
                    if heal and not any(bool(res.get(k)) for k in STRONG):
                        try:
                            verify_pins()
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                stop.wait(interval)
            except Exception:
                break
    except Exception:
        pass


def start_watchdog(interval=2.0, heal=True):
    try:
        try:
            interval = float(interval)
        except Exception:
            return None
        if interval != interval or interval < 0.1:
            interval = 0.1
        elif interval > 3600.0:
            interval = 3600.0
        stop = _PIN_THREAD_EVENT()
        t = _PIN_THREAD_THREAD(target=_watch_loop, args=(stop, interval, heal), daemon=True)
        t.start()
        try:
            _WD_STOPS.add(stop)
        except Exception:
            pass
        return stop
    except Exception:
        return None


def stop_all_watchdogs():
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    try:
        stops = list(_WD_STOPS)
        for _s in stops:
            try:
                _s.set()
            except Exception:
                continue
        return True
    except Exception:
        return False


_SELF_FP = _self_fp()

_snapshot_timing_baseline()
_TIMING_BASELINE_SANCTIONED = _TIMING_BASELINE
