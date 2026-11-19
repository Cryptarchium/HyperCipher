"""anti_reflection: Python reflection/introspection saldiri tespit katmani.

Tehdit modeli (arastirma sentezi - 3x ReSearch):
  - Sinif-hiyerarsi tirmanisi (Checkmarx "Glass Sandbox" 2025, SmartTLDR deep-dive,
    yaklang pyjail cheat-sheet, FastGPT GHSA-5jmh-5f2m-89jg 2026-07-01):
    ``().__class__.__bases__[0].__subclasses__()`` ile tum yuklu siniflara erisim,
    ``__init__.__globals__`` ile modul namespace sizintisi (``os.system``/``popen``),
    ``warnings.catch_warnings`` / ``os._wrap_close`` / ``subprocess.Popen`` klasik
    hedefler. Kapsama: her obje ``object``'ten turedi + kapsulleme YOK -> ayni-process
    icinde mutlak onleme mumkun DEGIL (CPython veri modeli, docs 3.14). Bu modul
    ONLEME degil TESPIT katmanidir (fail-closed tripwire).
  - Statik-kontrolden kacis (FastGPT GHSA, chs.us "Six layers" 2026-07,
    PraisonAI PYSEC-2026-483, GHSA-XM98-3VCF-FPH7 ContextForge):
    ``getattr(x, "__subcl" + "asses__")`` (ast.BinOp, Constant degil),
    ``chr(95)*2 + ...``, ``"{0.__class__}".format()`` / ``format_map`` /
    f-string (runtime getattr, AST'nin gormedigi), ``print.__self__`` ->
    ``builtins`` modulu -> ``vars(b)`` -> ``__import__`` (4-bosluk zinciri),
    ``b.exec(...)`` / ``d["exec"](...)`` (ast.Attribute/Subscript call,
    ast.Name kontrolunu atlar). Ders: dunder-name denylist + ``isinstance(func,
    ast.Name)`` yetersiz; non-constant isim + tum reflection-primitifleri
    (str.format/f-string/%/template/getattr-wrapper) numaralandirilmali.
  - Cerceve/kapanis/nesne-kesfi (sandboxaudit SB01-SB15, bpo-42800 GH-24182,
    n8n CVE-2026-0863, Langflow CVE-2025-3248, RestrictedPython CVE-2025-22153):
    ``sys._getframe`` / ``inspect.stack|currentframe`` + ``f_code/f_globals/
    f_locals/gi_frame/gi_code/tb_frame/cr_*`` (AUDIT_READ, PEP 578),
    ``__closure__[i].cell_contents`` (lexical closure peel, GM dev.to 2026-09),
    ``gc.get_objects/get_referrers`` (nesne kesfi), ``__code__/co_freevars/
    co_consts`` + ``types.CodeType/compile`` (kod-nesnesi insasi),
    ``__reduce__/__reduce_ex__`` (pickle; bu modulde WEAK sinyal, derin
    tarama anti_decompile/anti_data_flow'dadir), ``__mro__/__bases__/
    __dict__/vars/dir`` (kesif), ``AttributeError.obj`` (3.10+, SB13),
    metaclass/decorator ``__init_subclass__/__set_name__`` (SB15).
  - Gozlem/duvar-ornekleri (PEP 578, sys.addaudithook docs, strictaccess
    limitations, DaniWeb private-attr cozumu, pyprotect, Descriptor HowTo):
    audit-hook'lar gozlem icindir, sandbox DEGILDIR (ctypes ile atlatilir);
    ``object.__getattribute__`` override'i ``object.__getattribute__`` ile
    atlatilir; closure/mappingproxy okumaya karsi korumasizdir; ``__slots__``
    gizlilik degil duzen-aracidir. Bu modul audit-hook'u ZORLAMA icin DEGIL,
    IOC sayaci icin kullanir (danisman, fail-safe: hook asla yukseltmez,
    sadece sayar; karar ``check_all``'dedir).

Kapsam (kardeslerle cakisma yok):
  - anti_hook: monkey-patch/``__code__`` degisimi/wrapt/native kanca; BU modul
    reflection ERISIM DESENINI (ladder/globals/closure/frame/dinamik-cozum)
    tutar. ``__code__`` tek-basina burada sinyal DEGILDIR (FP korumasi);
    yalnizca hassas-sonek (co_freevars/co_consts/replace/CodeType) ile WEAK.
  - anti_tamper: dosya/bytecode/attr-degisimi; BU modul okuma-kesif desenini
    tutar (degisiklik degil erisim).
  - anti_error_leakage: hata-metni; BU modul ``AttributeError.obj`` +
    traceback-frame okuma DESENINI tutar (metin degil davranis).
  - anti_decompile/anti_bytecode/anti_data_flow/anti_constant: genel
    bytecode/sabit-akisi; BU modul SADECE reflection-primitiflerine bakar.
  - anti_memory_inspection: canli bellek; BU modul Python-nesne-grafigi
    uzerinden erisimi tutar.
  - anti_sandbox/anti_vm/anti_debug/anti_trace: ortam/izleme; cakisma yok.

Sinyal kurallari (FP-guvenli, isim-korelasyonlu - veri-akisi yok, dokumante):
  - Tarama birlesiktir: co + tum ic-ice co'lar (nested def/lambda/
    comprehension; KONTROL-7 K8a) tek vocab'da toplanir. "ayni co" asagida
    bu birlesik gorunumu ifade eder.
  - class_hierarchy_traversal (STRONG): ``__class__`` + en az biri
    (``__subclasses__`` | ``__bases__`` | ``__mro__`` | ``__base__``) VEYA
    ciplak ``__subclasses__``/``mro()`` VEYA (1b) ``__dict__``/``vars`` +
    subscript ile ladder-dunder hedefleme (mappingproxy merdiveni, K8b).
    Tek ``__class__`` (normal OOP) sayilmaz; hedefsiz ciplak ``__dict__``
    recon-only sayilmaz.
  - globals_escape (STRONG): HERHANGI ``__globals__`` okuma (LangFlow/
    chs.us/sandboxaudit-SB06 endustri standardi: tum dunder-erisim red;
    mesru kullanim nadir + kotu-pratik). Ortakli okuma de ayni sinyal.
  - closure_cell_escape (STRONG): ``__closure__`` + ``cell_contents`` ayni co.
    Tek ``__closure__`` sayilmaz.
  - dynamic_dunder_resolve (STRONG): getattr/setattr/delattr/``__getattribute__``/
    attrgetter-methodcaller-get_field-vformat ailesi + (a) dunder-sabiti
    (``__code__`` HARIC) VEYA (b) string-insasi (BINARY_ADD/MODULO,
    BINARY_OP +/% (0/6; |/&/* HARIC - TUR-7c FP), FORMAT_VALUE'siz
    BUILD_STRING, ``chr``) VEYA (c) MATCH_CLASS + tuple-const dunder
    (match/case sinif-deseni, mcp-use #1735) VEYA (4c) reflect-ailesi +
    ``dir`` + BINARY_SUBSCR (InCTF 2018 dir()+indeks; for-in sayilmaz) VEYA
    (4d) super()-suz manuel ``__init_subclass__``/``__set_name__`` cagrisi
    (SB15; isbirlikci super() muaftir). Ciplak f-string + bayrak-``|=`` + ``'='*50``
    (b) sayilmaz. Sabit non-dunder isimli getattr sayilmaz.
  - frame_introspection (WEAK): ``_getframe/currentframe/stack/trace/
    gi_frame/gi_code/f_code/f_globals/f_locals/tb_frame/cr_frame/cr_code/
    ag_frame/ag_code`` + ``inspect`` baglami. Mesru debugger FP'si operatorde.
  - format_string_introspection (WEAK): (``format`` | ``format_map`` |
    FORMAT_VALUE) + dunder (chs.us dersi).
  - builtins_module_leak (WEAK): ``__self__`` + (``vars`` | ``__dict__`` |
    ``__builtins__``) VEYA ciplak ``__builtins__`` okuma (PraisonAI dersi).
  - gc_object_discovery (WEAK): ``gc`` + ``get_objects/get_referrers/
    get_referents`` (SB09).
  - code_object_access (WEAK): ``__code__`` + hassas-sonek (co_freevars/
    co_consts/co_names/co_code/replace/cell_contents) VEYA ``CodeType`` VEYA
    (``compile`` + ``__code__``). Tek defansif ``__code__`` sayilmaz.
  - reflection_probe_anomaly (WEAK, runtime): audit-hook sayaci 60s'de >=50
    dunder-erisimi (IOC; eforlu tarama).
  - pin_mismatch / sensor_health (STRONG): standart altyapi.
  - Trip >=1 STRONG veya >=2 WEAK. Tek WEAK trip uretmez.

Sinirlar (bilincli tercihler, dokumante rezidu):
  - Isim-korelasyonu veri-akisi DEGILDIR: ayni (birlesik) gorunumde gecen
    iki isim baglantisiz da olabilir (asiri-yaklasim, yonu guvenli:
    suphede True). Tersine, cok-adimli daginik oruntuler (degiskende
    tasinan isimler) gorunmez (eksik-yaklasim). Tam veri-akisi
    anti_data_flow'dadir.
  - Ayni-process hostile-code'a karsi mutlak sinir YOKTUR (CPython evrensel
    introspection + mutable-runtime + obje-graf erisilebilirligi). Bu modul
    citayi yukseltir + iz birakir (tripwire), garanti vermez.
  - Audit-hook danismandir; ``ctypes``/C-seviyesi okuma gorunmez.
  - ``check_all()`` yalnizca watch()+pin() kayitlarini + sayaci tarar.
  - Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

from __future__ import annotations

import sys as _sys
import threading as _threading
import time as _time


class ReflectionDetected(RuntimeError):
    """Opak tripwire hatasi: yuzey detay sizdirmaz."""

    pass


def _raise() -> None:
    raise ReflectionDetected("protected")


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


# ---------------------------------------------------------------------------
# Pin'li referanslar (import-aninda bagla; anti_hook dersi: erken import)
# ---------------------------------------------------------------------------

_PIN_DIS_GET_INSTRUCTIONS = _take_dis_pin("get_instructions")
_PIN_DIS_OPMAP = _take_dis_pin("opmap")
_PIN_DIS_HASCONST = _take_dis_pin("hasconst")
_PIN_SYS_ADDAUDITHOOK = getattr(_sys, "addaudithook", None)
_PIN_TIME_MONOTONIC = _time.monotonic
_PIN_THREAD_RLOCK = _threading.RLock
_PIN_THREAD_THREAD = _threading.Thread
_PIN_THREAD_EVENT = _threading.Event
_PIN_GETATTR = getattr
_PIN_HASATTR = hasattr
_PIN_ISINSTANCE = isinstance
_PIN_LEN = len
_PIN_SET = set
_PIN_LIST = list
_PIN_FROZENSET = frozenset
_PIN_STR = str

_LOCK = _PIN_THREAD_RLOCK()

# sinyal agirliklari: STRONG=100, WEAK=30 (kardes konvansiyon)
WEIGHTS = {
    "class_hierarchy_traversal": 100,
    "globals_escape": 100,
    "closure_cell_escape": 100,
    "dynamic_dunder_resolve": 100,
    "pin_mismatch": 100,
    "sensor_health": 100,
    "frame_introspection": 30,
    "format_string_introspection": 30,
    "builtins_module_leak": 30,
    "gc_object_discovery": 30,
    "code_object_access": 30,
    "bare_import_escape": 100,
    "reflection_probe_anomaly": 30,
}
STRONG = _PIN_FROZENSET({
    "class_hierarchy_traversal",
    "globals_escape",
    "closure_cell_escape",
    "dynamic_dunder_resolve",
    "bare_import_escape",
    "pin_mismatch",
    "sensor_health",
})
_THRESHOLD_TRIP = 100
_INSN_CAP = 20000
_PROBE_WINDOW_S = 60.0
_PROBE_THRESHOLD = 50

# ---------------------------------------------------------------------------
# Tehlike sozlukleri (sandboxaudit SB01-SB15 sentezi)
# ---------------------------------------------------------------------------

# Merdiven: __class__ + ortak VEYA ciplak __subclasses__ VEYA mro() cagrisi
# (TUR-5: LangFlow _BLOCKED_ATTRIBUTES "mro" paritesi - int.mro() dunder'siz
# hiyerarsiye ulasir; ciplak object.__subclasses__() FastGPT merdiveninin
# kisa yoludur; mesru .mro()/__subclasses__ kullanimi kripto-kodda yok)
_LADDER_PARTNERS = _PIN_FROZENSET({
    "__subclasses__", "__bases__", "__mro__", "__base__",
})
# Dinamik cozum ailesi (TUR-5 genisletme: LangFlow paritesi - attrgetter/
# methodcaller/get_field/vformat ailesi runtime-string ile ayni traversali
# yapar, AST-attr kontrolune gorunmez)
_REFLECT_CALLS = _PIN_FROZENSET({
    "getattr", "setattr", "delattr", "__getattribute__", "__getattr__",
    "attrgetter", "methodcaller", "get_field", "get_value", "vformat",
    "format_field", "convert_field",
})
# Tum dunder gozlem kumesii (sabit-tarama icin)
_DUNDER_ALL = _PIN_FROZENSET({
    "__class__", "__bases__", "__base__", "__mro__", "__subclasses__",
    "__globals__", "__dict__", "__builtins__", "__code__", "__closure__",
    "__func__", "__self__", "__init__", "__import__", "__loader__",
    "__spec__", "__reduce__", "__reduce_ex__", "__getattribute__",
    "__getattr__", "__setattr__", "__delattr__", "__slots__",
    "__init_subclass__", "__set_name__",
    "cell_contents", "co_freevars", "co_consts", "co_names", "co_code",
    "gi_frame", "gi_code", "f_code", "f_globals", "f_locals",
    "tb_frame", "cr_frame", "cr_code", "ag_frame", "ag_code",
})
# FP istisnasi: defansif okuma (kardes moduller + bu modul kullanir)
_DEFENSIVE_ONLY_OK = _PIN_FROZENSET({"__code__"})
# Cerceve API isimleri (WEAK)
_FRAME_NAMES = _PIN_FROZENSET({
    "_getframe", "currentframe", "getframe", "stack", "trace",
    "gi_frame", "gi_code", "f_code", "f_globals", "f_locals",
    "tb_frame", "cr_frame", "cr_code", "ag_frame", "ag_code",
    "inspect", "traceback", "frame",
})

_WATCH: dict = {}
_PINS: dict = {}
_ALERT_HOOK = None
_PROBE_TIMES: list = []
_RF_ADMINS: dict = {}
_RF_ADMIN_LOCKED = False
_RF_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _RF_ADMIN_DENIED
    try:
        if _RF_ADMIN_LOCKED:
            with _LOCK:
                _RF_ADMIN_DENIED += 1
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
            _RF_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _rf_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_RF_ADMINS)
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
            if want is not None and fn == want and not fn.startswith("<"):
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


def _rf_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _RF_ADMIN_DENIED
    try:
        with _LOCK:
            _RF_ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()
# KONTROL-6: prob sayacindan muaf gurultu. ``__code__`` en gurultulu mesru
# erisimdir (bpo-42800: tum tarayicilar + bu modulun kendi _co_of'u;
# muafiyetsiz self-trip ispatlandi). Kotucul kullanim statik sinyalde.
_PROBE_NOISE = _PIN_FROZENSET({"__code__"})
_AUDIT_INSTALLED = False
_WATCHDOG_THREAD = None
_WATCHDOG_STOP = None
_PING_SEEN = False
_PING_TOKEN = "ping-8f3a2c1d"

__all__ = [
    "ReflectionDetected",
    "WEIGHTS",
    "STRONG",
    "watch",
    "unwatch",
    "pin",
    "verify_pins",
    "seal",
    "scan_function",
    "scan_module",
    "check_all",
    "score",
    "is_compromised",
    "is_reflected",
    "assert_clean",
    "guard",
    "status",
    "set_alert_hook",
    "note_reflection_probe",
    "reset_counters",
    "install_audit_hook",
    "enforce_audit_hook",
    "configure_probe",
    "harden",
    "authorize_admin",
    "start_watchdog",
    "stop_watchdog",
]


# ---------------------------------------------------------------------------
# Yardimcilar
# ---------------------------------------------------------------------------

def _co_of(f):
    """Fonksiyon/metod/kod -> code object (yoksa None)."""
    try:
        import types as _t
        if _PIN_ISINSTANCE(f, _t.CodeType):
            return f
        return _PIN_GETATTR(f, "__code__", None)
    except Exception:
        return None


def _snapshot_instructions(co):
    """Talimat listesi (cap'li; hata -> bos)."""
    try:
        out = []
        for _i, _ins in enumerate(_PIN_DIS_GET_INSTRUCTIONS(co)):
            if _i >= _INSN_CAP:
                break
            out.append(_ins)
        return out
    except Exception:
        return []


def _collect(insns):
    """attr-isimleri, global-isimler, sabit-stringler, opcode kumesii."""
    attrs = _PIN_SET()
    names = _PIN_SET()
    consts = []
    ops = _PIN_SET()
    try:
        for _ins in insns:
            try:
                ops.add(_ins.opname)
            except Exception:
                continue
            try:
                if _ins.opname in ("LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR",
                                   "DELETE_ATTR", "LOAD_FROM_DICT_OR_ATTR",
                                   "LOAD_SUPER_ATTR"):
                    if _PIN_ISINSTANCE(_ins.argval, str):
                        attrs.add(_ins.argval)
                elif _ins.opname in ("LOAD_GLOBAL", "LOAD_NAME",
                                     "LOAD_CLASSDEREF", "LOAD_DEREF",
                                     "LOAD_FAST", "LOAD_CLOSURE",
                                     "IMPORT_NAME", "IMPORT_FROM"):
                    if _PIN_ISINSTANCE(_ins.argval, str):
                        names.add(_ins.argval)
            except Exception:
                continue
    except Exception:
        pass
    return attrs, names, consts, ops


def _const_strings(co):
    """co_consts icindeki tum string sabitler (tuple/frozenset-ici dahil).

    TUR-8: match/case ``MatchClass.kwd_attrs`` dunder'i tuple-const icine
    saklar (``(('__class__',))`` + MATCH_CLASS) - mcp-use #1735 dersi.
    Tuple/frozenset iclerine de inilir (cap'li); FP riski dusuk (mesru
    kripto-kodda dunder-icerikli tuple-const yok).
    """
    out = []
    try:
        stack = [_PIN_GETATTR(co, "co_consts", ())]
        seen = 0
        count = 0
        while stack and seen < 512 and count < 4096:
            seen += 1
            try:
                consts = stack.pop()
            except Exception:
                break
            try:
                for _c in consts:
                    try:
                        count += 1
                        if _PIN_ISINSTANCE(_c, str):
                            out.append(_c)
                        elif _PIN_ISINSTANCE(_c, (tuple, frozenset)):
                            # kwd_attrs gibi ic-ice sabitler (tek seviye)
                            try:
                                for _s in _c:
                                    try:
                                        count += 1
                                        if _PIN_ISINSTANCE(_s, str):
                                            out.append(_s)
                                    except Exception:
                                        continue
                            except Exception:
                                continue
                        elif _PIN_HASATTR(_c, "co_consts"):
                            stack.append(_PIN_GETATTR(_c, "co_consts", ()))
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return out


def _dunder_in_strings(strs):
    """String listesinde gecen tehlike-dunder'lar."""
    found = _PIN_SET()
    try:
        for _s in strs:
            try:
                if not _PIN_ISINSTANCE(_s, str):
                    continue
                for _d in _DUNDER_ALL:
                    try:
                        if _d in _s:
                            found.add(_d)
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return found


def _iter_code(co):
    """co + ic-ice code object'leri gez (cap'li liste doner).

    KONTROL-7 (K8a): saldirgan merdiveni nested def/lambda/comprehension
    icine saklayabilir (``def outer(): def inner(): ladder``) - yalnizca
    ust co taranirsa gorunmez. PyInstaller search_recursively + dis
    _disassemble_recursive + SO recursive-walk standart deseni. Cap'li
    (64 co) ve hatasiz (fail-closed degil fail-silent: bos doner).
    """
    out = []
    try:
        stack = [co]
        seen = 0
        while stack and seen < 64 and _PIN_LEN(out) < 64:
            seen += 1
            try:
                cur = stack.pop()
            except Exception:
                break
            if cur is None:
                continue
            out.append(cur)
            try:
                for _c in (_PIN_GETATTR(cur, "co_consts", ()) or ()):
                    try:
                        if _PIN_HASATTR(_c, "co_consts"):
                            stack.append(_c)
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return out


def _scan_one(co):
    """Tek code-object -> sinyal dict'i (True=risk)."""
    res = {
        "class_hierarchy_traversal": False,
        "globals_escape": False,
        "closure_cell_escape": False,
        "dynamic_dunder_resolve": False,
        "bare_import_escape": False,
        "frame_introspection": False,
        "format_string_introspection": False,
        "builtins_module_leak": False,
        "gc_object_discovery": False,
        "code_object_access": False,
    }
    try:
        if co is None:
            return res
    except Exception:
        return res
    try:
        # KONTROL-7 (K8a): tum ic-ice co'larin birlesik gorunumu (nested
        # saldiri merdiveni ust co'da gorunmezdi). Cap toplam insn icin.
        attrs, names, co_names, ops = (
            _PIN_SET(), _PIN_SET(), _PIN_SET(), _PIN_SET())
        insns = []
        try:
            _cos = _iter_code(co)
        except Exception:
            _cos = [co]
        for _cc in _cos:
            try:
                if _PIN_LEN(insns) >= _INSN_CAP:
                    break
                try:
                    _ii = _snapshot_instructions(_cc)
                except Exception:
                    _ii = []
                insns.extend(_ii)
                try:
                    _a, _n, _c, _o = _collect(_ii)
                    attrs.update(_a)
                    names.update(_n)
                    ops.update(_o)
                except Exception:
                    pass
                try:
                    for _nm in (_PIN_GETATTR(_cc, "co_names", ()) or ()):
                        try:
                            co_names.add(_nm)
                        except Exception:
                            continue
                except Exception:
                    pass
            except Exception:
                continue
        const_strs = _const_strings(co)
        dunder_consts = _dunder_in_strings(const_strs)
        # attr+name birlesik gorunum (LOAD_ATTR argval'lari co_names'te
        # degildir; ikisini birlestir)
        vocab = _PIN_SET(attrs)
        vocab.update(names)
        vocab.update(co_names)

        # -- 1. merdiven (STRONG): klasik zincir VEYA ciplak __subclasses__
        # VEYA mro() cagrisi (TUR-5; LangFlow "mro" paritesi) --
        try:
            if "__class__" in vocab and bool(vocab & _LADDER_PARTNERS):
                res["class_hierarchy_traversal"] = True
            elif "__subclasses__" in vocab:
                res["class_hierarchy_traversal"] = True
            elif "mro" in attrs:
                res["class_hierarchy_traversal"] = True
        except Exception:
            pass

        # -- 1b. mappingproxy merdiveni (STRONG, KONTROL-7 K8b):
        # ``__dict__``/``vars`` + subscript ile ladder-dunder hedefleme
        # (``().__class__.__dict__["__subclasses__"]()`` - pyjail klasigi;
        # InCTF/dir-varyantlari ayni aile). Ciplak ``__dict__`` okuma
        # (hedef yoksa) ateslemez - recon-only kabul-rezidu.
        try:
            if not res["class_hierarchy_traversal"]:
                try:
                    _ladder_const = bool(
                        _PIN_SET(dunder_consts) & _LADDER_PARTNERS)
                except Exception:
                    _ladder_const = False
                if _ladder_const and "BINARY_SUBSCR" in ops and (
                        "__dict__" in attrs or "vars" in vocab):
                    res["class_hierarchy_traversal"] = True
        except Exception:
            pass

        # -- 2. globals sizintisi (STRONG): HERHANGI __globals__ okuma --
        # (TUR-3 arastirma: LangFlow _is_blocked_attribute tum dunder'i red,
        # chs.us AST katmani tum dunder'i yasaklar, SB06 HIGH. Mesru
        # __globals__ okuma nadir/kotu-pratik -> FP riski dusuk. TUR-5:
        # attrgetter/get_field gibi runtime-string tasiyicilar const'ta
        # __globals__ birakir -> vocab disi const da reflect-ailesiyle atesler.)
        try:
            if "__globals__" in vocab:
                res["globals_escape"] = True
            elif ("__globals__" in dunder_consts
                    and bool(vocab & _REFLECT_CALLS)):
                res["globals_escape"] = True
        except Exception:
            pass

        # -- 3. closure peel (STRONG) --
        try:
            if "__closure__" in vocab and "cell_contents" in vocab:
                res["closure_cell_escape"] = True
        except Exception:
            pass

        # -- 3b. ciplak import-kacisi (STRONG, R-3): getattr-ailesi
        # OLMADAN ciplak __import__ + tehlikeli-cagri (pyjail klasigi:
        # __import__('os').system('sh')). reflect-gate'e takilmaz; ayri
        # sinyalkapanir. Ayrica __builtins__-SUBSCR ile __import__ kurtarma
        # (getattr(__builtins__...) varyanti reflect-ailesinde, bu dal
        # SUBSCR-yolunu tutar).
        try:
            _danger_exec = {"system", "popen", "execv", "execve", "execvp",
                            "execl", "spawnl", "spawnlp", "spawnv",
                            "spawnve", "socket", "connect", "remove",
                            "unlink", "open", "exec", "eval"}
            _has_import = (("__import__" in names or "__import__" in co_names)
                           and "IMPORT_NAME" not in ops)
            _has_call = bool({"CALL", "CALL_FUNCTION", "CALL_METHOD",
                              "CALL_FUNCTION_EX", "PRECALL"} & ops)
            if _has_import and _has_call and bool(attrs & _danger_exec):
                res["bare_import_escape"] = True
            elif ("__builtins__" in vocab and "BINARY_SUBSCR" in ops
                    and _has_call and bool(attrs & _danger_exec)):
                res["bare_import_escape"] = True
        except Exception:
            pass

        # -- 4. dinamik dunder cozumu (STRONG) --
        # (TUR-7 FP duzeltmesi: (b) karartma yolu YALNIZCA gercek
        # string-insasi (BINARY_OP/BUILD_STRING/chr) sayar; ciplak
        # FORMAT_VALUE (her f-string) + mesru getattr("O_NOFOLLOW") FP
        # uretiyordu. FORMAT_VALUE+dunder zaten format_string sinyalinde.)
        try:
            reflect_present = bool(vocab & _REFLECT_CALLS)
            if reflect_present:
                # (a) acik dunder sabiti (defansif __code__ haric)
                hard = _PIN_SET(dunder_consts) - _DEFENSIVE_ONLY_OK
                try:
                    hard.update({a for a in attrs if a in _DUNDER_ALL
                                 and a not in _DEFENSIVE_ONLY_OK})
                except Exception:
                    pass
                if bool(hard):
                    res["dynamic_dunder_resolve"] = True
                else:
                    # (TUR-7b: opcode-duyarli insa tespiti. BINARY_OP arg
                    # haritasi (3.11+): 0=+, 6=% (string-insasi) sayilir;
                    # 7=|/1=& bayrak-birlestirme HARIC, 5=* tekrar HARIC
                    # (TUR-7c). BUILD_STRING yalnizca FORMAT_VALUE'siz
                    # sayilir (aksi halde f-string montajidir).)
                    # (TUR-7c: MULTIPLY (5) HARIC - hcli.main'de '='*50 gibi
                    # mesru tekrar + defansif getattr FP uretti. Gerekce:
                    # sabit-tekrar ("_"*2) const-fold ile (a)'ya duser,
                    # degisken-tekrar egzotik; chr() yolu ayrica kapali.
                    # + (0) ve % (6) kalir: "__subcl"+"asses__",
                    # "%s" % dunder.)
                    try:
                        str_build = False
                        has_format_value = False
                        has_build_string = False
                        for _ins in insns:
                            try:
                                _op = _ins.opname
                                if _op == "FORMAT_VALUE":
                                    has_format_value = True
                                elif _op == "BUILD_STRING":
                                    has_build_string = True
                                elif _op in ("BINARY_ADD", "BINARY_MODULO"):
                                    str_build = True
                                    break
                                elif _op == "BINARY_OP":
                                    try:
                                        if int(_ins.arg) in (0, 6):
                                            str_build = True
                                            break
                                    except Exception:
                                        continue
                            except Exception:
                                continue
                        if not str_build and has_build_string \
                                and not has_format_value:
                            str_build = True
                        if not str_build and "chr" in co_names:
                            str_build = True
                    except Exception:
                        str_build = False
                    if str_build:
                        # (b) karartilmis isim: getattr + string-insasi
                        # (FastGPT/PraisonAI dersi: non-constant isim)
                        res["dynamic_dunder_resolve"] = True
                    else:
                        # (c) TUR-8: match/case sinif-deseni (mcp-use #1735).
                        # kwd_attrs tuple-const'undaki dunder
                        # (``(('__class__',))``) + MATCH_CLASS. Ayrica
                        # asagidaki -- 4b -- bagimsiz blogu vardir.
                        try:
                            if "MATCH_CLASS" in ops and bool(
                                    _PIN_SET(dunder_consts)
                                    - _DEFENSIVE_ONLY_OK):
                                res["dynamic_dunder_resolve"] = True
                        except Exception:
                            pass
        except Exception:
            pass

        # -- 4b. match/case sinif-deseni (STRONG, TUR-8, bagimsiz) --
        # Saf match-case hicbir getattr cagrisi icermediginden reflect
        # gate'ine takilir; bu yuzden MATCH_CLASS + tuple-const dunder
        # burada bagimsiz atesler (mcp-use #1735; mesru desende
        # dunder yok denecek kadar nadirdir).
        try:
            if not res.get("dynamic_dunder_resolve"):
                try:
                    _mc_ops = {i.opname for i in insns}
                except Exception:
                    _mc_ops = set()
                if "MATCH_CLASS" in _mc_ops:
                    try:
                        _mc_dun = _dunder_in_strings(_const_strings(co))
                    except Exception:
                        _mc_dun = set()
                    try:
                        if bool(_PIN_SET(_mc_dun) - _DEFENSIVE_ONLY_OK):
                            res["dynamic_dunder_resolve"] = True
                    except Exception:
                        pass
        except Exception:
            pass

        # -- 4c. dir()+indeks cozumu (STRONG, KONTROL-7 K9): dir() ile ismi
        # runtime'da uretme (InCTF 2018: getattr([], dir([])[1]) - kaynakta
        # yasakli literal hic gecmez). for-in iterasyonunda BINARY_SUBSCR
        # uretilmez, o yuzden sayilmaz.
        try:
            if not res.get("dynamic_dunder_resolve"):
                if (bool(vocab & _REFLECT_CALLS) and "dir" in vocab
                        and "BINARY_SUBSCR" in ops):
                    res["dynamic_dunder_resolve"] = True
        except Exception:
            pass

        # -- 4d. subclass-hook cagrisi (STRONG, FR-1 SB15): manuel
        # __init_subclass__/__set_name__ cagrisi (Langflow CVE-2025-3248
        # sinifi; sandboxaudit SB15 HIGH). super() ile isbirlikci cagri
        # muaftir (PEP 487 dokumante deseni) - super gondermesi names/
        # varnames/freevars'ta aranir (golgeleme dahil). Rezidu: sahte
        # super() tanimlayip hook cagiran egzotik kacinma (marjinal).
        try:
            if not res.get("dynamic_dunder_resolve"):
                if bool({"__init_subclass__", "__set_name__"} & attrs):
                    try:
                        _has_super = False
                        for _cc2 in _iter_code(co):
                            try:
                                _nn2 = _PIN_SET(
                                    _PIN_GETATTR(_cc2, "co_names", ()))
                                for _tup in (
                                        _PIN_GETATTR(_cc2, "co_varnames", ()),
                                        _PIN_GETATTR(_cc2, "co_freevars", ())):
                                    try:
                                        for _nm2 in (_tup or ()):
                                            try:
                                                _nn2.add(_nm2)
                                            except Exception:
                                                continue
                                    except Exception:
                                        continue
                                if "super" in _nn2:
                                    _has_super = True
                                    break
                            except Exception:
                                continue
                    except Exception:
                        _has_super = False
                    if not _has_super:
                        res["dynamic_dunder_resolve"] = True
        except Exception:
            pass

        # -- 5. cerceve (WEAK) --
        try:
            if bool(vocab & _FRAME_NAMES):
                # "frame"/"trace" tek basina cok genel; digerleriyle sartli
                _generic = {"frame", "trace"}
                _specific = _PIN_SET(vocab & _FRAME_NAMES) - _generic
                if bool(_specific):
                    res["frame_introspection"] = True
                elif "inspect" in vocab and ("stack" in vocab
                                             or "currentframe" in vocab
                                             or "_getframe" in vocab):
                    res["frame_introspection"] = True
        except Exception:
            pass

        # -- 6. format-string introspection (WEAK, chs.us) --
        try:
            _has_format = ("format" in attrs or "format_map" in attrs
                           or "FORMAT_VALUE" in ops)
            if _has_format and bool(
                    (vocab & _DUNDER_ALL) | dunder_consts):
                res["format_string_introspection"] = True
        except Exception:
            pass

        # -- 7. builtins sizintisi (WEAK, PraisonAI) --
        try:
            if "__self__" in vocab and bool(
                    vocab & {"vars", "__dict__", "__builtins__"}):
                res["builtins_module_leak"] = True
            elif "__builtins__" in vocab:
                res["builtins_module_leak"] = True
        except Exception:
            pass

        # -- 8. gc kesfi (WEAK, SB09) --
        try:
            if (("gc" in co_names or "gc" in names)
                    and bool(vocab & {"get_objects", "get_referrers",
                                      "get_referents"})):
                res["gc_object_discovery"] = True
            elif bool(vocab & {"get_objects", "get_referrers",
                               "get_referents"}) and "gc" in vocab:
                res["gc_object_discovery"] = True
        except Exception:
            pass

        # -- 9. kod-nesnesi erisimi (WEAK; tek __code__ FP korumali) --
        # FR-2 (SB05): ciplak compile/eval/exec cagrisi da WEAK'tir
        # (SECCON/TJCTF/pbiernat/modelscan: CodeType zincirinin girisi).
        # Yalnizca LOAD_GLOBAL/NAME (``names``) sayilir: ``re.compile``
        # attribute-erisimi degildir (tum kardes regex'leri + hyper_cipher
        # FP korumasi). ``type(`` tek basina sayilmaz (asiri yaygin).
        try:
            _sensitive = {"co_freevars", "co_consts", "co_names", "co_code",
                          "replace", "cell_contents", "CodeType"}
            if "__code__" in vocab and bool(vocab & _sensitive):
                res["code_object_access"] = True
            elif "CodeType" in vocab:
                res["code_object_access"] = True
            elif "compile" in vocab and "__code__" in vocab:
                res["code_object_access"] = True
            elif bool({"compile", "eval", "exec"} & names):
                res["code_object_access"] = True
        except Exception:
            pass
    except Exception:
        pass
    return res


# ---------------------------------------------------------------------------
# watch / pin / seal
# ---------------------------------------------------------------------------

def watch(f):
    """Izleme listesine ekle (True=eklendi)."""
    try:
        co = _co_of(f)
        if co is None:
            return False
        with _LOCK:
            _WATCH[id(f)] = f
        return True
    except Exception:
        return False


def unwatch(f):
    """Izlemeden cikar (YONETIM: kayitli operator sart — korlestirme kapali)."""
    if not _rf_check_admin():
        _rf_deny_admin("unwatch")
    try:
        with _LOCK:
            _WATCH.pop(id(f), None)
        return True
    except Exception:
        return False


def pin(f):
    """Baseline parmak-izi al (True=ok)."""
    try:
        co = _co_of(f)
        if co is None:
            return False
        fp = _code_fp(co)
        if not fp:
            return False
        with _LOCK:
            _PINS[id(f)] = (f, fp)
        return True
    except Exception:
        return False


def _code_fp(co):
    """Kod parmak-izi: davranis-belirleyen alanlar (pyobfus P2-9 deseni).

    FR-3 guclendirme: eski surum co_code'u HIC icermiyordu (ayni isim/
    sabitli bytecode-degisimi gorunmezdi) + ic-ice co'larin SADECE adini
    aliyordu (govde-degisimi gorunmezdi) + siralamayi sorted() ile
    siliyordu. Simdi: co_code bytes + co_consts (sira-korunur, recursive)
    + co_names (sira-korunur) + varnames/freevars/cellvars + flags +
    argcount'lar. filename/firstlineno/linetable DIS (derleme-baglam,
    davranis degil). Ayni-process pin karsilastirmasi oldugundan FP
    riski yoktur (tam-esitlik).
    """
    try:
        import hashlib as _h

        def _norm_const(_c, _depth=0):
            try:
                if _depth > 16:
                    return ("<depth>",)
                if _PIN_HASATTR(_c, "co_consts"):
                    try:
                        return ("code", _code_fp(_c))
                    except Exception:
                        try:
                            return ("code",
                                    _PIN_STR(_PIN_GETATTR(_c, "co_name",
                                                          "?")))
                        except Exception:
                            return ("code", "?")
                if _PIN_ISINSTANCE(_c, (str, bytes, int, float,
                                        complex, bool, type(None))):
                    return ("v", repr(_c))
                if _PIN_ISINSTANCE(_c, tuple):
                    try:
                        return ("t", tuple(
                            _norm_const(_x, _depth + 1) for _x in _c))
                    except Exception:
                        return ("t", "?")
                if _PIN_ISINSTANCE(_c, frozenset):
                    try:
                        return ("f", sorted(repr(_x) for _x in _c))
                    except Exception:
                        return ("f", "?")
                return ("o", type(_c).__name__)
            except Exception:
                return ("?",)

        parts = []
        try:
            _raw = _PIN_GETATTR(co, "co_code", b"")
            try:
                _code_bytes = bytes(_raw)
            except Exception:
                _code_bytes = repr(_raw).encode("utf-8", "replace")
            parts.append(_code_bytes.hex())
        except Exception:
            parts.append("?")
        try:
            parts.append(repr(tuple(
                _norm_const(_c) for _c in
                (_PIN_GETATTR(co, "co_consts", ()) or ()))))
        except Exception:
            parts.append("?")
        for _field in ("co_names", "co_varnames", "co_freevars",
                       "co_cellvars"):
            try:
                parts.append(repr(tuple(
                    _PIN_GETATTR(co, _field, ())) or ()))
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
        return _h.sha256("|".join(parts).encode("utf-8",
                                                "replace")).hexdigest()
    except Exception:
        return ""


def verify_pins():
    """Pin'li baseline degisti mi (True=risk)."""
    try:
        with _LOCK:
            items = _PIN_LIST(_PINS.items())
        for _k, (_f, _fp) in items:
            try:
                co = _co_of(_f)
                if co is None:
                    return True
                if _code_fp(co) != _fp:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def seal(*funcs):
    """Verilen fonksiyonlari watch+pin'le (adet doner)."""
    n = 0
    try:
        for _f in funcs:
            try:
                if watch(_f) and pin(_f):
                    n += 1
                elif watch(_f):
                    n += 1
            except Exception:
                continue
    except Exception:
        pass
    return n


def scan_function(f):
    """Tek fonksiyon tara (sinyal dict; hata -> {})."""
    try:
        co = _co_of(f)
        if co is None:
            return {}
        return _scan_one(co)
    except Exception:
        return {}


def _unwrap_callable(v):
    """staticmethod/classmethod/property zarfini ac (yoksa aynen doner).

    KONTROL-6 (K7): vars(cls) ham descriptor dondurur (staticmethod objesi
    FunctionType degildir) -> taramadan kacardi. CPython: sm.__func__,
    cm.__func__, prop.fget. stdlib-only, hatada orijinal doner.
    """
    try:
        import types as _t
        if _PIN_ISINSTANCE(v, (staticmethod, classmethod)):
            try:
                _f = _PIN_GETATTR(v, "__func__", None)
                if _PIN_ISINSTANCE(_f, _t.FunctionType):
                    return _f
            except Exception:
                pass
            return v
        if _PIN_ISINSTANCE(v, property):
            try:
                for _acc in ("fget", "fset", "fdel"):
                    try:
                        _f = _PIN_GETATTR(v, _acc, None)
                        if _PIN_ISINSTANCE(_f, _t.FunctionType):
                            return _f
                    except Exception:
                        continue
            except Exception:
                pass
            return v
    except Exception:
        pass
    return v


def scan_module(mod):
    """Modul/sinif icindeki fonksiyonlari tara (R-4: __all__ + vars BIRLESIK).

    Bos-olmayan __all__ artik taramayi SINIRLAMAZ (decoy-listesi kacisi
    kapali): __all__'dakiler + vars() tamami taranir.
    """
    out = {}
    try:
        import types as _t
        try:
            names = _PIN_GETATTR(mod, "__all__", None)
        except Exception:
            names = None
        items = []
        seen = set()
        if names:
            for _n in names:
                try:
                    items.append((_n, _PIN_GETATTR(mod, _n)))
                    seen.add(_n)
                except Exception:
                    continue
        try:
            for _n, _v in _PIN_LIST(vars(mod).items()):
                try:
                    if _n not in seen:
                        items.append((_n, _v))
                        seen.add(_n)
                except Exception:
                    continue
        except Exception:
            if not items:
                return {}
        for _n, _v in items:
            try:
                _v = _unwrap_callable(_v)
                if _PIN_ISINSTANCE(_v, _t.FunctionType):
                    out[_n] = _scan_one(_PIN_GETATTR(_v, "__code__", None))
                elif _PIN_ISINSTANCE(_v, type):
                    try:
                        members = _PIN_LIST(vars(_v).items())
                    except Exception:
                        continue
                    for _mn, _mv in members:
                        try:
                            _mv = _unwrap_callable(_mv)
                            if _PIN_ISINSTANCE(_mv, _t.FunctionType):
                                out["%s.%s" % (_n, _mn)] = _scan_one(
                                    _PIN_GETATTR(_mv, "__code__", None))
                        except Exception:
                            continue
            except Exception:
                continue
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Sensor sagligi + runtime prob sayaci (audit-hook danisman)
# ---------------------------------------------------------------------------

def _check_sensor_health():
    """Sensor altyapisi saglam mi (True=risk) — R-6: audit-hook CANLILIK
    dahil. Ping testi: hook kurulur, benzersiz olay audit'lenir, hook'un
    atesledigi dogrulanir. Kurulmamis/olu hook = STRONG (kor gozetim)."""
    try:
        _ = _PIN_LIST(_PIN_DIS_OPMAP.items())
        _ = 100 in (_PIN_DIS_HASCONST or [])
        import hashlib as _h
        _ = _h.sha256(b"x").hexdigest()
    except Exception:
        return True
    try:
        if not _AUDIT_INSTALLED:
            try:
                if not install_audit_hook():
                    return True
            except Exception:
                return True
        global _PING_SEEN
        try:
            with _LOCK:
                _PING_SEEN = False
        except Exception:
            pass
        try:
            _sys.audit("anti_reflection.ping", _PING_TOKEN)
        except Exception:
            return True
        try:
            with _LOCK:
                seen = _PING_SEEN
        except Exception:
            seen = False
        if not seen:
            return True
        return False
    except Exception:
        return True


def _audit_hook(event, args):
    """Danisman IOC sayaci: asla yukseltmez, sadece sayar (fail-safe).

    R-1: direkt `x.__class__` okuma audit OLAYI YAYMAZ (PEP 578: yalnizca
    kisitli-uye fallback'i `object.__getattr__` atesler) — okuma-gorunmezligi
    yapisaldir. Guvenilir runtime-dallar: `object.__getattr__` (kisitli-uye
    erisimi) + `gc.*` (nesne kesfi) + `sys._getframe` (cerceve-yuruyusu;
    PEP 578 "Detect when code is accessing frames directly"). _PROBE_NOISE
    muafiyeti KALDIRILDI (basarili okuma zaten olay yaymaz; fallback
    sayimi esik emer).
    """
    try:
        if event == "anti_reflection.ping":
            try:
                global _PING_SEEN
                with _LOCK:
                    _PING_SEEN = True
            except Exception:
                pass
            return
        if event == "sys._getframe":
            note_reflection_probe()
            return
        if event != "object.__getattr__":
            try:
                if (_PIN_ISINSTANCE(event, str)
                        and event.startswith("gc.")):
                    note_reflection_probe()
            except Exception:
                pass
            return
        try:
            name = args[1] if _PIN_LEN(args) > 1 else ""
        except Exception:
            name = ""
        try:
            if _PIN_ISINSTANCE(name, str) and name in _DUNDER_ALL:
                note_reflection_probe()
        except Exception:
            pass
    except Exception:
        pass


def install_audit_hook():
    """Audit-hook'u kur (True=kuruldu/aktif; kalici, kaldirilamaz - PEP 578)."""
    global _AUDIT_INSTALLED
    try:
        if _AUDIT_INSTALLED:
            return True
        if _PIN_SYS_ADDAUDITHOOK is None:
            return False
        try:
            _PIN_SYS_ADDAUDITHOOK(_audit_hook)
        except Exception:
            return False
        _AUDIT_INSTALLED = True
        return True
    except Exception:
        return False


def enforce_audit_hook():
    """Kardes-parite: audit gozlemini zorla-aktif et (True=aktif)."""
    try:
        return bool(install_audit_hook())
    except Exception:
        return False


def note_reflection_probe():
    """Bir dunder-erisim gozlemi isaretle (IOC sayaci).

    KONTROL-6 (K5): uyari edge-trigger - yalnizca esige ULASILAN cagrida
    bir kez atilir (spam onlenir; pencere dolmadan ek uyari yok).
    """
    try:
        now = _PIN_TIME_MONOTONIC()
        crossed = False
        with _LOCK:
            _PROBE_TIMES.append(now)
            try:
                cutoff = now - _PROBE_WINDOW_S
                while _PROBE_TIMES and _PROBE_TIMES[0] < cutoff:
                    _PROBE_TIMES.pop(0)
                crossed = _PIN_LEN(_PROBE_TIMES) == _PROBE_THRESHOLD
            except Exception:
                pass
        if crossed:
            try:
                _fire_alert("reflection_probe_anomaly")
            except Exception:
                pass
        return True
    except Exception:
        return False


def reset_counters():
    """Prob penceresini sifirla (YONETIM: kayitli operator sart)."""
    if not _rf_check_admin():
        _rf_deny_admin("reset_counters")
    try:
        with _LOCK:
            try:
                _PROBE_TIMES.clear()
            except Exception:
                pass
        return True
    except Exception:
        return False


def configure_probe(threshold=None, window_s=None):
    """Prob esigi/penceresi ayarla (True=ok; operator-tuning).

    FR-4 (IDS thresholding doktrini): sabit 50/60s her ortama uymaz;
    operator ortama gore ayarlar (SYN-flood esigi gibi). Siki
    dogrulama: threshold int 10..10000, window 10..3600s; disindakiler
    REDDEDILIR (deger degismez). YONETIM: kayitli operator sart
    (R-5: esik-yukseltme + pencere-silme saldirisi kapali).
    """
    if not _rf_check_admin():
        _rf_deny_admin("configure_probe")
    global _PROBE_THRESHOLD, _PROBE_WINDOW_S
    try:
        if threshold is None and window_s is None:
            return False
        try:
            _t = int(threshold) if threshold is not None else None
        except Exception:
            return False
        try:
            _w = float(window_s) if window_s is not None else None
        except Exception:
            return False
        if _t is not None and not (10 <= _t <= 10000):
            return False
        if _w is not None and not (10.0 <= _w <= 3600.0):
            return False
        with _LOCK:
            if _t is not None:
                _PROBE_THRESHOLD = _t
            if _w is not None:
                _PROBE_WINDOW_S = _w
            try:
                _PROBE_TIMES.clear()
            except Exception:
                pass
        return True
    except Exception:
        return False


def _probe_tripped():
    """Pencere esigi asildi mi (True=risk)."""
    try:
        now = _PIN_TIME_MONOTONIC()
        with _LOCK:
            try:
                cutoff = now - _PROBE_WINDOW_S
                while _PROBE_TIMES and _PROBE_TIMES[0] < cutoff:
                    _PROBE_TIMES.pop(0)
                return _PIN_LEN(_PROBE_TIMES) >= _PROBE_THRESHOLD
            except Exception:
                return False
    except Exception:
        return False


def set_alert_hook(fn):
    """Tehlike kancasi kur (True=ok; cagri sessiz, detay sizdirmaz).

    YONETIM: None-disarm kayitli operator sart.
    """
    if fn is None and not _rf_check_admin():
        _rf_deny_admin("set_alert_hook")
    global _ALERT_HOOK
    try:
        if fn is None:
            with _LOCK:
                _ALERT_HOOK = None
            return True
        if not callable(fn):
            return False
        with _LOCK:
            _ALERT_HOOK = fn
        return True
    except Exception:
        return False


def _fire_alert(signal, detail=None):
    """Kancayi atesle (hatalar yutulur; detayda sir olmaz)."""
    try:
        with _LOCK:
            fn = _ALERT_HOOK
        if fn is None:
            return False
        try:
            fn(signal)
            return True
        except Exception:
            try:
                fn(signal, {})
                return True
            except Exception:
                return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# check_all / score / is_compromised (+ alias) / assert / guard / status
# ---------------------------------------------------------------------------

_CHECKS = (
    ("class_hierarchy_traversal", "_watch"),
    ("globals_escape", "_watch"),
    ("closure_cell_escape", "_watch"),
    ("dynamic_dunder_resolve", "_watch"),
    ("bare_import_escape", "_watch"),
    ("frame_introspection", "_watch"),
    ("format_string_introspection", "_watch"),
    ("builtins_module_leak", "_watch"),
    ("gc_object_discovery", "_watch"),
    ("code_object_access", "_watch"),
    ("reflection_probe_anomaly", "_probe"),
    ("pin_mismatch", "_pins"),
    ("sensor_health", None),
)

_LIGHT = _PIN_FROZENSET({"class_hierarchy_traversal", "globals_escape",
                         "closure_cell_escape", "dynamic_dunder_resolve",
                         "bare_import_escape",
                         "pin_mismatch", "sensor_health"})


def check_all(light_only=False):
    """Tum sinyalleri tara (dict: sinyal -> bool; True=risk)."""
    results = {}
    try:
        with _LOCK:
            watched = _PIN_LIST(_WATCH.values())
    except Exception:
        watched = []
    for _name, _src in _CHECKS:
        try:
            if light_only and _name not in _LIGHT:
                continue
        except Exception:
            pass
        try:
            if _src == "_pins":
                results[_name] = bool(verify_pins())
            elif _src == "_probe":
                results[_name] = bool(_probe_tripped())
            elif _src == "_watch":
                hit = False
                for _f in watched:
                    try:
                        r = _scan_one(_co_of(_f))
                        if r.get(_name):
                            hit = True
                            break
                    except Exception:
                        continue
                results[_name] = hit
            else:
                results[_name] = bool(_check_sensor_health())
        except Exception:
            results[_name] = True
    return results


def _score_from(results):
    score = 0
    strong_hit = False
    weak_hits = 0
    try:
        for _k, _v in results.items():
            if not _v:
                continue
            try:
                score += WEIGHTS.get(_k, 0)
            except Exception:
                pass
            try:
                if _k in STRONG:
                    strong_hit = True
                else:
                    weak_hits += 1
            except Exception:
                continue
        tripped = bool(strong_hit or weak_hits >= 2)
    except Exception:
        return 0, _THRESHOLD_TRIP, True
    return score, _THRESHOLD_TRIP, tripped


def score(light_only=False):
    """(skor, esik, trip) doner."""
    try:
        return _score_from(check_all(light_only=light_only))
    except Exception:
        return 0, _THRESHOLD_TRIP, True


def is_compromised(light_only=False):
    """Tripwire atti mi (True=risk; hata -> True fail-closed)."""
    try:
        _, _, tripped = _score_from(check_all(light_only=light_only))
        return bool(tripped)
    except Exception:
        return True


def is_reflected(light_only=False):
    """Parite alias: is_compromised ile ayni."""
    try:
        return bool(is_compromised(light_only=light_only))
    except Exception:
        return True


def assert_clean(light_only=False):
    """Temiz degilse opak ReflectionDetected yukselt."""
    if is_compromised(light_only=light_only):
        _raise()
    return True


def guard(func):
    """Dekorator: cagri-oncesi + sonrasi assert_clean (fail-closed iki uc)."""
    try:
        import functools as _ft

        @_ft.wraps(func)
        def _w(*a, **k):
            assert_clean()
            try:
                r = func(*a, **k)
            except ReflectionDetected:
                raise
            except Exception as e:
                try:
                    if is_compromised():
                        raise ReflectionDetected("protected") from e
                except ReflectionDetected:
                    raise
                except Exception:
                    pass
                raise
            assert_clean()
            return r
        return _w
    except Exception:
        return func


def status(light_only=False):
    """Durum ozeti (sinyaller + skor + trip)."""
    try:
        r = check_all(light_only=light_only)
        s, t, trip = _score_from(r)
        return {"signals": r, "score": s, "threshold": t, "tripped": trip}
    except Exception:
        return {"signals": {}, "score": -1, "threshold": _THRESHOLD_TRIP,
                "tripped": True}


def harden():
    """Sertlestir: audit-gozlem + cagiran-modul muhurleme + durum.

    R-2: bos-_WATCH korlugu kapanir — cagiran cercevenin modul
    global'larindaki fonksiyonlar seal() ile izlemeye alinir.
    """
    out = {}
    try:
        try:
            out["audit_hook"] = bool(enforce_audit_hook())
        except Exception:
            out["audit_hook"] = False
        try:
            import types as _t
            try:
                fr = _sys._getframe(1)
                g = dict(fr.f_globals) if fr is not None else {}
            except Exception:
                g = {}
            sealed = 0
            for _n, _v in g.items():
                try:
                    if isinstance(_v, _t.FunctionType):
                        sealed += int(bool(seal(_v)))
                except Exception:
                    continue
            out["sealed"] = sealed
        except Exception:
            out["sealed"] = -1
        try:
            out["watched"] = _PIN_LEN(_PIN_LIST(_WATCH.values()))
        except Exception:
            out["watched"] = -1
        try:
            out["tripped"] = bool(is_compromised(light_only=True))
        except Exception:
            out["tripped"] = True
    except Exception:
        out = {"audit_hook": False, "sealed": -1, "watched": -1, "tripped": True}
    return out


# ---------------------------------------------------------------------------
# Watchdog (kardes-parite; light tarama, sessiz)
# ---------------------------------------------------------------------------

def _watchdog_loop(stop_ev, interval):
    try:
        while not stop_ev.wait(interval):
            try:
                if is_compromised(light_only=True):
                    try:
                        _fire_alert("watchdog_trip")
                    except Exception:
                        pass
                    return
            except Exception:
                return
    except Exception:
        pass


def start_watchdog(interval=5.0):
    """Arka-plan gozcusu baslat (True=calisiyor)."""
    global _WATCHDOG_THREAD, _WATCHDOG_STOP, _RF_ADMIN_LOCKED
    try:
        with _LOCK:
            _RF_ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        if _WATCHDOG_THREAD is not None:
            try:
                if _WATCHDOG_THREAD.is_alive():
                    return True
            except Exception:
                pass
        try:
            iv = float(interval)
        except Exception:
            iv = 5.0
        if iv < 1.0:
            iv = 1.0
        if iv > 300.0:
            iv = 300.0
        stop_ev = _PIN_THREAD_EVENT()
        th = _PIN_THREAD_THREAD(target=_watchdog_loop, args=(stop_ev, iv),
                                daemon=True)
        _WATCHDOG_STOP = stop_ev
        _WATCHDOG_THREAD = th
        th.start()
        return True
    except Exception:
        return False


def stop_watchdog():
    """Gozcuyu durdur (YONETIM: kayitli operator sart)."""
    if not _rf_check_admin():
        _rf_deny_admin("stop_watchdog")
    global _WATCHDOG_THREAD, _WATCHDOG_STOP
    try:
        try:
            if _WATCHDOG_STOP is not None:
                _WATCHDOG_STOP.set()
        except Exception:
            pass
        _WATCHDOG_THREAD = None
        _WATCHDOG_STOP = None
        return True
    except Exception:
        return False
