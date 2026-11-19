# -*- coding: utf-8 -*-
"""anti_introspection: Python introspection/members kesif tespit katmani.

Tehdit modeli (arastirma sentezi - 3x ReSearch):
  - inspect modulu kotu-kullanimi (docs.python.org/3/library/inspect 3.11-3.14,
    PEP 563/649 annotation gecikmesi, get_type_hints eval riski,
    Code Pathfinder PYSEC-006, sandboxaudit SB14):
    ``inspect.getmembers/getsource/getfile/stack/getouterframes/currentframe/
    signature/get_annotations/getattr_static/classify_class_attrs/getclosurevars``
    + ``vars()/__dict__/dir()`` + ``type/__class__/__module__/__qualname__/
    __annotations__`` ile canli-nesne meta-verisinin pasif kesfi.
  - typing.get_type_hints eval-enjeksiyonu (PEP 563 from __future__ import annotations):
    ``typing.get_type_hints(obj)`` string-annotation'lari ``eval()`` ile cozer.
  - mappingproxy sizintisi (CPython GH-152405): ``vars(list) == Evil()`` ham dict.
  - Frame/traceback zinciri (bpo-42800 GH-24182, Heym <0.0.21): tb_frame.f_back.f_builtins.

Kapsam (kardeslerle cakisma yok):
  - anti_reflection: sinif-hiyerarsi/globals/closure; BU modul pasif MEMBER kesfi.
  - Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
  - Trip >=1 STRONG veya >=2 WEAK.
"""
from __future__ import annotations
import sys as _sys
import threading as _threading
import time as _time

class IntrospectionDetected(RuntimeError):
    pass

def _raise() -> None:
    raise IntrospectionDetected("protected")

def _load_dis():
    """dis'i lazy yukle + sys.modules'tan tahliye et (self-FP onler).

    Kardes konvansiyon (anti_hook/_code_head): kalici `import dis`
    bytecode.tool_present WEAK'ini kendi kendine atesler.
    """
    try:
        added = "dis" not in _sys.modules
        import dis as _d
        return _d, added
    except Exception:
        return None, False

def _take_dis_pin(attr: str):
    mod, added = _load_dis()
    try:
        if mod is None:
            return None
        return getattr(mod, attr, None)
    finally:
        try:
            if added and "dis" in _sys.modules:
                del _sys.modules["dis"]
        except Exception:
            pass

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
WEIGHTS = {
    "inspect_stack_traversal": 100,
    "type_hint_eval": 100,
    "mappingproxy_bypass": 100,
    "annotation_code_exec": 100,
    "pin_mismatch": 100,
    "sensor_health": 100,
    "inspect_module_import": 30,
    "vars_dict_probe": 30,
    "dir_enumeration": 30,
    "signature_inspection": 30,
    "type_introspection": 30,
    "dataclass_introspection": 30,
    "dynamic_attr_construct": 30,
    "introspection_probe_anomaly": 30,
}
STRONG = _PIN_FROZENSET({
    "inspect_stack_traversal",
    "type_hint_eval",
    "mappingproxy_bypass",
    "annotation_code_exec",
    "pin_mismatch",
    "sensor_health",
})
_THRESHOLD_TRIP = 100
_INSN_CAP = 20000
_PROBE_WINDOW_S = 60.0
_PROBE_THRESHOLD = 50
_INSPECT_FUNCS = _PIN_FROZENSET({
    "getmembers", "getsource", "getfile", "getsourcelines",
    "getouterframes", "getinnerframes", "stack", "trace",
    "currentframe", "getframeinfo", "signature", "getfullargspec",
    "get_annotations", "getattr_static", "classify_class_attrs",
    "getclosurevars", "getclasstree", "getmro",
    "getmodule", "getsourcefile", "getabsfile", "findsource",
    "getdoc", "getcomments", "getblock", "unwrap", "getargvalues",
    "getcallargs", "formatargvalues", "getmembers_static",
    "getgeneratorstate", "getcoroutinestate", "getasyncgenstate",
})
_INSPECT_STACK_FUNCS = _PIN_FROZENSET({
    "stack", "getouterframes", "getinnerframes", "currentframe",
    "trace", "getframeinfo",
})
_FRAME_ATTRS = _PIN_FROZENSET({
    "f_back", "f_code", "f_globals", "f_locals", "f_builtins",
    "tb_frame", "tb_next", "gi_frame", "gi_code",
    "cr_frame", "cr_code", "ag_frame", "ag_code",
    "_getframe", "currentframe",
})
_DUNDER_INTRO = _PIN_FROZENSET({
    "__dict__", "__class__", "__module__", "__qualname__",
    "__annotations__", "__mro__", "__bases__", "__code__",
    "__closure__", "__wrapped__", "__dataclass_fields__",
})
_DATACLASS_FUNCS = _PIN_FROZENSET({
    "fields", "is_dataclass", "asdict", "astuple", "replace",
})
_WATCH: dict = {}
_PINS: dict = {}
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
            import os as _o
            if not _o.path.isfile(fn):
                return False
        except Exception:
            return False
        with _LOCK:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin():
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


def _deny_admin(op):
    """Yonetim reddi: fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _LOCK:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()
_ALERT_HOOK = None
_PROBE_TIMES: list = []
_PROBE_NOISE = _PIN_FROZENSET({"__code__", "__dict__"})
_AUDIT_INSTALLED = False
_WATCHDOG_THREAD = None
_WATCHDOG_STOP = None
__all__ = [
    "IntrospectionDetected","WEIGHTS","STRONG","watch","unwatch","pin","verify_pins","seal","scan_function","scan_module","check_all","score","is_compromised","is_introspected","assert_clean","guard","status","set_alert_hook","note_introspection_probe","reset_counters","install_audit_hook","enforce_audit_hook","configure_probe","harden","authorize_admin","start_watchdog","stop_watchdog",
]

def _co_of(f):
    try:
        import types as _t
        if _PIN_ISINSTANCE(f, _t.CodeType):
            return f
        return _PIN_GETATTR(f, "__code__", None)
    except Exception:
        return None

def _snapshot_instructions(co):
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
    attrs = _PIN_SET()
    names = _PIN_SET()
    ops = _PIN_SET()
    try:
        for _ins in insns:
            try:
                ops.add(_ins.opname)
            except Exception:
                continue
            try:
                if _ins.opname in ("LOAD_ATTR", "LOAD_METHOD", "STORE_ATTR","DELETE_ATTR", "LOAD_FROM_DICT_OR_ATTR","LOAD_SUPER_ATTR"):
                    if _PIN_ISINSTANCE(_ins.argval, str):
                        attrs.add(_ins.argval)
                elif _ins.opname in ("LOAD_GLOBAL", "LOAD_NAME","LOAD_CLASSDEREF", "LOAD_DEREF","LOAD_FAST", "LOAD_CLOSURE","IMPORT_NAME", "IMPORT_FROM"):
                    if _PIN_ISINSTANCE(_ins.argval, str):
                        names.add(_ins.argval)
            except Exception:
                continue
    except Exception:
        pass
    return attrs, names, ops

def _const_strings(co):
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
    found = _PIN_SET()
    try:
        for _s in strs:
            try:
                if not _PIN_ISINSTANCE(_s, str):
                    continue
                for _d in _DUNDER_INTRO:
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

def _dunder_fragments(strs):
    """Dunder-parca sabitler ('__cl', 'ass__', '_' zincirleri).

    Research (argusgate/Endor Labs pattern): saldirgan hassas isimleri
    birlestirme/chr/join ile kurar; literal tarayici kurulu ismi goremez.
    Parca + kurucu-isaret = dinamik-erisim suphesi.
    """
    found = _PIN_SET()
    try:
        for _s in strs:
            try:
                if not _PIN_ISINSTANCE(_s, str):
                    continue
                if _PIN_LEN(_s) < 2:
                    continue
                for _d in _DUNDER_INTRO:
                    try:
                        if _s != _d and _s in _d:
                            found.add(_s)
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return found

def _has_hex_escape_blob(strs):
    """4+ ardisik \\xNN kacisi = kodlanmis isim (argusgate CRITICAL kurali)."""
    try:
        import re as _re
        for _s in strs:
            try:
                if not _PIN_ISINSTANCE(_s, str):
                    continue
                if _re.search(r"(?:\\x[0-9a-fA-F]{2}){4,}", _s):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False

def _iter_code(co):
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
    res = {
        "inspect_stack_traversal": False,
        "type_hint_eval": False,
        "mappingproxy_bypass": False,
        "annotation_code_exec": False,
        "inspect_module_import": False,
        "vars_dict_probe": False,
        "dir_enumeration": False,
        "signature_inspection": False,
        "type_introspection": False,
        "dataclass_introspection": False,
        "dynamic_attr_construct": False,
    }
    try:
        if co is None:
            return res
    except Exception:
        return res
    try:
        attrs, names, ops = _PIN_SET(), _PIN_SET(), _PIN_SET()
        co_names = _PIN_SET()
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
                    _a, _n, _o = _collect(_ii)
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
        vocab = _PIN_SET(attrs)
        vocab.update(names)
        vocab.update(co_names)
        try:
            _has_inspect = "inspect" in vocab or "inspect" in names or "inspect" in co_names or "inspect" in const_strs
            _has_stack_func = bool(vocab & _INSPECT_STACK_FUNCS)
            _has_frame_attr = bool(vocab & _FRAME_ATTRS)
            if _has_stack_func and (_has_inspect or _has_frame_attr):
                res["inspect_stack_traversal"] = True
            elif "_getframe" in vocab and ("sys" in vocab or "inspect" in vocab or "sys" in names or "inspect" in names or "inspect" in const_strs):
                res["inspect_stack_traversal"] = True
        except Exception:
            pass
        try:
            if "get_type_hints" in vocab or "get_args" in vocab or "get_origin" in vocab:
                res["type_hint_eval"] = True
            elif "get_type_hints" in dunder_consts or "get_args" in dunder_consts:
                res["type_hint_eval"] = True
        except Exception:
            pass
        try:
            _has_vars = "vars" in vocab
            _has_eq = "__eq__" in vocab or "__eq__" in dunder_consts or "__eq__" in attrs
            _has_ror = "__ror__" in vocab or "__ror__" in dunder_consts or "__ror__" in attrs
            _has_or = "__or__" in vocab or "__or__" in dunder_consts
            _has_compare = "COMPARE_OP" in ops
            _has_binary_or = "BINARY_OR" in ops or "BINARY_OP" in ops
            if _has_vars and (_has_eq or _has_ror or _has_or) and (_has_compare or _has_binary_or):
                res["mappingproxy_bypass"] = True
            elif _has_vars and "__eq__" in vocab and _has_compare:
                res["mappingproxy_bypass"] = True
            elif _has_vars and _has_ror and _has_binary_or:
                res["mappingproxy_bypass"] = True
        except Exception:
            pass
        try:
            _has_ann = "__annotations__" in vocab or "__annotations__" in dunder_consts or "__annotations__" in attrs
            _has_exec = bool(vocab & {"eval", "exec", "get_type_hints"})
            _has_eval_str = ("get_annotations" in vocab or "signature" in vocab) and ("eval_str" in vocab or "eval_str" in const_strs or "eval_str" in dunder_consts)
            if _has_ann and (_has_exec or _has_eval_str):
                res["annotation_code_exec"] = True
            elif "signature" in vocab and ("eval_str" in vocab or "eval_str" in const_strs):
                res["annotation_code_exec"] = True
            elif "__annotations__" in attrs and ("eval" in co_names or "get_type_hints" in vocab or "eval_str" in vocab or "eval_str" in const_strs):
                res["annotation_code_exec"] = True
        except Exception:
            pass
        try:
            _has_inspect_any = bool(vocab & _INSPECT_FUNCS)
            _has_inspect_import = "inspect" in names or "inspect" in co_names
            if _has_inspect_import and _has_inspect_any:
                res["inspect_module_import"] = True
            elif _has_inspect_any and "inspect" in vocab:
                res["inspect_module_import"] = True
        except Exception:
            pass
        try:
            if "vars" in vocab or "__dict__" in vocab or "__dict__" in attrs or "vars" in const_strs:
                res["vars_dict_probe"] = True
            elif "__dict__" in dunder_consts:
                res["vars_dict_probe"] = True
        except Exception:
            pass
        try:
            if "dir" in vocab or "dir" in const_strs:
                res["dir_enumeration"] = True
        except Exception:
            pass
        try:
            _sig_funcs = {"signature", "getfullargspec", "get_annotations","getattr_static", "classify_class_attrs", "getclosurevars","getsource", "getfile", "getmembers"}
            if bool(vocab & _sig_funcs):
                res["signature_inspection"] = True
        except Exception:
            pass
        try:
            _type_markers = {"__module__", "__qualname__", "__annotations__", "__orig_class__", "__orig_bases__", "__orig_class__"}
            if bool(vocab & _type_markers) or bool(attrs & _type_markers):
                res["type_introspection"] = True
            elif bool(dunder_consts & _type_markers):
                res["type_introspection"] = True
            elif "type" in vocab and ("__class__" in vocab or "__module__" in vocab):
                res["type_introspection"] = True
        except Exception:
            pass
        try:
            _has_dc_mod = "dataclasses" in vocab or "dataclasses" in names or "dataclasses" in co_names or "dataclasses" in const_strs
            _has_dc_func = bool(vocab & _DATACLASS_FUNCS)
            _has_dc_field = "__dataclass_fields__" in vocab or "__dataclass_fields__" in attrs or "__dataclass_fields__" in dunder_consts
            if (_has_dc_mod and _has_dc_func) or _has_dc_field:
                res["dataclass_introspection"] = True
        except Exception:
            pass
        try:
            _has_getattr = "getattr" in vocab or "getattr" in names
            _has_chr = "chr" in vocab or "chr" in names
            _has_concat = "BINARY_OP" in ops or "BINARY_ADD" in ops
            _has_join = "join" in vocab or "format" in vocab
            _has_attrgetter = "attrgetter" in vocab or "attrgetter" in names
            _frags = _dunder_fragments(const_strs)
            if _has_attrgetter:
                res["dynamic_attr_construct"] = True
            elif _has_getattr and (_has_chr or _has_concat or _has_join):
                res["dynamic_attr_construct"] = True
            elif bool(_frags) and (_has_chr or _has_concat or _has_join or _has_getattr):
                res["dynamic_attr_construct"] = True
            elif _has_hex_escape_blob(const_strs):
                res["dynamic_attr_construct"] = True
        except Exception:
            pass
    except Exception:
        pass
    return res

def watch(f):
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
    if not _check_admin():
        _deny_admin("unwatch")
    try:
        with _LOCK:
            _WATCH.pop(id(f), None)
        return True
    except Exception:
        return False

def pin(f):
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
                            return ("code", _PIN_STR(_PIN_GETATTR(_c, "co_name","?")))
                        except Exception:
                            return ("code", "?")
                if _PIN_ISINSTANCE(_c, (str, bytes, int, float,complex, bool, type(None))):
                    return ("v", repr(_c))
                if _PIN_ISINSTANCE(_c, tuple):
                    try:
                        return ("t", tuple(_norm_const(_x, _depth + 1) for _x in _c))
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
            parts.append(repr(tuple(_norm_const(_c) for _c in (_PIN_GETATTR(co, "co_consts", ()) or ()))))
        except Exception:
            parts.append("?")
        for _field in ("co_names", "co_varnames", "co_freevars","co_cellvars"):
            try:
                parts.append(repr(tuple(_PIN_GETATTR(co, _field, ())) or ()))
            except Exception:
                parts.append("?")
        for _field in ("co_flags", "co_argcount", "co_posonlyargcount","co_kwonlyargcount"):
            try:
                parts.append(_PIN_STR(_PIN_GETATTR(co, _field, 0)))
            except Exception:
                parts.append("0")
        try:
            parts.append(_PIN_STR(_PIN_GETATTR(co, "co_name", "?")))
        except Exception:
            parts.append("?")
        return _h.sha256("|".join(parts).encode("utf-8","replace")).hexdigest()
    except Exception:
        return ""

def verify_pins():
    """P4: fail-closed pin-dogrulama (suphede True).

    id-anahtar + guclu referans (_PINS degeri f'yi diri tutar) sayesinde
    GC-adres-reuse imkansizdir; pin-basina exception artik `continue`
    DEGIL True dondurur (korluk degil suphe).
    """
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
                return True
        return False
    except Exception:
        return True

def seal(*funcs):
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
    try:
        co = _co_of(f)
        if co is None:
            return {}
        return _scan_one(co)
    except Exception:
        return {}

def _unwrap_callable(v):
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
    out = {}
    try:
        import types as _t
        try:
            names = _PIN_GETATTR(mod, "__all__", None)
        except Exception:
            names = None
        items = []
        if names:
            for _n in names:
                try:
                    items.append((_n, _PIN_GETATTR(mod, _n)))
                except Exception:
                    continue
        else:
            try:
                items = _PIN_LIST(vars(mod).items())
            except Exception:
                return {}
        for _n, _v in items:
            try:
                _v = _unwrap_callable(_v)
                if _PIN_ISINSTANCE(_v, _t.FunctionType):
                    try:
                        _vmod = _PIN_GETATTR(_v, "__module__", None)
                        _mname = _PIN_GETATTR(mod, "__name__", None)
                        if _vmod is not None and _mname is not None and _vmod != _mname:
                            continue
                    except Exception:
                        pass
                    out[_n] = _scan_one(_PIN_GETATTR(_v, "__code__", None))
                elif _PIN_ISINSTANCE(_v, type):
                    try:
                        _tmod = _PIN_GETATTR(_v, "__module__", None)
                        _mname2 = _PIN_GETATTR(mod, "__name__", None)
                        if _tmod is not None and _mname2 is not None and _tmod != _mname2:
                            continue
                    except Exception:
                        pass
                    try:
                        members = _PIN_LIST(vars(_v).items())
                    except Exception:
                        continue
                    for _mn, _mv in members:
                        try:
                            _mv = _unwrap_callable(_mv)
                            if _PIN_ISINSTANCE(_mv, _t.FunctionType):
                                out["%s.%s" % (_n, _mn)] = _scan_one(_PIN_GETATTR(_mv, "__code__", None))
                        except Exception:
                            continue
            except Exception:
                continue
    except Exception:
        pass
    return out

def _check_sensor_health():
    try:
        _ = _PIN_LIST(_PIN_DIS_OPMAP.items())
        _ = 100 in (_PIN_DIS_HASCONST or [])
        import hashlib as _h
        _ = _h.sha256(b"x").hexdigest()
        return False
    except Exception:
        return True

def _audit_hook(event, args):
    """P3: gercek audit-olaylari (PEP 578 tablosu-parite).

    - object.__getattr__: GERCEK olay (kisitli builtin uyeler icin ateslenir:
      member_get/func_get_code — docs "Detect access to restricted attributes").
      Dar ama yuksek-degerlidir; _PROBE_NOISE muafiyeti KALDIRILDI (esik emer).
    - sys._getframe: GERCEK olay ("Detect when code is accessing frames
      directly") — cerceve-yuruyusu tespiti BURADADIR.
    - inspect.* olAYI YOKTUR (CPython audit tablosunda boyle event yok);
      eski prefix-dali olu beklentiydi, kaldirildi.
    """
    try:
        if event == "sys._getframe":
            note_introspection_probe()
            return
        if event != "object.__getattr__":
            return
        try:
            name = args[1] if _PIN_LEN(args) > 1 else ""
        except Exception:
            name = ""
        try:
            if _PIN_ISINSTANCE(name, str) and name in _DUNDER_INTRO:
                note_introspection_probe()
        except Exception:
            pass
    except Exception:
        pass

def install_audit_hook():
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
    try:
        return bool(install_audit_hook())
    except Exception:
        return False

def note_introspection_probe():
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
                _fire_alert("introspection_probe_anomaly")
            except Exception:
                pass
        return True
    except Exception:
        return False

def reset_counters():
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

_CHECKS = (
    ("inspect_stack_traversal", "_watch"),
    ("type_hint_eval", "_watch"),
    ("mappingproxy_bypass", "_watch"),
    ("annotation_code_exec", "_watch"),
    ("inspect_module_import", "_watch"),
    ("vars_dict_probe", "_watch"),
    ("dir_enumeration", "_watch"),
    ("signature_inspection", "_watch"),
    ("type_introspection", "_watch"),
    ("dataclass_introspection", "_watch"),
    ("dynamic_attr_construct", "_watch"),
    ("introspection_probe_anomaly", "_probe"),
    ("pin_mismatch", "_pins"),
    ("sensor_health", None),
)
_LIGHT = _PIN_FROZENSET({"inspect_stack_traversal", "type_hint_eval","mappingproxy_bypass", "annotation_code_exec","dynamic_attr_construct", "pin_mismatch", "sensor_health"})

def check_all(light_only=False):
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
    try:
        return _score_from(check_all(light_only=light_only))
    except Exception:
        return 0, _THRESHOLD_TRIP, True

def is_compromised(light_only=False):
    try:
        _, _, tripped = _score_from(check_all(light_only=light_only))
        return bool(tripped)
    except Exception:
        return True

def is_introspected(light_only=False):
    try:
        return bool(is_compromised(light_only=light_only))
    except Exception:
        return True

def assert_clean(light_only=False):
    if is_compromised(light_only=light_only):
        _raise()
    return True

def guard(func):
    """P5: giris + cikis dogrulamali guard (fail-closed iki uc)."""
    try:
        import functools as _ft
        @_ft.wraps(func)
        def _w(*a, **k):
            assert_clean()
            try:
                r = func(*a, **k)
            except IntrospectionDetected:
                raise
            except Exception as e:
                try:
                    if is_compromised():
                        raise IntrospectionDetected("protected") from e
                except IntrospectionDetected:
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
    try:
        r = check_all(light_only=light_only)
        s, t, trip = _score_from(r)
        return {"signals": r, "score": s, "threshold": t, "tripped": trip}
    except Exception:
        return {"signals": {}, "score": -1, "threshold": _THRESHOLD_TRIP,"tripped": True}

def harden():
    """P1: tek-cagrilik varsayilan-postur — cagiran modulu muhurler + audit kurar.

    Bos-_WATCH korlugu kapanir: harden() cagiran cercevenin modul
    global'larindaki tum fonksiyon/siniflari seal() ile izlemeye alir.
    Operator boot'ta `harden()` cagirir; sonrasi izlenen-yuzey aktiftir.
    """
    out = {}
    try:
        try:
            out["audit_hook"] = bool(enforce_audit_hook())
        except Exception:
            out["audit_hook"] = False
        try:
            sealed = 0
            try:
                fr = _sys._getframe(1)
                g = dict(fr.f_globals) if fr is not None else {}
            except Exception:
                g = {}
            try:
                import types as _t
                for _n, _v in g.items():
                    try:
                        if _PIN_ISINSTANCE(_v, _t.FunctionType):
                            sealed += int(bool(seal(_v)))
                        elif _PIN_ISINSTANCE(_v, type):
                            try:
                                sealed += seal(*[m for m in vars(_v).values()
                                                 if _PIN_ISINSTANCE(m, _t.FunctionType)])
                            except Exception:
                                continue
                    except Exception:
                        continue
            except Exception:
                pass
            out["sealed"] = sealed
            out["watched"] = _PIN_LEN(_PIN_LIST(_WATCH.values()))
        except Exception:
            out["sealed"] = -1
            out["watched"] = -1
        try:
            out["tripped"] = bool(is_compromised(light_only=True))
        except Exception:
            out["tripped"] = True
    except Exception:
        out = {"audit_hook": False, "sealed": -1, "watched": -1, "tripped": True}
    return out

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
    global _WATCHDOG_THREAD, _WATCHDOG_STOP, _ADMIN_LOCKED
    try:
        with _LOCK:
            _ADMIN_LOCKED = True
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
        th = _PIN_THREAD_THREAD(target=_watchdog_loop, args=(stop_ev, iv),daemon=True)
        _WATCHDOG_STOP = stop_ev
        _WATCHDOG_THREAD = th
        th.start()
        return True
    except Exception:
        return False

def stop_watchdog():
    """Watchdog'u durdur (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_watchdog")
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
