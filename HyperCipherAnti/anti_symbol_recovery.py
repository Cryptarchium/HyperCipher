# -*- coding: utf-8 -*-
"""anti_symbol_recovery: Python sembol-tablosu kurtarma tespit katmani.

Tehdit modeli (arastirma sentezi - 3x ReSearch):
  - R1 symbol-recovery (communitytools reverse-engineering, unfuck rename_vars/
    cleanup_code_obj, wowsdeob BUILD_CLASS, PjOrion symbolrenamer.py,
    gopy code.h, runebook co_qualname):
    ``co.co_consts / co.co_names / co.co_varnames + dis.dis(co)`` ile
    kayip isimleri elle kurma; ``LOAD_CONST->co_consts / LOAD_GLOBAL->co_names /
    STORE_FAST->co_varnames`` haritalamasi; ``rename(code_obj)`` ile
    ``co_varnames->varN + co_name->coNNN`` (types.CodeType 12-arg) spoof'u;
    ``co_qualname`` (3.11+) dotted-path kurtarma (Foo.bar, Foo.<locals>.inner);
    ``unfuck`` junk-name (bos/underscore/digit/keyword/non-ascii) -> unknown_N.
  - R2 symtable/ast/dis/marshal (docs.python.org dis/symtable/ast,
    CPython Lib/dis.py _get_code_object, unpyc3 Code(co_cellvars+co_freevars),
    pyobfuscate marshal/pyc, refinery Marshal._load_object CODE):
    ``symtable.symtable(src)+get_identifiers/get_symbols/lookup``;
    ``ast.parse->ast.unparse`` minify/layout kurtarma;
    ``marshal.loads(blob)+dis.dis`` .pyc/marshal blob cozme;
    ``co_cellvars+co_freevars`` deref isimleri.
  - R3 audit-hook (PEP 578, audit-events table, docs.sys addaudithook,
    bpo-42800 GH-24182 AUDIT_READ):
    ``__code__/f_code/gi_code/cr_code/ag_code/tb_frame`` erisimi
    ``object.__getattr__`` audit-event uretir; hook'lar kalici, kaldirilamaz.

Kapsam (kardeslerle cakisma yok):
  - anti_string_extraction: co_consts STRINGS yuzeyi; BU modul SYMBOL TABLOLARI
    (co_names/co_varnames/cell-free/qualname/symtable/ast).
  - anti_constant_analysis: sabit-tur/entropi; BU modul isim-kurtarma kombolari.
  - anti_bytecode_analysis: opcode-akisi; BU modul names/vars/qualname dump kombosu.
  - anti_decompile: marshal/pyc KURTARMA; BU modul marshal+dis ILE sembol cikarma.
  - anti_introspection: pasif member kesfi (getmembers/signature/vars/dir);
    BU modul sembol-tablosu RECOVERY (symtable/ast/dis/marshal/qualname-spoof).
  - anti_reflection: sinif-hiyerarsi/globals/closure; BU modul code-obj isimleri.
  - Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
  - Trip >=1 STRONG veya >=2 WEAK.
"""
from __future__ import annotations
import sys as _sys
import threading as _threading
import time as _time

class SymbolRecoveryDetected(RuntimeError):
    pass

def _raise() -> None:
    raise SymbolRecoveryDetected("protected")

def _load_dis():
    """dis'i lazy yukle + sys.modules'tan tahliye et (self-FP onler)."""
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
    "symbol_table_dump": 100,
    "qualname_spoof": 100,
    "marshal_code_load": 100,
    "symtable_ast_extraction": 100,
    "pin_mismatch": 100,
    "sensor_health": 100,
    "dunder_name_probe": 30,
    "dir_enumeration": 30,
    "code_attr_access": 30,
    "disassembly_import": 30,
    "cell_free_harvest": 30,
    "symbol_probe_anomaly": 30,
}
STRONG = _PIN_FROZENSET({
    "symbol_table_dump",
    "qualname_spoof",
    "marshal_code_load",
    "symtable_ast_extraction",
    "pin_mismatch",
    "sensor_health",
})
_THRESHOLD_TRIP = 100
_INSN_CAP = 20000
_PROBE_WINDOW_S = 60.0
_PROBE_THRESHOLD = 50
_SYMBOL_TABLE_ATTRS = _PIN_FROZENSET({
    "co_names", "co_varnames", "co_consts", "co_name",
    "co_qualname", "co_filename", "co_firstlineno",
    "co_argcount", "co_nlocals", "co_code",
})
_DIS_VERBS = _PIN_FROZENSET({
    "get_instructions", "dis", "disassemble", "Bytecode",
    "code_info", "findlinestarts", "get_code_object",
    "code_walker", "show",
})
_MARSHAL_FUNCS = _PIN_FROZENSET({
    "loads", "load",
    "unmarshal", "read_code", "dec_module",
})
_SYMTABLE_FUNCS = _PIN_FROZENSET({
    "symtable", "get_identifiers", "get_symbols", "lookup",
    "get_name", "get_type", "is_nested",
})
_CELL_ATTRS = _PIN_FROZENSET({
    "co_cellvars", "co_freevars", "co_nlocals",
    "cellvars", "freevars", "derefnames",
    "gi_frame", "gi_code", "cr_frame", "cr_code",
    "ag_frame", "ag_code",
})
_NAME_DUNDERS = _PIN_FROZENSET({
    "__name__", "__qualname__", "__module__",
})
_CODE_ATTRS = _PIN_FROZENSET({
    "__code__", "co_code", "co_filename", "f_code",
    "tb_frame", "gi_code", "gi_frame",
})
_DUNDER_SYMBOL = _PIN_FROZENSET({
    "__name__", "__qualname__", "__module__",
    "__code__", "co_names", "co_varnames", "co_consts",
    "co_qualname", "co_cellvars", "co_freevars",
})
_WATCH: dict = {}
_PINS: dict = {}
_ALERT_HOOK = None
_ALERTED = False
_PROBE_TIMES: list = []
_PROBE_NOISE = _PIN_FROZENSET({"__code__", "__dict__"})
_AUDIT_INSTALLED = False
_WATCHDOG_THREAD = None
_WATCHDOG_STOP = None
_SY_ADMINS: dict = {}
_SY_ADMIN_LOCKED = False
_SY_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _SY_ADMIN_DENIED
    try:
        if _SY_ADMIN_LOCKED:
            with _LOCK:
                _SY_ADMIN_DENIED += 1
            return False
        try:
            import sys as _s
            fr = _s._getframe(1)
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
            _SY_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _sy_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_SY_ADMINS)
        if not allowed:
            return False
        try:
            import sys as _s2
            fr = _s2._getframe(2)
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


def _sy_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _SY_ADMIN_DENIED
    try:
        with _LOCK:
            _SY_ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()
__all__ = [
    "SymbolRecoveryDetected","WEIGHTS","STRONG","watch","unwatch","pin","verify_pins","seal","scan_function","scan_module","check_all","score","is_compromised","is_symbol_recovered","assert_clean","guard","status","set_alert_hook","note_symbol_probe","reset_counters","install_audit_hook","enforce_audit_hook","configure_probe","harden","authorize_admin","start_watchdog","stop_watchdog",
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
                for _d in _DUNDER_SYMBOL:
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
        "symbol_table_dump": False,
        "qualname_spoof": False,
        "marshal_code_load": False,
        "symtable_ast_extraction": False,
        "dunder_name_probe": False,
        "dir_enumeration": False,
        "code_attr_access": False,
        "disassembly_import": False,
        "cell_free_harvest": False,
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
            _NAMES_TABLE = {"co_names", "co_varnames"}
            _has_names = bool((vocab & _NAMES_TABLE) or (attrs & _NAMES_TABLE))
            _has_names_const = bool(dunder_consts & _NAMES_TABLE)
            _has_dis = bool(vocab & _DIS_VERBS)
            _has_dis_const = any(_PIN_ISINSTANCE(_s, str) and _s in _DIS_VERBS for _s in const_strs)
            if (_has_names or _has_names_const) and (_has_dis or _has_dis_const):
                res["symbol_table_dump"] = True
            elif "co_names" in vocab and "co_varnames" in vocab and _has_dis:
                res["symbol_table_dump"] = True
        except Exception:
            pass
        try:
            _has_replace = "replace" in vocab or "replace" in attrs
            _has_codetype = "CodeType" in vocab or "CodeType" in co_names
            _has_qn = bool((vocab & {"co_name", "co_qualname", "qualname"}) or (attrs & {"co_name", "co_qualname"}))
            _has_qn_const = bool(dunder_consts & {"co_qualname"}) or "qualname" in const_strs
            if (_has_replace or _has_codetype) and (_has_qn or _has_qn_const):
                res["qualname_spoof"] = True
            elif _has_codetype and ("co_varnames" in vocab or "co_varnames" in attrs):
                res["qualname_spoof"] = True
        except Exception:
            pass
        try:
            _has_marshal = "marshal" in vocab or "marshal" in names or "marshal" in co_names or "marshal" in const_strs
            _has_mfunc = bool(vocab & _MARSHAL_FUNCS)
            _has_mfunc_const = any(_PIN_ISINSTANCE(_s, str) and _s in _MARSHAL_FUNCS for _s in const_strs)
            if _has_marshal and (_has_mfunc or _has_mfunc_const):
                res["marshal_code_load"] = True
        except Exception:
            pass
        try:
            _has_sym = "symtable" in vocab or "symtable" in names or "symtable" in co_names or "symtable" in const_strs
            _has_symfunc = bool(vocab & _SYMTABLE_FUNCS)
            if _has_sym and _has_symfunc:
                res["symtable_ast_extraction"] = True
            else:
                try:
                    _has_ast = "ast" in vocab or "ast" in names or "ast" in co_names or "ast" in const_strs
                    _has_parse = "parse" in vocab or "parse" in const_strs
                    _has_unparse = "unparse" in vocab or "unparse" in const_strs
                    _has_compile = "compile" in vocab or "PyCF_ONLY_AST" in vocab or "PyCF_ONLY_AST" in const_strs
                    if _has_ast and _has_parse and (_has_unparse or _has_compile):
                        res["symtable_ast_extraction"] = True
                except Exception:
                    pass
        except Exception:
            pass
        try:
            if bool((vocab & _NAME_DUNDERS) or (attrs & _NAME_DUNDERS)) or bool(dunder_consts & _NAME_DUNDERS):
                res["dunder_name_probe"] = True
            elif "__qualname__" in const_strs or "__name__" in const_strs:
                res["dunder_name_probe"] = True
        except Exception:
            pass
        try:
            if "dir" in vocab or "dir" in const_strs:
                res["dir_enumeration"] = True
        except Exception:
            pass
        try:
            if bool((vocab & _CODE_ATTRS) or (attrs & _CODE_ATTRS)) or bool(dunder_consts & _CODE_ATTRS):
                res["code_attr_access"] = True
            elif "__code__" in const_strs or "co_filename" in const_strs:
                res["code_attr_access"] = True
        except Exception:
            pass
        try:
            _has_dis_mod = "dis" in names or "dis" in co_names or "dis" in const_strs
            _has_dis_any = bool(vocab & _DIS_VERBS)
            if (_has_dis_mod and _has_dis_any) or (_has_dis_any and "dis" in vocab):
                if not res["symbol_table_dump"]:
                    res["disassembly_import"] = True
            elif _has_dis_any:
                res["disassembly_import"] = True
        except Exception:
            pass
        try:
            if bool((vocab & _CELL_ATTRS) or (attrs & _CELL_ATTRS)):
                res["cell_free_harvest"] = True
            elif "co_cellvars" in const_strs or "co_freevars" in const_strs:
                res["cell_free_harvest"] = True
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
    """Izlemeden cikar (YONETIM: kayitli operator sart — susturma kapali)."""
    if not _sy_check_admin():
        _sy_deny_admin("unwatch")
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
        try:
            parts.append(_PIN_STR(_PIN_GETATTR(co, "co_qualname", "?")))
        except Exception:
            parts.append("?")
        try:
            parts.append(_PIN_STR(_PIN_GETATTR(co, "co_filename", "?")))
        except Exception:
            parts.append("?")
        try:
            parts.append(_PIN_STR(_PIN_GETATTR(co, "co_firstlineno", 0)))
        except Exception:
            parts.append("0")
        return _h.sha256("|".join(parts).encode("utf-8","replace")).hexdigest()
    except Exception:
        return ""

def verify_pins():
    """Pin'li baseline degisti mi (True=risk) — fail-closed iki uc."""
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
    """Verilen fonksiyonlari watch+pin'le (SADECE basarili pin sayilir).

    MED-fix: izlenip pinlenemeyen fonksiyon artik sealed sayilmaz
    (operator pinli-koruma varsayamaz).
    """
    n = 0
    try:
        for _f in funcs:
            try:
                if watch(_f) and pin(_f):
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
    try:
        if event != "object.__getattr__":
            try:
                if (_PIN_ISINSTANCE(event, str) and (
                    event.startswith("symtable.") or event.startswith("ast.") or
                    event.startswith("dis.") or event.startswith("marshal."))):
                    note_symbol_probe()
            except Exception:
                pass
            return
        try:
            name = args[1] if _PIN_LEN(args) > 1 else ""
        except Exception:
            name = ""
        try:
            if (_PIN_ISINSTANCE(name, str) and name in _DUNDER_SYMBOL and name not in _PROBE_NOISE):
                note_symbol_probe()
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

def note_symbol_probe():
    """Prob gozlemi isaretle (LOW-fix: >= esik + latch'li tek-ates).

    Eski `==` kenari esigi ATLayarak asan patlamalarda alert'i
    kaciriyordu; verdict zaten `>=` kullanir. _ALERTED latch spam'i
    onler (pencere bosalinca reset).
    """
    try:
        now = _PIN_TIME_MONOTONIC()
        fire = False
        with _LOCK:
            global _ALERTED
            _PROBE_TIMES.append(now)
            try:
                cutoff = now - _PROBE_WINDOW_S
                while _PROBE_TIMES and _PROBE_TIMES[0] < cutoff:
                    _PROBE_TIMES.pop(0)
                hot = _PIN_LEN(_PROBE_TIMES) >= _PROBE_THRESHOLD
            except Exception:
                hot = False
            if hot and not _ALERTED:
                _ALERTED = True
                fire = True
            elif not hot:
                _ALERTED = False
        if fire:
            try:
                _fire_alert("symbol_probe_anomaly")
            except Exception:
                pass
        return True
    except Exception:
        return False

def reset_counters():
    """Prob penceresini sifirla (YONETIM: kayitli operator sart)."""
    if not _sy_check_admin():
        _sy_deny_admin("reset_counters")
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
    """Prob esigi/penceresi (YONETIM: kayitli operator sart — CRIT-fix).

    Saldirgan esigi 10000'e cekip pencereyi silemez.
    """
    if not _sy_check_admin():
        _sy_deny_admin("configure_probe")
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
    """Alert kancasi (YONETIM: None-disarm kayitli operator sart)."""
    if fn is None and not _sy_check_admin():
        _sy_deny_admin("set_alert_hook")
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
    ("symbol_table_dump", "_watch"),
    ("qualname_spoof", "_watch"),
    ("marshal_code_load", "_watch"),
    ("symtable_ast_extraction", "_watch"),
    ("dunder_name_probe", "_watch"),
    ("dir_enumeration", "_watch"),
    ("code_attr_access", "_watch"),
    ("disassembly_import", "_watch"),
    ("cell_free_harvest", "_watch"),
    ("symbol_probe_anomaly", "_probe"),
    ("pin_mismatch", "_pins"),
    ("sensor_health", None),
)
_LIGHT = _PIN_FROZENSET({"symbol_table_dump", "qualname_spoof","marshal_code_load", "symtable_ast_extraction","pin_mismatch", "sensor_health"})

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

def is_symbol_recovered(light_only=False):
    try:
        return bool(is_compromised(light_only=light_only))
    except Exception:
        return True

def assert_clean(light_only=False):
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
            except SymbolRecoveryDetected:
                raise
            except Exception as e:
                try:
                    if is_compromised():
                        raise SymbolRecoveryDetected("protected") from e
                except SymbolRecoveryDetected:
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
    """Sertlestir: audit + cagiran-modul muhurleme + durum (tek-cagri postur).

    MED-fix: bos-_WATCH + kapali-audit default-korlugu kapanir — cagiran
    cercevenin fonksiyonlari seal() ile izlenir, audit-hook kurulur.
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
                import sys as _s
                fr = _s._getframe(1)
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
    global _WATCHDOG_THREAD, _WATCHDOG_STOP, _SY_ADMIN_LOCKED
    try:
        with _LOCK:
            _SY_ADMIN_LOCKED = True
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
        th = _PIN_THREAD_THREAD(target=_watchdog_loop, args=(stop_ev, iv),daemon=True)
        _WATCHDOG_STOP = stop_ev
        _WATCHDOG_THREAD = th
        th.start()
        return True
    except Exception:
        return False

def stop_watchdog():
    """Gozcuyu durdur (YONETIM: kayitli operator sart)."""
    if not _sy_check_admin():
        _sy_deny_admin("stop_watchdog")
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
