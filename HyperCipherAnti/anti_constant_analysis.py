"""anti_constant_analysis: sabit-tablosu (co_consts) butunluk katmani.

Tehdit modeli (sabit-tablosu saldirilari):
  - OOB const/name referansi: LOAD_CONST/LOAD_GLOBAL operandlari co_consts/
    co_names disi gosterir (HITCON "V O I D" / B01lers awpcode deseni) ->
    sandbox kacisi, bellek disi okuma. CPython sinir denetlemez.
  - marshal-asamali yuk: co_consts icinde bytes/blob + marshal.loads/exec/
    eval isimleri -> sifreli next-stage (ML-model Lambda, pickle
    __reduce__ + BINBYTES, .pyc magic'siz gomulu).
  - Gizli anahtar-sozcuk: bytes sabitine gomulu exec/eval/decode zinciri
    (b'\\x65\\x76...' parser-seviyesi cozumlenir, kaynak-grep gorunmez).
  - Yuksek-entropi sabit: 64+ karakter, >4.5 bit/karakter (base64/zlib
    gomulu yuk tasima olasiligi).
  - getattr-dolaylama: getattr(os/subprocess/builtins, "sistem") ile
    dogrudan import'tan kacinma.
  - Pin: kritik fonksiyonlarin __code__'u parmak-izlenir; degisim
    (monkey-patch'in en derini: __code__ takasi) yakalanir. CPython
    3.11+ code-hash co_code'u ICERMEZ -> parmak izi co_code'u ACIKCA
    katar (Objects/codeobject.c code_hash notu).

Kapsam (kardeslerle cakisma yok):
  - anti_bytecode_analysis opcode-akisini, anti_decompile kurtarmayi,
    anti_hook func-butunlugunu tutar; BU modul SABIT TABLOSU'nu inceler
    (const degerleri, isim tablosu, OOB gecerliligi, pin).
  - anti_patch sys.modules snapshot/restore yapar; bu modul TESPIT uretir.

Sinirlar (bilincli tercihler):
  - Trip >=1 STRONG veya >=2 WEAK. Tek WEAK trip uretmez.
  - check_all() yalnizca watch() ile izlenen + pin() ile muhurlenen
    fonksiyonlari tarar (bos kayit = temiz). scan_function/scan_module
    ile istenen hedef acikca taranir.
  - Yorum/docstring (co_consts[0]) anahtar-sozcuk/entropi taramasinda
    WEAK `docstring_conceal` sinyaliyle taranir (F19: covert-channel;
    tek WEAK trip uretmez, FP-guvenli).

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

import hashlib as _hashlib
import math as _math
import sys as _sys
import threading as _threading


def _get_dis():
    """dis'i lazy yukle + sys.modules'tan tahliye et (self-FP onler)."""
    try:
        added = "dis" not in _sys.modules
        import dis as _d
        return _d, added
    except Exception:
        return None, False


def _drop_dis(added: bool) -> None:
    try:
        if added and "dis" in _sys.modules:
            del _sys.modules["dis"]
    except Exception:
        pass


class ConstantAnalysisDetected(RuntimeError):
    pass


def _raise():
    raise ConstantAnalysisDetected("protected")


_LOCK = _threading.RLock()

_VER = _sys.version_info[:2]

WEIGHTS = {
    "const_oob": 100,
    "exec_marshal_chain": 100,
    "high_entropy_const": 100,
    "pin_mismatch": 100,
    "getattr_indirection": 30,
    "const_hidden_keyword": 30,
    "deep_nesting": 30,
    "docstring_conceal": 30,
    "sensor_health": 100,
}
STRONG = frozenset({"const_oob", "exec_marshal_chain",
                    "high_entropy_const", "pin_mismatch", "sensor_health"})
_THRESHOLD_TRIP = 100

_ENTROPY_MIN_LEN = 64
_ENTROPY_BITS = 4.5
_NEST_DEPTH_WEAK = 5

_DANGER_NAMES = frozenset({"marshal", "exec", "eval", "compile",
                           "__import__", "open", "input", "globals",
                           "locals", "vars", "getattr", "setattr",
                           "delattr", "breakpoint", "memoryview"})
_DECODE_NAMES = frozenset({"b64decode", "a85decode", "unhexlify", "fromhex",
                           "decompress", "decompressobj", "loads", "load",
                           "decode", "decrypt", "b32decode", "b16decode"})
_GETATTR_TARGETS = frozenset({"exec", "eval", "__import__", "system",
                              "popen", "compile", "marshal", "loads",
                              "globals", "builtins", "__builtins__"})
_HIDDEN_KEYWORDS = ("exec(", "eval(", "__import__(", "b64decode", "fromhex",
                    "marshal.", "subprocess", "os.system", "socket.",
                    "urlopen", "ctypes.", "compile(", "getattr(",
                    "popen", "system(")

_DIRECT_NAME_OPS = frozenset({
    "LOAD_NAME", "STORE_NAME", "DELETE_NAME", "STORE_GLOBAL",
    "DELETE_GLOBAL", "IMPORT_NAME", "IMPORT_FROM", "STORE_ATTR",
    "DELETE_ATTR", "LOAD_FROM_DICT_OR_GLOBALS", "LOAD_ATTR",
    "LOAD_GLOBAL", "LOAD_SUPER_ATTR",
})

_WATCH = {}
_PINS = {}
_WATCHDOG_STOP = None
_WATCHDOG_THREAD = None


def _shannon(data):
    try:
        if not data:
            return 0.0
        if isinstance(data, str):
            data = data.encode("utf-8", "ignore")
        n = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        return -sum((c / n) * _math.log2(c / n) for c in freq.values())
    except Exception:
        return 0.0


def _iter_code(root, _depth=0, _seen=None):
    try:
        if _seen is None:
            _seen = set()
        if _depth > 32:
            return
        if id(root) in _seen:
            return
        _seen.add(id(root))
        yield root, _depth
        try:
            consts = getattr(root, "co_consts", ())
        except Exception:
            return
        for c in consts or ():
            try:
                import types as _t
                if isinstance(c, _t.CodeType):
                    for item in _iter_code(c, _depth + 1, _seen):
                        yield item
            except Exception:
                continue
    except Exception:
        return


def _code_fp(co):
    try:
        h = _hashlib.sha256()
        try:
            h.update(bytes(getattr(co, "co_code", b"") or b""))
        except Exception:
            pass
        try:
            h.update(repr(getattr(co, "co_consts", ())).encode("utf-8", "ignore"))
        except Exception:
            pass
        try:
            h.update(repr(getattr(co, "co_names", ())).encode("utf-8", "ignore"))
        except Exception:
            pass
        try:
            h.update(repr(getattr(co, "co_varnames", ())).encode("utf-8", "ignore"))
        except Exception:
            pass
        return h.hexdigest()
    except Exception:
        return ""


def _consts_flat(co, skip_doc=True, _depth=0, _seen=None):
    """Duzlestirilmis sabitler: konteyner + IC-ICE code nesnelerine iner (F20).

    Saldirgan blob'u nested inner() icine saklayamaz; danger-ismi dis
    tabloda, blob ic tabloda olsa zincir kurulur.
    """
    out = []
    try:
        if _seen is None:
            _seen = set()
        if _depth > 32:
            return out
        try:
            if id(co) in _seen:
                return out
            _seen.add(id(co))
        except Exception:
            pass
        try:
            import types as _t
            _CodeType = _t.CodeType
        except Exception:
            _CodeType = None
        consts = getattr(co, "co_consts", ()) or ()
        for i, c in enumerate(consts):
            if skip_doc and i == 0 and isinstance(c, str):
                continue
            out.append(c)
            if isinstance(c, (tuple, list, frozenset)):
                try:
                    stack = list(c)
                    while stack:
                        x = stack.pop()
                        out.append(x)
                        if isinstance(x, (tuple, list, frozenset)):
                            stack.extend(list(x))
                except Exception:
                    pass
            elif _CodeType is not None and isinstance(c, _CodeType):
                try:
                    out.extend(_consts_flat(c, skip_doc=False,
                                           _depth=_depth + 1, _seen=_seen))
                except Exception:
                    pass
    except Exception:
        pass
    return out


def _names_all(co):
    names = set()
    try:
        for sub, _d in _iter_code(co):
            try:
                for n in getattr(sub, "co_names", ()) or ():
                    if isinstance(n, str):
                        names.add(n)
            except Exception:
                continue
    except Exception:
        pass
    return names


def _nest_depth(x, _d=0):
    try:
        if _d > 32:
            return _d
        if isinstance(x, (tuple, list, frozenset)):
            best = _d
            for i in x:
                v = _nest_depth(i, _d + 1)
                if v > best:
                    best = v
            return best
        return _d
    except Exception:
        return _d


def _has_const_op(opname, op):
    try:
        _d, _added = _get_dis()
        try:
            if _d is not None and op in _d.hasconst:
                return True
        finally:
            _drop_dis(_added)
    except Exception:
        pass
    return opname in ("LOAD_CONST", "RETURN_CONST", "LOAD_CONST_IMMORTAL")


def _check_oob_code(co):
    try:
        for sub, _d in _iter_code(co):
            try:
                consts = getattr(sub, "co_consts", ()) or ()
                names = getattr(sub, "co_names", ()) or ()
                nlen = len(names)
                clen = len(consts)
                try:
                    _d, _added = _get_dis()
                    try:
                        instrs = list(_d.get_instructions(sub)) if _d is not None else []
                    finally:
                        _drop_dis(_added)
                except Exception:
                    return True
                for ins in instrs:
                    try:
                        op = ins.opcode
                        arg = ins.arg
                        if arg is None:
                            continue
                        if _has_const_op(ins.opname, op):
                            if arg >= clen:
                                return True
                            continue
                        if ins.opname not in _DIRECT_NAME_OPS:
                            continue
                        idx = arg
                        if ins.opname in ("LOAD_GLOBAL", "LOAD_ATTR"):
                            if _VER >= (3, 11):
                                idx >>= 1
                        elif ins.opname == "LOAD_SUPER_ATTR":
                            if _VER >= (3, 12):
                                idx >>= 2
                        if idx >= nlen:
                            return True
                    except Exception:
                        continue
            except Exception:
                continue
        return False
    except Exception:
        return False


_B64CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEXCHARS = frozenset("0123456789abcdefABCDEF")


def _charset_ratio(t, charset):
    try:
        if not t:
            return 0.0
        hit = sum(1 for ch in t if ch in charset)
        return hit / len(t)
    except Exception:
        return 0.0


def _normalize_scan_text(t):
    """Tarama-oncesi normalizasyon (F18): whitespace + ayirac temizligi.

    Saldirgan base64/hex'i boslukla doldurup entropi/charset testinden
    kacar; normalize edilmis formda yuk aynen cozulur (strip-sonrasi
    decode identik byte uretir). Tespit sekle bakar, decode'a degil.
    """
    try:
        if not isinstance(t, str):
            try:
                t = bytes(t).decode("ascii", "ignore")
            except Exception:
                return ""
        try:
            t = "".join(t.split())
        except Exception:
            pass
        try:
            for _sep in ("-", "_", ".", ":", "/", "|", ","):
                t = t.replace(_sep, "")
        except Exception:
            pass
        return t
    except Exception:
        return ""


def _shaped_payload(t):
    try:
        t = _normalize_scan_text(t)
        if not isinstance(t, str):
            return False
        if len(t) < _ENTROPY_MIN_LEN:
            return False
        ent = _shannon(t)
        if _charset_ratio(t, _B64CHARS) >= 0.9 and ent > _ENTROPY_BITS:
            return True
        if _charset_ratio(t, _HEXCHARS) >= 0.95 and ent > 2.5:
            return True
        return False
    except Exception:
        return False


def _scan_docstring(co):
    """WEAK: docstring covert-channel (F19). co_consts[0] str icerigi
    anahtar-sozcuk/entropi ile taranir; tek WEAK trip uretmez (FP-guvenli).
    """
    try:
        consts = getattr(co, "co_consts", ()) or ()
        if not consts or not isinstance(consts[0], str):
            return False
        doc = consts[0]
        if len(doc) < 16:
            return False
        low = doc.lower()
        for kw in _HIDDEN_KEYWORDS:
            if kw in low:
                return True
        if _shaped_payload(doc):
            return True
        return False
    except Exception:
        return True


def _scan_one(co):
    res = {k: False for k in WEIGHTS}
    try:
        res["const_oob"] = bool(_check_oob_code(co))
    except Exception:
        pass
    try:
        names = _names_all(co)
        flat = _consts_flat(co, skip_doc=True)
        has_exec = bool(names & _DANGER_NAMES)
        has_blob = False
        try:
            for c in flat:
                if isinstance(c, (bytes, bytearray)) and len(c) >= 16:
                    has_blob = True
                    break
                if isinstance(c, str) and _shaped_payload(c):
                    has_blob = True
                    break
        except Exception:
            pass
        if has_exec and has_blob:
            res["exec_marshal_chain"] = True
    except Exception:
        pass
    try:
        for c in _consts_flat(co, skip_doc=True):
            try:
                if isinstance(c, (str, bytes, bytearray)) and _shaped_payload(c):
                    res["high_entropy_const"] = True
                    break
            except Exception:
                continue
    except Exception:
        pass
    try:
        names = _names_all(co)
        if "getattr" in names:
            try:
                strs = {c for c in _consts_flat(co, skip_doc=True) if isinstance(c, str)}
                if strs & _GETATTR_TARGETS:
                    res["getattr_indirection"] = True
            except Exception:
                pass
    except Exception:
        pass
    try:
        for c in _consts_flat(co, skip_doc=True):
            try:
                if isinstance(c, str):
                    if len(c) < 16:
                        continue
                    low = c.lower()
                    for kw in _HIDDEN_KEYWORDS:
                        if kw in low:
                            res["const_hidden_keyword"] = True
                            break
                    if res["const_hidden_keyword"]:
                        break
                elif isinstance(c, (bytes, bytearray)):
                    if len(c) < 16:
                        continue
                    try:
                        t = bytes(c).decode("ascii", "ignore").lower()
                    except Exception:
                        continue
                    for kw in _HIDDEN_KEYWORDS:
                        if kw in t:
                            res["const_hidden_keyword"] = True
                            break
                    if res["const_hidden_keyword"]:
                        break
            except Exception:
                continue
    except Exception:
        pass
    try:
        for sub, _d in _iter_code(co):
            try:
                for c in getattr(sub, "co_consts", ()) or ():
                    if _nest_depth(c) >= _NEST_DEPTH_WEAK:
                        res["deep_nesting"] = True
                        break
                if res["deep_nesting"]:
                    break
            except Exception:
                continue
    except Exception:
        pass
    try:
        res["docstring_conceal"] = bool(_scan_docstring(co))
    except Exception:
        res["docstring_conceal"] = True
    return res


def _co_of(f):
    try:
        import types as _t
        if isinstance(f, _t.CodeType):
            return f
        return getattr(f, "__code__", None)
    except Exception:
        return None


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


def verify_pins():
    try:
        with _LOCK:
            items = list(_PINS.items())
        for _k, (f, fp) in items:
            try:
                co = _co_of(f)
                if co is None:
                    return True
                if _code_fp(co) != fp:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return True


def scan_function(f):
    try:
        co = _co_of(f)
        if co is None:
            return {}
        return _scan_one(co)
    except Exception:
        return {}


def scan_module(mod):
    out = {}
    try:
        import types as _t
        names = getattr(mod, "__all__", None)
        items = []
        if names:
            for n in names:
                try:
                    items.append((n, getattr(mod, n)))
                except Exception:
                    continue
        else:
            try:
                items = list(vars(mod).items())
            except Exception:
                return {}
        for n, v in items:
            try:
                if isinstance(v, _t.FunctionType):
                    out[n] = _scan_one(getattr(v, "__code__"))
                elif isinstance(v, type):
                    for mn, mv in list(vars(v).items()):
                        try:
                            if isinstance(mv, _t.FunctionType):
                                out["%s.%s" % (n, mn)] = _scan_one(getattr(mv, "__code__"))
                        except Exception:
                            continue
            except Exception:
                continue
    except Exception:
        pass
    return out


def _check_sensor_health():
    try:
        _d, _added = _get_dis()
        try:
            _ = list(_d.opmap.items())
            _ = 100 in _d.hasconst
        finally:
            _drop_dis(_added)
        _ = _hashlib.sha256(b"x").hexdigest()
        return False
    except Exception:
        return True


_CHECKS = (
    ("const_oob", "_watch"),
    ("exec_marshal_chain", "_watch"),
    ("high_entropy_const", "_watch"),
    ("pin_mismatch", "_pins"),
    ("getattr_indirection", "_watch"),
    ("const_hidden_keyword", "_watch"),
    ("deep_nesting", "_watch"),
    ("docstring_conceal", "_watch"),
    ("sensor_health", None),
)

_LIGHT = frozenset({"const_oob", "exec_marshal_chain", "pin_mismatch",
                    "sensor_health"})


def check_all(light_only=False):
    results = {}
    try:
        with _LOCK:
            watched = list(_WATCH.values())
    except Exception:
        watched = []
    for name, src in _CHECKS:
        if light_only and name not in _LIGHT:
            continue
        try:
            if src == "_pins":
                results[name] = bool(verify_pins())
            elif src == "_watch":
                hit = False
                for f in watched:
                    try:
                        r = _scan_one(_co_of(f))
                        if r.get(name):
                            hit = True
                            break
                    except Exception:
                        hit = True
                        break
                results[name] = hit
            else:
                results[name] = bool(_check_sensor_health())
        except Exception:
            results[name] = True
    return results


def _score_from(results):
    score = 0
    strong_hit = False
    weak_hits = 0
    for k, v in results.items():
        if not v:
            continue
        w = WEIGHTS.get(k, 0)
        score += w
        if k in STRONG:
            strong_hit = True
        else:
            weak_hits += 1
    tripped = bool(strong_hit or weak_hits >= 2)
    return score, _THRESHOLD_TRIP, tripped


def score(light_only=False):
    return _score_from(check_all(light_only=light_only))


def is_compromised(light_only=False):
    try:
        _, _, tripped = _score_from(check_all(light_only=light_only))
        return bool(tripped)
    except Exception:
        return True


def assert_clean(light_only=False):
    if is_compromised(light_only=light_only):
        _raise()
    return True


def guard(func):
    try:
        import functools as _ft

        @_ft.wraps(func)
        def _w(*a, **k):
            assert_clean()
            return func(*a, **k)
        return _w
    except Exception:
        return func


def status(light_only=False):
    try:
        r = check_all(light_only=light_only)
        s, t, trip = _score_from(r)
        return {"signals": r, "score": s, "threshold": t, "tripped": trip}
    except Exception:
        return {"signals": {}, "score": -1, "threshold": _THRESHOLD_TRIP,
                "tripped": True}


def _watchdog_loop(stop_ev, interval):
    try:
        while not stop_ev.wait(interval):
            try:
                if is_compromised(light_only=True):
                    return
            except Exception:
                return
    except Exception:
        pass


def start_watchdog(interval=0.05):
    global _WATCHDOG_STOP, _WATCHDOG_THREAD
    try:
        with _LOCK:
            if _WATCHDOG_THREAD is not None and _WATCHDOG_THREAD.is_alive():
                return True
            stop_ev = _threading.Event()
            th = _threading.Thread(target=_watchdog_loop,
                                   args=(stop_ev, float(interval)),
                                   daemon=True)
            _WATCHDOG_STOP = stop_ev
            _WATCHDOG_THREAD = th
            th.start()
            return True
    except Exception:
        return False


def stop_all_watchdogs():
    global _WATCHDOG_STOP, _WATCHDOG_THREAD
    try:
        with _LOCK:
            ev, th = _WATCHDOG_STOP, _WATCHDOG_THREAD
            _WATCHDOG_STOP, _WATCHDOG_THREAD = None, None
        try:
            if ev is not None:
                ev.set()
        except Exception:
            pass
        try:
            if th is not None and th.is_alive():
                th.join(timeout=1.0)
        except Exception:
            pass
        return True
    except Exception:
        return False


__all__ = [
    "ConstantAnalysisDetected",
    "watch", "unwatch", "pin", "verify_pins",
    "scan_function", "scan_module",
    "check_all", "score", "is_compromised", "assert_clean",
    "guard", "status", "start_watchdog", "stop_all_watchdogs",
]

try:
    _s = _sys.modules.get("dis")
    if _s is not None and getattr(_s, "__spec__", None) is not None:
        if getattr(getattr(_s, "__spec__", None), "name", "") == "dis":
            try:
                del _sys.modules["dis"]
            except Exception:
                pass
except Exception:
    pass
del _s
