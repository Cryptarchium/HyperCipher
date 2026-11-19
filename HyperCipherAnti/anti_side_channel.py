"""anti_side_channel: yan-kanal (timing/cache) sizinti tespit katmani.

Tehdit modeli (arastirma sentezi):
  - Timing karsilastirma: sir uzerinde `==`/`!=` (erken-cikis) -> bayt
    bayt kurtarma (HMAC-karsilastirma sizintisi; unseel/trailofbits:
    sabit-zamanli karsilastirma O(n), erken-cikis O(1)). Uretim cozumu
    `hmac.compare_digest` (C, 3.10+ OpenSSL CRYPTO_memcmp) veya
    `cryptography.hazmat.primitives.constant_time.bytes_eq`.
  - Zayif RNG: `random.*` ile anahtar/nonce uretimi -> tahmin edilebilir
    (trailofbits: secrets.token_bytes/randbelow/choice kullan).
  - Secret-indexli tablo: secret ile dizi-indexleme -> cache hatti
    uzerinden index sizintisi (Flush+Reload/Prime+Probe; unseel kural 2:
    secret bellek adresi YOK; tum girdileri tara + maskele).
  - Secret-dalli akis: secret kosullu `if`/erken-return (unseel kural 1).
  - Degisken-sureli aritmetik: secret uzerinde `/`, `%`, `//`
    (KyberSlash 2023: ML-KEM bolme ile anahtar kurtarma).
  - Erken-cikis dongusu: dongu ici karsilastir + return (memcmp sekli).
  - Uzunluk-oracle sekli: len() kontrolu + aninda False (tip/uzunluk
    ipucu; compare_digest uzunlugu sizdirir - dokumante sinir).
  - Jitter tek basina COZUM DEGIL (ortalama ile elenir; unseel):
    savunma = varyasyonu kaldir (sabit-zaman) + korlestirme (blinding)
    + rate-limit; jitter yalnizca katman.

Kapsam (kardeslerle cakisma yok):
  - anti_constant_analysis sabit-tur/entropi/OOB tutar; BU modul
    ZAMANLAMA-DAVRANIS yuzeyini (karsilastirma sekli, RNG kaynagi,
    dallanma/indexleme Sekli, bolme) inceler.
  - anti_key_extraction RAM hijyenini, anti_memory_inspection canli
    bellegi, anti_error_leakage hata-oracle'ini tutar; bu modul
    STATIK bytecode + runtime-gecikme korelasyonunu tutar.
  - anti_bytecode_analysis opcode-akisini tutar; bu modul yan-kanal
    SEMANTIGINI (secret-aktor tespiti) tutar.

Sinirlar (bilincli tercihler):
  - Trip >=1 STRONG veya >=2 WEAK. Tek WEAK trip uretmez.
  - Secret-tahmini isim-sezgiselidir (key/secret/token/mac/tag/
    digest/signature/nonce/salt/priv/...): isim disi tasiyan sir
    gorunmez (dokumante rezidu; veri-akisi yok).
  - compare_digest/bytes_eq iceren fonksiyon karsilastirma sinyalinden
    muaftir (guvenli-oruntu).
  - check_all() yalnizca watch()+pin() kayitlarini tarar.
  - Donanim-kanallari (cldemote/Demote+Reload, GhostRace SRC, SSBleed
    MDP, RS-contention, guc/EM) saf-Python ile KAPATILAMAZ: savunma
    sabit-zamanli kaynak + verify-then-decrypt sirasi + masking'tir;
    mikromimari gozlem bu modulun disidir (dokumante rezidu).

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

import hashlib as _hashlib
import hmac as _hmac
import re as _re
import statistics as _statistics
import threading as _threading
import time as _time


class SideChannelDetected(RuntimeError):
    pass


def _raise():
    raise SideChannelDetected("protected")


_LOCK = _threading.RLock()

WEIGHTS = {
    "timing_unsafe_compare": 100,
    "weak_random": 100,
    "secret_indexed_lookup": 100,
    "pin_mismatch": 100,
    "sensor_health": 100,
    "secret_branch": 30,
    "variable_time_arith": 30,
    "early_exit_loop": 30,
    "length_oracle_shape": 30,
    "timing_probe_anomaly": 30,
    "unsafe_search_method": 30,
    "pow_secret_exp": 30,
    "oracle_shape": 30,
}
STRONG = frozenset({"timing_unsafe_compare", "weak_random",
                    "secret_indexed_lookup", "pin_mismatch",
                    "sensor_health"})
_THRESHOLD_TRIP = 100
_INSN_CAP = 20000

try:
    _RE_SECRET_NAME = _re.compile(
        r"(key|secret|token|passwd|password|mac\b|tag|digest|hmac|"
        r"signature|sig\b|nonce|salt|priv|seed|credential|auth|session|"
        r"apikey|api_key|otp|pin\b|cipher|plain|ssn|card|cvv)",
        _re.IGNORECASE)
except Exception:
    _RE_SECRET_NAME = None

_SAFE_COMPARE_NAMES = frozenset({"compare_digest", "bytes_eq",
                                 "timingSafeEqual", "FixedTimeEquals",
                                 "secure_compare", "constant_time_compare",
                                 "timing_safe_equal", "ct_equal"})

_EARLY_EXIT_METHODS = frozenset({"startswith", "endswith", "find",
                                 "rfind", "index", "rindex", "count"})

_JUMP_OPS = frozenset({"POP_JUMP_IF_FALSE", "POP_JUMP_IF_TRUE",
                       "POP_JUMP_IF_NONE", "POP_JUMP_IF_NOT_NONE",
                       "POP_JUMP_FORWARD_IF_FALSE",
                       "POP_JUMP_FORWARD_IF_TRUE",
                       "POP_JUMP_FORWARD_IF_NONE",
                       "POP_JUMP_FORWARD_IF_NOT_NONE",
                       "POP_JUMP_BACKWARD_IF_FALSE",
                       "POP_JUMP_BACKWARD_IF_TRUE",
                       "POP_JUMP_BACKWARD_IF_NONE",
                       "POP_JUMP_BACKWARD_IF_NOT_NONE",
                       "JUMP_IF_TRUE_OR_POP", "JUMP_IF_FALSE_OR_POP"})


def _name_is_secret(name):
    try:
        if not isinstance(name, str):
            return False
        if name.endswith(("_BYTES", "_LEN", "_SIZE", "_BITS")):
            return False
        if name.endswith(("Error", "Warning", "Exception")):
            return False
        if _RE_SECRET_NAME is None:
            return False
        return _RE_SECRET_NAME.search(name) is not None
    except Exception:
        return False


def _iter_code(root, _depth=0, _seen=None):
    try:
        if _seen is None:
            _seen = set()
        if _depth > 32:
            return
        if id(root) in _seen:
            return
        _seen.add(id(root))
        yield root
        for c in getattr(root, "co_consts", ()):
            try:
                if hasattr(c, "co_code"):
                    for sub in _iter_code(c, _depth + 1, _seen):
                        yield sub
            except Exception:
                continue
    except Exception:
        return


def _insns(co):
    try:
        import sys as _s
        added = "dis" not in _s.modules
        import dis as _d
        try:
            out = list(_d.get_instructions(co))
        finally:
            try:
                if added and "dis" in _s.modules:
                    del _s.modules["dis"]
            except Exception:
                pass
        if len(out) > _INSN_CAP:
            out = out[:_INSN_CAP]
        return out
    except Exception:
        return []


_LOAD_OPS = frozenset({"LOAD_GLOBAL", "LOAD_NAME", "LOAD_FAST",
                       "LOAD_DEREF", "LOAD_CLOSURE", "LOAD_ATTR",
                       "LOAD_METHOD", "LOAD_FROM_GLOBAL", "LOAD_CLASSDEREF"})


def _tainted_names(insns):
    """SC-4: atama-yayilimli gizli-isim kumesi (taint-lite).

    Research (PyAegis taint-style source→sink): tohum = secret-isimli
    yuklemeler; yayilim: STORE_* hedefi TOS gizliyse kirlenir (toplama/
    f-string/SUBSCR/CALL-sonucu dahil); sabit-atama TEMIZLER
    (untaint). x = secret_key sonrasi x gizlidir (rename kacisi kapali);
    random = 5 sabiti temizdir (SC-2a FP kapali).
    """
    tainted = set()
    try:
        for idx, ins in enumerate(insns):
            try:
                op = ins.opname
                if op not in ("STORE_NAME", "STORE_FAST", "STORE_DEREF",
                              "STORE_ATTR", "STORE_GLOBAL"):
                    continue
                try:
                    target = ins.argval
                except Exception:
                    continue
                if not isinstance(target, str):
                    continue
                lo = idx - 12 if idx - 12 > 0 else 0
                win = insns[lo:idx]
                dirty = False
                cleansed = False
                for w in win:
                    try:
                        wop = w.opname
                        if wop in _LOAD_OPS:
                            try:
                                a = w.argval
                            except Exception:
                                a = None
                            if isinstance(a, str) and (a in tainted or _name_is_secret(a)):
                                dirty = True
                                break
                        elif wop == "LOAD_CONST":
                            cleansed = True
                    except Exception:
                        continue
                if dirty and not cleansed:
                    tainted.add(target)
                elif cleansed and not dirty:
                    tainted.discard(target)
            except Exception:
                continue
    except Exception:
        pass
    return tainted


def _window_has_secret(insns, idx, back=10):
    try:
        lo = idx - back if idx - back > 0 else 0
        try:
            tainted = _tainted_names(insns)
        except Exception:
            tainted = set()
        for ins in insns[lo:idx]:
            try:
                if ins.opname not in _LOAD_OPS:
                    continue
                arg = ins.argval
            except Exception:
                arg = None
            if isinstance(arg, str) and (arg in tainted or _name_is_secret(arg)):
                return True
        return False
    except Exception:
        return False


def _is_percent_format(insns, idx):
    try:
        lo = idx - 4 if idx - 4 > 0 else 0
        for ins in insns[lo:idx]:
            try:
                if ins.opname == "LOAD_CONST" and isinstance(ins.argval, str):
                    if "%" in ins.argval:
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _window_has_none(insns, idx, back=6):
    try:
        lo = idx - back if idx - back > 0 else 0
        for ins in insns[lo:idx]:
            try:
                if ins.opname == "LOAD_CONST" and ins.argval is None:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _jump_is_identity_check(insns, idx, back=6):
    try:
        lo = idx - back if idx - back > 0 else 0
        for ins in insns[lo:idx]:
            try:
                if ins.opname == "COMPARE_OP":
                    if str(ins.argval) in ("is", "is not"):
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _has_build_slice(insns, idx, back=5):
    try:
        lo = idx - back if idx - back > 0 else 0
        for ins in insns[lo:idx]:
            try:
                if ins.opname == "BUILD_SLICE":
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _is_len_of_secret(insns, idx, back=5):
    try:
        lo = idx - back if idx - back > 0 else 0
        win = insns[lo:idx]
        try:
            tainted = _tainted_names(insns)
        except Exception:
            tainted = set()
        saw_len = False
        for ins in win:
            try:
                if (ins.opname in ("LOAD_GLOBAL", "LOAD_NAME",
                                   "LOAD_FROM_GLOBAL")
                        and ins.argval == "len"):
                    saw_len = True
                    continue
                if saw_len and ins.opname not in _LOAD_OPS:
                    if ins.opname not in ("PRECALL", "PUSH_NULL"):
                        saw_len = False
                    continue
                if saw_len:
                    if (isinstance(ins.argval, str)
                            and (ins.argval in tainted or _name_is_secret(ins.argval))):
                        return True
                    saw_len = False
            except Exception:
                continue
        return False
    except Exception:
        return False


def _call_arg_is_secret(insns, idx, back=3):
    try:
        lo = idx - back if idx - back > 0 else 0
        try:
            tainted = _tainted_names(insns)
        except Exception:
            tainted = set()
        for ins in insns[lo:idx]:
            try:
                if ins.opname not in _LOAD_OPS:
                    continue
                if isinstance(ins.argval, str) and (ins.argval in tainted or _name_is_secret(ins.argval)):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _uses_safe_compare(co):
    try:
        names = set(getattr(co, "co_names", ()))
        for n in names:
            if n in _SAFE_COMPARE_NAMES:
                return True
        return False
    except Exception:
        return False


_RANDOM_FUNCS = frozenset({"random", "randint", "randrange",
                            "choice", "choices", "shuffle", "sample",
                            "uniform", "getrandbits", "randbytes"})


def _uses_weak_random(co):
    """SC-2: zayif-RNG kullanimi — isim-degil DAVRANIS-bazli.

    (+) IMPORT_NAME random / from-random-import (gercek modul yukleme).
    (+) random-modul attr cagrisi (secrets-receiver haric).
    (+) __import__('ran'+'dom') / getattr(r,'rand'+'int') dinamik-yollari
        (string-insa + getattr + import-cagrisi korelasyonu).
    (-) KALDIRILDI: `if "random" in names` fallback'i (benign `random = 5`
        global'i STRONG trip'liyordu — SC-2a FP).
    """
    try:
        insns = _insns(co)
        for idx, ins in enumerate(insns):
            try:
                if ins.opname == "IMPORT_NAME" and "random" in str(ins.argval).lower() and "secrets" not in str(ins.argval).lower():
                    return True
                if ins.opname in ("LOAD_METHOD", "LOAD_ATTR"):
                    if ins.argval in _RANDOM_FUNCS:
                        if _receiver_is_secrets(insns, idx):
                            continue
                        return True
            except Exception:
                continue
        try:
            has_dyn_import = False
            has_getattr = False
            has_str_build = False
            for ins in insns:
                try:
                    if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME") and ins.argval in ("__import__", "getattr"):
                        if ins.argval == "__import__":
                            has_dyn_import = True
                        else:
                            has_getattr = True
                    if ins.opname in ("BINARY_OP", "BINARY_ADD", "BUILD_STRING", "FORMAT_VALUE"):
                        has_str_build = True
                    if ins.opname in ("LOAD_METHOD", "LOAD_ATTR") and ins.argval == "join":
                        has_str_build = True
                except Exception:
                    continue
            # Sabit-katlanmis dinamik-yol (derleyici "ran"+"dom"u katlar):
            # getattr-CALL + kisa rand-const (+ optional string-insa).
            if has_dyn_import or has_getattr or has_str_build:
                try:
                    consts = [c for c in getattr(co, "co_consts", ()) or ()
                              if isinstance(c, str) and len(c) <= 16
                              and " " not in c and "\n" not in c]
                except Exception:
                    consts = []
                try:
                    if (has_getattr or has_dyn_import) and any("rand" in c.lower() for c in consts):
                        return True
                except Exception:
                    pass
            if (has_dyn_import or has_getattr) and has_str_build:
                for ins in insns:
                    try:
                        if ins.opname in ("LOAD_METHOD", "LOAD_ATTR") and ins.argval in _RANDOM_FUNCS:
                            return True
                    except Exception:
                        continue
        except Exception:
            pass
        return False
    except Exception:
        return False


def _receiver_is_secrets(insns, idx, back=4):
    try:
        lo = idx - back if idx - back > 0 else 0
        for ins in insns[lo:idx]:
            try:
                if ins.opname in ("LOAD_GLOBAL", "LOAD_NAME",
                                  "LOAD_FROM_GLOBAL"):
                    if ins.argval == "secrets":
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _scan_one(co):
    out = {}
    try:
        insns = _insns(co)
        if not insns:
            return out
        names = set(getattr(co, "co_names", ()))
        has_safe = _uses_safe_compare(co)
        ops = [i.opname for i in insns]
        # STRONG: timing-unsafe compare (== / != / in with secret actor)
        if not has_safe:
            try:
                for idx, ins in enumerate(insns):
                    if ins.opname == "COMPARE_OP":
                        try:
                            cop = str(ins.argval)
                        except Exception:
                            cop = ""
                        if cop in ("is", "is not"):
                            continue
                        if cop not in ("==", "!="):
                            continue
                        if _window_has_none(insns, idx, back=6):
                            continue
                        if _window_has_secret(insns, idx, back=12):
                            out["timing_unsafe_compare"] = True
                            break
                    elif ins.opname == "CONTAINS_OP":
                        if _window_has_secret(insns, idx, back=6):
                            out["timing_unsafe_compare"] = True
                            break
            except Exception:
                pass
        # STRONG: weak RNG source
        try:
            if _uses_weak_random(co):
                out["weak_random"] = True
        except Exception:
            pass
        # STRONG: secret-indexed lookup (BINARY_SUBSCR on secret index)
        try:
            for idx, ins in enumerate(insns):
                if ins.opname != "BINARY_SUBSCR":
                    continue
                if _has_build_slice(insns, idx, back=5):
                    continue
                if _window_has_secret(insns, idx, back=8):
                    out["secret_indexed_lookup"] = True
                    break
        except Exception:
            pass
        # WEAK: secret-conditioned branch
        try:
            for idx, ins in enumerate(insns):
                if ins.opname not in _JUMP_OPS:
                    continue
                try:
                    if "NONE" in ins.opname:
                        continue
                except Exception:
                    pass
                if _jump_is_identity_check(insns, idx, back=6):
                    continue
                if _window_has_secret(insns, idx, back=8):
                    out["secret_branch"] = True
                    break
        except Exception:
            pass
        # WEAK: variable-time arithmetic on secret (%-format disi)
        try:
            for idx, ins in enumerate(insns):
                is_mod = False
                try:
                    if ins.opname in ("BINARY_TRUE_DIVIDE",
                                      "BINARY_FLOOR_DIVIDE",
                                      "BINARY_MODULO"):
                        is_mod = True
                    elif ins.opname == "BINARY_OP":
                        try:
                            is_mod = (int(ins.arg) & 0xFF) in (2, 6, 11)
                        except Exception:
                            is_mod = False
                except Exception:
                    is_mod = False
                if not is_mod:
                    continue
                if _is_percent_format(insns, idx):
                    continue
                if _window_has_secret(insns, idx, back=8):
                    out["variable_time_arith"] = True
                    break
        except Exception:
            pass
        # WEAK: early-exit loop (secret karsilastirmali dongu + return)
        try:
            has_loop = ("FOR_ITER" in ops or "SETUP_LOOP" in ops)
            n_ret = sum(1 for o in ops if o == "RETURN_VALUE")
            if has_loop and n_ret >= 2:
                for idx, ins in enumerate(insns):
                    try:
                        if ins.opname != "COMPARE_OP":
                            continue
                    except Exception:
                        continue
                    if _window_has_secret(insns, idx, back=10):
                        out["early_exit_loop"] = True
                        break
        except Exception:
            pass
        # WEAK: length-oracle shape (len(secret) + False donus)
        try:
            if "len" in names:
                src_consts = [c for c in getattr(co, "co_consts", ())]
                has_false = False
                for c in src_consts:
                    if c is False:
                        has_false = True
                        break
                if has_false and "COMPARE_OP" in ops:
                    for idx, ins in enumerate(insns):
                        try:
                            if ins.opname != "CALL":
                                continue
                        except Exception:
                            continue
                        if _is_len_of_secret(insns, idx, back=5):
                            out["length_oracle_shape"] = True
                            break
        except Exception:
            pass
        # WEAK: early-terminating search method on secret
        try:
            for idx, ins in enumerate(insns):
                try:
                    if ins.opname not in ("LOAD_METHOD", "LOAD_ATTR"):
                        continue
                    if ins.argval not in _EARLY_EXIT_METHODS:
                        continue
                except Exception:
                    continue
                if _window_has_secret(insns, idx, back=10):
                    out["unsafe_search_method"] = True
                    break
        except Exception:
            pass
        # WEAK: builtin pow() with secret exponent (non-constant-time exp)
        try:
            if "pow" in names:
                for idx, ins in enumerate(insns):
                    try:
                        if ins.opname != "CALL":
                            continue
                    except Exception:
                        continue
                    if _window_has_secret(insns, idx, back=14):
                        out["pow_secret_exp"] = True
                        break
        except Exception:
            pass
        # WEAK: oracle shape (unpad + distinct error paths)
        try:
            blob = " ".join(str(n) for n in names).lower()
            if ("unpad" in blob or "depad" in blob or "padding" in blob):
                n_out = (sum(1 for o in ops if o == "RETURN_VALUE")
                         + sum(1 for o in ops if "RAISE" in o))
                if n_out >= 2:
                    out["oracle_shape"] = True
        except Exception:
            pass
        return out
    except Exception:
        return out


def _co_of(f):
    try:
        co = getattr(f, "__code__", None)
        if co is not None and hasattr(co, "co_code"):
            return co
        return None
    except Exception:
        return None


_WATCH = {}
_PINS = {}
_SC_ADMINS = {}
_SC_ADMIN_LOCKED = False
_SC_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _SC_ADMIN_DENIED
    try:
        if _SC_ADMIN_LOCKED:
            with _LOCK:
                _SC_ADMIN_DENIED += 1
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
            _SC_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _sc_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_SC_ADMINS)
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


def _sc_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _SC_ADMIN_DENIED
    try:
        with _LOCK:
            _SC_ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()


def harden():
    """SC-1: tek-cagrilik varsayilan-postur — cagiran modulu muhurler.

    Bos-_WATCH korlugu kapanir: cagiran cercevenin modul global'larindaki
    tum fonksiyonlar watch()+pin() ile izlemeye alinir. Operator boot'ta
    `harden()` cagirir; sonrasi static-yuzey aktiftir.
    """
    out = {}
    try:
        try:
            import sys as _s3
            fr = _s3._getframe(1)
            g = dict(fr.f_globals) if fr is not None else {}
        except Exception:
            g = {}
        sealed = 0
        try:
            import types as _t3
            for _n, _v in g.items():
                try:
                    if isinstance(_v, _t3.FunctionType):
                        ok_w = watch(_v)
                        ok_p = _pin_one(_v)
                        if ok_w and ok_p:
                            sealed += 1
                except Exception:
                    continue
        except Exception:
            pass
        out["sealed"] = sealed
        try:
            with _LOCK:
                out["watched"] = len(_WATCH)
        except Exception:
            out["watched"] = -1
        try:
            out["tripped"] = bool(is_compromised())
        except Exception:
            out["tripped"] = True
    except Exception:
        out = {"sealed": -1, "watched": -1, "tripped": True}
    return out


def _code_fp(co):
    try:
        h = _hashlib.sha256()
        h.update(bytes(getattr(co, "co_code", b"")))
        h.update(repr(tuple(getattr(co, "co_names", ()))).encode())
        return h.hexdigest()
    except Exception:
        return ""


def watch(f):
    try:
        with _LOCK:
            _WATCH[id(f)] = f
        return True
    except Exception:
        return False


def unwatch(f):
    """Izlemeden cikar (YONETIM: kayitli operator sart — korlestirme kapali)."""
    if not _sc_check_admin():
        _sc_deny_admin("unwatch")
    try:
        with _LOCK:
            _WATCH.pop(id(f), None)
        return True
    except Exception:
        return False


def _pin_one(f):
    try:
        co = _co_of(f)
        if co is None:
            return False
        with _LOCK:
            _PINS[id(f)] = (_code_fp(co), f)
        return True
    except Exception:
        return False


def pin(f):
    """Kritik fonksiyonu sabitle (YONETIM: kayitli operator sart).

    Pinleme guven-kokudur: kayitsiz re-pin mesrulastirmasi kapali.
    """
    if not _sc_check_admin():
        _sc_deny_admin("pin")
    return bool(_pin_one(f))


def verify_pins():
    try:
        with _LOCK:
            items = list(_PINS.items())
        for _fid, (fp, f) in items:
            try:
                co = _co_of(f)
                if co is None:
                    return True
                if _code_fp(co) != fp:
                    return True
            except Exception:
                return True
        return False
    except Exception:
        return True


def scan_function(f):
    try:
        co = _co_of(f)
        if co is None:
            return {}
        agg = {}
        for sub in _iter_code(co):
            try:
                r = _scan_one(sub)
                for k, v in r.items():
                    if v:
                        agg[k] = True
            except Exception:
                continue
        return agg
    except Exception:
        return {}


def scan_module(mod):
    try:
        agg = {}
        try:
            mod_name = getattr(mod, "__name__", "")
        except Exception:
            mod_name = ""
        for name in dir(mod):
            if name.startswith("_"):
                continue
            try:
                f = getattr(mod, name)
            except Exception:
                continue
            try:
                if mod_name and getattr(f, "__module__", mod_name) != mod_name:
                    continue
            except Exception:
                continue
            try:
                r = scan_function(f)
                for k, v in r.items():
                    if v:
                        agg[k] = True
            except Exception:
                continue
        return agg
    except Exception:
        return {}


def _check_infra_health() -> bool:
    """SC-3: ALTYAPI sagligi (pin-durumundan BAGIMSIZ).

    dis/hashlib/time/threading calisiyor mu? Bozuk altyapi True (risk);
    pin-uyusmazligi AYRI sinyaldir (asagida). Karisim kaldirildi.
    """
    try:
        import dis as _d
        _ = list(_d.get_instructions(_check_infra_health))
        import hashlib as _h
        _ = _h.sha256(b"x").hexdigest()
        _ = _time.monotonic()
        _ = _threading.RLock()
        return False
    except Exception:
        return True


def _check_sensor_health():
    try:
        if _check_infra_health():
            return {"sensor_health": True}
        return {}
    except Exception:
        return {"sensor_health": True}


def check_all(light_only=False):
    try:
        agg = {}
        with _LOCK:
            targets = list(_WATCH.values())
        for f in targets:
            try:
                r = scan_function(f)
                for k, v in r.items():
                    if v:
                        agg[k] = True
            except Exception:
                continue
        try:
            h = _check_sensor_health()
            for k, v in h.items():
                if v:
                    agg[k] = True
        except Exception:
            agg["sensor_health"] = True
        try:
            if verify_pins():
                agg["pin_mismatch"] = True
        except Exception:
            agg["pin_mismatch"] = True
        return agg
    except Exception:
        return {"sensor_health": True}


def _score_from(results):
    try:
        strong = 0
        weak = 0
        points = 0
        for k, v in results.items():
            if not v:
                continue
            try:
                w = int(WEIGHTS.get(k, 0))
            except Exception:
                w = 0
            points += w
            if k in STRONG:
                strong += 1
            else:
                weak += 1
        tripped = (strong >= 1) or (weak >= 2)
        return (strong, weak, points, tripped)
    except Exception:
        return (0, 0, 0, True)


def score(light_only=False):
    try:
        r = check_all(light_only=light_only)
        s, w, p, _t = _score_from(r)
        return (s, w, p)
    except Exception:
        return (0, 0, 0)


def is_compromised(light_only=False):
    try:
        r = check_all(light_only=light_only)
        _s, _w, _p, tripped = _score_from(r)
        return bool(tripped)
    except Exception:
        return True


def assert_clean(light_only=False):
    try:
        if is_compromised(light_only=light_only):
            _raise()
        return None
    except SideChannelDetected:
        raise
    except Exception:
        _raise()


def guard(func):
    try:
        def _wrapped(*a, **k):
            try:
                assert_clean()
            except Exception:
                _raise()
            return func(*a, **k)
        try:
            _wrapped.__name__ = getattr(func, "__name__", "wrapped")
        except Exception:
            pass
        return _wrapped
    except Exception:
        return func


def status(light_only=False):
    try:
        r = check_all(light_only=light_only)
        s, w, p, t = _score_from(r)
        return {"tripped": bool(t), "strong": s, "weak": w,
                "points": p, "results": dict(r)}
    except Exception:
        return {"tripped": True, "strong": 0, "weak": 0,
                "points": 0, "results": {"sensor_health": True}}


def secure_compare(a, b):
    """Uretim guvenli karsilastirma: hmac.compare_digest sarmalayi."""
    try:
        if isinstance(a, str):
            a = a.encode("utf-8")
        if isinstance(b, str):
            b = b.encode("utf-8")
        if not isinstance(a, (bytes, bytearray, memoryview)):
            return False
        if not isinstance(b, (bytes, bytearray, memoryview)):
            return False
        return bool(_hmac.compare_digest(bytes(a), bytes(b)))
    except Exception:
        return False


def mask_secret(data):
    """Boolean-masking: sirri (maske, maskeli) ciftine boler.

    DPA-vari gozlemlere karsi ara-degerler maskeli tasinir; maske
    secrets-token'dur. Cozum sirasinda birlestirilir. Sessiz:
    hata -> (b"", b"").
    """
    try:
        import os as _os
        if isinstance(data, str):
            data = data.encode("utf-8")
        if not isinstance(data, (bytes, bytearray, memoryview)):
            return (b"", b"")
        raw = bytes(data)
        mask = _os.urandom(len(raw)) if raw else b""
        masked = bytes(x ^ y for x, y in zip(raw, mask))
        return (mask, masked)
    except Exception:
        return (b"", b"")


def unmask_secret(pair):
    """mask_secret ciftini sabit-zamanli karsilastirmaya uygun birlestirir."""
    try:
        mask, masked = pair
        mask = bytes(mask)
        masked = bytes(masked)
        if len(mask) != len(masked):
            return b""
        out = bytearray(len(mask))
        for i in range(len(mask)):
            out[i] = mask[i] ^ masked[i]
        return bytes(out)
    except Exception:
        return b""


def probe_timing(verify_fn, base=b"K" * 512, positions=(0, 128, 256, 384),
                 repeats=3000, threshold=5.0, confirm_runs=2,
                 deadline_s=30.0, max_calls=24000):
    """Runtime gecikme-korelasyon sondasi (SC-5: deadline + cagri-capi).

    base'in ilk k baytini paylasan girdilerle verify_fn'in ortalama
    suresini olcer; eslesen-prefix uzadikca sure anlamli artiyorsa
    (fark > threshold * stderr) True (sizinti) doner. Erken-cikis
    karsilastirmanin klasik imzasidir. TVLA §6 ruhu: karar
    `confirm_runs` bagimsiz olcumde TEKRARLANIRSA verilir.
    SC-5: deadline_s (varsayilan 30sn) + max_calls (24000) asilirsa
    sondaj DURUR (False) — zararli/yavas verify_fn DEFANSIF prob'u
    CPU-DoS'a ceviremez. Sessiz: hata -> False.
    """
    try:
        import os as _os
        try:
            runs = int(confirm_runs)
        except Exception:
            runs = 2
        if runs < 1:
            runs = 1
        if runs > 4:
            runs = 4
        try:
            reps = int(repeats)
        except Exception:
            reps = 3000
        if reps < 10:
            reps = 10
        if reps > 10000:
            reps = 10000
        try:
            deadline = float(deadline_s)
        except Exception:
            deadline = 30.0
        if deadline <= 0:
            deadline = 30.0
        try:
            call_cap = int(max_calls)
        except Exception:
            call_cap = 24000
        if call_cap <= 0:
            call_cap = 24000
        try:
            t_end = _time.monotonic() + deadline
        except Exception:
            t_end = 0.0
        calls = [0]
        expired = [False]

        def _time_left():
            try:
                if t_end <= 0:
                    return True
                return _time.monotonic() < t_end
            except Exception:
                return True

        hits = 0
        for _run in range(runs):
            means = []
            ok = True
            for k in positions:
                if not _time_left() or calls[0] >= call_cap:
                    expired[0] = True
                    ok = False
                    break
                try:
                    prefix = bytes(base[:k])
                    tail_len = len(base) - k
                    samples = []
                    for _i in range(reps):
                        if not _time_left() or calls[0] >= call_cap:
                            expired[0] = True
                            break
                        try:
                            tail = (_os.urandom(tail_len)
                                    if tail_len > 0 else b"")
                            cand = prefix + bytes(tail)
                            if len(cand) != len(base):
                                continue
                            calls[0] += 1
                            t0 = _time.perf_counter()
                            try:
                                verify_fn(cand)
                            except Exception:
                                pass
                            t1 = _time.perf_counter()
                            samples.append(t1 - t0)
                        except Exception:
                            continue
                    if expired[0] or not samples:
                        ok = False
                        break
                    samples.sort()
                    trim = samples[: max(1, int(len(samples) * 0.9))]
                    try:
                        mu = _statistics.fmean(trim)
                        sd = (_statistics.stdev(trim)
                              if len(trim) > 1 else 0.0)
                        se = (sd / (len(trim) ** 0.5)
                              if len(trim) > 0 else 0.0)
                    except Exception:
                        ok = False
                        break
                    means.append((mu, se))
                except Exception:
                    ok = False
                    break
            if expired[0]:
                return False
            if not ok or len(means) < 2:
                continue
            try:
                (first_mu, first_se) = means[0]
                (last_mu, last_se) = means[-1]
                try:
                    sigmas = float(threshold)
                except Exception:
                    sigmas = 5.0
                err = (first_se + last_se) / 2.0
                if err <= 0:
                    continue
                mono_up = all(means[i + 1][0] >= means[i][0]
                              for i in range(len(means) - 1))
                gap = (last_mu - first_mu) / err
                if bool(gap > sigmas and mono_up):
                    hits += 1
            except Exception:
                continue
        return bool(hits >= runs)
    except Exception:
        return False


_WATCHDOGS = []


def _watchdog_loop(stop_ev, interval):
    try:
        while not stop_ev.is_set():
            try:
                if is_compromised():
                    break
            except Exception:
                break
            try:
                stop_ev.wait(interval)
            except Exception:
                break
    except Exception:
        return


def start_watchdog(interval=0.05):
    global _SC_ADMIN_LOCKED
    try:
        with _LOCK:
            _SC_ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        with _LOCK:
            if _WATCHDOGS:
                return True
        stop_ev = _threading.Event()
        try:
            iv = float(interval)
        except Exception:
            iv = 0.05
        t = _threading.Thread(target=_watchdog_loop,
                              args=(stop_ev, iv), daemon=True)
        with _LOCK:
            _WATCHDOGS.append((t, stop_ev))
        t.start()
        return True
    except Exception:
        return False


def stop_all_watchdogs():
    """Tum watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _sc_check_admin():
        _sc_deny_admin("stop_all_watchdogs")
    try:
        with _LOCK:
            items = list(_WATCHDOGS)
            _WATCHDOGS.clear()
        for _t, ev in items:
            try:
                ev.set()
            except Exception:
                continue
        return True
    except Exception:
        return False
