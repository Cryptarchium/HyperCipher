"""anti_oracle: decrypt-oracle (padding/error/length) davranis tespit katmani.

Tehdit modeli (arastirma sentezi - 7x ReSearch):
  - Padding oracle (Vaudenay 2002, ASP.NET CVE-2010-3332, POODLE
    CVE-2014-3566, Lucky13 CVE-2013-0169, python-jose #402, OWASP
    WSTG): CBC+pad cozumu MAC-dogrulamasindan ONCE calisirsa tek bit
    (padding gecerli/gecersiz) tam decrypt+forge primitive'ine donusur.
    Cozum verify-then-decrypt: Encrypt-then-MAC, MAC sabit-zamanli
    (hmac.compare_digest) ONCE, unpad YALNIZCA sonra, TEK generic hata.
  - Bleichenbacher/Marvin (1998, ROBOT, IETF CFRG rsa-guidance-05,
    hexproof 2026): RSA PKCS#1 v1.5 decrypt'te Ok/Err biti = oracle.
    Stopgap implicit-rejection: hata yerine key+ciphertext-turevimli
    deterministik sentetik donus (OpenSSL 3.2+, sad-rsa, RFC 3218
    same-work-same-error). CVE-2026-69247: 4 ayri hata mesaji =
    multi-bit oracle; 2. vaka uzunlugu mesaja gomdu (kritik).
  - Hata-mesaji oracli: farkli basarisizliklara farkli exception/mesaj
    (python-jose: "Invalid padding bytes." vs "Invalid JWE Auth Tag").
    Tek tip hata sart; status-kod/body/sure de normalize edilmeli
    (metin birligi yeterli DEGIL - Lucky13 dersi).
  - Karsilastirma oracli: tag/MAC uzerinde `==` (erken-cikis) ->
    bayt-bayt kurtarma (CWE-208; cozum compare_digest/bytes_eq).
  - Prob-oracle: saldiri GURULTULUDUR (~128 req/bayt; PadBuster,
    padding-oracle PyPI): kisa-surede cok basarisiz-decrypt = IOC.
    Rate-limit + izleme sart.

Kapsam (kardeslerle cakisma yok):
  - anti_side_channel GENEL secret karsilastirma/RNG/dal/index seklini
    tutar; BU modul SADECE tag/MAC/digest karsilastirmasina
    (oracle-baglamli) + verify-UNPAD SIRASINA + hata-ayrilabilirligine
    + implicit-rejection varligina + prob-sayacina bakar.
  - anti_error_leakage GENEL hata-metin sizintisini tutar; BU modul
    decrypt-basarisizliklarinin AYIRT EDILEBILIRLIGINI (bit sayisi,
    uzunluk-gomme, Ok/Err) tutar.
  - anti_key_extraction RAM hijyenini, anti_memory_inspection canli
    bellegi tutar; bu modul decrypt-ORACLE DAVRANISINI tutar.

Sinyal kurallari (FP-guvenli):
  - padding_order_violation (STRONG): unpad-cagrisi var VE (verify
    cagrisi YOK VEYA ilk-unpad ilk-verify'den ONCE). Sabit pattern:
    verify-once-unpad gecer. Dogrulama-sonrasi session-kontrolu
    (verify_session gibi MAC-disi) sayilmaz - verify isim kumesi
    MAC-ozeldir.
  - error_oracle_shape (STRONG): ayni co'da >=2 FARKLI non-yapisal
    hata mesaji + oracle baglami (python-jose #402, CVE-2026-69247:
    "Invalid padding bytes." vs "Invalid JWE Auth Tag" gibi ayrilabilen
    bitler) VEYA (RSA/PKCS1 baglami + >=1 raise + sentinel yok).
    Yapisal kontroller (uzunluk/tip/flag/keyfile/header - public
    bilgi, CFRG: public-girdi kontrolu side-channel-free olmak zorunda
    DEGIL) sayilmaz; AYNI sabit mesajin tekrari tek bit sayilir
    (verify+unpad ayni CipherError mesaji = PASS). Tek generic raise
    + verify-once = PASS (onerilen minimum).
  - length_oracle_shape (STRONG): raise-oncesi pencerede DEGER-GOMEN
    dinamik insa (f-string / .format / %-format) + oracle baglami
    (CVE-2026-69247 2. vaka: uzunlugun mesaja gomulmesi). Sade
    uzunluk-karsilastirmasi + sabit mesaj yapisaldir, sayilmaz.
  - insecure_tag_compare (WEAK): tag/mac/digest uzerinde ==/!= +
    guvenli-compare yok (oracle-baglamli).
  - missing_implicit_rejection (WEAK): RSA baglami + raise +
    sentinel/implicit isimleri yok (Marvin stopgap).
  - oracle_probe_anomaly (WEAK, runtime): 60s penceresinde
    >=100 basarisiz-decrypt (IOC sayaci).
  - Trip >=1 STRONG veya >=2 WEAK. Tek WEAK trip uretmez.

Sinirlar (bilincli tercihler):
  - Secret-tahmini isim-sezgiselidir; isim disi tasiyan sir gorunmez
    (dokumante rezidu; veri-akisi yok).
  - compare_digest/bytes_eq iceren fonksiyon tag-compare sinyalinden
    muaftir (guvenli-oruntu).
  - check_all() yalnizca watch()+pin() kayitlarini tarar.
  - Sarmalayici donus sulari (status-kod/body normalizasyonu), ag-rate-limit
    ve HSM-ici RSA bu modulun disidir; uniform_decrypt TEK-mesaj
    katmanidir, HTTP katmani degildir (dokumante rezidu).

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

import functools as _functools
import hashlib as _hashlib
import hmac as _hmac
import re as _re
import threading as _threading
import time as _time


class OracleDetected(RuntimeError):
    pass


class OracleDecryptError(RuntimeError):
    """uniform_decrypt TEK hata tipi: hangi asama basarisiz - belli degil."""

    pass


def _raise():
    raise OracleDetected("protected")


_LOCK = _threading.RLock()

WEIGHTS = {
    "padding_order_violation": 100,
    "error_oracle_shape": 100,
    "length_oracle_shape": 100,
    "pin_mismatch": 100,
    "sensor_health": 100,
    "insecure_tag_compare": 30,
    "missing_implicit_rejection": 30,
    "oracle_probe_anomaly": 30,
}
STRONG = frozenset({"padding_order_violation", "error_oracle_shape",
                    "length_oracle_shape", "pin_mismatch",
                    "sensor_health"})
_THRESHOLD_TRIP = 100
_INSN_CAP = 20000
_PROBE_WINDOW_S = 60.0
_PROBE_THRESHOLD = 100

try:
    _RE_ORACLE_CTX = _re.compile(
        r"(decrypt|unpad|depad|unseal|decode_token|open_box|box_open|"
        r"secretbox|verify_tag|check_mac|deobfuscat|depadd)",
        _re.IGNORECASE)
except Exception:
    _RE_ORACLE_CTX = None

try:
    _RE_RSA_CTX = _re.compile(
        r"(rsa|pkcs1|pkcs_1|private_decrypt|oaep|bleichenbacher|emsa|"
        r"rsadp|decrypt_rsa)",
        _re.IGNORECASE)
except Exception:
    _RE_RSA_CTX = None

try:
    _RE_TAG_NAME = _re.compile(
        r"((?<![A-Za-z])tag(?![A-Za-z])|mac\b|hmac|digest|signature|"
        r"sig\b|auth_tag|authtag|expected_(tag|mac|digest|signature)|"
        r"received_tag|given_tag)",
        _re.IGNORECASE)
except Exception:
    _RE_TAG_NAME = None

_UNPAD_NAMES = frozenset({"unpad", "_unpad", "_unpad_iso7816",
                          "strip_padding", "remove_padding", "unpadder",
                          "strip_pad", "remove_pad", "check_padding"})
_VERIFY_NAMES = frozenset({"compare_digest", "bytes_eq", "check_mac",
                           "verify_tag", "verify_mac", "check_tag",
                           "verify_hmac", "authenticate_tag",
                           "_verify_tag", "_check_mac",
                           "constant_time_compare", "secure_compare",
                           "timing_safe_equal", "ct_equal"})
_SAFE_COMPARE_NAMES = frozenset({"compare_digest", "bytes_eq",
                                 "timingSafeEqual", "FixedTimeEquals",
                                 "secure_compare", "constant_time_compare",
                                 "timing_safe_equal", "ct_equal"})
_SENTINEL_NAMES = frozenset({"sentinel", "implicit_reject",
                             "implicit_rejection", "rejected_sentinel",
                             "synthetic", "uniform_decrypt", "single_error",
                             "implicit", "synthetic_message"})
_CALL_OPS = frozenset({"CALL", "CALL_FUNCTION", "CALL_METHOD",
                       "CALL_FUNCTION_EX", "CALL_METHOD_KW", "PRECALL",
                       "CALL_KW"})
_LOAD_OPS = frozenset({"LOAD_METHOD", "LOAD_ATTR", "LOAD_GLOBAL",
                       "LOAD_NAME", "LOAD_DEREF", "LOAD_CLASSDEREF"})


def _name_in(text, rx):
    try:
        if not isinstance(text, str) or rx is None:
            return False
        return rx.search(text) is not None
    except Exception:
        return False


def _iter_code(root, _depth=0, _seen=None):
    if _seen is None:
        _seen = set()
    try:
        if root is None or id(root) in _seen or _depth > 32:
            return
        _seen.add(id(root))
        yield root
        consts = getattr(root, "co_consts", ()) or ()
        for c in consts:
            try:
                import types as _t
                if isinstance(c, _t.CodeType):
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
    except Exception:
        return []
    if len(out) > _INSN_CAP:
        return out[:_INSN_CAP]
    return out


def _window_has_tag(insns, idx, back=10):
    try:
        lo = idx - back if idx - back > 0 else 0
        for j in range(lo, idx + 1):
            try:
                a = insns[j].argval
            except Exception:
                continue
            if isinstance(a, str) and _name_in(a, _RE_TAG_NAME):
                return True
        return False
    except Exception:
        return False


def _operand_window_has_tag(insns, idx, back=4):
    """O-2/O-5: karsilastirilan OPERAND'larda tag-isi var mi? (dar-pencere).

    Research (VNX-CRYPTO-008 + hmac docs): tehlike ==/!='in NEYI
    karsilastirdigidir — operand tag/mac/digest/signature tasiyorsa
    + guvenli-compare yoksa sinyal, fonksiyon ADI ne olursa olsun.
    Dar operand-penceresi (4): `import hmac` uzaktaki masum `==`'i
    kirletmez (O-5 FP kapanir); rename kacisi kapanir (O-2).
    """
    try:
        lo = idx - back if idx - back > 0 else 0
        for j in range(lo, idx + 1):
            try:
                ins = insns[j]
                if ins.opname not in _LOAD_OPS:
                    continue
                a = ins.argval
            except Exception:
                continue
            if isinstance(a, str) and _name_in(a, _RE_TAG_NAME):
                return True
        return False
    except Exception:
        return False


def _window_has_tag_call(insns, idx, back=10):
    """Operand disinda tag-ureten cagri (hmac.new/digest/hexdigest) kaniti."""
    try:
        lo = idx - back if idx - back > 0 else 0
        for j in range(lo, idx + 1):
            try:
                ins = insns[j]
                if ins.opname not in _LOAD_OPS:
                    continue
                a = ins.argval
            except Exception:
                continue
            if not isinstance(a, str):
                continue
            try:
                low = a.lower()
            except Exception:
                continue
            if low in ("digest", "hexdigest", "new", "hmac", "sign",
                       "signature", "mac", "tag", "verify", "authenticate"):
                return True
        return False
    except Exception:
        return False


def _compare_operands_dynamic(insns, idx, back=4):
    """Karsilastirmanin iki yani da dinamik mi (sabit-vs-degisken degil)?"""
    try:
        lo = idx - back if idx - back > 0 else 0
        loads = 0
        consts = 0
        for j in range(lo, idx):
            try:
                op = insns[j].opname
                if op in ("LOAD_CONST",):
                    consts += 1
                elif op in _LOAD_OPS:
                    loads += 1
            except Exception:
                continue
        return loads >= 2 and consts == 0
    except Exception:
        return False


def _window_has_none(insns, idx, back=6):
    try:
        lo = idx - back if idx - back > 0 else 0
        for j in range(lo, idx):
            try:
                if insns[j].opname in ("LOAD_CONST",):
                    if insns[j].argval is None:
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _jump_is_identity_check(insns, idx, back=6):
    try:
        lo = idx - back if idx - back > 0 else 0
        for j in range(lo, idx):
            try:
                if insns[j].opname in ("IS_OP", "COMPARE_OP"):
                    av = insns[j].argval
                    if av == "is" or av == 8 or av == 9:
                        return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _call_names(insns):
    """LOAD_* (isim) + CALL* zincirindeki cagri isimleri + indexleri."""
    found = []
    try:
        for i, ins in enumerate(insns):
            try:
                if ins.opname not in _LOAD_OPS:
                    continue
                nm = ins.argval
                if not isinstance(nm, str):
                    continue
                for k in range(i + 1, min(i + 8, len(insns))):
                    try:
                        if insns[k].opname in _CALL_OPS:
                            found.append((nm, i))
                            break
                        if insns[k].opname not in (
                                "LOAD_FAST", "LOAD_CONST", "LOAD_DEREF",
                                "LOAD_GLOBAL", "LOAD_ATTR", "LOAD_METHOD",
                                "LOAD_NAME", "DUP_TOP", "PRECALL",
                                "CACHE", "NOP"):
                            break
                    except Exception:
                        break
            except Exception:
                continue
    except Exception:
        pass
    return found


def _uses_safe_compare(co):
    try:
        names = set(getattr(co, "co_names", ()) or ())
        for n in list(names) + list(getattr(co, "co_varnames", ()) or ()):
            try:
                if isinstance(n, str) and n in _SAFE_COMPARE_NAMES:
                    return True
            except Exception:
                continue
        for sub in _iter_code(co):
            try:
                for n in getattr(sub, "co_names", ()) or ():
                    if isinstance(n, str) and n in _SAFE_COMPARE_NAMES:
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _has_sentinel(co):
    try:
        for sub in _iter_code(co):
            try:
                for n in (list(getattr(sub, "co_names", ()) or ())
                          + list(getattr(sub, "co_varnames", ()) or ())):
                    if isinstance(n, str) and n in _SENTINEL_NAMES:
                        return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _is_oracle_context(co, calls):
    try:
        if _name_in(co.co_name, _RE_ORACLE_CTX):
            return True
        for nm, _ in calls:
            if _name_in(nm, _RE_ORACLE_CTX):
                return True
            if nm in _UNPAD_NAMES or nm in _VERIFY_NAMES:
                return True
        return False
    except Exception:
        return False


def _is_rsa_context(co, calls):
    try:
        blob = (getattr(co, "co_name", "") + " "
                + " ".join(getattr(co, "co_names", ()) or ()))
        if _name_in(blob, _RE_RSA_CTX):
            return True
        for nm, _ in calls:
            if _name_in(nm, _RE_RSA_CTX):
                return True
        return False
    except Exception:
        return False


_STRUCTURAL_ERR_WORDS = frozenset({"kisa", "short", "uzun", "length",
    "boyut", "size", "flag", "keyfile", "header", "version", "tip",
    "type", "bos", "empty", "aralik", "range", "sinir", "bound",
    "gecersiz-arg", "invalid-arg", "form", "eksik", "missing", "saha",
    "field"})


def _raise_has_dynamic_message(insns, site, back=12):
    """O-3 hassasiyeti: argumansiz raise (CALL 0) MESAJ TASIMAZ — sayilmaz.

    `raise ValueError` (CALL oparg 0) uniform-bos pattern'dir; `raise
    ValueError(msg)` (oparg>=1) veya deger-re-raise (CALL'suz `raise err`)
    dinamik mesaj tasir. Bleichenbacher dersi: ayirt-edilebilir tek bit
    oracle'dir, bos raise degil.
    """
    try:
        lo = site - back if site - back > 0 else 0
        for j in range(site - 1, lo - 1, -1):
            try:
                op = insns[j].opname
                if op in ("CALL", "CALL_FUNCTION", "CALL_METHOD",
                          "CALL_FUNCTION_EX", "CALL_KW"):
                    try:
                        return int(insns[j].argval) >= 1
                    except Exception:
                        return True
            except Exception:
                continue
        return True
    except Exception:
        return True


def _raise_message_const(insns, site, back=12):
    """Raise-oncesi penceredeki sabit hata mesajini cikar (yoksa None)."""
    try:
        lo = site - back if site - back > 0 else 0
        for j in range(site - 1, lo - 1, -1):
            try:
                if (insns[j].opname == "LOAD_CONST"
                        and isinstance(insns[j].argval, str)
                        and insns[j].argval):
                    return insns[j].argval
            except Exception:
                continue
        return None
    except Exception:
        return None


def _is_structural_msg(msg):
    try:
        if not isinstance(msg, str):
            return False
        low = msg.lower()
        for w in _STRUCTURAL_ERR_WORDS:
            if w in low:
                return True
        return False
    except Exception:
        return False


def _raise_sites(insns):
    sites = []
    try:
        for i, ins in enumerate(insns):
            try:
                if ins.opname == "RAISE_VARARGS":
                    if ins.argval == 0:
                        continue
                    sites.append(i)
            except Exception:
                continue
    except Exception:
        pass
    return sites


def _raise_leaks_length(insns, site, back=14):
    try:
        lo = site - back if site - back > 0 else 0
        window = insns[lo:site]
        for ins in window:
            try:
                if ins.opname == "FORMAT_VALUE":
                    return True
                if ins.opname == "BUILD_STRING":
                    return True
                if ins.opname in _LOAD_OPS and ins.argval == "format":
                    return True
            except Exception:
                continue
        # %-format: BINARY_OP + ayni pencerede '%' iceren sabit. Sade
        # aritmetik (toplama/bit-op) sayilmaz - aksi halde her uzunluk
        # kontrolu yanlis-pozitif uretir.
        try:
            has_binop = any(w.opname in ("BINARY_OP", "BINARY_MODULO")
                            for w in window)
            if has_binop:
                for w in window:
                    try:
                        if (w.opname == "LOAD_CONST"
                                and isinstance(w.argval, str)
                                and "%" in w.argval):
                            return True
                    except Exception:
                        continue
        except Exception:
            pass
        return False
    except Exception:
        return False


def _scan_one(co):
    res = {"padding_order_violation": False, "error_oracle_shape": False,
           "length_oracle_shape": False, "insecure_tag_compare": False,
           "missing_implicit_rejection": False}
    try:
        insns = _insns(co)
        if not insns:
            return res
        calls = _call_names(insns)
        ctx = _is_oracle_context(co, calls)
        rsa = _is_rsa_context(co, calls)
        if not ctx and not rsa:
            return res
        unpad_idx = [i for nm, i in calls if nm in _UNPAD_NAMES]
        verify_idx = [i for nm, i in calls if nm in _VERIFY_NAMES]
        # SIRA: unpad-once-verify -> VIOLATION (guclu).
        if unpad_idx and (not verify_idx
                          or min(unpad_idx) < min(verify_idx)):
            res["padding_order_violation"] = True
        sites = _raise_sites(insns)
        n_raise = len(sites)
        has_sentinel = _has_sentinel(co)
        # HATA-BITI: >=2 FARKLI non-yapisal mesaj (multi-bit oracle)
        # VEYA RSA+raise+sentinel-yok. Ayni sabit mesajin tekrari ve
        # yapisal (public) kontroller sayilmaz.
        try:
            distinct = set()
            unknowns = 0
            for s in sites:
                m = _raise_message_const(insns, s)
                if m is None:
                    try:
                        if _raise_has_dynamic_message(insns, s):
                            unknowns += 1
                    except Exception:
                        unknowns += 1
                elif not _is_structural_msg(m):
                    distinct.add(m)
            # O-3: tek DINAMIK mesaj bile bittir (Bleichenbacher Ok/Err dersi:
            # ayirt-edilebilir tek bit = oracle). Tek SABIT nonstructural
            # mesaj (onerilen uniform pattern) PASS kalir.
            multi_bit = len(distinct) >= 2 or unknowns >= 1 or (
                len(distinct) >= 1 and unknowns >= 1)
        except Exception:
            multi_bit = n_raise >= 2
        if multi_bit:
            res["error_oracle_shape"] = True
        elif rsa and n_raise >= 1 and not has_sentinel:
            res["error_oracle_shape"] = True
            res["missing_implicit_rejection"] = True
        # UZUNLUK-GOMME: raise-oncesi format/len penceresi (O-7: yapisal
        # mesaj muaf — public length check FP degil).
        for s in sites:
            try:
                if _raise_leaks_length(insns, s):
                    try:
                        _m = _raise_message_const(insns, s)
                    except Exception:
                        _m = None
                    if _m is not None and _is_structural_msg(_m):
                        continue
                    res["length_oracle_shape"] = True
                    break
            except Exception:
                continue
        # TAG-KARSILASTIRMA (O-2/O-5): DAVRANIS-bazli, isim-bagimsiz.
        # Kural: ==/!= + (operand'da tag-isi VEYA tag-ureten cagri) +
        # iki-yan-dinamik + guvenli-compare yok. ctx-gate YOK (rename
        # kacisi kapali); dar-pencere hmac-import FP'sini oldurur.
        if not _uses_safe_compare(co):
            try:
                for i, ins in enumerate(insns):
                    try:
                        if ins.opname != "COMPARE_OP":
                            continue
                        if ins.argval not in ("==", "!=", 2, 3):
                            continue
                        if _window_has_none(insns, i, back=3):
                            continue
                        if _jump_is_identity_check(insns, i):
                            continue
                        if not (_operand_window_has_tag(insns, i)
                                or _window_has_tag_call(insns, i)):
                            continue
                        if not _compare_operands_dynamic(insns, i):
                            if not _window_has_tag_call(insns, i):
                                continue
                        res["insecure_tag_compare"] = True
                        break
                    except Exception:
                        continue
            except Exception:
                pass
        return res
    except Exception:
        return res


def _co_of(f):
    """O-6: cok-seviyeli unwrap (partial/sarili/staticmethod/classmethod).

    functools.partial.func, __wrapped__ zinciri, __func__ (bound method),
    classmethod/staticmethod.__func__ — derinlik-cap 8, dongu-korumali.
    Tek-seviye kacis (sarili decrypt) kapanir.
    """
    try:
        import types as _t
        seen = set()
        cur = f
        for _ in range(8):
            try:
                if cur is None or id(cur) in seen:
                    break
                seen.add(id(cur))
                if isinstance(cur, _t.FunctionType):
                    return cur.__code__
                if isinstance(cur, _t.CodeType):
                    return cur
                if isinstance(cur, _functools.partial):
                    cur = cur.func
                    continue
                if isinstance(cur, (staticmethod, classmethod)):
                    try:
                        cur = cur.__func__
                    except Exception:
                        break
                    continue
                if isinstance(cur, _t.MethodType):
                    try:
                        cur = cur.__func__
                    except Exception:
                        break
                    continue
                nxt = getattr(cur, "__wrapped__", None)
                if isinstance(nxt, (_t.FunctionType, _t.MethodType,
                                    _functools.partial, staticmethod,
                                    classmethod)):
                    cur = nxt
                    continue
                fn = getattr(cur, "func", None)
                if isinstance(fn, (_t.FunctionType, _t.MethodType,
                                   _functools.partial)):
                    cur = fn
                    continue
                try:
                    fn2 = getattr(cur, "__func__", None)
                    if isinstance(fn2, (_t.FunctionType, _t.MethodType)):
                        cur = fn2
                        continue
                except Exception:
                    pass
                break
            except Exception:
                break
    except Exception:
        pass
    return None


def _code_fp(co):
    try:
        parts = [bytes(getattr(co, "co_code", b"") or b"")]
        consts = []
        for sub in _iter_code(co):
            try:
                for c in getattr(sub, "co_consts", ()) or ():
                    if isinstance(c, (bytes, str, int, float)):
                        consts.append(repr(c).encode("utf8", "ignore"))
                for n in getattr(sub, "co_names", ()) or ():
                    consts.append(str(n).encode("utf8", "ignore"))
            except Exception:
                continue
        h = _hashlib.sha256()
        h.update(parts[0])
        for c in sorted(consts):
            h.update(c)
        return h.hexdigest()
    except Exception:
        return ""


_WATCHED = {}
_PINS = {}
_FAIL_TS = []
_SENSOR = {"watchdog": False, "last_ok": 0.0}
_ALERT_HOOK = None
_ALERTED = False


def watch(f):
    try:
        co = _co_of(f)
        if co is None:
            return False
        with _LOCK:
            _WATCHED[getattr(f, "__qualname__", repr(f))] = f
        return True
    except Exception:
        return False


def unwatch(f):
    """Izlemeden cikar (YONETIM: kayitli operator sart — korlestirme kapali)."""
    if not _oracle_check_admin():
        _oracle_deny_admin("unwatch")
    try:
        with _LOCK:
            return _WATCHED.pop(
                getattr(f, "__qualname__", repr(f)), None) is not None
    except Exception:
        return False


def pin(f):
    try:
        co = _co_of(f)
        if co is None:
            return False
        with _LOCK:
            _PINS[getattr(f, "__qualname__", repr(f))] = _code_fp(co)
        return True
    except Exception:
        return False


def verify_pins():
    bad = {}
    try:
        with _LOCK:
            items = list(_PINS.items())
            watched = dict(_WATCHED)
        for qn, fp in items:
            try:
                f = watched.get(qn)
                if f is None:
                    bad[qn] = True
                    continue
                co = _co_of(f)
                if co is None or _code_fp(co) != fp:
                    bad[qn] = True
            except Exception:
                bad[qn] = True
    except Exception:
        pass
    return bad


def scan_function(f):
    empty = {"padding_order_violation": False, "error_oracle_shape": False,
             "length_oracle_shape": False, "insecure_tag_compare": False,
             "missing_implicit_rejection": False, "pin_mismatch": False,
             "oracle_probe_anomaly": False}
    try:
        co = _co_of(f)
        if co is None:
            return dict(empty)
        out = dict(empty)
        try:
            one = _scan_one(co)
            for k in one:
                out[k] = bool(one[k])
        except Exception:
            pass
        try:
            qn = getattr(f, "__qualname__", None)
            with _LOCK:
                fp = _PINS.get(qn) if qn else None
            if fp is not None and _code_fp(co) != fp:
                out["pin_mismatch"] = True
        except Exception:
            pass
        try:
            if _probe_anomaly():
                out["oracle_probe_anomaly"] = True
        except Exception:
            pass
        return out
    except Exception:
        return dict(empty)


def scan_module(mod):
    agg = {"padding_order_violation": False, "error_oracle_shape": False,
           "length_oracle_shape": False, "insecure_tag_compare": False,
           "missing_implicit_rejection": False, "pin_mismatch": False,
           "oracle_probe_anomaly": False}
    try:
        name = getattr(mod, "__name__", "")
        for attr in dir(mod):
            try:
                f = getattr(mod, attr)
                co = _co_of(f)
                if co is None:
                    continue
                if getattr(f, "__module__", None) != name:
                    continue
                one = scan_function(f)
                for k in agg:
                    if one.get(k):
                        agg[k] = True
            except Exception:
                continue
    except Exception:
        pass
    return agg


def _check_sensor_health():
    try:
        import sys as _s
        if getattr(_s, "gettrace", None) and _s.gettrace() is not None:
            return True
        mods = set(getattr(_s, "modules", {}) or {})
        for bad in ("pyinstrument", "cProfile", "profile", "pstats",
                    "yappi", "line_profiler", "memory_profiler"):
            if bad in mods:
                return True
        return False
    except Exception:
        return False


def _probe_anomaly():
    try:
        now = _time.monotonic()
        with _LOCK:
            while _FAIL_TS and now - _FAIL_TS[0] > _PROBE_WINDOW_S:
                _FAIL_TS.pop(0)
            hot = len(_FAIL_TS) >= _PROBE_THRESHOLD
            global _ALERTED
            if hot and not _ALERTED:
                _ALERTED = True
                hook = _ALERT_HOOK
                count = len(_FAIL_TS)
            elif not hot:
                _ALERTED = False
                hook = None
                count = 0
            else:
                hook = None
                count = 0
        if hook is not None:
            try:
                hook(count)
            except Exception:
                pass
        return hot
    except Exception:
        return False


def set_alert_hook(fn):
    """IOC atesleyici (YONETIM: None-disarm kayitli operator sart).

    Varsayilan sessiz (None): modul tek basina hicbir dis etkiye sahip
    degildir. SOC/entegrasyon isteyen hook kurar; hook hatasi yutulur
    (tespit asla kirilmaz). Skorlamayi etkilemez.
    """
    if fn is None and not _oracle_check_admin():
        _oracle_deny_admin("set_alert_hook")
    try:
        global _ALERT_HOOK
        with _LOCK:
            if fn is None:
                _ALERT_HOOK = None
                return True
            if not callable(fn):
                return False
            _ALERT_HOOK = fn
            return True
    except Exception:
        return False


def note_decrypt_failure():
    """Basarisiz-decrypt IOC sayacina isaret koy (sessiz, sayac)."""
    try:
        with _LOCK:
            _FAIL_TS.append(_time.monotonic())
            while (_FAIL_TS
                   and _FAIL_TS[0] < _FAIL_TS[-1] - _PROBE_WINDOW_S):
                _FAIL_TS.pop(0)
    except Exception:
        pass


def failure_count():
    try:
        now = _time.monotonic()
        with _LOCK:
            while _FAIL_TS and now - _FAIL_TS[0] > _PROBE_WINDOW_S:
                _FAIL_TS.pop(0)
            return len(_FAIL_TS)
    except Exception:
        return 0


def reset_counters():
    """IOC sayacini sifirla (YONETIM: kayitli operator sart)."""
    if not _oracle_check_admin():
        _oracle_deny_admin("reset_counters")
    try:
        with _LOCK:
            _FAIL_TS.clear()
        return True
    except Exception:
        return False


def uniform_decrypt(fn):
    """Decrypt-fonksiyonunu TEK-mesaj sarmalayiciya al.

    Tum basarisizliklar OracleDecryptError("decryption failed") olur:
    padding-etiketi/uzunluk/anahtar ayrilamaz (same-error). Her
    basarisizlik IOC sayacini artirir. HTTP status/body normalizasyonu
    cagiran katmanin isidir (dokumante).
    """
    @_functools.wraps(fn)
    def _w(*a, **k):
        try:
            return fn(*a, **k)
        except OracleDecryptError:
            note_decrypt_failure()
            raise
        except Exception:
            note_decrypt_failure()
            raise OracleDecryptError("decryption failed")
    return _w


def rejected_sentinel(key, ciphertext, length):
    """Marvin-workaround ruhu: deterministik sentetik mesaj.

    key + ciphertext'ten HMAC-SHA256 sayac zinciriyle `length` bayt
    uretir (NIST SP 800-108 sayac-modu iskeleti: K(i) = PRF(KIN,
    [i] || Label || 0x00 || Context || [L]); sayac 1'den baslar,
    L = istenen toplam bayt. ayni (key, ciphertext) her zaman ayni
    sentetigi verir (replay ogrenemez), farkli girdi farkli sentetik
    verir. Uyari: DONDURULEN uzunluk bekleyen cagiran icin uzunluk
    sabittir; genel API'de uzunluk-gizleme garanti EDILMEZ
    (dokumante sinir).
    """
    try:
        if not isinstance(key, (bytes, bytearray)) or not key:
            raise OracleDecryptError("decryption failed")
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise OracleDecryptError("decryption failed")
        n = int(length)
        if n < 0 or n > 1 << 20:
            raise OracleDecryptError("decryption failed")
        out = bytearray()
        seed = b"implicit-reject-v1\x00" + bytes(ciphertext)
        total = n.to_bytes(4, "big")
        ctr = 1
        while len(out) < n:
            msg = ctr.to_bytes(4, "big") + seed + total
            out.extend(_hmac.new(bytes(key), msg,
                                 _hashlib.sha256).digest())
            ctr += 1
            if ctr > 1 << 16:
                break
        return bytes(out[:n])
    except OracleDecryptError:
        raise
    except Exception:
        raise OracleDecryptError("decryption failed")


def check_all(light_only=False):
    res = {"padding_order_violation": False, "error_oracle_shape": False,
           "length_oracle_shape": False, "insecure_tag_compare": False,
           "missing_implicit_rejection": False, "pin_mismatch": False,
           "oracle_probe_anomaly": False, "sensor_health": False}
    try:
        with _LOCK:
            fns = list(_WATCHED.values())
        for f in fns:
            try:
                one = scan_function(f)
                for k in res:
                    if k in one and one[k]:
                        res[k] = True
            except Exception:
                continue
        try:
            if verify_pins():
                res["pin_mismatch"] = True
        except Exception:
            pass
        try:
            if _check_sensor_health():
                res["sensor_health"] = True
        except Exception:
            pass
        try:
            if _probe_anomaly():
                res["oracle_probe_anomaly"] = True
        except Exception:
            pass
    except Exception:
        pass
    return res


def _score_from(results):
    pts = 0
    strong = 0
    weak = 0
    try:
        for k, v in results.items():
            if not v:
                continue
            w = int(WEIGHTS.get(k, 0))
            pts += w
            if k in STRONG:
                strong += 1
            else:
                weak += 1
    except Exception:
        pass
    return pts, strong, weak


def score(light_only=False):
    try:
        r = check_all(light_only=light_only)
        pts, strong, weak = _score_from(r)
        return pts, strong, weak
    except Exception:
        return 100, 1, 0


def is_compromised(light_only=False):
    try:
        pts, strong, weak = score(light_only=light_only)
        if strong >= 1:
            return True
        if weak >= 2:
            return True
        return pts >= _THRESHOLD_TRIP
    except Exception:
        return True


def assert_clean(light_only=False):
    try:
        if is_compromised(light_only=light_only):
            _raise()
    except OracleDetected:
        raise
    except Exception:
        _raise()


def guard(func):
    @_functools.wraps(func)
    def _w(*a, **k):
        assert_clean()
        try:
            r = func(*a, **k)
        except OracleDetected:
            raise
        except Exception as e:
            try:
                if is_compromised():
                    raise OracleDetected("protected") from e
            except OracleDetected:
                raise
            except Exception:
                pass
            raise
        assert_clean()
        return r
    return _w


def status(light_only=False):
    try:
        r = check_all(light_only=light_only)
        pts, strong, weak = _score_from(r)
        return {"tripped": bool(is_compromised(light_only=light_only)),
                "strong": strong, "weak": weak, "points": pts,
                "results": r,
                "probe_failures_60s": failure_count()}
    except Exception:
        return {"tripped": True, "strong": 1, "weak": 0, "points": 100,
                "results": {}, "probe_failures_60s": 0}


_ORACLE_ADMINS = {}
_ORACLE_ADMIN_LOCKED = False
_ORACLE_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ORACLE_ADMIN_DENIED
    try:
        if _ORACLE_ADMIN_LOCKED:
            with _LOCK:
                _ORACLE_ADMIN_DENIED += 1
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
            _ORACLE_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _oracle_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_ORACLE_ADMINS)
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


def _oracle_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _ORACLE_ADMIN_DENIED
    try:
        with _LOCK:
            _ORACLE_ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()


def harden():
    """O-1: tek-cagrilik varsayilan-postur — cagiran modulu muhurler.

    Bos-_WATCHED korlugu kapanir: harden() cagiran cercevenin modul
    global'larindaki tum fonksiyonlari watch()+pin() ile izlemeye alir.
    Operator boot'ta `harden()` cagirir; sonrasi static-yuzey aktiftir.
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
                        if watch(_v) and pin(_v):
                            sealed += 1
                except Exception:
                    continue
        except Exception:
            pass
        out["sealed"] = sealed
        try:
            with _LOCK:
                out["watched"] = len(_WATCHED)
        except Exception:
            out["watched"] = -1
        try:
            out["tripped"] = bool(is_compromised())
        except Exception:
            out["tripped"] = True
    except Exception:
        out = {"sealed": -1, "watched": -1, "tripped": True}
    return out


def _watchdog_loop(stop_ev, interval):
    try:
        while not stop_ev.wait(interval):
            try:
                bad = bool(is_compromised())
                with _LOCK:
                    _SENSOR["watchdog"] = True
                    if not bad:
                        _SENSOR["last_ok"] = _time.monotonic()
            except Exception:
                continue
    except Exception:
        pass


def start_watchdog(interval=0.05):
    global _ORACLE_ADMIN_LOCKED
    try:
        with _LOCK:
            _ORACLE_ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        iv = float(interval)
        if iv < 0.005:
            iv = 0.005
        if iv > 5.0:
            iv = 5.0
    except Exception:
        iv = 0.05
    try:
        import threading as _t
        stop_ev = _t.Event()
        th = _t.Thread(target=_watchdog_loop, args=(stop_ev, iv),
                       daemon=True)
        th.start()
        with _LOCK:
            _SENSOR["watchdog"] = True
        return stop_ev, th
    except Exception:
        return None, None


def stop_all_watchdogs():
    """Watchdog bayragini indir (YONETIM: kayitli operator sart)."""
    if not _oracle_check_admin():
        _oracle_deny_admin("stop_all_watchdogs")
    try:
        with _LOCK:
            _SENSOR["watchdog"] = False
            _SENSOR["last_ok"] = 0.0
        return True
    except Exception:
        return False
