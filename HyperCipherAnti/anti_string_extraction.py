"""anti_string_extraction: strings-tablosu sizinti tespit katmani.

Tehdit modeli (strings cikarma saldirilari):
  - Duz-metin sir: co_consts icinde `strings -n 4` / memstrings /
    String-Analyzer ile dogrudan yakalanan yapisal sirlar (AWS anahtari,
    GitHub PAT, Slack/Discord token, JWT, PEM basligi, Bearer, password=
    atamasi, Luhn-gecerli kart numarasi). Kaynak-grep'ten kacan hex/bytes
    gomuleri ascii-cozumle ile yakalanir.
  - Kodlanmis sir: base64/hex gorunumlu uzun sabitlerin cozumu okunabilir
    metin + (gizli desen | yuksek entropi | ag gostergesi) icerir
    (pyobfus raporu: base64/XOR/Fernet tek basina guvenlik DEGIL; AST
    duzeyinde sifrelenmemis literal co_consts'ta durur -> bu modul o
    durusu TESPIT eder, sifreleme yapmaz).
  - Yuksek-entropi string: 48+ karakter, bosluksuz, >4.5 bit/karakter
    (Stringy/strung "entropy" bandi; packed/sifreli blob suphesi).
  - Ag gostergesi (WEAK): http(s) URL, gecerli IPv4 (0-255 oktet
    dogrulamali), .onion. Tek basina trip uretmez.
  - Supheli anahtar-sozcuk (WEAK): acikca saldirgan-araci sozlugu
    (mimikatz/lsass/meterpreter/shellcode/...). Jenerik dev kelimeleri
    (password, secret, token tek basina) BURADA DEGIL: onlar yapisal
    desenle (password=deger) plaintext_secret'te aranir.
  - String yogunlugu (WEAK): tek fonksiyon govdesinde 48+ karakterli
    6+ bosluksuz sabit -> toplu strings-dump yuzeyi.
  - Charcode-insa (WEAK): 16+ tamsayili sabit demeti (%90 baski
    karakteri) -> chr() zinciriyle strings'ten kacis suphesi; tek
    basina trip uretmez.
  - Pin: izlenen fonksiyonun string-tablosu parmak-izlenir (co_code +
    sirali string sabitleri); __code__ takasi / const-duzenleme yakalanir.

Kapsam (kardeslerle cakisma yok):
  - anti_constant_analysis sabit-tur/entropi/OOB/pin-genel'i tutar;
    BU modul STRINGS YUZEYINI inceler (yapisal sir desenleri, cozumlu
    yuk, ag gostergeleri, yogunluk, string-pini).
  - anti_key_extraction RAM/swap hijyenini, anti_dump core-dump'i,
    anti_memory_inspection canli-bellek taramasini tutar; bu modul
    STATIK strings yuzeyini (co_consts) tarar, TESPIT uretir.
  - anti_bytecode_analysis opcode-akisini, anti_decompile kurtarmayi
    tutar.

Sinirlar (bilincli tercihler):
  - Trip >=1 STRONG veya >=2 WEAK. Tek WEAK trip uretmez.
  - check_all() yalnizca watch() ile izlenen + pin() ile muhurlenen
    fonksiyonlari tarar (bos kayit = temiz). scan_function/scan_module
    ile istenen hedef acikca taranir.
  - Yorum/docstring (her code nesnesinin co_consts[0] str'i) taramada
    YOK SAYILIR (FP karsiti).
  - Runtime bellek-dump (o an cozulmus plaintext) bu modulun disi:
    o yuzey anti_memory_inspection/anti_dump'un alanidir (dokumante
    rezidu; pyobfus notu: runtime plaintext her zaman vardir).

Sessiz, stdlib-only, fail-closed. True=risk, False=temiz.
"""

import base64 as _base64
import binascii as _binascii
import hashlib as _hashlib
import math as _math
import re as _re
import sys as _sys
import threading as _threading


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


_PIN_DIS_OPMAP = _take_dis_pin("opmap")
_PIN_DIS_HASCONST = _take_dis_pin("hasconst")


class StringExtractionDetected(RuntimeError):
    pass


def _raise():
    raise StringExtractionDetected("protected")


_LOCK = _threading.RLock()

WEIGHTS = {
    "plaintext_secret": 100,
    "encoded_secret": 100,
    "high_entropy_string": 100,
    "constructed_secret": 100,
    "hostile_callable": 100,
    "pin_mismatch": 100,
    "network_indicator": 30,
    "suspicious_keyword": 30,
    "string_concentration": 30,
    "charcode_build": 30,
    "sensor_health": 100,
}
STRONG = frozenset({"plaintext_secret", "encoded_secret",
                    "high_entropy_string", "constructed_secret",
                    "hostile_callable", "pin_mismatch",
                    "sensor_health"})
_THRESHOLD_TRIP = 100

_ENTROPY_MIN_LEN = 48
_ENTROPY_BITS = 4.5
_CONCENTRATION_MIN_LEN = 48
_CONCENTRATION_COUNT_WEAK = 6
_BLOB_MIN_LEN = 32
_CHARCODE_MIN_ITEMS = 16
_SAMPLE_CAP = 65536

try:
    _RE_AWS = _re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")
except Exception:
    _RE_AWS = None
try:
    _RE_GITHUB = _re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"
        r"|github_pat_[A-Za-z0-9_]{20,}")
except Exception:
    _RE_GITHUB = None
try:
    _RE_SLACK = _re.compile(
        r"\bxox[a-z]-[A-Za-z0-9\-]{10,}\b"
        r"|\bxapp-[A-Za-z0-9\-.]{10,}\b")
except Exception:
    _RE_SLACK = None
try:
    _RE_DISCORD_MFA = _re.compile(r"\bmfa\.[A-Za-z0-9_\-]{20,}\b")
except Exception:
    _RE_DISCORD_MFA = None
try:
    _RE_AWS_JOINED = _re.compile(r"AKIA[0-9A-Z]{16}")
except Exception:
    _RE_AWS_JOINED = None
try:
    _RE_DISCORD_JOINED = _re.compile(
        r"[A-Za-z0-9_\-]{23,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{27,}")
except Exception:
    _RE_DISCORD_JOINED = None
try:
    _RE_OPENAI = _re.compile(
        r"sk-(?:(?:proj|svcacct|admin|service)-[A-Za-z0-9_\-]{10,100}"
        r"|[A-Za-z0-9]{20,42})T3BlbkFJ[A-Za-z0-9_\-]{10,100}")
except Exception:
    _RE_OPENAI = None
try:
    _RE_STRIPE = _re.compile(
        r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{10,}\b")
except Exception:
    _RE_STRIPE = None
try:
    _RE_ANTHROPIC = _re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{10,}\b")
except Exception:
    _RE_ANTHROPIC = None
try:
    _RE_AWS_SECRET = _re.compile(
        r"(?i)aws[_-]?secret[_-]?access[_-]?key[\"'\s:=]+"
        r"([A-Za-z0-9/+=]{40})")
except Exception:
    _RE_AWS_SECRET = None
try:
    _RE_CONNSTR = _re.compile(
        r"(?i)\b[a-z][a-z0-9+.\-]{1,20}://[^/\s'\"@]{1,64}"
        r":[^@\s/'\"]{4,}@")
except Exception:
    _RE_CONNSTR = None
try:
    _RE_GOOGLE = _re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
except Exception:
    _RE_GOOGLE = None
try:
    _RE_MAILGUN = _re.compile(r"\bkey-[A-Za-z0-9]{32}\b")
except Exception:
    _RE_MAILGUN = None
try:
    _RE_DISCORD = _re.compile(
        r"\b[MN][A-Za-z0-9_\-]{23}\.[\w\-]{6}\.[\w\-]{27,}\b")
except Exception:
    _RE_DISCORD = None
try:
    _RE_JWT = _re.compile(
        r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"
        r"(?:\.[A-Za-z0-9_\-]{10,})?\b")
except Exception:
    _RE_JWT = None
try:
    _RE_BEARER = _re.compile(
        r"Bearer\s+([A-Za-z0-9\-._~+/=]{4,})", _re.IGNORECASE)
except Exception:
    _RE_BEARER = None
try:
    _RE_CRED = _re.compile(
        r"(?i)(?:password|passwd|pwd|api[_-]?key|secret|token"
        r"|(?<!mon)(?<!tur)(?<!don)(?<!hoc)(?<!joc)key(?!board))"
        r"\s*[:=]\s*['\"]?([^\s'\"]{4,})")
except Exception:
    _RE_CRED = None
try:
    _RE_URL = _re.compile(r"https?://[^\s'\"<>]{4,}", _re.IGNORECASE)
except Exception:
    _RE_URL = None
try:
    _RE_IPV4 = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
except Exception:
    _RE_IPV4 = None
try:
    _RE_CC = _re.compile(r"\b\d{13,19}\b")
except Exception:
    _RE_CC = None
try:
    _RE_B64_RUN = _re.compile(r"[A-Za-z0-9+/]{32,}={0,2}")
except Exception:
    _RE_B64_RUN = None
try:
    _RE_B32_RUN = _re.compile(r"[A-Z2-7]{32,}={0,6}")
except Exception:
    _RE_B32_RUN = None

_PEM_MARKER = "-----BEGIN "
_ONION_MARKER = ".onion"

_SUSPICIOUS_KEYWORDS = (
    "mimikatz", "lsass", "meterpreter", "shellcode", "cobaltstrike",
    "reverse_shell", "reverse shell", "keylog", "ransomware",
    "command-and-control", "c2_server", "c2server", "botnet",
    "rootkit", "backdoor", "privilege escalation", "credential dumping",
    "pass-the-hash", "pass the hash", "kerberoast", "bloodhound",
    "powershell -enc", "powershell -e ", "frombase64string",
)

_B64CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEXCHARS = frozenset("0123456789abcdefABCDEF")
_B32CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=")
_B32_NOPAD_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
_XOR_MAX_BYTES = 4096
_XOR_MAX_BLOBS = 5

_WATCH = {}
_PINS = {}
_SE_ADMINS = {}
_SE_ADMIN_LOCKED = False
_SE_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    Ilk start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _SE_ADMIN_DENIED
    try:
        if _SE_ADMIN_LOCKED:
            with _LOCK:
                _SE_ADMIN_DENIED += 1
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
            _SE_ADMINS[name] = fn
        return True
    except Exception:
        return False


def _se_check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _LOCK:
            allowed = dict(_SE_ADMINS)
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


def _se_deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _SE_ADMIN_DENIED
    try:
        with _LOCK:
            _SE_ADMIN_DENIED += 1
    except Exception:
        pass
    _raise()
_WATCHDOG_STOP = None
_WATCHDOG_THREAD = None


def _low_diversity(t):
    try:
        if not isinstance(t, str) or len(t) < _BLOB_MIN_LEN:
            return True
        return len(set(t[:1024])) <= 2
    except Exception:
        return False


def _shannon(data):
    try:
        if not data:
            return 0.0
        if isinstance(data, str):
            data = data.encode("utf-8", "ignore")
        if len(data) > _SAMPLE_CAP:
            data = data[:_SAMPLE_CAP]
        n = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        return -sum((c / n) * _math.log2(c / n) for c in freq.values())
    except Exception:
        return 0.0


def _charset_ratio(t, charset):
    try:
        if not t:
            return 0.0
        if len(t) > _SAMPLE_CAP:
            t = t[:_SAMPLE_CAP]
        hit = sum(1 for ch in t if ch in charset)
        return hit / len(t)
    except Exception:
        return 0.0


def _printable_ratio(t):
    try:
        if not t:
            return 0.0
        if len(t) > _SAMPLE_CAP:
            t = t[:_SAMPLE_CAP]
        ok = 0
        for ch in t:
            o = ord(ch)
            if ch in ("\n", "\r", "\t") or (32 <= o < 127):
                ok += 1
        return ok / len(t)
    except Exception:
        return 0.0


def _luhn_ok(digits):
    try:
        if not digits or not digits.isdigit():
            return False
        if len(set(digits)) == 1:
            return False
        total = 0
        for i, ch in enumerate(reversed(digits)):
            d = ord(ch) - 48
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            total += d
        return total % 10 == 0
    except Exception:
        return False


def _valid_ipv4(t):
    try:
        parts = t.split(".")
        if len(parts) != 4:
            return False
        for p in parts:
            if not p.isdigit() or not 0 <= int(p) <= 255:
                return False
            if len(p) > 1 and p[0] == "0" and len(p) > 3:
                return False
        return True
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


def _string_fp(co):
    """Davranis-parmak-izi: co_code + TUM const-turleri + isimler + flags.

    HIGH-fix: eski surum int/float/None/bool const'lari + co_names/
    varnames'i yok sayiyordu (`return 1`→`return 99999` ayni fp'yi
    veriyordu). Simdi: sira-korunur full-const + names + argcount/flags.
    """
    try:
        h = _hashlib.sha256()
        try:
            h.update(bytes(getattr(co, "co_code", b"") or b""))
        except Exception:
            pass
        try:
            consts = []

            def _norm(c, depth=0):
                try:
                    if depth > 8:
                        return ("<depth>",)
                    if isinstance(c, str):
                        return ("s", c)
                    if isinstance(c, (bytes, bytearray)):
                        try:
                            return ("b", bytes(c).decode("ascii", "ignore"))
                        except Exception:
                            return ("b", len(bytes(c)))
                    if isinstance(c, bool):
                        return ("bool", c)
                    if isinstance(c, (int, float)):
                        return ("n", repr(c))
                    if c is None:
                        return ("none",)
                    if isinstance(c, (tuple, list, frozenset)):
                        try:
                            return ("t", tuple(_norm(x, depth + 1) for x in c))
                        except Exception:
                            return ("t", "?")
                    if hasattr(c, "co_consts"):
                        return ("code", getattr(c, "co_name", "?"))
                    return ("o", type(c).__name__)
                except Exception:
                    return ("?",)

            for _sub, _d in _iter_code(co):
                try:
                    sub_consts = getattr(_sub, "co_consts", ()) or ()
                    for i, c in enumerate(sub_consts):
                        if i == 0 and isinstance(c, str):
                            continue
                        consts.append(_norm(c))
                except Exception:
                    continue
            for s in consts:
                h.update(repr(s).encode("utf-8", "ignore"))
                h.update(b"\x00")
        except Exception:
            pass
        try:
            for _sub, _d in _iter_code(co):
                try:
                    h.update(repr(tuple(getattr(_sub, "co_names", ()) or ())).encode("utf-8", "ignore"))
                    h.update(repr(tuple(getattr(_sub, "co_varnames", ()) or ())).encode("utf-8", "ignore"))
                except Exception:
                    continue
        except Exception:
            pass
        try:
            for _f in ("co_argcount", "co_posonlyargcount", "co_kwonlyargcount", "co_flags"):
                try:
                    h.update(repr(getattr(co, _f, 0)).encode("utf-8", "ignore"))
                except Exception:
                    continue
        except Exception:
            pass
        return h.hexdigest()
    except Exception:
        return ""


def _consts_flat(co, skip_doc=True):
    out = []
    try:
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
    except Exception:
        pass
    return out


def _all_strings(co, include_doc=False):
    """co_consts string yuzeyi (MED-fix: include_doc ile docstring DAHIL).

    Research (gitleaks/trufflehog): scanner'lar yorum/docstring AYRIMI
    YAPMAZ — docstring'deki sir gercek sizintidir (strings-dump gorur).
    Varsayilan False (entropy/keyword FP kalkani); plaintext/encoded
    kontrolleri True ile cagirir.
    """
    out = []
    try:
        for _sub, _d in _iter_code(co):
            try:
                consts = getattr(_sub, "co_consts", ()) or ()
                for i, c in enumerate(consts):
                    if i == 0 and isinstance(c, str) and not include_doc:
                        continue
                    if isinstance(c, str):
                        out.append(c)
                    elif isinstance(c, (bytes, bytearray)):
                        try:
                            out.append(bytes(c).decode("ascii", "ignore"))
                        except Exception:
                            continue
                    elif isinstance(c, (tuple, list, frozenset)):
                        try:
                            stack = list(c)
                            while stack:
                                x = stack.pop()
                                if isinstance(x, str):
                                    out.append(x)
                                elif isinstance(x, (bytes, bytearray)):
                                    try:
                                        out.append(bytes(x).decode(
                                            "ascii", "ignore"))
                                    except Exception:
                                        pass
                                elif isinstance(x, (tuple, list, frozenset)):
                                    stack.extend(list(x))
                        except Exception:
                            pass
            except Exception:
                continue
    except Exception:
        pass
    return out


def _cred_value_looks_secret(v):
    # Gitleaks allowlist sentezi: salt-sozluk degeri (orn. log mesaji
    # "secret: material") REDDEDILIR. Deger ya karisik-siniflidir
    # (rakam/sembol/buyuk-kucuk karisimi) ya da yuksek entropilidir.
    try:
        if not isinstance(v, str):
            return False
        v = v.strip("'\"` \t;,.)]}")
        if len(v) < 4:
            return False
        try:
            if _re.fullmatch(r"[a-zA-Z_.\-]+", v):
                return bool(len(v) >= 16 and _shannon(v) >= 4.0)
        except Exception:
            pass
        return True
    except Exception:
        return False


def _decode_charcode_tuples(co):
    """Charcode-demeti cozumu: int-tuple'lari string'e cevir (constructed-secret)."""
    out = []
    try:
        for _sub, _d in _iter_code(co):
            try:
                consts = getattr(_sub, "co_consts", ()) or ()
                for i, c in enumerate(consts):
                    if i == 0 and isinstance(c, str):
                        continue
                    if not isinstance(c, (tuple, list)):
                        continue
                    try:
                        items = list(c)
                    except Exception:
                        continue
                    if len(items) < _CHARCODE_MIN_ITEMS:
                        continue
                    try:
                        ok = all(isinstance(x, int) and not isinstance(x, bool)
                                 and (32 <= x <= 126 or x in (9, 10, 13)) for x in items)
                    except Exception:
                        continue
                    if not ok:
                        continue
                    try:
                        out.append("".join(chr(x) for x in items))
                    except Exception:
                        continue
            except Exception:
                continue
    except Exception:
        pass
    return out


def _has_charcode_build(co):
    try:
        for _sub, _d in _iter_code(co):
            try:
                consts = getattr(_sub, "co_consts", ()) or ()
                for i, c in enumerate(consts):
                    if i == 0 and isinstance(c, str):
                        continue
                    if not isinstance(c, (tuple, list, frozenset)):
                        continue
                    try:
                        items = list(c)
                    except Exception:
                        continue
                    if len(items) < _CHARCODE_MIN_ITEMS:
                        continue
                    ok = 0
                    total = 0
                    for x in items:
                        if not isinstance(x, int) or isinstance(x, bool):
                            break
                        total += 1
                        if 32 <= x <= 126 or x in (9, 10, 13):
                            ok += 1
                    else:
                        if total >= _CHARCODE_MIN_ITEMS and ok / total >= 0.9:
                            return True
                        continue
                    continue
            except Exception:
                continue
        return False
    except Exception:
        return False


def _has_plaintext_secret(t, relax_bounds=False):
    try:
        if not isinstance(t, str) or len(t) < 4:
            return False
        if _RE_AWS is not None and _RE_AWS.search(t):
            return True
        if relax_bounds:
            try:
                if _RE_AWS_JOINED is not None and _RE_AWS_JOINED.search(t):
                    return True
                if (_RE_DISCORD_JOINED is not None
                        and _RE_DISCORD_JOINED.search(t)):
                    return True
            except Exception:
                pass
        if _RE_GITHUB is not None and _RE_GITHUB.search(t):
            return True
        if _RE_SLACK is not None and _RE_SLACK.search(t):
            return True
        if _RE_OPENAI is not None and _RE_OPENAI.search(t):
            return True
        if _RE_STRIPE is not None and _RE_STRIPE.search(t):
            return True
        if _RE_ANTHROPIC is not None and _RE_ANTHROPIC.search(t):
            return True
        if _RE_AWS_SECRET is not None and _RE_AWS_SECRET.search(t):
            return True
        if _RE_CONNSTR is not None and _RE_CONNSTR.search(t):
            return True
        if _RE_GOOGLE is not None and _RE_GOOGLE.search(t):
            return True
        if _RE_MAILGUN is not None and _RE_MAILGUN.search(t):
            return True
        if _RE_DISCORD is not None and _RE_DISCORD.search(t):
            return True
        if _RE_DISCORD_MFA is not None and _RE_DISCORD_MFA.search(t):
            return True
        if _RE_JWT is not None and _RE_JWT.search(t):
            return True
        if _PE_Marker(t):
            return True
        if _RE_BEARER is not None:
            try:
                for mb in _RE_BEARER.finditer(t):
                    try:
                        if _cred_value_looks_secret(mb.group(1)):
                            return True
                    except Exception:
                        continue
            except Exception:
                pass
        if _RE_CRED is not None:
            try:
                for mc in _RE_CRED.finditer(t):
                    try:
                        if _cred_value_looks_secret(mc.group(1)):
                            return True
                    except Exception:
                        continue
            except Exception:
                pass
        if _RE_CC is not None:
            try:
                for m in _RE_CC.finditer(t):
                    if _luhn_ok(m.group(0)):
                        return True
            except Exception:
                pass
        return False
    except Exception:
        return False


def _PE_Marker(t):
    try:
        return _PEM_MARKER in t
    except Exception:
        return False


def _b64_raw(s):
    try:
        pad = (-len(s)) % 4
        if pad:
            s += "=" * pad
        return _base64.b64decode(s, validate=True)
    except Exception:
        return None


def _try_b64_decode_relaxed(t):
    """Kisa-blob b64 cozumu (min 20): cikti secret-desen sartlidir."""
    try:
        s = "".join(t.split())
        if len(s) < 20:
            return None
        try:
            if len(set(s[:1024])) <= 2:
                return None
        except Exception:
            pass
        raw = None
        if _charset_ratio(s, _B64CHARS) >= 0.9:
            raw = _b64_raw(s)
        if raw is None and ("-" in s or "_" in s):
            try:
                u = s.replace("-", "+").replace("_", "/")
            except Exception:
                u = s
            if _charset_ratio(u, _B64CHARS) >= 0.9:
                raw = _b64_raw(u)
        if raw is None:
            return None
        try:
            txt = raw.decode("utf-8", "ignore")
        except Exception:
            return None
        if len(txt) < 4 or _printable_ratio(txt) < 0.85:
            return None
        return txt
    except Exception:
        return None


def _try_b64_decode(t):
    try:
        s = "".join(t.split())
        if len(s) < _BLOB_MIN_LEN:
            return None
        if _low_diversity(s):
            return None
        raw = None
        if _charset_ratio(s, _B64CHARS) >= 0.9:
            raw = _b64_raw(s)
        if raw is None and ("-" in s or "_" in s):
            try:
                u = s.replace("-", "+").replace("_", "/")
            except Exception:
                u = s
            if _charset_ratio(u, _B64CHARS) >= 0.9:
                raw = _b64_raw(u)
        if raw is None:
            return None
        try:
            txt = raw.decode("utf-8", "ignore")
        except Exception:
            return None
        if len(txt) < 8 or _printable_ratio(txt) < 0.85:
            return None
        return txt
    except Exception:
        return None


def _hex_raw(s):
    try:
        return _binascii.unhexlify(s)
    except Exception:
        return None


def _try_hex_decode(t):
    try:
        s = "".join(t.split())
        if len(s) < _BLOB_MIN_LEN:
            return None
        if _low_diversity(s):
            return None
        if len(s) % 2 == 1:
            return None
        if _charset_ratio(s, _HEXCHARS) < 0.95:
            return None
        raw = _hex_raw(s)
        if raw is None:
            return None
        try:
            txt = raw.decode("utf-8", "ignore")
        except Exception:
            return None
        if len(txt) < 8 or _printable_ratio(txt) < 0.85:
            return None
        return txt
    except Exception:
        return None


def _try_b32_decode(t):
    try:
        s = "".join(t.split()).rstrip("=")
        if len(s) < _BLOB_MIN_LEN:
            return None
        if _low_diversity(s):
            return None
        if _charset_ratio(s, _B32_NOPAD_CHARS) < 0.95:
            return None
        pad = (-len(s)) % 8
        if pad:
            s += "=" * pad
        try:
            raw = _base64.b32decode(s)
        except Exception:
            return None
        try:
            txt = raw.decode("utf-8", "ignore")
        except Exception:
            return None
        if len(txt) < 8 or _printable_ratio(txt) < 0.85:
            return None
        return txt
    except Exception:
        return None


def _try_xor_sensitive(raw):
    try:
        if not isinstance(raw, (bytes, bytearray)):
            return False
        if len(raw) < 8 or len(raw) > _XOR_MAX_BYTES:
            return False
        for k in range(1, 256):
            try:
                txt = bytes(b ^ k for b in raw).decode("utf-8", "ignore")
            except Exception:
                continue
            if len(txt) < 8 or _printable_ratio(txt) < 0.85:
                continue
            try:
                if _decoded_is_sensitive(txt):
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def _decoded_is_sensitive(txt):
    try:
        if _has_plaintext_secret(txt):
            return True
        if _RE_URL is not None and _RE_URL.search(txt):
            return True
        if _RE_IPV4 is not None:
            try:
                for m in _RE_IPV4.finditer(txt):
                    if _valid_ipv4(m.group(0)):
                        return True
            except Exception:
                pass
        if _ONION_MARKER in txt.lower():
            return True
        if len(txt) >= 16 and _shannon(txt) > 4.0:
            return True
        return False
    except Exception:
        return False


def _has_network_indicator(t):
    try:
        if not isinstance(t, str) or len(t) < 7:
            return False
        if _RE_URL is not None and _RE_URL.search(t):
            return True
        if _RE_IPV4 is not None:
            try:
                for m in _RE_IPV4.finditer(t):
                    if _valid_ipv4(m.group(0)):
                        return True
            except Exception:
                pass
        if _ONION_MARKER in t.lower():
            return True
        return False
    except Exception:
        return False


def _has_suspicious_keyword(t):
    try:
        if not isinstance(t, str) or len(t) < 12:
            return False
        low = t.lower()
        for kw in _SUSPICIOUS_KEYWORDS:
            if kw in low:
                return True
        return False
    except Exception:
        return False


def _is_high_entropy_string(t):
    try:
        if isinstance(t, (bytes, bytearray)):
            try:
                t = bytes(t).decode("ascii", "ignore")
            except Exception:
                return False
        if not isinstance(t, str):
            return False
        if len(t) < _ENTROPY_MIN_LEN:
            return False
        if " " in t or "\\" in t:
            return False
        return _shannon(t) > _ENTROPY_BITS
    except Exception:
        return False


def _scan_one(co):
    res = {k: False for k in WEIGHTS}
    if co is None:
        res["hostile_callable"] = True
        return res
    try:
        strs = _all_strings(co, include_doc=True)
    except Exception:
        strs = []
    try:
        strs_plain = _all_strings(co, include_doc=False)
    except Exception:
        strs_plain = strs
    try:
        for s in strs:
            try:
                if _has_plaintext_secret(s):
                    res["plaintext_secret"] = True
                    break
            except Exception:
                continue
    except Exception:
        pass
    try:
        xor_n = 0
        for s in strs:
            try:
                if not isinstance(s, str):
                    continue
                try:
                    if " " in s or "\t" in s or "\n" in s:
                        _eff = len("".join(s.split()))
                    else:
                        _eff = len(s)
                except Exception:
                    _eff = 0
                if _eff < 20:
                    continue
                if " " in s and _charset_ratio(
                        s.replace(" ", ""), _B64CHARS) < 0.9:
                    if "%" in s or len(s) < 48:
                        continue
                dec = _try_b64_decode(s)
                if dec is None:
                    dec = _try_hex_decode(s)
                if dec is None:
                    dec = _try_b32_decode(s)
                if dec is not None and _decoded_is_sensitive(dec):
                    res["encoded_secret"] = True
                    break
                if xor_n < _XOR_MAX_BLOBS:
                    try:
                        hs = "".join(s.split())
                        if (len(hs) >= _BLOB_MIN_LEN and len(hs) % 2 == 0
                                and not _low_diversity(hs)
                                and _charset_ratio(hs, _HEXCHARS) >= 0.95):
                            raw = _hex_raw(hs[:_XOR_MAX_BYTES * 2])
                            if raw is not None:
                                xor_n += 1
                                if _try_xor_sensitive(raw):
                                    res["encoded_secret"] = True
                                    break
                    except Exception:
                        pass
                if _RE_B64_RUN is not None and len(s) >= 64:
                    try:
                        for m in _RE_B64_RUN.finditer(s):
                            frag = m.group(0)
                            if len(frag) < 48:
                                continue
                            dec2 = _try_b64_decode(frag)
                            if (dec2 is not None
                                    and _decoded_is_sensitive(dec2)):
                                res["encoded_secret"] = True
                                break
                    except Exception:
                        pass
                    if res["encoded_secret"]:
                        break
                # MED-fix: spaceless parca-aramasi — boslukla bolunmus blob
                # spaceless formda taranir ("QUtJ … ON0" kacisi kapali).
                # Kisa parcalar (>=20) da denenir: cikti secret-deseni
                # sartina baglidir (FP kalkani desendedir, uzunlukta degil).
                try:
                    hs = "".join(s.split())
                    if len(hs) >= 20:
                        decs = _try_b64_decode_relaxed(hs)
                        if decs is not None and _decoded_is_sensitive(decs):
                            res["encoded_secret"] = True
                except Exception:
                    pass
                if res["encoded_secret"]:
                    break
                if (not res["encoded_secret"] and _RE_B32_RUN is not None
                        and len(s) >= 64):
                    try:
                        for m3 in _RE_B32_RUN.finditer(s):
                            frag3 = m3.group(0)
                            if len(frag3) < 48:
                                continue
                            dec3 = _try_b32_decode(frag3)
                            if (dec3 is not None
                                    and _decoded_is_sensitive(dec3)):
                                res["encoded_secret"] = True
                                break
                    except Exception:
                        pass
                    if res["encoded_secret"]:
                        break
            except Exception:
                continue
    except Exception:
        pass
    try:
        for s in strs_plain:
            try:
                if _is_high_entropy_string(s):
                    res["high_entropy_string"] = True
                    break
            except Exception:
                continue
    except Exception:
        pass
    try:
        for s in strs_plain:
            try:
                if _has_network_indicator(s):
                    res["network_indicator"] = True
                    break
            except Exception:
                continue
    except Exception:
        pass
    try:
        for s in strs_plain:
            try:
                if _has_suspicious_keyword(s):
                    res["suspicious_keyword"] = True
                    break
            except Exception:
                continue
    except Exception:
        pass
    try:
        n = 0
        for s in strs_plain:
            try:
                if (isinstance(s, str)
                        and len(s) >= _CONCENTRATION_MIN_LEN
                        and " " not in s and "\\" not in s):
                    n += 1
                    if n >= _CONCENTRATION_COUNT_WEAK:
                        break
            except Exception:
                continue
        if n >= _CONCENTRATION_COUNT_WEAK:
            res["string_concentration"] = True
    except Exception:
        pass
    try:
        if _has_charcode_build(co):
            res["charcode_build"] = True
    except Exception:
        pass
    # HIGH-fix: insa-EDILMIS sir — charcode demeti cozumu secret-desenine
    # uyuyorsa TEK WEAK degil STRONG (runtime-kurulu sir artik gorunur).
    try:
        if not res.get("constructed_secret"):
            for built in _decode_charcode_tuples(co):
                try:
                    if _has_plaintext_secret(built):
                        res["constructed_secret"] = True
                        break
                except Exception:
                    continue
    except Exception:
        pass
    try:
        if not res["plaintext_secret"] or not res["network_indicator"]:
            try:
                parts = [s for s in strs_plain
                         if isinstance(s, str) and 2 <= len(s) <= 4096]
                big = "".join(parts[:200])[:100000]
            except Exception:
                big = ""
            if big and len(big) >= 8:
                if not res["plaintext_secret"]:
                    try:
                        if _has_plaintext_secret(big, relax_bounds=True):
                            res["plaintext_secret"] = True
                    except Exception:
                        pass
                if not res["network_indicator"]:
                    try:
                        if _has_network_indicator(big):
                            res["network_indicator"] = True
                    except Exception:
                        pass
    except Exception:
        pass
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
    """Izlemeden cikar (YONETIM: kayitli operator sart — susturma kapali)."""
    if not _se_check_admin():
        _se_deny_admin("unwatch")
    try:
        with _LOCK:
            _WATCH.pop(id(f), None)
        return True
    except Exception:
        return False


def pin(f):
    """String-tablosu parmak-izi al (True=ok).

    CRIT-fix: mevcut pin'den FARKLI tabloyla re-pin REDDEDILIR (overwrite
    yok — swap-sonrasi pin() ile aklama kapanir). Bilincli re-baseline
    icin admin-gated repin() kullanilir.
    """
    try:
        co = _co_of(f)
        if co is None:
            return False
        fp = _string_fp(co)
        if not fp:
            return False
        with _LOCK:
            old = _PINS.get(id(f))
            if old is not None and old[1] != fp:
                return False
            _PINS[id(f)] = (f, fp)
        return True
    except Exception:
        return False


def repin(f):
    """Bilincli re-baseline (YONETIM: kayitli operator sart)."""
    if not _se_check_admin():
        _se_deny_admin("repin")
    try:
        co = _co_of(f)
        if co is None:
            return False
        fp = _string_fp(co)
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
                if _string_fp(co) != fp:
                    return True
            except Exception:
                continue
        return False
    except Exception:
        return False


def scan_function(f):
    """Tek fonksiyon tara (MED-fix: hostile __code__ fail-CLOSED).

    __code__'siz/raise-eden obje artik {} DEGIL hostile_callable=True
    doner — dusmanca callable temiz sayilmaz.
    """
    try:
        co = _co_of(f)
        if co is None:
            return {"hostile_callable": True}
        return _scan_one(co)
    except Exception:
        return {"hostile_callable": True}


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
                try:
                    if isinstance(v, (staticmethod, classmethod)):
                        v = v.__func__
                except Exception:
                    pass
                if isinstance(v, _t.FunctionType):
                    out[n] = _scan_one(getattr(v, "__code__"))
                elif isinstance(v, type):
                    for mn, mv in list(vars(v).items()):
                        try:
                            try:
                                if isinstance(mv, (staticmethod,
                                                  classmethod)):
                                    mv = mv.__func__
                            except Exception:
                                pass
                            if isinstance(mv, _t.FunctionType):
                                out["%s.%s" % (n, mn)] = _scan_one(
                                    getattr(mv, "__code__"))
                        except Exception:
                            continue
            except Exception:
                continue
    except Exception:
        pass
    return out


def _check_sensor_health():
    try:
        _ = list(_PIN_DIS_OPMAP.items())
        _ = 100 in (_PIN_DIS_HASCONST or [])
        _ = _hashlib.sha256(b"x").hexdigest()
        _ = _base64.b64encode(b"x")
        _ = _binascii.hexlify(b"x")
        return False
    except Exception:
        return True


_CHECKS = (
    ("plaintext_secret", "_watch"),
    ("encoded_secret", "_watch"),
    ("high_entropy_string", "_watch"),
    ("constructed_secret", "_watch"),
    ("hostile_callable", "_watch"),
    ("pin_mismatch", "_pins"),
    ("network_indicator", "_watch"),
    ("suspicious_keyword", "_watch"),
    ("string_concentration", "_watch"),
    ("charcode_build", "_watch"),
    ("sensor_health", None),
)

_LIGHT = frozenset({"plaintext_secret", "encoded_secret",
                    "constructed_secret", "hostile_callable",
                    "pin_mismatch", "sensor_health"})


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
                        continue
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
    """Dekorator: cagri-oncesi + sonrasi assert_clean (fail-closed iki uc)."""
    try:
        import functools as _ft

        @_ft.wraps(func)
        def _w(*a, **k):
            assert_clean()
            try:
                r = func(*a, **k)
            except StringExtractionDetected:
                raise
            except Exception as e:
                try:
                    if is_compromised():
                        raise StringExtractionDetected("protected") from e
                except StringExtractionDetected:
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
    global _WATCHDOG_STOP, _WATCHDOG_THREAD, _SE_ADMIN_LOCKED
    try:
        with _LOCK:
            _SE_ADMIN_LOCKED = True
    except Exception:
        pass
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
    """Watchdog'lari durdur (YONETIM: kayitli operator sart)."""
    if not _se_check_admin():
        _se_deny_admin("stop_all_watchdogs")
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
    "StringExtractionDetected",
    "watch", "unwatch", "pin", "repin", "verify_pins",
    "authorize_admin",
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
