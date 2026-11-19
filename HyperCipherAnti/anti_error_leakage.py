"""anti_error_leakage: hata-mesaji / traceback bilgi-sizintisi savunmasi.

Tehdit modeli (CWE-209 + CWE-200 + OWASP padding/error-oracle):
  Saldirgan hata ciktisini okur: (a) dogrudan dondurulen traceback (dosya
  yollari, kod yapisi, kutuphane surumleri, SQL), (b) exception mesajina
  gomulmus kimlik bilgisi (DSN sifresi, token, URL userinfo), (c) frame
  locals (istek yuku stack'te serilesir), (d) farkli hatalara farkli
  cevaplar = error oracle (padding-oracle ailesi: ok/failed disi her sinyal
  1 bit sizintidir), (e) log satirina gomulmus secret (retention'dan
  silinemez).
Savunma (OpenSSF pyscg-0050 + CodeQL py-stack-trace-exposure):
  SPLIT & FILTER: disariya tek tip genel mesaj + error-id; detay yalnizca
  server-side redakte logda. Tum hata durumlari tek tip cevap verir.

Kapsam disi (durustluk): zamanlama-oracle tam sabit-zamanlilik (saf
   Python'da garanti edilemez), install sirasinda henuz acilmamis loop'lar
   (mevcut + GELECEK loop'lar new_event_loop sarimiyla kaplanir; sarim-oncesi
   acilmis loop install aninda da kaplanir), C-seviyesi fatal
   (abort/segfault), log arka-ucuna sizmis veri (uretim noktasinda redakte
   edilir, geriye donuk temizlik yoktur).
"""

import collections as _collections
import logging as _logging
import re as _re
import secrets as _secrets
import sys as _sys
import threading as _threading
import traceback as _traceback
import warnings as _warnings


def _get_asyncio():
    """Lazy asyncio (import-aninda asyncio->inspect->dis zinciri sys.modules'i
    kirletip kardes WEAK sinyalini ateslemesin diye)."""
    try:
        import asyncio as _aio
        return _aio
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Sabitler
# ---------------------------------------------------------------------------

STRONG = 100
WEAK = 30

_MAX_DETAIL_RING = 128
_MAX_EXC_TEXT = 512
_MAX_FRAMES = 20
_MAX_CHAIN = 3
_MAX_RECORD = 8192
_TRUNC = "...[truncated]"
_GENERIC_OUT = "operation failed"
_GENERIC_ID_PREFIX = "ERROR id="

# Anahtar-adina gore redakte edilir (buyuk/kucuk duyarsiz). R21: tam-esleme
# + govde-parca esleme (normalize: camel/snake/kebab/dot bolunur). "tokenizer",
# "keyboard", "bypass", "passport" CARPMAZ (parca-esitligi, alt-string degil);
# "AWS_SECRET_ACCESS_KEY", "oldPassword", "x-auth-token" YAKALANIR.
_SECRET_KEYS = frozenset({
    "api_key", "apikey", "api-secret", "api_secret", "secret", "secret_key",
    "secretkey", "client_secret", "consumer_secret", "private_key",
    "privatekey", "public_key", "password", "passwd", "pwd", "pass",
    "token", "access_token", "refresh_token", "auth_token", "id_token",
    "auth", "authorization", "credential", "credentials", "session_key",
    "sessionkey", "session_token", "webhook_secret", "signing_secret",
    "encryption_key", "decryption_key", "master_key", "db_password",
    "dbpassword", "db_pass", "db_user", "dbpassword", "connection_string",
    "dsn", "database_url", "auth_token", "authtoken", "bearer", "otp",
    "pin", "cvv", "card_number", "cardnumber", "ssn", "social_security",
})

_KEY_STEMS = frozenset({
    "password", "passwords", "passwd", "pwd", "pass", "secret", "secrets",
    "token", "tokens", "auth", "credential", "credentials", "private",
    "session", "sessions", "cookie", "cookies", "dsn", "otp", "otps",
    "pin", "pins", "cvv", "cvvs", "ssn", "ssns",
})


_SAFE_KEY_RES = (
    _re.compile(r"(?i)(?:^|_)(name|names|id|ids|type|version|uri|url|path|file|dir|code|status|label|kind|issuer|alias|hint)(?:_|$)"),
    _re.compile(r"(?i)^(fake|dummy|test|example|sample|mock|placeholder|template|stub|demo|public)_[A-Za-z0-9_]*"),
    _re.compile(r"(?i)(?:^|_)(fake|dummy|examples?|samples?|mocks?|placeholders?|templates?|stubs?|demos?|tests?)(?:_|$)"),
    _re.compile(r"(?i)^(keyword|monkeys?|donkeys?|keyboards?|hotkey|keycode|key_codes?|safety_pin|rolling_pin|api_version|client_version|map_key|define_key|translation_key)$"),
)


def _is_secret_key(key, value=None):
    """Tam-esleme + normalize-parca esleme (MEDIUM-11 sirali).

    Sira: (1) exact _SECRET_KEYS uyumu HER ZAMAN True (allowlist bile
    ezemez); (2) stem-parca vurusunda safe-pattern varsa DEGER'e bakilir:
    deger secret-sekilli (has_secret) ise True — `token_hint` altinda
    gercek token sizamaz; opak/diyagnostik deger korunur (gitleaks
    #1587: secret_name/api_version teshis-bilgisi, operator korlugu yok).
    """
    try:
        if not isinstance(key, str) or not key:
            return False
        kl = key.lower()
        if kl in _SECRET_KEYS:
            return True
        try:
            spaced = _re.sub(r"(?<=[a-z])(?=[A-Z])", "_", key)
        except Exception:
            spaced = key
        try:
            parts = _re.split(r"[^A-Za-z0-9]+", spaced.lower())
        except Exception:
            return False
        stem_hit = False
        for p in parts:
            try:
                if p and p in _KEY_STEMS:
                    stem_hit = True
                    break
            except Exception:
                continue
        if not stem_hit:
            return False
        try:
            safe_hit = False
            for rx in _SAFE_KEY_RES:
                try:
                    if rx.search(key):
                        safe_hit = True
                        break
                except Exception:
                    continue
            if not safe_hit:
                return True
            if value is None:
                return False
            try:
                return bool(has_secret(value))
            except Exception:
                return False
        except Exception:
            return False
    except Exception:
        return False

# Deger-deseni redaksiyonu: bicimi baska hicbir sey olamayacak kalemler
# (key-bazli kuralin yakalayamadigi, adi bilinmeyen alanlardaki degerler).
_VALUE_PATTERNS = (
    # Authorization: Bearer <token> / Basic <b64> basliklari.
    (_re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)\S+"),
     r"\1[REDACTED]"),
    # Ciplak "Bearer <token>" metni.
    (_re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/=]{8,}"), "Bearer [REDACTED]"),
    # URL userinfo: scheme://user:PASS@host (sifre kismi). R22: ic-kosular
    # SINIRLI ({0,32}/{1,128}/{1,256}) — sinirsiz `[..]*` uzun harf-kosusunda
    # O(n^2) geri-izlemeye dusuyordu (2MB 'x' kosusu ~35sn olculdu). Gercek
    # semalar <32, user <128, sifre <256 karakterdir; otesi belgeli sinir.
    (_re.compile(r"(?i)([a-z][a-z0-9+.\-]{0,32}://[^/\s:@]{1,128}:)[^/\s@]{1,256}(@)"), r"\1[REDACTED]\2"),
    # form/query: password=...& / token:... / "api_key": "..." (JSON).
    (_re.compile(r"(?i)(password|passwd|pwd|secret|token|api[-_]?key|auth|sessionkey|dsn)\s*[:=]\s*[^&\s,\"'};]+"),
     r"\1=[REDACTED]"),
    (_re.compile(r"(?i)\"[^\"]*(?:password|passwd|secret|token|api[-_]?key|private[-_]?key)\"\s*:\s*\"[^\"]*\""),
     '"[REDACTED-key]":"[REDACTED]"'),
    # Bilinen token one-kleri (R20: en-ozelden genele; tum govdeler
    # uzunluk-sinirli, kelime-sinirli — yanlis-pozitif disi).
    (_re.compile(r"\bsk-(?:ant|proj|svcacct|admin)-[A-Za-z0-9_\-]{8,}"), "sk-[REDACTED]"),
    (_re.compile(r"\bsk-(?:live|test)-[A-Za-z0-9]{8,}\b"), "sk-[REDACTED]"),
    (_re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"), "sk-[REDACTED]"),
    (_re.compile(r"\bgh[pousr]_[A-Za-z0-9]{8,}\b"), "gh_[REDACTED]"),
    (_re.compile(r"\bxox[bpasx]-[A-Za-z0-9\-]{8,}"), "xox-[REDACTED]"),
    (_re.compile(r"\bAKIA[0-9A-Z]{12,}"), "AKIA[REDACTED]"),
    (_re.compile(r"\bgsk_[A-Za-z0-9]{8,}"), "gsk_[REDACTED]"),
    (_re.compile(r"\bxai-[A-Za-z0-9]{8,}"), "xai-[REDACTED]"),
    (_re.compile(r"\bhf_[A-Za-z0-9]{8,}"), "hf_[REDACTED]"),
    (_re.compile(r"\br8_[A-Za-z0-9]{8,}"), "r8_[REDACTED]"),
    (_re.compile(r"\bpplx-[A-Za-z0-9]{8,}"), "pplx-[REDACTED]"),
    (_re.compile(r"\bAIza[A-Za-z0-9_\-]{16,}"), "AIza[REDACTED]"),
    (_re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "[JWT]"),
    (_re.compile(r"\bgAAAAAB[A-Za-z0-9\-_]{20,}={0,2}"), "[FERNET-CIPHERTEXT]"),
    # PEM bloklari (ozel anahtar / sertifika govdesi). Govde {0,4096} ile
    # sinirli + scrub giriste pre-truncate uygular (R7): sinirsiz tembel
    # `[\s\S]*?` dusmanca-uzun girdide O(n^2) geri-izlemeye duserdi.
    (_re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{0,4096}?-----END [A-Z0-9 ]*PRIVATE KEY-----"),
     "-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----"),
)


# ---------------------------------------------------------------------------
# Durum
# ---------------------------------------------------------------------------

_HARDENED = False
_prev_hooks: dict = {}
_detail_lock = _threading.Lock()
_detail_ring: _collections.deque = _collections.deque(maxlen=_MAX_DETAIL_RING)
_filter_lock = _threading.Lock()
_watchdog_stop: _threading.Event | None = None
_watchdog_thread: _threading.Thread | None = None


class ErrorLeakageDetected(Exception):
    """Hata-sizintisi durusu triplendiginde guard() tarafindan yukselen tip."""


# ---------------------------------------------------------------------------
# Cekirdek: scrub / has_secret
# ---------------------------------------------------------------------------

def scrub(text, limit=_MAX_RECORD):
    """Metindeki kimlik-bilgisi desenlerini redakte eder (idempotent).

    Fail-closed: temsil edilemeyen / patlayan girdide guvenli yer-tutucu
    doner, asla ham girdi donmez.
    """
    try:
        s = text if isinstance(text, str) else str(text)
    except Exception:
        return "[unrepresentable]"
    try:
        # R7: desenlerden ONCE buda (uzun girdi = dusmanca girdi varsayilir;
        # tum repl'ler girdiden kisa oldugundan sonradan budamaya gerek yok).
        if len(s) > limit:
            s = s[:limit]
        for rx, repl in _VALUE_PATTERNS:
            try:
                s = rx.sub(repl, s)
            except Exception:
                continue
        if len(s) > limit:
            s = s[:max(0, limit - len(_TRUNC))] + _TRUNC
        return s
    except Exception:
        return "[redacted-error]"


def has_secret(text):
    """Scrub'un degistirecegi girdi varsa True (sizinti-artigi taramasi).

    Pencere-taramali: dev girdi 64KB pencerelerde (2KB bindirmeli) taranir;
    boylece uzak-ofsette secret bulunurken her pencere sinirli-maliyetlidir
    (toplam dogrusal). 32MB sonrasi durur (belgeli sinir; hata-mesaji icin
    asiri-buyuk girdi dusmanca varsayilir).
    """
    try:
        s = text if isinstance(text, str) else str(text)
    except Exception:
        return False
    try:
        _WIN = 65536
        _OVERLAP = 2048
        _MAXWIN = 512
        n = len(s)
        if n <= _WIN:
            windows = (s,)
        else:
            windows = []
            try:
                pos = 0
                count = 0
                while pos < n and count < _MAXWIN:
                    windows.append(s[pos:pos + _WIN])
                    if pos + _WIN >= n:
                        break
                    pos += _WIN - _OVERLAP
                    count += 1
                windows = tuple(windows)
            except Exception:
                windows = (s[:_WIN],)
        for w in windows:
            for rx, _ in _VALUE_PATTERNS:
                try:
                    if rx.search(w):
                        return True
                except Exception:
                    continue
        return False
    except Exception:
        return False


def _scrub_key_value(key, value):
    try:
        if _is_secret_key(key, value):
            return "[REDACTED]"
    except Exception:
        pass
    try:
        return scrub(value) if isinstance(value, str) else value
    except Exception:
        return "[REDACTED]"


def _oneline(s):
    """R10 (CWE-117 log-forging): kullanici-kontrollu metindeki ham CR/LF'yi
    kacisli forma indirger. Yapisal ayraclar (traceback satirlari) buna
    dokunulmaz; yalnizca GOMULU mesaj parcalari tek-satirlanir, boylece
    saldirgan log'a sahte satir enjekte edemez."""
    try:
        if not isinstance(s, str):
            return s
        return s.replace("\r", "\\r").replace("\n", "\\n")
    except Exception:
        return "[redacted-error]"


_MAX_STRUCT_DEPTH = 8


def _scrub_obj(obj, _depth=0, _seen=None):
    """R17: yapisal log yukunu yinelemeli redakte eder (dict-mesaj, dict-arg,
    ic-ice extra). redactly/logprivacy deseni: hassas-anahtar her zaman
    maskelenir, yaprak-stringler scrub+oneline'dan gecer. Dongu-korumali,
    derinlik-sinirli; bilinmeyen turler oldugu gibi birakilir (formatter
    uyumu bozulmaz; ozel __repr__ icindeki secret caller-tasarim siniridir).
    """
    try:
        if isinstance(obj, str):
            try:
                return _oneline(scrub(obj))
            except Exception:
                return "[redacted]"
        if _depth >= _MAX_STRUCT_DEPTH:
            return "[max-depth]"
        if isinstance(obj, dict):
            if _seen is None:
                _seen = set()
            if id(obj) in _seen:
                return "[cycle]"
            _seen = _seen | {id(obj)}
            out = {}
            try:
                items = list(obj.items())
            except Exception:
                return "[unreadable]"
            for k, v in items:
                try:
                    if _is_secret_key(k, v):
                        out[k] = "[REDACTED]"
                    else:
                        out[k] = _scrub_obj(v, _depth + 1, _seen)
                except Exception:
                    try:
                        out[k] = "[redacted]"
                    except Exception:
                        pass
            return out
        if isinstance(obj, (list, tuple)):
            if _seen is None:
                _seen = set()
            if id(obj) in _seen:
                return "[cycle]"
            _seen = _seen | {id(obj)}
            try:
                items = list(obj)
            except Exception:
                return "[unreadable]"
            clean = []
            for v in items:
                try:
                    clean.append(_scrub_obj(v, _depth + 1, _seen))
                except Exception:
                    clean.append("[redacted]")
            try:
                return tuple(clean) if isinstance(obj, tuple) else clean
            except Exception:
                return clean
        if isinstance(obj, (set, frozenset)):
            try:
                return sorted((_scrub_obj(v, _depth + 1, _seen or set())
                               for v in obj),
                              key=lambda x: str(x)[:64])
            except Exception:
                return "[unreadable]"
        return obj
    except Exception:
        return "[redacted]"


# ---------------------------------------------------------------------------
# Error-id korelasyonu (disariya id, detay server-side ring'de)
# ---------------------------------------------------------------------------

_id_lock = _threading.Lock()
_id_counter = 0
_id_seed = None


def _fallback_id():
    """CSPRNG-olu korelasyon-id: surekli-sayac + tek-seferlik tohum.

    Zayif-saat makinelerinde (kaba monotonic/process_time, allocator
    adres-tekrar) ham-karisim SABIT cikar -> tum id'ler ayni olurdu
    (kanitlandi). Sayac proces-ici TEKLIGI garantiler; tohum ilk
    kullanimda en-iyi-kaynaktan (os.urandom, yoksa karisim) uretilir.
    Seviye: korelasyon-tanimlayici, auth-token DEGIL.
    """
    global _id_counter, _id_seed
    try:
        with _id_lock:
            if _id_seed is None:
                try:
                    import os as _os
                    _id_seed = _os.urandom(16)
                except Exception:
                    try:
                        import os as _os2
                        import time as _ts
                        _id_seed = ("%s-%s-%s-%s" % (
                            _ts.monotonic_ns(), _ts.process_time_ns(),
                            _os2.getpid(),
                            _threading.get_ident())).encode("utf-8", "ignore")
                    except Exception:
                        _id_seed = b"errleak-fallback-seed"
            _id_counter += 1
            n = _id_counter
            seed = _id_seed
        try:
            import hashlib as _hl
            return _hl.sha256(seed + b"#" + str(n).encode("ascii")).hexdigest()[:16]
        except Exception:
            return "%016x" % (n & 0xFFFFFFFFFFFFFFFF)
    except Exception:
        try:
            import time as _t3
            return "%016x" % (int(_t3.monotonic() * 1000000) & 0xFFFFFFFFFFFFFFFF)
        except Exception:
            return "deadbeefdeadbeef"


def _new_error_id():
    try:
        return _secrets.token_hex(8)
    except Exception:
        pass
    # R15: CSPRNG olu ise sessiz-zayif-id YOK -> _fallback_id (sayacli).
    # id'ler auth-token DEGILDIR, lookup yalnizca proces-icidir.
    try:
        return _fallback_id()
    except Exception:
        return "deadbeefdeadbeef"


def _store_detail(error_id, detail):
    try:
        with _detail_lock:
            _detail_ring.append((error_id, detail))
    except Exception:
        pass


def lookup_detail(error_id):
    """Operator tarafi: id -> redakte detay (yoksa None).

    LOW-6 notu: __all__ disinda tutulur (kesif yuzeyi kucuk); ayni-proses
    cagiran guvenilir-sinirdadir (client/stderr'den id goren dis dunya
    bu fonksiyona erisemez — erisirse proses zaten guvenilir degildir).
    Icerik value-scrub'ludur.
    """
    try:
        with _detail_lock:
            for eid, det in _detail_ring:
                if eid == error_id:
                    return det
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# SafeError: tek-tip dis-mesaj (error-oracle direnci)
# ---------------------------------------------------------------------------

class SafeError(Exception):
    """Disariya her zaman ayni mesaji veren hata tipi.

    Tum hata durumlari tek tip cevap verir (ok/disari-failed disi sinyal
    yok): str() sabittir, ayrinti yalnizca error-id ile ring'dedir.
    Zincir tasiyarak sizintiyi geri sizdirmamak icin `from None` ile
    yukseltin (bkz. collapse()).
    """

    def __init__(self, message=None, *, detail=None):
        self.error_id = _new_error_id()
        try:
            # R6: gomme baglanti default-kapali (dis-gorunum + ic-graf ayni
            # anda temiz; raise sirasinda yeniden baglanmaya karsi).
            self.__suppress_context__ = True
        except Exception:
            pass
        try:
            inner = scrub(message) if message is not None else ""
        except Exception:
            inner = ""
        try:
            extra = scrub(detail) if detail is not None else ""
        except Exception:
            extra = ""
        self._detail = extra or inner
        _store_detail(self.error_id, self._detail)
        super().__init__("%s [%s%s]" % (_GENERIC_OUT, "id=", self.error_id))

    def __str__(self):
        try:
            return "%s [%s%s]" % (_GENERIC_OUT, "id=", self.error_id)
        except Exception:
            return _GENERIC_OUT

    def __repr__(self):
        try:
            return "SafeError(id=%r)" % (self.error_id,)
        except Exception:
            return "SafeError(id=?)"

    @property
    def id(self):
        return self.error_id

    def server_detail(self):
        """Redakte edilmis server-side detay (operator)."""
        return self._detail


def collapse(exc):
    """Herhangi bir hatayi bilgi sizdirmadan SafeError'a indirger.

    Orijinal zincir bilerek tasinmaz (`__cause__`/`__context__` yok):
    zincir traceback + mesaj tasiyarak oracle'i geri acardi.
    """
    try:
        desc = safe_error_description(exc)
    except Exception:
        desc = "unrepresentable"
    try:
        tb = format_traceback_safe(exc)
    except Exception:
        tb = "[traceback unavailable]"
    err = SafeError(detail="%s\n%s" % (desc, tb))
    return err


def safe_error_description(exc):
    """`TipAdi: redakte-mesaj` (512B cap). Log `error=` alanlari icin."""
    try:
        tname = type(exc).__name__
    except Exception:
        tname = "UnknownError"
    try:
        msg = str(exc)
        if not isinstance(msg, str):
            msg = ""
    except Exception:
        try:
            a0 = exc.args[0] if getattr(exc, "args", None) else ""
            msg = a0 if isinstance(a0, str) else ""
        except Exception:
            msg = ""
    try:
        msg = scrub(msg, limit=_MAX_EXC_TEXT)
    except Exception:
        msg = "[redacted-error]"
    try:
        msg = _oneline(msg)
    except Exception:
        msg = "[redacted-error]"
    if not msg:
        return tname
    cand = "%s: %s" % (tname, msg)
    if len(cand) > _MAX_EXC_TEXT + 64:
        cand = cand[:_MAX_EXC_TEXT] + _TRUNC
    return cand


# ---------------------------------------------------------------------------
# Traceback bicimleme (locals ASLA serilesmez)
# ---------------------------------------------------------------------------

def format_traceback_safe(exc, *, limit=_MAX_RECORD):
    """Redakte edilmis traceback metni: tip+mesaj+dosya/satir/fonksiyon.

    Frame locals bilerek yoktur: locals istek yuku / secret tasiyabilir ve
    uretim logunda oracle'a donusur. Zincir derinligi 3, frame 20 ile
    sinirlidir (bellek-pinning'e karsi).
    """
    out: list = []
    try:
        seen = 0
        cur = exc
        while cur is not None and seen < _MAX_CHAIN:
            try:
                tname = type(cur).__name__
            except Exception:
                tname = "UnknownError"
            try:
                raw = str(cur)
                if not isinstance(raw, str):
                    raw = ""
                msg = scrub(raw, limit=_MAX_EXC_TEXT)
                msg = _oneline(msg)
            except Exception:
                msg = "[redacted-error]"
            out.append("%s: %s" % (tname, msg))
            try:
                tb = getattr(cur, "__traceback__", None)
                frames = _traceback.extract_tb(tb) if tb is not None else []
            except Exception:
                frames = []
            try:
                frames = frames[-_MAX_FRAMES:]
            except Exception:
                pass
            for fr in frames:
                try:
                    out.append("  File %s, line %s, in %s" % (
                        scrub(_scrub_path(str(fr.filename)), limit=256),
                        fr.lineno,
                        scrub(str(fr.name), limit=128)))
                except Exception:
                    continue
            try:
                notes = getattr(cur, "__notes__", None) or []
                for _n in list(notes)[:_MAX_CHAIN]:
                    try:
                        out.append("  note: %s" % _oneline(
                            scrub(str(_n), limit=_MAX_EXC_TEXT)))
                    except Exception:
                        continue
            except Exception:
                pass
            try:
                _sub = getattr(cur, "exceptions", None)
                if _sub is not None:
                    for _s in list(_sub)[:_MAX_CHAIN]:
                        if _s is cur:
                            continue
                        try:
                            _st = type(_s).__name__
                        except Exception:
                            _st = "UnknownError"
                        try:
                            _sm = _oneline(
                                scrub(str(_s), limit=_MAX_EXC_TEXT))
                        except Exception:
                            _sm = "[redacted-error]"
                        out.append("  sub: %s: %s" % (_st, _sm))
            except Exception:
                pass
            try:
                nxt = getattr(cur, "__cause__", None) or getattr(
                    cur, "__context__", None)
            except Exception:
                nxt = None
            if nxt is cur:
                break
            cur = nxt
            seen += 1
        if cur is not None:
            out.append("[chain truncated]")
    except Exception:
        return "[traceback unavailable]"
    try:
        text = "\n".join(out) or "[no traceback]"
        if len(text) > limit:
            text = text[:max(0, limit - len(_TRUNC))] + _TRUNC
        return text
    except Exception:
        return "[traceback unavailable]"


def _scrub_path(path):
    """Dosya-yolundaki ev-dizini onekini maskele (CWE-209: yol=kullanici adi).
    C:\\Users\\alice\\app.py -> C:\\Users\\~\\app.py ; yoksa aynen doner."""
    try:
        if not isinstance(path, str) or not path:
            return path
        try:
            import os as _os
            home = _os.path.expanduser("~")
        except Exception:
            home = ""
        if home and len(home) > 1:
            try:
                if path == home:
                    return "~"
                if path.startswith(home):
                    rest = path[len(home):]
                    if rest[:1] in ("", "/", "\\"):
                        return "~" + rest
            except Exception:
                pass
        return path
    except Exception:
        return "[path]"


def _clear_residue(exc_value, exc_tb):
    """R8: sizinti-artigini temizle (frame-locals + last_* referanslari).

    Yakalanmamis hata yorumlayicide 3 yerde yasar: (1) traceback'in
    frame-locals'i (istek yuku/secret), (2) sys.last_exc/last_value/
    last_traceback (ham mesaj + frame grafigi), (3) stderr (hook zaten
    genel mesaja indirger). clear_frames (1)'i, last_* silme (2)'yi
    koparir. Hepsi best-effort: temizlik kendisi asla hata yukseltmez.
    """
    try:
        if exc_tb is not None:
            try:
                _traceback.clear_frames(exc_tb)
            except Exception:
                pass
    except Exception:
        pass
    for attr in ("last_exc", "last_type", "last_value", "last_traceback"):
        try:
            if hasattr(_sys, attr):
                try:
                    delattr(_sys, attr)
                except Exception:
                    try:
                        setattr(_sys, attr, None)
                    except Exception:
                        pass
        except Exception:
            pass
    try:
        if exc_value is not None:
            try:
                exc_value.__traceback__ = None
            except Exception:
                pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Logging: RedactFilter (ureten-thread'de, logger-seviyesi) + Formatter
# ---------------------------------------------------------------------------

class RedactFilter(_logging.Filter):
    """Dort alani kapsar: msg, args (tuple/dict), extra'lar, exc args.

    Logger-seviyesine takilir (handler'a degil): kayit kuyruga/kopyaya/
    handler'a ulasmadan once ureten thread'de redakte edilir. args,
    render sonrasi temizlenir (asagidaki handler ham degeri kurtaramaz).

    R9: exc_text on-render redakte edilir (baska handler'in ham cache'i
    asagiya sizamaz); stack_info da scrub'lenir (dosya-yolu/kaynak satiri
    tasir). R10: gomulu mesaj parcalari tek-satirlanir (CWE-117).
    """

    def filter(self, record):
        try:
            if isinstance(getattr(record, "msg", None), str):
                try:
                    record.msg = _oneline(scrub(record.msg))
                except Exception:
                    record.msg = "[redacted]"
            else:
                # R17: dict-mesaj / yapisal yuk (JSON formatter ham basardi).
                try:
                    if getattr(record, "msg", None) is not None:
                        record.msg = _scrub_obj(record.msg)
                except Exception:
                    pass
            args = getattr(record, "args", None)
            if args:
                try:
                    if isinstance(args, dict):
                        record.args = {k: _scrub_key_value(k, v)
                                       for k, v in args.items()}
                    else:
                        record.args = tuple(
                            _scrub_obj(a) for a in args)
                except Exception:
                    try:
                        record.args = ()
                    except Exception:
                        pass
            try:
                std = set(_logging.LogRecord("", 0, "", 0, "", (), None).__dict__)
            except Exception:
                std = set()
            try:
                for key in list(vars(record)):
                    if key in std or key in ("msg", "args", "exc_info",
                                            "exc_text", "stack_info", "sinfo"):
                        continue
                    try:
                        val = getattr(record, key)
                    except Exception:
                        continue
                    try:
                        if _is_secret_key(key, val):
                            setattr(record, key, "[REDACTED]")
                        elif isinstance(val, str):
                            setattr(record, key, _oneline(scrub(val)))
                        else:
                            # R17: ic-ice extra (nested dict/list) yinelemeli.
                            try:
                                setattr(record, key, _scrub_obj(val))
                            except Exception:
                                pass
                    except Exception:
                        pass
            except Exception:
                pass
            try:
                sinfo = getattr(record, "stack_info", None)
                if isinstance(sinfo, str) and sinfo:
                    try:
                        record.stack_info = _oneline(scrub(sinfo))
                    except Exception:
                        try:
                            record.stack_info = None
                        except Exception:
                            pass
            except Exception:
                pass
            try:
                exc_info = getattr(record, "exc_info", None)
                if exc_info and exc_info[1] is not None:
                    exc = exc_info[1]
                    try:
                        eargs = getattr(exc, "args", None)
                        if eargs and isinstance(eargs[0], str):
                            exc.args = (_oneline(scrub(eargs[0])),) + tuple(eargs[1:])
                    except Exception:
                        pass
                    try:
                        record.exc_text = format_traceback_safe(exc)
                    except Exception:
                        try:
                            record.exc_text = "[traceback unavailable]"
                        except Exception:
                            pass
            except Exception:
                pass
        except Exception:
            pass
        return True


class SanitizedFormatter(_logging.Formatter):
    """Traceback'i redakte edilmis, sinirli, locals'siz bicimler.

    Ilk formatter'in cache'ledigi exc_text'i ezer: baska handler'in ham
    render'i asagiya sizamaz.
    """

    def formatException(self, ei):
        try:
            _t, exc, _tb = ei
        except Exception:
            return "[bad exc_info]"
        try:
            return format_traceback_safe(exc)
        except Exception:
            return "[traceback unavailable]"

    def format(self, record):
        try:
            try:
                record.exc_text = None
            except Exception:
                pass
            text = super().format(record)
            if len(text) > _MAX_RECORD:
                text = text[:_MAX_RECORD - len(_TRUNC)] + _TRUNC
            return text
        except Exception:
            try:
                return "LOG-FORMAT-FAILURE level=%s" % getattr(
                    record, "levelname", "?")
            except Exception:
                return "LOG-FORMAT-FAILURE"


def _attach_filter_obj(logger=None):
    """RedactFilter'i takar; eklenen nesneyi doner (vardiysa None)."""
    try:
        lg = logger if logger is not None else _logging.getLogger()
        for f in getattr(lg, "filters", []):
            try:
                if isinstance(f, RedactFilter):
                    return None
            except Exception:
                continue
        obj = RedactFilter()
        lg.addFilter(obj)
        return obj
    except Exception:
        return None


def _attach_filter_to_handler(handler):
    """Handler'a RedactFilter tak (idempotent). Donus: eklendiyse True."""
    try:
        for f in getattr(handler, "filters", []):
            try:
                if isinstance(f, RedactFilter):
                    return False
            except Exception:
                continue
        handler.addFilter(RedactFilter())
        return True
    except Exception:
        return False


def harden_all_loggers():
    """HIGH duzeltmesi: kok + TUM logger'lar + TUM handler'lara filtre.

    Logger-filtreleri child'lara yayilmaz (CPython belgeli); o yuzden her
    mevcut logger ve her handler tek-tek kaplanir. Donus: kapsanan sayisi.
    """
    covered = 0
    try:
        try:
            _attach_filter_obj()
            covered += 1
        except Exception:
            pass
        try:
            mgr = getattr(_logging, "root", None)
            mgr = getattr(getattr(mgr, "manager", None), "loggerDict", None) or {}
            names = list(mgr.keys())
        except Exception:
            names = []
        for name in names:
            try:
                lg = _logging.getLogger(name)
            except Exception:
                continue
            try:
                _attach_filter_obj(lg)
                covered += 1
            except Exception:
                pass
            try:
                for h in list(getattr(lg, "handlers", []) or []):
                    try:
                        if _attach_filter_to_handler(h):
                            covered += 1
                    except Exception:
                        continue
            except Exception:
                pass
        try:
            for h in list(getattr(_logging.getLogger(), "handlers", []) or []):
                try:
                    if _attach_filter_to_handler(h):
                        covered += 1
                except Exception:
                    continue
        except Exception:
            pass
    except Exception:
        pass
    return covered


def logging_coverage():
    """Posture: filtre-kapsami denetimi (yeni logger/handler acigi gorunur)."""
    out = {"loggers_total": 0, "loggers_covered": 0,
           "handlers_total": 0, "handlers_covered": 0, "uncovered": []}
    try:
        try:
            mgr = getattr(getattr(_logging.root, "manager", None), "loggerDict", None) or {}
            names = ["root"] + list(mgr.keys())
        except Exception:
            names = ["root"]
        for name in names:
            try:
                lg = _logging.getLogger() if name == "root" else _logging.getLogger(name)
            except Exception:
                continue
            out["loggers_total"] += 1
            try:
                has = any(isinstance(f, RedactFilter) for f in getattr(lg, "filters", []))
            except Exception:
                has = False
            if has:
                out["loggers_covered"] += 1
            else:
                out["uncovered"].append("logger:" + str(name)[:80])
            try:
                handlers = list(getattr(lg, "handlers", []) or [])
            except Exception:
                handlers = []
            for h in handlers:
                out["handlers_total"] += 1
                try:
                    hf = any(isinstance(f, RedactFilter) for f in getattr(h, "filters", []))
                except Exception:
                    hf = False
                if hf:
                    out["handlers_covered"] += 1
                else:
                    out["uncovered"].append("handler:" + type(h).__name__ + "@" + str(name)[:48])
        out["uncovered"] = out["uncovered"][:32]
    except Exception:
        pass
    return out


_ORIG_ADD_HANDLER = None


def _wrap_add_handler():
    """Gelecekteki handler'lara otomatik filtre (HIGH: yeni-sink acigi kapali)."""
    global _ORIG_ADD_HANDLER
    try:
        if _ORIG_ADD_HANDLER is not None:
            return True
        try:
            orig = _logging.Logger.addHandler
        except Exception:
            return False

        def _guarded_add_handler(self, hdlr):
            try:
                _attach_filter_to_handler(hdlr)
            except Exception:
                pass
            return orig(self, hdlr)

        try:
            _logging.Logger.addHandler = _guarded_add_handler
        except Exception:
            return False
        _ORIG_ADD_HANDLER = orig
        return True
    except Exception:
        return False


def _unwrap_add_handler():
    """addHandler sarimini kaldir (uninstall)."""
    global _ORIG_ADD_HANDLER
    try:
        if _ORIG_ADD_HANDLER is not None:
            try:
                _logging.Logger.addHandler = _ORIG_ADD_HANDLER
            except Exception:
                pass
            _ORIG_ADD_HANDLER = None
        return True
    except Exception:
        return False


def attach_filter(logger=None):
    """RedactFilter'i logger'a tak (yoksa kok). Idempotent."""
    try:
        _attach_filter_obj(logger)
        return True
    except Exception:
        return False


def _detach_filter_obj(logger=None, obj=None):
    """R14: yalnizca BIZIM ekledigimiz filtreyi kaldir (simetrik teardown).
    removeFilter yanlis-nesnede ValueError atar; once kimlik-kontrolu."""
    try:
        if obj is None:
            return False
        lg = logger if logger is not None else _logging.getLogger()
        try:
            if obj in getattr(lg, "filters", []):
                lg.removeFilter(obj)
                return True
        except Exception:
            pass
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Hook sertlestirme: excepthook / thread / unraisable / warnings / asyncio
# ---------------------------------------------------------------------------

def _emit_server_side(level, text):
    """R18: canli exception ASLA iletilmez (exc_info=None). Kayit canli
    (tip,deger,traceback) uclusu tasiyorsa duz bir handler ham mesaji
    basardi; yalnizca onceden-redakte edilmis metin gider."""
    try:
        lg = _logging.getLogger("hyperCipherAnti.error")
        lg.log(level, "%s", scrub(text))
    except Exception:
        pass


def _emit_client(text):
    try:
        _sys.stderr.write("%s\n" % text)
        _sys.stderr.flush()
    except Exception:
        try:
            import os as _os
            _os.write(2, b"ERROR internal failure\n")
        except Exception:
            pass


def _handle_crash(exc_type, exc_value, exc_tb, where):
    # Operator-fesih tipleri her zaman orijinale delege edilir (sessiz
    # yutma yok, cikis kodu korunur).
    try:
        if exc_type is not None and issubclass(exc_type, KeyboardInterrupt):
            try:
                _sys.__excepthook__(exc_type, exc_value, exc_tb)
            except Exception:
                pass
            return
        if exc_type is not None and issubclass(exc_type, SystemExit):
            # INFO-2 notu: sessiz donus stdlib-paritesidir (thread/
            # unraisable/asyncio yollarinda stdlib de SystemExit'i sessiz
            # gecer; main-thread zaten hook'a ugramaz). Davranis sapmasi
            # yok, cikis kodu korunur.
            return
    except Exception:
        pass
    error_id = _new_error_id()
    try:
        if exc_value is not None:
            desc = safe_error_description(exc_value)
            tb = format_traceback_safe(exc_value)
        else:
            try:
                tname = exc_type.__name__ if exc_type else "Unknown"
            except Exception:
                tname = "Unknown"
            desc, tb = tname, "[no exception value]"
        _store_detail(error_id, "%s @%s\n%s" % (desc, where, tb))
        _emit_server_side(_logging.CRITICAL,
                          "uncaught [%s] id=%s: %s\n%s" % (where, error_id, desc, tb))
    except Exception:
        pass
    try:
        _clear_residue(exc_value, exc_tb)
    except Exception:
        pass
    _emit_client("%s%s" % (_GENERIC_ID_PREFIX, error_id))


def _excepthook_main(exc_type, exc_value, exc_tb):
    try:
        _handle_crash(exc_type, exc_value, exc_tb, "main")
    except Exception:
        _emit_client("ERROR internal failure")


def _excepthook_thread(args):
    try:
        try:
            t = (args.exc_type, args.exc_value, args.exc_traceback)
        except Exception:
            return
        _handle_crash(t[0], t[1], t[2], "thread")
    except Exception:
        _emit_client("ERROR internal failure")


def _unraisable_hook(args):
    try:
        try:
            exc = getattr(args, "exc_value", None)
            tb = getattr(exc, "__traceback__", None) if exc is not None else None
            _handle_crash(type(exc) if exc is not None else None, exc, tb,
                          "unraisable")
        except Exception:
            return
    except Exception:
        pass


def _showwarning_hook(message, category, filename, lineno, file=None, line=None):
    # Ham showwarning stderr'e dosya-yolu basar; onun yerine redakte log.
    try:
        try:
            text = _warnings.formatwarning(message, category, filename,
                                           lineno, line)
        except Exception:
            text = "warning"
        _emit_server_side(_logging.WARNING, "warning: %s" % _oneline(scrub(text)))
    except Exception:
        pass


def _asyncio_hook(loop, context):
    try:
        exc = (context or {}).get("exception") if isinstance(context, dict) else None
        if exc is None:
            # R18: default-handler'a devretME (callback-argolarini + nesne
            # repr'lerini ham basardi: gh-112997). Redakte ozet bizde.
            # error_id TEK uretilir: client ciktisiyla ring kaydi eslesir.
            error_id = _new_error_id()
            try:
                raw_msg = ""
                try:
                    raw_msg = str((context or {}).get("message", ""))[:512]
                except Exception:
                    raw_msg = ""
                _store_detail(error_id, "asyncio-note @asyncio\n%s" % raw_msg)
                _emit_server_side(_logging.ERROR,
                                  "asyncio-note id=%s: %s" % (
                                      error_id, _oneline(scrub(raw_msg))))
            except Exception:
                pass
            _emit_client("%s%s" % (_GENERIC_ID_PREFIX, error_id))
            return
        error_id = _new_error_id()
        try:
            desc = safe_error_description(exc)
            tb = format_traceback_safe(exc)
            _store_detail(error_id, "%s @asyncio\n%s" % (desc, tb))
            _emit_server_side(_logging.ERROR,
                              "asyncio id=%s: %s\n%s" % (error_id, desc, tb))
        except Exception:
            pass
        _emit_client("%s%s" % (_GENERIC_ID_PREFIX, error_id))
    except Exception:
        pass


_ORIG_NEW_LOOP = None

_ADMIN_MODULES: dict = {}
_ADMIN_LOCKED = False
_ADMIN_DENIED = 0


def authorize_admin():
    """Operator modulunu kaydet (SADECE kilit-oncesi; boot sirasinda cagrilir).

    start_watchdog() kaydi kilitler. Donus: True=kaydedildi.
    """
    global _ADMIN_DENIED
    try:
        if _ADMIN_LOCKED:
            with _filter_lock:
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
            import os as _os
            if not _os.path.isfile(fn):
                return False
        except Exception:
            return False
        with _filter_lock:
            _ADMIN_MODULES[name] = fn
        return True
    except Exception:
        return False


def _check_admin() -> bool:
    """Dogrudan cagiran cerceve kayitli operator modulu mu? (dosya-dogrulamali)."""
    try:
        with _filter_lock:
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
            if (want is not None and fn == want and not fn.startswith("<")):
                try:
                    import os as _os2
                    if _os2.path.isfile(fn):
                        return True
                except Exception:
                    pass
        except Exception:
            pass
        return False
    except Exception:
        return False


def _deny_admin(op: str):
    """Yonetim reddi: fail-closed opak hata."""
    global _ADMIN_DENIED
    try:
        with _filter_lock:
            _ADMIN_DENIED += 1
    except Exception:
        pass
    raise ErrorLeakageDetected("protected")


def _wrap_asyncio():
    """INFO-2: mevcut + GELECEK loop'lara handler (sadece asyncio yukluyse).

    Yeni loop'lar new_event_loop sarimiyla otomatik kaplanir; uninstall
    sarimi kaldirir (mevcut loop'lardaki redakte-handler zararsiz kalir).
    """
    global _ORIG_NEW_LOOP
    try:
        try:
            aio = _sys.modules.get("asyncio")
            if aio is None:
                return False
        except Exception:
            return False
        try:
            loop = aio.get_running_loop()
        except Exception:
            loop = None
        if loop is None:
            try:
                loop = aio.get_event_loop()
            except Exception:
                loop = None
        if loop is not None:
            try:
                if loop.get_exception_handler() is None:
                    loop.set_exception_handler(_asyncio_hook)
            except Exception:
                pass
        if _ORIG_NEW_LOOP is None:
            try:
                _ORIG_NEW_LOOP = aio.new_event_loop

                def _guarded_new_loop(*a, **k):
                    lp = _ORIG_NEW_LOOP(*a, **k)
                    try:
                        if lp.get_exception_handler() is None:
                            lp.set_exception_handler(_asyncio_hook)
                    except Exception:
                        pass
                    return lp

                aio.new_event_loop = _guarded_new_loop
            except Exception:
                pass
        return True
    except Exception:
        return False


def _unwrap_asyncio():
    """new_event_loop sarimini kaldir (uninstall)."""
    global _ORIG_NEW_LOOP
    try:
        if _ORIG_NEW_LOOP is not None:
            try:
                aio = _sys.modules.get("asyncio")
                if aio is not None:
                    aio.new_event_loop = _ORIG_NEW_LOOP
            except Exception:
                pass
            _ORIG_NEW_LOOP = None
        return True
    except Exception:
        return False


def install_hardening():
    """Butun sizinti-hook'larini tak. Idempotent, fail-closed."""
    global _HARDENED
    try:
        if _HARDENED:
            return True
        try:
            _prev_hooks["excepthook"] = _sys.excepthook
        except Exception:
            pass
        try:
            _prev_hooks["thread_excepthook"] = _threading.excepthook
        except Exception:
            pass
        try:
            _prev_hooks["unraisablehook"] = _sys.unraisablehook
        except Exception:
            pass
        try:
            _prev_hooks["showwarning"] = _warnings.showwarning
        except Exception:
            pass
        try:
            _sys.excepthook = _excepthook_main
        except Exception:
            pass
        try:
            _threading.excepthook = _excepthook_thread
        except Exception:
            pass
        try:
            _sys.unraisablehook = _unraisable_hook
        except Exception:
            pass
        try:
            _warnings.showwarning = _showwarning_hook
        except Exception:
            pass
        try:
            _prev_hooks["raise_exceptions"] = bool(_logging.raiseExceptions)
        except Exception:
            pass
        try:
            _logging.raiseExceptions = False
        except Exception:
            pass
        try:
            _aio = _get_asyncio()
            loop = _aio.get_event_loop() if _aio is not None else None
            if loop is not None:
                try:
                    _prev_hooks["asyncio_handler"] = loop.get_exception_handler()
                except Exception:
                    pass
                try:
                    loop.set_exception_handler(_asyncio_hook)
                except Exception:
                    pass
        except Exception:
            pass
        try:
            _prev_hooks["filter_added"] = _attach_filter_obj()
        except Exception:
            pass
        try:
            harden_all_loggers()
        except Exception:
            pass
        try:
            _wrap_add_handler()
        except Exception:
            pass
        try:
            _wrap_asyncio()
        except Exception:
            pass
        _HARDENED = True
        return True
    except Exception:
        return False


def uninstall():
    """Hook'lari geri yukle (test/teardown icin)."""
    global _HARDENED
    try:
        for name, target_set in (
                ("excepthook", lambda f: setattr(_sys, "excepthook", f)),
                ("thread_excepthook", lambda f: setattr(_threading, "excepthook", f)),
                ("unraisablehook", lambda f: setattr(_sys, "unraisablehook", f)),
                ("showwarning", lambda f: setattr(_warnings, "showwarning", f))):
            try:
                if name in _prev_hooks:
                    target_set(_prev_hooks[name])
            except Exception:
                pass
        try:
            if "raise_exceptions" in _prev_hooks:
                _logging.raiseExceptions = bool(_prev_hooks["raise_exceptions"])
        except Exception:
            pass
        try:
            # R14: sadece bizim ekledigimiz filtre kaldirilir; kullanicinin
            # kendi RedactFilter'i (veya onceki kurulum) korunur.
            _detach_filter_obj(obj=_prev_hooks.get("filter_added"))
        except Exception:
            pass
        try:
            _unwrap_add_handler()
        except Exception:
            pass
        try:
            _unwrap_asyncio()
        except Exception:
            pass
        try:
            if "asyncio_handler" in _prev_hooks:
                try:
                    _aio = _get_asyncio()
                    loop = _aio.get_event_loop() if _aio is not None else None
                    if loop is not None:
                        prev = _prev_hooks["asyncio_handler"]
                        if prev is None:
                            try:
                                loop.set_exception_handler(None)
                            except Exception:
                                pass
                        else:
                            try:
                                loop.set_exception_handler(prev)
                            except Exception:
                                pass
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass
    _HARDENED = False
    return True


def is_hardened():
    return bool(_HARDENED)


# ---------------------------------------------------------------------------
# Sinyaller
# ---------------------------------------------------------------------------

def _sig_bare_excepthook():
    """S1 (STRONG): ham excepthook = yakalanmamis traceback stderr'e acik."""
    try:
        cur = _sys.excepthook
        orig = _sys.__excepthook__
    except Exception:
        return None
    try:
        if cur is orig:
            return True
        if getattr(cur, "__name__", "") == "_excepthook_main" and cur.__module__ == __name__:
            return False
        return False
    except Exception:
        return None


def _sig_bare_thread_hook():
    """S2 (STRONG): ham thread-hook = worker traceback'i stderr'e acik."""
    try:
        import threading as _t
        cur = _t.excepthook
        dflt = _t.__excepthook__ if hasattr(_t, "__excepthook__") else None
    except Exception:
        return None
    try:
        if dflt is not None and cur is dflt:
            return True
        if getattr(cur, "__name__", "") == "_excepthook_thread" and cur.__module__ == __name__:
            return False
        if getattr(cur, "__module__", "") == "threading" and getattr(
                cur, "__name__", "") in ("_thread_excepthook", "threading_excepthook"):
            return True
        return False
    except Exception:
        return None


def _sig_bare_unraisable():
    """S3 (STRONG): ham unraisable-hook = GC/async-artigi ham basilir."""
    try:
        cur = _sys.unraisablehook
    except Exception:
        return None
    try:
        if getattr(cur, "__name__", "") == "_unraisable_hook" and cur.__module__ == __name__:
            return False
        try:
            mod = getattr(cur, "__module__", "") or ""
            if mod == "sys" or "unraisable" in getattr(cur, "__name__", ""):
                return True
        except Exception:
            pass
        return False
    except Exception:
        return None


def _sig_loud_raise_exceptions():
    """S4 (STRONG): logging.raiseExceptions acik = bozuk sink stderr'e basar."""
    try:
        return bool(_logging.raiseExceptions)
    except Exception:
        return None


def _sig_no_redaction_filter():
    """W1 (WEAK): RedactFilter kapsami eksik = log-satiri sizintiya acik.

    Zorlama handler-seviyesindedir (her yayim filtreden gecer); handler
    yoksa logger-seviyesine bakilir. Sertlestirme sonrasi False doner.
    """
    try:
        cov = logging_coverage()
        try:
            ht = int(cov.get("handlers_total", 0) or 0)
            hc = int(cov.get("handlers_covered", 0) or 0)
            if ht > 0:
                return ht > hc
            lt = int(cov.get("loggers_total", 0) or 0)
            lc = int(cov.get("loggers_covered", 0) or 0)
            return lt > lc
        except Exception:
            return True
    except Exception:
        return None


def _sig_warnings_not_captured():
    """W2 (WEAK): ham showwarning = uyari-yolu dosya-yolu sizdirir."""
    try:
        cur = _warnings.showwarning
    except Exception:
        return None
    try:
        if getattr(cur, "__name__", "") == "_showwarning_hook" and cur.__module__ == __name__:
            return False
        return True
    except Exception:
        return None


def _sig_debug_dev_flags():
    """W3 (WEAK): -X dev / -d = ayiklayici-detay uretimi acik."""
    try:
        fl = _sys.flags
        if bool(getattr(fl, "dev_mode", False)) or bool(getattr(fl, "debug", False)):
            return True
        return False
    except Exception:
        return None


def _sig_residual_secret():
    """W4 (WEAK): son hata-degerinde kimlik deseni = sizinti zaten olmus."""
    try:
        last = getattr(_sys, "last_value", None)
        if last is None:
            return False
        try:
            s = last.args[0] if getattr(last, "args", None) else str(last)
            s = s if isinstance(s, str) else str(s)
        except Exception:
            return None
        return bool(has_secret(s))
    except Exception:
        return None


def _sig_hardening_not_installed():
    """W5 (WEAK): modul sertlestirmesi bu processte aktif degil."""
    try:
        return not bool(_HARDENED)
    except Exception:
        return None


_SIGNALS = (
    ("bare_excepthook", True, _sig_bare_excepthook),
    ("bare_thread_hook", True, _sig_bare_thread_hook),
    ("bare_unraisable", True, _sig_bare_unraisable),
    ("loud_raise_exceptions", True, _sig_loud_raise_exceptions),
    ("no_redaction_filter", False, _sig_no_redaction_filter),
    ("warnings_not_captured", False, _sig_warnings_not_captured),
    ("debug_dev_flags", False, _sig_debug_dev_flags),
    ("residual_secret", False, _sig_residual_secret),
    ("hardening_not_installed", False, _sig_hardening_not_installed),
)


# ---------------------------------------------------------------------------
# Ortak API (kardes modullerle ayni sekil)
# ---------------------------------------------------------------------------

def _raw_results():
    out = {}
    for name, _strong, fn in _SIGNALS:
        try:
            out[name] = fn()
        except Exception:
            out[name] = None
    return out


def _score_from(res):
    s = w = 0
    for name, strong, _fn in _SIGNALS:
        v = res.get(name)
        if v is True:
            if strong:
                s += 1
            else:
                w += 1
    return (s, w, s * STRONG + w * WEAK)


def score():
    """(strong_sayisi, weak_sayisi, toplam_puan). None = bilinmiyor."""
    return _score_from(_raw_results())


def status():
    """Durum ozeti: tripped = >=1 STRONG veya >=2 WEAK."""
    try:
        res = _raw_results()
        s, w, pts = _score_from(res)
    except Exception:
        return {"tripped": None, "strong": 0, "weak": 0, "points": 0,
                "results": {}, "hardened": is_hardened()}
    try:
        tripped = bool(s >= 1 or w >= 2)
    except Exception:
        tripped = None
    try:
        admin = {"admin_authorized": len(_ADMIN_MODULES),
                 "admin_locked": _ADMIN_LOCKED, "admin_denied": _ADMIN_DENIED}
    except Exception:
        admin = {}
    out = {"tripped": tripped, "strong": s, "weak": w, "points": pts,
           "results": res, "hardened": is_hardened()}
    try:
        out.update(admin)
    except Exception:
        pass
    return out


def check_all():
    return status()


def harden():
    """Sertlestirmeyi kur + redakte filtreyi tak. Her zaman True doner."""
    try:
        install_hardening()
    except Exception:
        pass
    try:
        attach_filter()
    except Exception:
        pass
    return True


def guard(fn, *args, **kwargs):
    """Once sizinti-durusunu denetler, sonra calistirir (fail-closed).

    Trip aninda fn HIC calismaz; cikista tekrar denetlenir.
    """
    try:
        st = status()
    except Exception:
        st = {"tripped": None}
    if st.get("tripped"):
        raise ErrorLeakageDetected("protected")
    # R6: collapse except-ICINDE kurulur ama raise blok-DISINDA yapilir.
    # Except-blok cikisinda thread exception-context'i None'a doner
    # (PEP 3134 kural 4); boylece SafeError.__context__ bos kalir:
    # `from None` yalnizca gorunumu bastirir, baglantiyi koparmazdi.
    err = None
    try:
        out = fn(*args, **kwargs)
    except ErrorLeakageDetected:
        raise
    except SafeError:
        raise
    except Exception as e:
        try:
            err = collapse(e)
        except Exception:
            err = None
        if err is None:
            try:
                err = SafeError(detail="[collapse failed]")
            except Exception:
                err = None
    if err is not None:
        raise err from None
    try:
        st2 = status()
    except Exception:
        st2 = {"tripped": None}
    if st2.get("tripped"):
        raise ErrorLeakageDetected("protected")
    return out


def assert_no_leakage():
    st = status()
    if st.get("tripped"):
        raise ErrorLeakageDetected("protected")
    return True


def start_watchdog(interval=5.0):
    """Periyodik durus denetimi (daemon). Trip'te stderr'e tek-tip satir."""
    global _watchdog_stop, _watchdog_thread, _ADMIN_LOCKED
    try:
        with _filter_lock:
            _ADMIN_LOCKED = True
    except Exception:
        pass
    try:
        _stop_watchdogs_impl()
    except Exception:
        pass
    try:
        iv = float(interval)
        if not (0.5 <= iv <= 3600.0):
            iv = 5.0
    except Exception:
        iv = 5.0
    stop = _threading.Event()
    _watchdog_stop = stop

    def _loop():
        try:
            emitted = False
            while not stop.wait(iv):
                try:
                    st = status()
                except Exception:
                    continue
                if st.get("tripped"):
                    # Manda-baski: trip surerken her tick yazma (stderr
                    # seli = log-DoS). Ilk tespitte tek satir, sonrasi sessiz.
                    if not emitted:
                        _emit_client("ERROR error-leakage posture tripped")
                        emitted = True
                else:
                    emitted = False
        except Exception:
            pass

    try:
        th = _threading.Thread(target=_loop, name="errleak-watchdog",
                              daemon=True)
        _watchdog_thread = th
        th.start()
        return True
    except Exception:
        return False


def _stop_watchdogs_impl():
    global _watchdog_stop, _watchdog_thread
    try:
        if _watchdog_stop is not None:
            try:
                _watchdog_stop.set()
            except Exception:
                pass
        th = _watchdog_thread
        if th is not None:
            try:
                if th.is_alive():
                    th.join(timeout=2.0)
            except Exception:
                pass
    except Exception:
        pass
    _watchdog_stop = None
    _watchdog_thread = None
    return True


def stop_all_watchdogs():
    """Watchdog'u durdur (YONETIM: kayitli operator sart)."""
    if not _check_admin():
        _deny_admin("stop_all_watchdogs")
    return _stop_watchdogs_impl()


__all__ = [
    "STRONG", "WEAK",
    "ErrorLeakageDetected", "SafeError",
    "scrub", "has_secret", "safe_error_description", "format_traceback_safe",
    "collapse", "lookup_detail",
    "RedactFilter", "SanitizedFormatter", "attach_filter",
    "harden_all_loggers", "logging_coverage",
    "install_hardening", "uninstall", "is_hardened", "authorize_admin",
    "status", "score", "check_all", "harden", "guard", "assert_no_leakage",
    "start_watchdog", "stop_all_watchdogs",
]
