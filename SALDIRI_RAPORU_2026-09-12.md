# HyperCipherAnti — 5 Ajan Adversarial Saldırı Raporu

Tarih: 2026-09-12
Kapsam: `Desktop\HyperCipher\HyperCipherAnti` — 34 modülün tamamı
Yöntem: 5 paralel Sisyphus Junior saldırı ajanı (deep + security-research). Her ajan dosyaları baştan okudu, canlı PoC ile ispatladı, hiçbir dosyayı değiştirmedi.
Ortam: CPython 3.11.0 / Windows (win32). LSP diagnostics: temiz.

## Özet Skor

| Grup | Dosyalar | Bulgu |
|---|---|---|
| Grup 1 (bg_2290e0b9) | analysis, bytecode, config-tamper, constant, control-flow, data-flow, debug | 32 bulgu: 2 CRITICAL, 12 HIGH, 12 MEDIUM, 6 LOW/INFO — "0 açık" iddiası ÇÜRÜTÜLDÜ |
| Grup 2 (bg_562146ea) | decompile, dump, emulation, environment, error-leakage, exception, extraction | 22 bulgu: 3 HIGH, 12 MEDIUM, 7 LOW/INFO — temiz dosya YOK |
| Grup 3 (bg_e567a615) | fuzzing, hook, import, instrumentation, introspection, key-extraction, memory | 40 bulgu: 1 CRITICAL, 13 HIGH, 18 MEDIUM, 8 LOW — tamamı PoC'lu |
| Grup 4 (bg_cd2598da) | module-manipulation, oracle, patch, profiling, reflection, sandbox, side-channel | 46 bulgu: 2 CRITICAL, 14 HIGH, 21 MEDIUM, 9 LOW — hiçbir dosya değiştirilmedi |
| Grup 5 (bg_3d2c1bf4) | string-extraction, symbol-recovery, tamper, trace, traceback, vm | 35 bulgu: 4 CRITICAL, 9 HIGH, 15 MEDIUM, 7 LOW/INFO — 14 PoC çalıştırıldı |

Toplam: 183 madde, 9 CRITICAL. Hiçbir ajan "tamamı temiz" raporu vermedi.

---

# GRUP 1 — analysis / bytecode / config-tamper / constant / control-flow / data-flow / debug

## 1. anti_analysis.py (1840 satır)

- **F1 HIGH** `anti_analysis.py:548-565` (`_check_timing_skew` + `_TIMING_BASELINE`) + `1547-1588` (`_self_fp`): baseline zehirleme timing katmanını kör eder. Saldırı: `aa._TIMING_BASELINE = 1e9` → `cur > base*8.0` asla true olmaz. Kanıt: `baseline before: 6.4e-06` → zehir sonrası `timing_skew: False`, `sensor_health: False`.
- **F2 HIGH** `1466-1485` (`watch`, `_WATCH_CAP=4096`): kimliksiz flood defender watch'larını VE pinleri atar (`_PINS.pop`, satır 1480). Saldırı: 5000 dummy lambda ile `watch()`. Kanıt: `pins before: 1` → `after: 0, defender pin surviving: False`.
- **F3 MEDIUM** `982-1047` (`_resolve_obfuscated_name`) + `1179-1203/1224-1238` (`audit_source`): `join` / slice-reverse / `fromhex` / `bytes()` inşası görünmez. Kanıt: `getattr(sys, "".join(["set","trace"]))(f)` → `tripped: False, []`; `getattr(sys, "ecarttes"[::-1])(f)` → `tripped: False, []`. (Direkt `"set"+"trace"` ve `chr()` zinciri yakalanıyor.)
- **F4 MEDIUM** `1307-1395` (`scan_function`): bytecode taraması `chr()`-kurulu hook isimlerini kaçırır. Kanıt: `getattr(s, chr(115)+chr(101)+…)` → `{}` (sinyal yok).
- **F5 LOW** `1621-1671` (`_raw_results`): asimetrik fail-open — `sensor_health` hariç her sinyal exception'da `False` döner.
- **F6 INFO** `355-361`, `693-721`: proses-dışı tracer (ikinci proses, kopya `.pyc` üzerinde offline `dis`) mimari olarak görünmez.

## 2. anti_bytecode_analysis.py (950 satır)

- **F7 CRITICAL** `472-499` (`seal`) + `550-571` (`verify`): seal CANLI modül özniteliğini değil ESKİ nesneyi doğrular. Saldırı: `seal(mod.legit)` sonrası `mod.legit = evil` → canlı kod hostile, verify hâlâ geçer. Kanıt: `verify: True | live result: PWNED | sealed fn result: 1`.
- **F8 HIGH** `262-281` (`reset_audit_flags`, public, auth yok): saldırgan `compile/exec/marshal` izlerini sıfırlar. Kanıt: `delta before: 2, swallowed: 2 | after: 0 | audit_event: False`.
- **F9 HIGH** `168-188` (`_quiet_audit` / `_AUDIT_TLS.suppress`): suppression sayacı düz yazılabilir thread-local. Saldırı: `_AUDIT_TLS.suppress = 999` → tüm olaylar sayılmayan `_AUDIT_INTERNAL` kanalına. Kanıt: suppressed exec sonrası `delta: 0` (normale `2`).
- **F10 MEDIUM** `502-520` (`unseal`) + `908-920` (`stop_all_watchdogs`): argsız `unseal()` TÜM seal'leri siler; watchdog kill-switch public/authsuz. Kanıt: `seals 2 → 0, verify: True`; `watchdogs stopped: 1`.
- **F11 MEDIUM** `642-649` (`_check_audit_events`): fail-open default — hook kurulu değilse `False` ("şüphe yok"). Kanıt: fresh state tüm sinyaller `False`, `analyzed` temiz.
- **F12 LOW** `610-631` (`_pinned_mismatch`): sadece `sys.modules` kimliği, `gc.get_objects`, `hashlib.sha256`, `time.perf_counter` pinli — `os._exit`, `threading.Lock/Event/Thread`, `_SYS_ADDAUDITHOOK` monkeypatchlenebilir.

## 3. anti_configuration_tamper.py (1022 satır)

- **F13 HIGH** `620-655` (`freeze_config` / `verify_frozen`): shallow-freeze aliasing — `snapshot = dict(plain)` iç içe mutable'ları paylaşır. Saldırı: `cfg["keys"].append("EVIL")` → `verify_frozen: False` (tespit edilmedi).
- **F14 HIGH** `879-897` (`score`/`is_compromised`/`status`) — hata durumunda fail-open: `score()` → `(0,0,0)`, `is_compromised()` → `False`, `status()` → `tripped: False`. Diğer tüm kardeş modüller fail-closed. Kanıt: `verify_pins` raise'e zorlandı → `score: (0,0,0), compromised: False, tripped: False`.
- **F15 MEDIUM** `405-427` (`pin_env`): re-pin kanıtı siler; sayaç/seal/auth yok. Kanıt: `tamper detected: True` → re-pin sonrası `False`.
- **F16 MEDIUM** `836-857` (`watch`/`unwatch`): registry `__qualname__` ile anahtarlı (çakışmada sessiz overwrite), `unwatch()` public. Kanıt: qualname-çakışması defender girdisini attı; `unwatch` sonrası `dangerous_env_target: False`.
- **F17 LOW** `657-686` (`minimal_env`): allowlist 512 char'a kadar attacker-etkili mutlak path'leri (`C:\Windows\Temp\evil`) geçirir.

## 4. anti_constant_analysis.py (726 satır)

- **F18 HIGH** `313-331` (`_shaped_payload`: `if " " in t or "\\" in t: return False`): tek-karakter doldurma entropy dedektörünü tamamen atlatır, payload korunur. Kanıt: saf 128-char b64 → `high_entropy_const: True`; aynı byte'lar 16'lı boşluklu gruplu (aynı 96 byte'a decode) → `False`. Hex blob'da aynı.
- **F19 MEDIUM** `185-205` (`_consts_flat(skip_doc=True)`): `co_consts[0]` docstring keyword VE entropy taramasından muaf. Saldırı: payload'ı docstring'e sakla. Kanıt: `exec(`, `os.system`, `socket`, `ctypes`, `compile(` içeren 100+ char docstring → tüm sinyaller `False`.
- **F20 MEDIUM** `334-361` (`exec_marshal_chain`): zincir tehlike-ismi + blob'u SADECE üst-seviye const tablosunda arar (nested code objelerine inmez). Saldırı: `import marshal` dışta, 64+ char blob sadece `inner()` içinde → zincir kurulmaz. Kanıt: nested-split fixture → `exec_marshal_chain: False`.
- **F21 LOW** `568-596` (`check_all`) + `476-491` (`verify_pins`): fail-open default — boş registry → all-`False` → `is_compromised: False`; sinyal exception'ları `False`'a maplenir.
- Dayanan alanlar: `"sys"+"tem"` concat yakalandı (`getattr_indirection: True`); dict-sarılı keyword stringler yakalandı.

## 5+6. anti_control_flow_analysis.py (669) & anti_data_flow_analysis.py (667) — ortak dedektör DNA'sı

- **F22 HIGH** ikisi de: `_module_present` = `sys.modules` isim kontrolü (`acf:164-190`, `adf:184-210`). Saldırı: `del sys.modules["angr"]` — motor nesnesi referansla yaşamaya ve çalışmaya devam eder. Kanıt: `dse baseline: True → sys.modules del sonrası: False`, `engine object still usable: angr`.
- **F23 HIGH** ikisi de: `_finder_tag` saldırgan-kontrollü `__module__`'a güvenir (`acf:465-472`, `adf:458-465`) + allowlist-prefix skip. Saldırı: `EvilFinder.__module__ = 'importlib.evil_loader'`. Kanıt: `sys.meta_path[0]`'daki hostile finder, tag `importlib.evil_loader.evilfinder` → iki modülde de `foreign_finder: False`.
- **F24 MEDIUM** ikisi de: trip kuralı `≥1 STRONG veya ≥2 WEAK`, finder TEK görünür WEAK — spoof'lu/gizli finder tek başına asla trip etmez; F22+F23 ile iki STRONG da karanlık. Kanıt: hostile finder yerleşikken `is_flow_analyzed: False`, `is_dataflow_analyzed: False`.
- **F25 MEDIUM** `adf:304-345` (`_check_runtime_trace`) re-pin (`adf:81-82`): `_SYS_GETTRACE/_SYS_GETPROFILE` overwrite edilebilir modül globalleri, pin kapsamı dışında. Saldırı: `sys.settrace(evil)` + `adf._SYS_GETTRACE = lambda: None`. Kanıt: `runtime_trace baseline: True → re-pin sonrası: False`; `pinned_mismatch: False`. (3.11 host'ta `sys.monitoring` bacağı yok — iki bacak birden kör.)
- **F26 LOW** ikisi de: saf ölçüm fail-open (`acf:367-433`, `adf:369-438`) — `co_code > 60000` byte / bilinmeyen tip / hata → `0.0` döner.

## 7. anti_debug.py (1018 satır)

- **F27 CRITICAL** `159-263` (`_check_trace_hooks`) vs `108-152` (`_check_pinned_mismatch`): shared-object aliasing ile tam trace-katmanı bypass. Pin `_SYS_GETTRACE`/`_SYS_GETPROFILE`/`_SYS_BREAKPOINTHOOK`'u doğrulamaz; saldırgan modül globallerini re-pin'leyip canlı öznitelikleri AYNI nesnelere patchler: identity check geçer, ikisi de `None` döner. Kanıt: aliasing sonrası `trace_hooks: False`, `is_debugged(include_timing=False): False` — saldırı öncesi kod `True` diyordu.
- **F28 HIGH** `519-544` (`_check_debugger_modules`) + `108-152` (`sys.modules` pin'i yok): canlı `sys.modules`'tan okur. Saldırı: `pdb`/`bdb`'siz scrubbed dict kopyasıyla değiştir. Kanıt: stripped kopya (`removed: ['bdb','pdb']`) → `debugger_modules: False`, `pinned_mismatch: False`, `pdb still functional: True`.
- **F29 MEDIUM** `462-516` (`_check_gc_tracers`, `_GC_TTL = 3.0`): 3 sn sonuç cache'i — temiz tarama sonrası yüklenen tracer TTL dolana kadar görünmez.
- **F30 MEDIUM** `933-976` (watchdog): timing kontrolü sadece her 10. tick'te (`tick % 10`) — `interval=0.5` ile timing katmanı 5 sn'nin ~4.5 sn'si kör; `stop_all_watchdogs()` (992) public/authsuz.
- **F31 LOW** `707-746` (`_check_env_vars`): in-place `del os.environ[...]` (aynı obje) identity pin'i geçirir, bayrak gider.
- **F32 LOW** platform delikleri (Windows): `_check_suspicious_modules` 2 Frida + 4 Sandboxie DLL ismi eşleştirir — rename edilmiş `frida-gadget.dll`/`gum-js` kaçar (Linux listesi kapsar, Windows kapsamaz). `_check_native` win32/linux/darwin dışı runtime'da `False`. Proses-dışı tracing (WinDbg attach) sadece ctypes native bacağına dayanır.

## Grup 1 sistemik bulgular

- **S1 HIGH** — Kimliksiz kill/re-baseline yüzeyi: `stop_all_watchdogs`, `unseal`/`unwatch`, `reset_audit_flags`, `pin_env` re-pin, `freeze_config` re-freeze — proses-içi her koddan sıfır capability ile çağrılabilir. Tehdit modeli ("late-loaded code") saldırganın ta kendisi.
- **S2 MEDIUM** — "Boş = temiz" postürü: 7 modül de hiçbir şey izlenmiyorsa/seal yoksa/pin yoksa temiz rapor verir. Koruma opt-in; arm edilmemiş deployment yeşil verir.
- **S3 MEDIUM** — Pin-check asimetrisi: analysis sensor pinler, debug kendi trace globallerini pinlemez, data_flow `sys.modules`'u pinlemez. Re-pin saldırıları (F25, F27) tam da unutan modülleri vurur.
- **S4 LOW** — Fail-open/fail-closed tutarsızlığı: config-tamper fail-open (F14), analysis karışık (F5), ölçüm helper'ları fail-open (F26). Kompozit verdict en zayıf halkayı miras alır.

## Grup 1 dayanan alanlar (saldırıldı, kırılamadı)

- `anti_analysis.audit_source`: direkt `"set"+"trace"` concat, `chr()` zincirleri, düz-değişken getattr, `import debugpy`, `__import__("debugpy")` hepsi trip eder. `scan_function` direkt `sys.settrace` ref'ini yakalar.
- `anti_bytecode_analysis`: audit-hook liveness probu (`audit_hook_active`, `_AUDIT_SEEN` sayaçlı) ve dual-lock tasarımı (`_AUDIT_LOCK` vs `_THREAD_LOCK`) naive saldırıya dayanır; `verify()` bozuk kayıtta fail-closed.
- `anti_configuration_tamper`: `_read_nofollow` symlink/size/tail-garbage check'leri, `pin_env`/`verify_env` round-trip ve `_UNSAFE_VAL_RE` shell-metachar filtrelemesi dokümante edildiği gibi çalıştı.
- `anti_debug`: pinli `perf_counter`/`monotonic`/`os.environ`-kimlik/`gc.get_objects` swap'te fail-closed trip eder; native Windows `NtQueryInformationProcess` + PEB + cross-validation bacakları kernel-seviyesi gizlenmenin altında API-hook spoof'una yapısal sağlam.
- Örneklenen dosyada `LspDiagnostics`: hata yok.

---

# GRUP 2 — decompile / dump / emulation / environment / error-leakage / exception / extraction

## 1. anti_decompile.py (1122 satır)

- **[HIGH-1]** `unseal()` argsız TÜM seal'leri siler (`453-461`); `verify()` sonra vacuous `True` (479-480). Kanıt: `seal(f)→1, verify→True, unseal()→1, verify→True, seals:0`.
- **[MEDIUM-1]** Import-blocker sökülebilir + bypasslanabilir (`_DecompilerBlocker`, `remove_blocker()` public). `sys.modules` enjeksiyonu / `SourceFileLoader` meta-path'e hiç dokunmaz. Offline `.pyc` hırsızlığı (gerçek decompiler iş akışı) ayrı proseste, tasarım gereği görünmez. Kanıt: `enforce→on:True, attacker removes:True, still on:False`.
- **[MEDIUM-2]** `mock*` allowlist prefix hostile finder'ı gizler (`_TRUSTED_PREFIXES` `"mock"` içerir, 793-794). Saldırı: finder modülünü `mock_evil` adlandır. Kanıt: tag `mock_evil.finder` → `_check_foreign_finder()→False`.
- **[MEDIUM-3]** Hijyen verdict'i 10 sn cache'li (`_HYGIENE_TTL = 10.0`, 704-705). Saldırı: temiz check (cache `False`), TTL penceresi içinde secret'lı kodu yerleştir; watchdog stale `False` kullanır. Cache 256 girdide `clear()`lenir (778-779) — saldırgan 256 modül ismiyle flood'layıp `True`'yu siler.
- **[LOW-1]** Proses-içi trip sinyalleri; gerçek decompilation proses-dışı. `.pyc`'yi kopyalayıp başka yerde uncompyle6/pycdc — korumalı proseste sıfır frame, STRONG'lar sessiz.

## 2. anti_dump.py (1444 satır)

- **[HIGH-2]** `SecureBuffer` plaintext `buf._buf` üzerinden okunabilir — kapsülleme yok (`949-983`: `__slots__` yok, name-mangling yok, düz `self._buf = bytearray(size)`). Saldırı: `bytes(buf._buf)` tek öznitelik okumayla "kilitli" key'i döker; `read()`/`use()` de tasarım gereği plaintext kopya verir. Kanıt: `write(SUPERSECRET…) → bytes(b._buf)[:16] == b'SUPERSECRETKEY12'`.
- **[MEDIUM-4]** `harden()` Windows'ta hiçbir şey yapmadan `no_core: True` raporlar (`315-316`: `if _resource is None: return _OS_NAME != "posix"`). Yanlış güvence. Kanıt (Win): `enforce_no_core→True`, `harden()→{'no_core': True, …}`.
- **[MEDIUM-5]** `protect()` 16-katı olmayan size'ı sessizce reddeder (`1062-1080`: `if self._size % 16 != 0: return False`). Kanıt: `SecureBuffer(20).protect()→False, protected:False` vs `SecureBuffer(32).protect()→True`.
- **[LOW-2]** Dumper-proses taraması isim-tabanlı; rename atlatır / Toolhelp hatası self-DoS. `procdump.exe` → `svchost_helper.exe` (substring yok) → görünmez. Tersine `_iter_win_processes()==[]` → `True` (fail-closed) — Toolhelp sabotajı temiz box'ta false positive.
- **[INFO-1]** `break_dumps()` kardeş modüllerin meşru hook'larını söker (`1252-1354`: `sys.excepthook`/thread/unraisable'i KENDİ import-time baseline'ına restore eder). `anti_error_leakage.install_hardening()` aktifse hook'ları "tampering" diye söker — dost ateşi.

## 3. anti_emulation.py (885 satır)

- **[HIGH-3]** `_check_hv_invalid_leaf()` ölü kod — hep `None` döner (docstring'ten ibaret, `return` yok, 669-676); vendor-imza kontrolü (702-713) `_check_timing_leaf()` içindeki erken `return` (695-699) SONRASINDA → erişilemez. 5 WEAK sinyalden 1'i asla ateşlenemez; verdict ≥2 WEAK ister ama en fazla 4 WEAK ateşlenebilir. Kanıt: `_check_hv_invalid_leaf()→None`; 362 char kaynakta SIFIR `return`.
- **[MEDIUM-6]** RX makine-kodu sayfası write-once, asla re-verify yok (`_ensure_exec`, 273-395; `_FN_*` cached, checksum/re-read yok). Saldırı: 4096 B sayfayı `mov eax,0; ret` stub'larıyla ez → HV biti 0, latency ~0 → tüm sinyaller kalıcı `False`. Dosyada verify yolu yok (grep'le doğrulandı).
- **[MEDIUM-7]** x86 CPUID blob ARM64'te guardsız çalışır — `_IS_X64 = sys.maxsize > 2**32` ARM64'te true (135); aynı x86 opcode darwin/ARM'de kullanılır. ARM64'te `0x0F 0xA2` illegal → SIGILL riski veya exception → `None` → her sinyal `False` → `is_emulated()→False` fail-open. `platform.machine()` kapısı yok.
- **[MEDIUM-8]** Watchdog tespit eder ama tepki vermez — trip sadece loop'tan `break` (813-824; `os._exit`/callback yok). `start_watchdog` `on_detect` parametresi almaz (827).
- **[LOW-3]** Sabit 2500-cycle eşiği, kalibrasyon yok (`_DELTA_THRESHOLD = 2500`, 522-523). Gürültülü bare metal FP, hızlı-host TCG FN.

## 4. anti_environment_analysis.py (1088 satır)

- **[MEDIUM-9]** Benign env var'lar STRONG trip — kitlesel false positive operatörü modülü kapatmaya iter. `PYTHONMALLOC=malloc` (distro/container default), `VSCODE_PID` (VS Code altındaki herkes), HERHANGİ `PYTHONPATH` (382: boş olmayan her değer → STRONG), `PYTHONPYCACHEPREFIX`/`PYTHONUSERBASE`/`PYTHONHOME` → temiz dev box'ta `is_anomalous()→True`. Kanıt: `PYTHONMALLOC=malloc→env_blocklist True, anomalous True`; `VSCODE_PID→True/True`; `PYTHONPATH=C:\mylibs→shadow True, anomalous True`; temiz env → hepsi `False`.
- **[MEDIUM-10]** `sitecustomize` varlığı tek başına STRONG (`572-591`). Ubuntu/apport, conda, enterprise imajları meşru preload → sıfır kötülükle STRONG trip (self-DoS).
- **[LOW-4]** Ölü allowlist girdileri `PYTHONSAFEPATH`/`PYTHONNOUSERSITE` STRONG sette (174-176) ama check'te `continue` ile atlanır (216-219) — liste-mantık kayması.
- **[LOW-5]** PATH yazılabilirlik kapısı sadece ilk 3 girdiye bakar (`entries[:3]`, 328-346) + `os.access` TOCTOU (264-280). Saldırı: 4.+ sıraya yazılabilir dir; check-use arası symlink-swap.

## 5. anti_error_leakage.py (1505 satır)

- **[HIGH-adayı]** Root'taki RedactFilter, kendi handler'lı child logger'lardan sızan kayıtları temizleMEZ — tam secret sızıntısı (`RedactFilter.filter` 723-812; `attach_filter` sadece root'a, 867-873). Saldırı: `logging.getLogger("app")` + özel `StreamHandler/FileHandler` → ham `password=hunter2…` sink'e redakte edilmeden düşer (CPython `callHandlers` yolunda ancestor *filter*'larına danışılmaz). Kanıt: `attach_filter()` sonrası özel handler'lı child logger `login failed password=hunter2-GHOST`'u KELİMESİ KELİMESİNE yaydı (`leaks:True`); root'a propagate olan kayıt da sızdı.
- **[MEDIUM-11]** Safe-key allowlist secret-stem'lerden ÖNCE kontrol edilir — `secret_name`/`token_hint` anahtarlı değerler redaktesiz geçer (`_is_secret_key`, 91-123: `_SAFE_KEY_RES` önce `False` döner; `name|hint` pattern'leri eşleşir). Saldırı: `secret_name`, `token_hint` alan adlı exfil/log. Kanıt: `_is_secret_key('secret_name')→False`; `_scrub_obj({'secret_name':'my-priv4te-pw-VALUE'})` → DEĞİŞMEDEN döndü.
- **[LOW-6]** Client-görünür `ERROR id=` proses-içi cross-boundary okumayla server-side detail ring'e lookup key (`909-919`/`959` stderr'e id basar; `lookup_detail(error_id)` public, caller kontrolsüz, 430-439). Saldırı: stderr'i gören "client" `lookup_detail(id)` çağırır → kayıtlı detayı (path, func adı, redakte ama yapısal traceback) alır. İçerik value-scrub'luydu → LOW.
- **[INFO-2]** Dokümante ama gerçek boşluklar: install sonrası açılan asyncio loop'ları hooksuz (1089-1101 sadece AKTİF loop'u patchler); `_handle_crash`'te `SystemExit` sessiz yutulur (931-936); `format_traceback_safe` path+symbol yayar (tasarım gereği yapısal oracle).

## 6. anti_exception_analysis.py (489 satır)

- **[MEDIUM-12]** `install()` o anki hook'u pinler — önceden kurulu evil hook güvenilir baseline olur (TOCTOU, 368-384: current'i saklar → sarar → SIFIR doğrulamayla `pin()`). Saldırı: `install()` ÖNCESİ `sys.excepthook = evil` → evil `_ORIGINALS`'a ve pin'e girer; `_opaque_hook` her uncaught traceback'i evil'e iletir; `is_analyzed()→False`. Kanıt: evil pre-install → `install()` → `_pinned_mismatch()→False`, `is_analyzed()→False`.
- **[MEDIUM-13]** Hook kimliği (type-name, module, qualname) — dövülebilir; post-install klon mismatch'i atlatır (`_hook_id` 75-81; `_pinned_mismatch` sadece tuple karşılaştırır, 117-135, obje kimliği yok). Saldırı: `install()` sonrası `sys.excepthook`'u aynı `__module__`/`__qualname__`'li taze fonksiyonla değiştir. Kanıt: forged klon → `_pinned_mismatch()→False`, `is_analyzed()→False`.
- **[LOW-7]** `guard` sadece exit'te kontrol eder, entry'de asla (477-489: `__enter__` çıplak `self`; assert sadece `__exit__`). Trip'li halde `with` gövdesi tamamen çalışır; tespit hasardan sonra.

## 7. anti_extraction.py (480 satır)

- **[MEDIUM-14]** Burst eşiği (25 olay / 5 sn) slow-drip ile atlatılır; ring + sayaç public sıfırlanabilir (85-86, 192-199; `reset_audit_flags` public, 154-163, `__all__`'da). Saldırı: 5 sn penceresinde ≤24 `marshal.loads` (100 dosya ~25 sn'de, tespit yok); veya batch aralarında `reset_audit_flags()`. Kanıt: 24 olay → `burst False, delta 24`; 29 olay → `burst True`; `reset→29 silindi → burst False`.
- **[MEDIUM-15]** Fail-open default — hook kapalı = kör; gerçek extraction zaten offline. `enforce_audit_hook` opt-in (120-130); `_AUDIT_INSTALLED` default `False` iken `_check_unpack_burst` `False` döner (192-199). Gerçek pyinstxtractor iş akışı (diskteki `.exe`'yi ayrı proseste oyma) bu prosesin frame/audit hook'una hiç girmez.
- **[LOW-8]** `frozen_ctx` iki spoof'lanabilir saf-Python bayrak (`310-324`: sadece `sys.frozen` / `sys._MEIPASS` tutarlılığı). Saldırı: `sys.frozen=True; sys._MEIPASS='C:\fake'` → tutarlı → `False` (temiz). Kanıt: spoof'lu çift → `frozen_ctx: False`.
- **[LOW-9]** Watchdog flag-only — trip dict girdisi set eder, kimseyi aksiyona zorlamaz (418-450; callback/exit yok). Tespit tepkisiz.

---

# GRUP 3 — fuzzing / hook / import / instrumentation / introspection / key-extraction / memory

## 1. anti_fuzzing.py

- **[HIGH] F1** — Harness tespiti isim-tabanlı; custom harness görünmez. `_check_harness_frames` (122-159) 8 gevşek + 4 katı isim + path izi arar. Saldırgan kendi döngüsüyle sürer (`def run_case(data)`). Kanıt: `def run_case(data): return af.is_fuzzed()` → `custom-harness fuzzed= False`.
- **[HIGH] F2** — `instrument_func`-only saldırı code-rewrite STRONG'unu atlatır. `_check_code_rewritten` (88-95) sadece kendi `_probe`'unu parmak izler. `atheris.instrument_func(victim_fn)` + custom loop → iki STRONG da (`code_rewritten`, `harness_frame`) `False` kalır.
- **[MEDIUM] F3** — Env kontrolü SADECE key'lere bakar, value'lar yok (201-218). Saldırı: fuzz marker'ı value ile taşı (`MYSTUFF=atheris_libfuzzer_running`). Kanıt: value-only → `fuzz_env= False`; key `MY_ATHERIS_OPT` → `True`.
- **[MEDIUM] F4** — `guard.__exit__` gövde raise ettiyse fuzz-trip'i yutar (367-373: `if exc is None: raise` — gövde raise ettiyse fuzz tespiti sessizce atılır). Saldırı: zararlı fuzz loop'unu hep exception'la biten `with guard():` içine sar.
- **[LOW] F5** — Sinyal başına fail-open/fail-closed asimetrisi: `check_all` (225-244) `code_rewritten`/`harness_frame` hata=varsayılan True, `tool_present`/`fuzz_env` hata=False.

## 2. anti_hook.py

- **[HIGH] H1** — `sys.modules['ctypes']` swap tüm native katmanı kör eder, `pinned_mismatch` sessiz. `_seen_import("ctypes")` (156-171) canlı `sys.modules`'tan okur ama `_check_pinned_mismatch` (925-996) sys/builtins/os/gc/threading pinler — **ctypes YOK**. Tüm native check'ler zehirlenebilir handle üzerinden. Kanıt: swapped ctypes → `pinned_mismatch= False`, `native_prologue= False`.
- **[HIGH] H2** — Hook-modül blocklist rename ile atlatılır (731-764: exact isim + sabit prefix listesi). Saldırı: keylogger modülünü `mykbd_evil`/`kbd` adlandır. Kanıt: `sys.modules['mykbd_evil']` → `False`; `sys.modules['keyboard']` → `True`.
- **[MEDIUM] H3** — `_check_frida_threads` Windows'ta ölü kod (1936-1938: `if _PIN_IS_WINDOWS: return False`). Her platform bir aileyi kaybeder.
- **[MEDIUM] H4** — `watch()` forward-reference: `_PIN_BASELINE_KEYS` 471. satırda kullanılır, 2274. satırda tanımlanır. Import sırasında `watch()` çağrısı `NameError` → except-pass ile yutulur → baseline digest sessizce güncellenmez.
- **[LOW] H5** — `start_watchdog` hook'lu durumda fail-open (2107: `assert_no_hook()` raise eder — watchdog başlamaz, trip'li watchdog yerine HİÇ watchdog yok). `check_all` sinyal exception'ını `False` kaydeder (1995-1998).

## 3. anti_import_analysis.py

- **[HIGH] I1** — Loader güveni spoof'lanabilir string karşılaştırma (`_loader_trusted`, 257-280). Saldırı: `FakeLoader.__module__ = '_frozen_importlib'` veya sınıf adı `SourceFileLoader`. Kanıt: iki spoof da → `_loader_trusted= True`.
- **[HIGH] I2** — Spec'siz sahte, stdlib üst-seviye isim giyince İKİ STRONG'u da atlatır (`_check_modules_ghost` 308-316: `loader None + spec None + top in stdtop → continue`; `_check_stdlib_shadow` 369-371: `__file__` yok → `continue`). Saldırı: `sys.modules['json'] = ModuleType(__spec__=None, __loader__=None, __file__ yok)`. Kanıt: replace sonrası `ghost= False, shadow= False`.
- **[HIGH] I3** — Spoof `__module__`'lu `path_hooks` girdisi kaçar (391-414: trusted prefix'e güven). Saldırı: `evil_hook.__module__ = 'importlib._bootstrap_external'`. Kanıt: spoof'lu hook → `foreign_path_hook= False`.
- **[MEDIUM] I4** — Watchdog sadece LIGHT seti izler; WEAK persistence görünmez (`_watchdog_loop` `is_compromised(light_only=True)` 716; `_LIGHT` 627-629 `unknown_meta_finder`, `foreign_path_hook`, `cwd_in_path`, `startup_vector` HARİÇ). `.pth`/hook/CWD-only dayanak watchdog'a hiç trip etmez.
- **[MEDIUM] I5** — `.pth` taraması dar + token-bölünebilir (472-519: sadece `_site_dirs()`, ilk 64 KB, literal token listesi). `getattr(__import__('o'+'s'),'sy'+'stem')` bölmesi, 64KB-sonrası decode, site-dirs dışı `.pth`/customize hepsi geçer.
- **[LOW] I6** — `guard` dekoratörü entry-only (682-692: pre-call `assert_clean()`, post-call kontrol yok).

## 4. anti_instrumentation.py

- **[MEDIUM] N1** — Frida-port probu default-port-only; Gadget config portu değiştirir (modülün kendi R8'i kabul eder). `_check_frida_port` (601-612) sadece 127.0.0.1:27042/27043 arar. Saldırı: Gadget `{"port": 45678}` veya Unix-socket transport. Kanıt: `_FRIDA_PORTS = (27042, 27043)` (598); R8 satır 157-160 configurability'yi kabul ederken sinyal sabit.
- **[MEDIUM] N2** — Parent allowlist rename ile atlatılır (`_check_dbi_parent`, 495-510: exact isimler + `pin[-_0-9]` kuralı). Saldırı: `copy pin.exe myrun.exe; myrun.exe -t tool -- target` → `dbi_parent=False`.
- **[MEDIUM] N3** — Steady-state Stalker `jit_burst`'e tasarım gereği görünmez (R18). Oran `second_max/median >= 15.0` (626-677) sadece ilk-compile burst'ünde ateşlenir; uniform yavaşlama median'ı da kaldırır. Modülün kendi TP'si canlı Stalker altında 3.9/3.3 ölçtü → False.
- **[MEDIUM] N4** — `score()`/`status()`/`evidence()` her biri full sensör suite'ini TEKRAR çalıştırır (120× `compile+exec` JIT probu dahil, çağrı başına ~0.6 sn). `status()` `_collect_results()` + `score()`→`_raw_results()` = çağrı başına 3 full run (859-866) — okumalar arası TOCTOU ile birbirinden ayrışabilir; ayrıca her run kardeş `anti_bytecode_analysis` sensörlerini trip'ler (self-incrimination, 619-622). Kanıt: `score()` wall `0.62s`.
- **[LOW] N5** — Watchdog trip observe-and-die (`_watchdog_loop` 797-808: trip'te sadece `_log()` + `break` — callback/raise yok).

## 5. anti_introspection.py

- **[CRITICAL] P1** — Default postür kör: hiçbir şey `watch()` edilmemişse modül ASLA trip edemez. 10 içerik sinyali sadece `_WATCH` okur (838-852); `_WATCH` boş başlar, `harden()` (926-943) hiçbir şeyi izlemez. Kanıt: fresh import → 13 sinyal `False`, `is_compromised= False`. `inspect.getmembers`, `vars()`, `dir()`, `__dict__` yürüyüşleri `seal()` yoksa temiz verdict.
- **[HIGH] P2** — Statik tarayıcı dinamik öznitelik isimlerine yenilir. `_scan_one` (272-420) literal `LOAD_ATTR`/`LOAD_GLOBAL` + const string eşleştirir. `getattr(o, chr(95)+…)`, `"__cl"+"ass__"`, `operator.attrgetter` `vocab`'a hiç girmez. Kanıt: `chr()`-yoluyla `getattr` fonksiyonu → her sinyal `False`.
- **[MEDIUM] P3** — `inspect.*` audit-hook dalı pratikte ölü. `_audit_hook` (652-673) `event.startswith("inspect.")` sayar ama canlı ölçümde `inspect.getmembers([])` HİÇ `inspect.*` audit olayı yaymıyor (gözlenen: `compile, exec, import, marshal.loads, object.__setattr__, open, sys._getframe` — `inspect.*` yok). Tek güvenilir dal `object.__getattr__`; `_PROBE_NOISE` (136) tam da en çok kullanılan `__code__`/`__dict__` handle'larını muaf tutar. Kanıt: audit-event örneğinde `inspect.*` yok.
- **[MEDIUM] P4** — `verify_pins()` exception'da fail-open + `id()`-anahtarlı pinler (522-529: pin başına `except: continue`, final `return False`; 450/519 `id(f)`). GC sonrası adres-reuse yanlış-nesne karşılaştırması.
- **[LOW] P5** — `guard` pre-check only (907-916); `check_all` dalları exception'ı `False`'a mapler (855-856).

## 6. anti_key_extraction.py

- **[HIGH] K1** — `audit_text` 256 KB cap ile sessizce körleşir (913-915: `if len(candidate) > 256*1024: continue`). Saldırı: secret içeren metni 256 KB üstüne pad'le → `audit_text` False. Kanıt: secret'lı 300 KB metin → `False`; küçük metin → `True`.
- **[HIGH] K2** — Immutable-copy taraması nested container/obje-özniteliği/bytearray'i tasarım gereği kaçırır (`_iter_candidate_buffers` 524-583: dict/list/tuple/set/frozenset/frame-locals SADECE derinlik-1; R11 bytearray'i bilerek hariç tutar). Saldırı: kopyayı nested tut (`{'a': {'inner': secret}}`), öznitelik (`obj.secret`), bytearray. Kanıt: nested-only `False`, obje-özniteliği `False`, bytearray-only `False` (düz-dict kopyalar yakalanıyor → `True` — boşluk tam derinlik≥2/attr/bytearray).
- **[HIGH] K3** — `KeyVault`/`SecureCell` gizliliği düz mutable özniteliklere dayanır. `vault._buf` normal öznitelik; `__getattribute__` guard/name-mangling yok. `_dead`/`_shielded`/`_locked` bayrakları da yazılabilir. Saldırı: `bytes(vault._buf)` `read()`/TTL/muhasebeyi bypass eder; `__dict__['_dead']=False` + buf-swap ile wipe edilmiş vault diriltilir. Kanıt: `bytes(v._buf)[:4]` okunabilir; wipe-sonrası flag-flip + buf-replace → `read()` `b'revive…'` döndürür.
- **[MEDIUM] K4** — Constructor ve her `read()` silinemez `bytes` kopyaları üretir (`__init__` 1679 `raw = bytes(material)` — immutable, zeroize edilemez; `read()`/`_plain()`/`verify()` `bytes` döndürür/temas eder). Modülün kendi tehdit modeli (R2/R7: "bytes/str SIFIRLANAMAZ") tam bunu mahkûm eder.
- **[MEDIUM] K5** — Default watchdog heavy sinyalleri hiç çalıştırmaz (`start_watchdog(deep_every=0)` default 1217-1224: sadece LIGHT set `cmdline/env/clipboard/history/perms/cloud` — `immutable_copies` + `dumpable_process` operatör `deep_every=N` vermedikçe çalışmaz).
- **[MEDIUM] K6** — `watched_file_perms` Windows'ta ölü (`_file_world_readable` 755-765 `os.name != 'posix'` → `None` → sinyal asla ateşlenemez). Projenin birincil deploy platformunda world-readable keyfile → sinyal yok. Kanıt: `os.name= nt`, `audit_file_perms= None`, `watched_file_perms= False`.
- **[LOW] K7** — `verify()` + `__len__` online guessing oracle kurar: `__len__` (1884-1890) exact secret uzunluğunu sızdırır; `verify()` (1810-1821) rate-limitsiz boolean döner (`hmac.compare_digest` timing'i engeller, guessing'i değil).
- **[LOW] K8** — `scan_own_image` sadece `sys.executable` okur (609-617) — script/frozen bundle/`.pyd`/DLL/shared lib kapsam dışı. `is_cloud_synced` prefix-match (802-820) symlink/junction/`subst` ile atlatılır.

## 7. anti_memory_inspection.py

- **[HIGH] M1** — `SecureCell._buf` doğrudan okunabilir/yazılabilir (erişim kontrolü yok). K3 ile aynı sınıf: düz `bytearray` öznitelik; `__getattribute__`/`__getattr__` bariyeri yok. Dokümante kontrat ("bytes(view) dışında erişim YOK", 1593-1602) uygulanmıyor. Saldırı: `bytes(cell._buf)` view/TTL/muhasebesiz secret'ı döker; `cell._buf[:] = …` sessiz tamper. Kanıt: `bytes(c._buf)[:5]` → canlı cell'den `b'hello'`.
- **[HIGH] M2** — HW-breakpoint STRONG sinyali kendi kabulüyle fiilen ölü. `_sig_hw_breakpoints` (591-635) `RtlCaptureContext` + Dr0-3 slot kullanır; kod yorumu (617-621) `RtlCaptureContext`'in Dr register'larını canlı breakpoint'lerle doldurmadığını söyler (gerçek tespit suspend + DİĞER thread'lerin `GetThreadContext`'ini ister). Bir STRONG sütun neredeyse hiç ateşlenemez.
- **[MEDIUM] M3** — `score()` tuple sırası `(total, s, w)` kardeş kontrat `(s, w, total)` ile çelişir (`_score_from_raw` 1431-1441 + docstring uyarısı 1432-1438 "existing callers" için korunuyor). Paylaşılan/kopya caller kodu `s, w, total = ami.score()` unpack'inde 3 değeri de sessizce yanlış okur.
- **[MEDIUM] M4** — Default watchdog observe-only (fail-open tepki). `_watch_loop` (1858-1872) trip'te sadece opsiyonel `cb` çağırır; `cb=None` (default) ile trip HİÇBİR şey üretmez — raise/exit/wipe yok.
- **[MEDIUM] M5** — Silinemez-tip sirkülasyonu (K4 ile aynı tasarım hatası). `SecureCell.__init__` 1612 `bytearray(data)` caller'ın `bytes` girdisini canlı bırakır; `_plain_bytes` (1687) `bytes` döner; `_CellView.__str__` (1575-1581) immutable `str`'e decode eder; `from_env` (1664) `bytes` temp'ten encode eder.
- **[LOW] M6** — `core_posture` WEAK stok sistemlerde True (alarm-yorgunluğu üretici, 1032-1059: RLIMIT_CORE soft ≠ 0 — çoğu Linux default'u). `_win_tool_scan_cached` 5 sn TTL (1073-1080) + Linux komşu taramada 256-PID cap (1189-1195) zaman/kapsam penceresi. `memfd_secret_available` (1500-1524) "capability probe" diye side-effect'li `syscall(447,0)` yapar.

## Grup 3 kesişen notlar

1. Fail-open `check_all` paterni: hook, introspection, import, key-extraction heavy path — tek sensörü raise ettirebilen saldırgan o sensörü kör eder. Sadece fuzzing'in iki STRONG'u ve instrumentation verdict'i fail-closed default'lu.
2. Baseline-poisoning penceresi: hook ve import-analysis import'ta snapshot alır; ilk import ÖNCESİ ekilen her şey (env, `sys.modules`, meta_path, `.pth`) güvenilir baseline olur.
3. Watchdog polling boşlukları: en hızlı default 0.2-0.5 sn; poll-arası install-then-remove saldırılar (geçici finder/env/hook) hiç gözlenmez.
4. `os`/`sys` modül-kimlik pinlemesi eksik: hook 5 modül pinler (sys/builtins/os/gc/threading) — `ctypes`, `importlib`, `site`, `io`, `socket`, `subprocess` swap'leri kimlik-kontrolsüz (H1 `ctypes`'i uçtan uca gösterdi).
5. Dayananlar: fuzzing trip-kural mantığı; introspection TTL/probe matematiği; import canonical-order + naive meta_path append/remove tespiti; key-extraction küçük-metin `audit_text`, `_looks_secret_shaped`, digest-only registry, `arm_exit_wipe`; memory `__reduce__`/`__copy__` blokları + x64-gate'li PEB offset'leri.

---

# GRUP 4 — module-manipulation / oracle / patch / profiling / reflection / sandbox / side-channel

## 1. anti_oracle.py

- **O-1 [HIGH]** `check_all()` sadece `watch()`'lu fonksiyonları tarar → default-kör (fail-open). `check_all()` L841-874 (`_WATCHED` döngü 847-848); docstring L69 kabul eder. Saldırı: decrypt rutininde `watch()` çağırma; modül temiz raporlar. Kanıt: fresh import → all-False, `is_compromised()` → `False`, `status()` tripped False. `guard()`/`assert_clean()` aynı körlüğü miras alır.
- **O-2 [HIGH]** Tag-compare tespiti oracle-vari FONKSİYON İSİMLERİNE kapılı — rename ile kaç. `_scan_one()` L457-460 (`if not ctx and not rsa: return res`), `_is_oracle_context()` L331-343. Saldırı: aynı `expected_tag == got` gövdesi `decrypt_token` adında bayrak (`insecure_tag_compare=True`), `check_tag` adında temiz (`False`). İsim-tabanlı, davranış-tabanlı değil.
- **O-3 [MEDIUM]** Tek dinamik raise multi-bit error-oracle tespitinden kaçar (`_scan_one()` L473-487: `multi_bit = len(distinct)>=2 or unknowns>=2 or (…)`). Saldırı: tek değişken mesajlı `raise ValueError(msg)` → `unknowns==1, distinct==0` → `error_oracle_shape=False`; 2 dinamik raise trip eder.
- **O-4 [MEDIUM]** `is_compromised()`/`score()` exception'da fail-OPEN, "fail-closed" docstring ile çelişir (L905-914 `except: return False`; L896-902 `return 0,0,0`; docstring L74 fail-closed iddia eder).
- **O-5 [MEDIUM]** False positive: `import hmac` + herhangi `==` → `insecure_tag_compare` ateşler (`_window_has_tag()` L218-231: 10-gerilik pencerede `hmac` stringi "tag context" sayılır). Kanıt: benign `decrypt_import_hmac(data): import hmac; return data == b'zz'` → `True`. Tek WEAK oracle sinyaline güveni aşındırır.
- **O-6 [LOW]** `_co_of()` tek-seviye unwrap — `functools.partial`/sarılı callable'ları kaçırır (L527-537: sadece `__wrapped__`/`func` bir seviye). Saldırı: zararlı decrypt'i `functools.partial`'a sar → `co is None` → `scan_function` boş döner.
- **O-7 [LOW]** Length-sinyali error-bit'lere uygulanan structural-message muafiyetini uygulamaz (`_raise_leaks_length()` L412-445 + L492-497 vs error-bit'lerde `_is_structural_msg()`). Meşru public length check (`f"invalid key length {len(k)}"`) STRONG `length_oracle_shape` set eder. Asimetrik FP.

## 2. anti_patch.py

- **P-1 [CRITICAL]** `unpin()` kimliksiz → saldırgan pinleri silip evil'i re-pin'ler (L333-338). Kanıt (PoC): `pin(good)` → `unpin(key)` → `True` → `pin(evil, key=same)` → `verify_pin` → `True`. Pinleme güven kökü 2 çağrıda sökülür.
- **P-2 [CRITICAL]** `reseal()` kirli durumu yeni baseline'a aklatır (L470-479: `_SEALED=False` + `seal()`; auth/onay yok). Kanıt: patch sonrası `reseal()` → truthy, snapshot'lar yeniden yazıldı, önceki tamper artık "temiz".
- **P-3 [HIGH]** Builtin SİLME kör; sadece EKLEME tespit edilir (`_check_builtins()` L568-573: `if len(cur_keys - snap) > 0: return True` — removal'lar yok sayılır). Kanıt: `seal()` anında `builtins._poc_tmp` varken sonra `delattr(builtins,'_poc_tmp')` → `_check_builtins()` → `False`.
- **P-4 [HIGH]** Builtin-modül swap açıkça atlanır (`_check_sys_modules()` L598-599: `if name in _sys.builtin_module_names: continue`). İsmi builtin modül olan girdinin değişimi `continue` ile geçilir.
- **P-5 [HIGH]** `guarded()` TOCTOU: post-check çalışmış zararlı çağrıyı geri alamaz (L357-398: pre-check 370 → `ref(*args)` 374 → post-check 390). Paralel thread pre-check ile çağrı arasında `ref.__code__`'u değiştirir; zararlı gövde çalışır-döner; post-raise etkiyi iptal etmez.
- **P-6 [MEDIUM]** Pre-seal penceresi fail-open; `seal()` ne kadar kirliyse onu snapshot'lar (üç check de `if not _SEALED: return False` — 540/561/590; `seal()` 425-448 koşulsuz snapshot). Saldırı: operatör seal'lemeden ÖNCE `sys.meta_path`/builtins'i patch'le → snapshot meşrulaştırır.
- **P-7 [MEDIUM]** Tripwire sadece `object.__setattr__`'ta `__code__`/pin-attr izler (`_audit_tripwire()` L275-301: `if event != "object.__setattr__": return`). C-seviyesi kod mutasyonu (ctypes ile code byte overwrite), `__dict__`/cell oyunları, `__code__`'a dokunmadan modül-seviyesi rebinding bu olayı hiç yaymaz.
- **P-8 [MEDIUM]** Watchdog sessizce öldürülebilir; `break_patch()` shipped detection oracle (`_stop()`/`stop_all_watchdogs()` 888-913 authsuz; `break_patch()` 811-827 `_TRIPWIRE_COUNT`'u +1/−1 oynatır). Saldırgan `stop_all_watchdogs()` ile heal loop'u öldürür; `break_patch()` ile kalıcı iz bırakmadan exact trip eşiğini öğrenir.
- **P-9 [LOW]** `restore()` `sys.modules`/`path_hooks` pinlerini tasarım gereği iyileştirmez; `_PINS` asla auto-restore edilmez (735-808 + docstring 20-21). `register_attr()`'u unutulan her attr'da evil binding kalır; `guarded()` bayat good ref'i çağırırken diğer caller'lar evil'i kullanır — split-brain execution.

## 3. anti_module_manipulation.py

- **M-1 [HIGH]** `stop_all_watchdogs()` başarı döndüren no-op (917-918: `def stop_all_watchdogs(): return True` — thread registry'e dokunmaz). Kanıt: `start_watchdog` + `stop_all_watchdogs()==True` sonrası thread sayısı 1→2, watchdog Event set edilmedi (leak + yanlış güvence).
- **M-2 [HIGH]** 4 import-bypass vektöründen sadece 2'si izlenir (`_gcd_import`/C-API/Cython izlenmez). `_check_import_fn()` (284-301) sadece `builtins.__import__` + `importlib.import_module`; dosyanın kendi tehdit modeli R3 (21-25) C-API, Cython cimport, `_frozen_importlib._gcd_import`'u bypass sayar.
- **M-3 [HIGH]** Loader-chain kontrolü unknown/None loader'ları atlar → tek-alan wipe STRONG'u atlatır (`_check_loader_chain()` 271-273: `if lname == "?" or lname == "None": continue`). Saldırı: sadece `mod.__loader__ = None` — STRONG `continue` ile atlanır; WEAK `loader_obscured` (336-353) loader VE spec ikisi de unknown ister, tek-alan wipe hiçbir şeyi ateşlemez.
- **M-4 [MEDIUM]** Swap/deletion kör noktaları: kayıp modüller yok sayılır; baseline sadece import'ta (`_check_module_swap()` 250-251 `if mod is None: continue`; `_snapshot_swap_baseline()` 225-240 + modül-seviyesi çağrı 921). A1 deletion STRONG'a görünmez; 921 sonrası lazy-import edilenler hiç baseline'lanmadı → swap karşılaştırılmaz.
- **M-5 [MEDIUM]** Shadow-hunt isim-filtreli + hacim-cap'li (`_check_unregistered_shadow()` 320: kritik set dışı/`os` prefixsiz isimler `continue`; 193/`_GC_SCAN_CAP=50000` + 312-313 `break`). Saldırı: kritik set dışı isimli shadow (`hyper_cipher_evil`, `implant`) atlanır; 50k+ gc objesiyle shadow scan cap'in ötesine itilir.
- **M-6 [MEDIUM]** `verify_pins()` `co_names`'i parmak izler — gövde/const değişimi görünmez (`pin()` 827-833 + `verify_pins()` 836-852 + `_func_names()` 483-504). Saldırı: aynı-process saldırgan `_WATCH[key]`'i aynı-`co_names`'li evil fonksiyonla yazar; davranışsal farklı iki fonksiyonun name-set'i aynı (boş) → verify geçer. İsimler ≠ davranış.
- **M-7 [LOW]** Statik `scan_module()` `pin_mismatch/sensor_health/manipulation_probe_anomaly = False` hardcode'lar (656-661). Statik tarama 12 sinyalin 3'ünü asla raporlayamaz.

## 4. anti_profiling.py

- **PR-1 [HIGH]** `pin()` `(type, __module__, __qualname__)` parmak izler — üçü de saldırgan-yazılabilir → full spoof (PoC). `_fn_id()` 73-81, `pin()` 84-93, `_pinned_mismatch()` 96-111. Kanıt: legit profiler → `pin()` → forged `__module__`/`__qualname__`'li evil → `setprofile(evil)` → `profile_tampered: False`. 2 öznitelik atamasıyla tespit yenilir.
- **PR-2 [HIGH]** Unhardened default kör: `pin()` yoksa tamper sinyali forced `False` (102-103: `if not pinned: return False`). `pin()`'i unutan her deployment'ta `setprofile` tampering tanımsal temiz. "fail-closed" iddiasına (31) karşı fail-open postür.
- **PR-3 [MEDIUM]** Profiler kapsamı 2 kanal + isim listesi; yappi/C-ext/custom monitoring ID'leri kaçar (`_check_profiler_active()` 122-142: sadece `getprofile` + `monitoring.get_tool(2)`; `_PROFILER_MODULES` 145-156). Non-2 tool id'li veya `setprofile`'a hiç dokunmayan C-seviyesi sampler en fazla TEK WEAK `tool_present` trip'ler (tek WEAK asla trip etmez, 231). 10-isimli sette olmayan custom loader adı onu da siler.
- **PR-4 [MEDIUM]** `guard.__exit__` gövde de raise ettiyse profiling trip'i yutar (330-336: `except: if exc is None: raise; return False`). Hata veren kodda profiling raporlanmaz.
- **PR-5 [LOW]** Watchdog sadece kimsenin poll etmeye zorlanmadığı internal flag set eder (`start_watchdog()` 274-306: `state["tripped"]=True`, hook/raise yok).

## 5. anti_reflection.py

- **R-1 [HIGH]** Runtime prob en yaygın merdivene sağır: direkt `x.__class__` audit olayı yaymaz (PoC). `_audit_hook()` (1054-1084) sadece `object.__getattr__` + `gc.*` sayar. Kanıt: audit hook kurulu + `().__class__.__bases__` çalıştı → SIFIR audit olayı, `_PROBE_TIMES` boş. WEAK `reflection_probe_anomaly` gerçek payload'lara karşı near-dead — sadece `getattr(x, name)`-tarzı çağrıları sayar.
- **R-2 [HIGH]** `check_all()` sadece izlenen fonksiyonları tarar → izlenmeyen saldırgan kodu görünmez (fail-open default, 1272-1306: `watched = _WATCH.values()`; PoC fresh `check_all()` all-False, `is_compromised()` False).
- **R-3 [HIGH]** Çıplak `__import__("os").system(...)` kaçışı all-False skorlar. `_scan_one()` — getattr ailesi olmadan çıplak `__import__`'u kapsayan sinyal yok (`reflect_present` ister, 565-566). Kanıt: `def evil_import(): return __import__('os').system('id')` → her sinyal False. Klasik sandbox-escape primitifi bu katmana tamamen görünmez.
- **R-4 [MEDIUM]** `scan_module()` payload'ı listelemeyen boş-olmayan `__all__` ile körlenir (998-1007: `if names:` → sadece listelenen isimler). Saldırı: `mod.__all__ = ['decoy']` → `scan_module` sadece `['decoy']` döner; `__subclasses__`'li `evil_ladder` hiç incelenmez.
- **R-5 [MEDIUM]** Saldırgan-ayarlanabilir + temizlenebilir prob: `configure_probe(10000, 10)` + `reset_counters()` authsuz (1154-1192, 1141-1151; PoC ikisi de True). Saldırgan eşiği 10000'e çekip 60 sn penceresini siler.
- **R-6 [MEDIUM]** `sensor_health` STRONG ölü kod — audit hook'u hiç kontrol etmez (`_check_sensor_health()` 1042-1051: `dis` opmap, `100 in hasconst`, `sha256(b"x")` bakar). Audit-hook yokluğu (kurulmamış/bozuk) tespit edilmez. 6 STRONG'dan 1'i inert.
- **R-7 [LOW]** Watch/pin anahtarları `id(f)` — stale-key karışıklığı (793/819/915). `_WATCH` strong ref tutar (izlenirken hafifletir) ama ref düşen her yolda (unwatch/GC) yeni obje id'yi reuse edip bayat `_PINS` girdisiyle çakışabilir.

## 6. anti_sandbox.py

- **S-1 [MEDIUM]** `joel` kullanıcı adı STRONG sandbox verdict trip'ler — substring FP (PoC). `_SB_USER_SUBS` (747-750) çıplak `"joe"` içerir; `_sig_known_identity()` (800-808) sınırsız `sub in user` yapar (sadece `"test"` word-boundary guard'lı, 803-806). Kanıt: mock user `joel` → `True`. Aynı sınıf: `USER=cape_hater`-tarzı env substring'leri `envblob` yoluyla.
- **S-2 [MEDIUM]** `_sensor` dekoratörü "fail-closed" başlığına rağmen fail-OPEN (165-181: `except: return False`). Kanıt: `os.path.exists` raise'e patch'lendi → `_sig_agent_artifacts()` → `False`. Her sinyal, bağımlılıkları fault'lanarak susturulabilir.
- **S-3 [MEDIUM]** Exoneration vetosu şişman modern sandbox ile erişilebilir → weak-only verdict bastırılır (bu host'ta PoC). `_exonerated()` (1866-1942: 5 oydan 3'ü ister); `is_sandboxed()` (1828-1830) exoneration'da weak-only'yi veto eder. Modern guest'ler FAT (8GB/4CPU/250GB, `/usr/bin` ≥ 50 girdi → apps oyu; ≥4GB+4CPU → resources oyu). PoC: `_exonerated()` → True; sentetik 2-family weak-only `{uptime_fresh, mouse_presence}` → `is_sandboxed()` → `False`. Veto demonstrably ateşliyor.
- **S-4 [MEDIUM]** Watchdog default aksiyonu `os._exit(1)` — kütüphane host prosesi öldürür; yavaş sinyaller onu aç bırakır. `start_watchdog()` (1973-2022, `os._exit(1)` 1998); sinyaller saniyeler tutar (`sleep_acceleration` 0.5s + `mouse_static` 2×1s + `agent_port` ~1s+, hepsi `check_all`'in tek `_LOCK`'u içinde, 1744-1754). Tespit = korunan app'in temizlenmeden intiharı; efektif aralık asla konfigüre edilen değil; reentrant-olmayan `_LOCK` (1729) concurrent verdict okuyucuları bloklar.
- **S-5 [LOW]** `testsigning`/`uac`/`hostname_guid`/8000-port check'leri dar kapsamlı (`_sig_agent_port()` 832-874: sadece localhost:8000 + banner'da sandbox marker şart; `_sig_hostname_guid()` 1627-1646: tam-GUID eşleşme). Non-8000 port, rename hostname, uzak agent host bypass.
- **S-6 [LOW/INFO]** CI/headless FP şekli: `mouse_presence` + `display_anomaly` her headless Linux host'ta ateşler (1028-1045 `/dev/input/mice` yok → True; 1267-1275 DISPLAY/Wayland/fb0 yok → True). Tasarım içerir (ikisi tek `interaction` family, 1767-1768 — tek başına trip yok) ama temiz CI runner'da ikinci-family weak (fresh boot, poverty) cross-family trip'i tamamlar.

## 7. anti_side_channel.py

- **SC-1 [HIGH]** `check_all()` sadece `_WATCH` tarar → boş default temiz (fail-open, 658-680: `targets = list(_WATCH.values())`; PoC `check_all()` → `{}`, `is_compromised()` → `False`). İzlenmeyen kripto kodda secret üzerinde `==`, `random` nonce, secret indexleme — hepsi raporlanmaz. Oracle/reflection ile aynı mimari körlük.
- **SC-2 [MEDIUM]** `weak_random` STRONG globalde `random` adlı HER ŞEYDE ateşler, `getattr` string-split ile bypass edilir (ikisi de PoC'lu). `_uses_weak_random()` (315-334, fallback 330-331: `if "random" in names: return True`). (a) benign `random = 5` global okuma → `weak_random: True` (self-FP, STRONG sinyalde); (b) `getattr(r, 'rand'+'int')(0, n)` → `{}` (gerçek `random` kullanımı görünmez). İsim-tabanlı, dataflow-tabanlı değil (36-38'de kabul edilmiş, sinyali iki yönlü de yeniyor).
- **SC-3 [MEDIUM]** `sensor_health` STRONG erişilemez; `pin_mismatch` health check'e karıştırılmış (`_check_sensor_health()` 649-655: `pin_mismatch` veya sadece-exception'da `sensor_health` döner). 5 STRONG'dan 1'i sadece exception yoluyla ateşlenebilir.
- **SC-4 [MEDIUM]** Tüm secret-actor check'leri isim-regex — local rename ile kaç. `_name_is_secret()` (119-131) + `_window_has_secret()` (180-194, 8-12 insn pencereli LOAD isimleri). Saldırı: `x = secret_key; if x == 1: …; t[x] = …; if x % 2: …` — downstream compare/branch/index/modulo sadece `x` görür → `timing_unsafe_compare`, `secret_branch`, `secret_indexed_lookup`, `variable_time_arith` hepsi kaçar. Maliyet ~0 alpha-rename ile 1 STRONG + 2 WEAK yenilir.
- **SC-5 [LOW]** `probe_timing()` timeout'suz, saldırgan-etkili `verify_fn`'e 24k çağrıya kadar çıkar (816-902: `repeats=3000` × pozisyon × `confirm_runs=2`, deadline yok). Zararlı/yavaş `verify_fn` DEFANSİF prob'u CPU-DoS'a çevirir; monotonic-increase + 5σ kapısı normal CI jitter'ında FN üretir.

## Grup 4 kesişen bulgular

- **X-1 [HIGH]** "Watch-then-judge" mimarisi: 7 modülden 4'ü (oracle, side_channel, reflection, module_manipulation-kısmen) izlemeye alınmamış adversary kodunda temiz rapor verir. 3 modülde canlı doğrulandı (all-False/boş default) + patch unsealed all-False.
- **X-2 [MEDIUM]** Fail-closed terminolojisi en az 3 modülde ters (`oracle.is_compromised→False`, `sandbox._sensor→False`, `profiling` unpinned→False) — başlıklar fail-closed iddia eder. Exception/deploy-edilmemiş durumlar "temiz" okunur.
- **X-3 [MEDIUM]** Aynı-proses saldırgan yönetim düzlemi: `unpin`/`reseal`/`reset_counters`/`configure_probe`/`stop_all_watchdogs` proses-içi herkesçe capability'siz çağrılabilir. Her stateful savunma tek çağrıyla nötr.
- **X-4 [LOW]** `verify_pins` semantiği modülden modüle farklı (oracle bad-dict, reflection/side_channel bool-mismatch, module_manipulation bool-clean) — glue code'da ters-tepki bug'larına davetiye.

---

# GRUP 5 — string-extraction / symbol-recovery / tamper / trace / traceback / vm

## 1. anti_string_extraction.py

- **[CRITICAL]** Public `unwatch()` tüm verdict'leri susturur (`watch()`/`unwatch()` 966-984). `check_all()` sadece `_WATCH` tarar (1108-1127); boş watch = all-False = `is_compromised()==False`. Kanıt: izlenen secret fn → `plaintext_secret: True`; `unwatch()` sonrası → all-False, `is_compromised: False`. Auth yok, unwatch'in kendisi trip etmez.
- **[CRITICAL]** Public `pin()` tamper'lı durumu re-baseline'lar (987-999). Saldırı: `fn.__code__` swap'le, sonra `pin(fn)` tekrar çağır. `_PINS[id(f)]` koşulsuz overwrite, `verify_pins()` yeşile döner. Kanıt: `pin → True`, swap, `verify: False`, re-`pin → True`, `verify: False`.
- **[HIGH]** `_string_fp()` non-string const değişimine kör (366-399). Saldırı: numerik/mantık sabitlerini patch'le (`return 1` → `return 99999`, jump hedefleri, int-arg'lı opcode operandları). Fingerprint `co_code` + sadece `str`/`bytes` const hash'ler; int/float/None/bool const'lar ve `co_names`/`co_varnames` yok sayılır. `LOAD_CONST idx; RETURN_VALUE` bytecode'u ikisinde de aynı, `co_code` bile eşleşir. Kanıt: `fp old == fp new` (`99552868…` ikisinde), swap sonrası `verify_pins: False`.
- **[HIGH]** Runtime-kurulu secret sadece 1 WEAK trip'ler → verdict temiz (scoring 1136-1150 + `_scan_one`). Saldırı: secret'ı `chr()` zinciriyle kur. Sadece `charcode_build` (WEAK, ağırlık 30) ateşlenir; trip ≥2 WEAK veya 1 STRONG ister. Kanıt: chr-kurulu `"AKIA…EXAMPLE"` → sadece `charcode_build: True`, `is_compromised: False`.
- **[MEDIUM]** Whitespace-split base64 `encoded_secret`'i atlatır (`_scan_one` 815-821). Saldırı: base64 blob'u boşlukla böl (`"QUtJ…ON0 VYQU…"`) — `" " in s` guard'ı `continue` eder. Kanıt: AWS-key payload'lı split-b64 → all-False.
- **[MEDIUM]** Docstring-slot secret tasarım gereği görünmez (`_all_strings` 431-432, `_consts_flat` 407). Saldırı: secret'ı fonksiyon docstring'i olarak taşı (`co_consts[0]` FP-azaltma diye atlanır). Kanıt: `def g(): "AKIAIOSFODNN7EXAMPLE"` → all-False.
- **[MEDIUM]** Hostile `__code__` fail-open (`scan_function` 1020-1027, `_scan_one` 796-801). `__code__` property'si raise eden obje → exception → `{}` / all-False; `check_all` temiz sayar. Kanıt: `scan_function(Evil()) → {}`, izlenen evil → `plaintext_secret: False, is_compromised: False`.
- **[LOW]** Registry'ler `id()`-anahtarlı (`_WATCH[id(f)]`, `_PINS[id(f)]`) — gc sonrası stale girdi + teorik id-reuse aliasing (2k-d denemede çakışma bulunamadı → LOW).

## 2. anti_symbol_recovery.py

- **[CRITICAL]** Public `configure_probe()` anomali sensörünü kapatır (754-782). Saldırı: `configure_probe(threshold=10000, window_s=10.0)` — auth yok, trip yok. Kanıt: `True` döner; 60× `note_symbol_probe()` → `symbol_probe_anomaly: False`.
- **[HIGH]** Public `unwatch()` ile statik sinyaller susturulur (`watch`/`unwatch` 434-451, `check_all` 865-875). Saldırı: `unwatch(evil_fn)` `symbol_table_dump`/`code_attr_access`'i verdict'ten çıkarır. Sadece (ayrıca yükseltilebilir) prob sayacı kalır, tek WEAK tek başına trip etmez. Kanıt: izlenirken → `{symbol_table_dump, code_attr_access, symbol_probe_anomaly}`; unwatch sonrası → sadece `symbol_probe_anomaly`, `is_compromised: False`.
- **[MEDIUM]** Audit hook default KAPALI; `arm_frame_watch()` olmadan `frame_access` ölü (433-436, 407-421). `tb_frame`/`f_code` ile frame hasadı sensöre yapısal görünmez. `harden()` arm eder ama default postür fail-open, uyarı yok. Kanıt: default'ta `frame_access: False`, `frame_watch_armed: False`.
- **[MEDIUM]** `seal()` pin-hatasını başarı sayar (558-571: `elif watch(_f): n += 1` — izlenip pinlenemeyen fonksiyon sealed sayısını artırır). Operatör N fonksiyonun pinli olduğuna inanır; gerçekte daha azı pinlidir.
- **[LOW]** Tek-WEAK trip etmez; prob alert kenarı `==` kullanır (`note_symbol_probe` 731: `crossed = len == threshold` alert callback'i sadece exact crossing'de ateşler; verdict `>=` kullanır).

## 3. anti_tamper.py

- **[CRITICAL]** Full registry rewrite TÜM sinyalleri atlatır (`_FUNC_BASE`/`_FUNC_REF`/`_FUNC_BIND`/`_BASELINE_DIGEST`). Saldırı (aynı-proses kod çalıştırma, ~6 statement): func fp+ref'i değiştir, `_FUNC_BIND`'i evil'in `(module, qualname)`'ine rebind et, `_BASELINE_DIGEST = _snapshot_baseline_digest()` ile recompute. 17 sinyal yeşil. Kanıt: full rewrite sonrası `is_tampered: False`, `_raw_results()` all-False. (Bind-fix'siz KISMİ rewrite `func_integrity` ile yakalanır — doğrulandı — yani bar tam "4 dict + digest rewrite", düşük ama sıfır değil.)
- **[HIGH]** `allow_module()` reseal guard'sız (970-978; her `register_*` `_note_reseal` çağırırken bu çağırmaz). Saldırı: seal sonrası `allow_module("evil_mod")` çağırıp import et. `unknown_module` geçer, `_RESEAL_VIOLATION` latch'lenmez. Kanıt: seal-sonrası `allow_module → True`, enjekte `sys.modules["totally_evil_mod"]` → `_check_unknown_module: False`, `reseal_violation: False`.
- **[HIGH]** `_content_digest` non-str dict key'leri yok sayar (459-470; `_mod_content` 493-497). Saldırı: payload'ı int/tuple key altına sakla (`{12345: "AKIA…"}`) — digest boş dict ile aynı `"m:{}"`. Kanıt: `{12345: "AKIAIOSFODNN7EXAMPLE", ("t",): "payload"}` → `"m:{}"`.
- **[HIGH]** Digest truncation derin/geniş yapıları kör eder (`_content_digest` 422-423, 450-462). Saldırı: (a) payload'ı 4 seviyeden derine göm → `"d4:dict"`'e collapse; (b) payload'ı 64-key/str-key-only penceresi dışına koy → sessizce düşer. Kanıt: 5-derin nesting → `m:{a=m:{b=m:{c=m:{d=d4:dict}}}}`; 65. key'i değiştir → digest değişmedi (`False`).
- **[MEDIUM]** `break_tamper()` sadece import machinery'yi onarır (1703-1749: `path/finders/hooks/import/modules` key'leri). File/func/attr/loader/pyc tampering tespit edilir ama ONARILMAZ. `harden()` (1752-1762) `break_tamper` sonrası `tampered` raporlar — operatör "hardened"ı "healed" okuyabilir.
- **[INFO]** Non-verbose `check_all()`/`status()` tüm sinyal detayını gizler (1687-1693, 1862-1867: `check_all → {"tampered": bool}`, `status → {"sealed": bool}`). Oracle-kapalı tasarım; operatör `_VERBOSE` olmadan triyaj verisi alamaz.

## 4. anti_trace.py

- **[HIGH]** Saldırgan tüm watchdog'ları public API ile öldürür (`stop_all_watchdogs()` 1048-1056 — auth/trip/alert yok). Kanıt: başlatılmış watchdog, saldırgan-stop → thread gitti. Bonus defect: `stop_all_watchdogs` event'leri set eder ama `_WATCHDOGS`'tan silmez (stale set-Event'ler birikir; liste sınırsız büyür — gözlenen `watchdogs after stop: [<Event set>]`).
- **[HIGH]** Pre-import kill-switch nötrleme pin-kör (pinler 112-116, check 119-205). Saldırı: `anti_trace` ilk import'undan ÖNCE `os._exit` / `builtins.breakpoint` (veya pinli her ref) patch'le. Pinler nötrlenmiş değerleri yakalar; `_check_pinned_mismatch` malicious==malicious karşılaştırır → temiz; watchdog'un default `os._exit(1)` aksiyonu no-op olur. Kanıt (fresh interpreter): pre-import nötrleme → `pinned_mismatch: False, is_traced: False`.
- **[MEDIUM]** Tracer-modül kontrolü alias import ile atlatılır (`_check_tracer_modules` 606-636). Saldırı: `trace`/`coverage`'ı `importlib` ile masum `sys.modules` alias'ı altında yükle (`"legit_utils"`). Exact-isim + top-level-prefix eşleşmesi ikisi de kaçar. Kanıt: `import trace → True`; aynı code object `legit_utils` olarak → `False`.
- **[MEDIUM]** GC-tracer cache kör pencere verir (`_GC_TTL=3.0`, `_check_gc_tracers` 681-702). Saldırı: defender poll'ünden hemen sonra `Coverage`/`CTracer`-tarzı obje başlat; 3 sn'e kadar tracing stale cached `False` ile servis edilir.
- **[MEDIUM]** Dev-environment false positive'leri (`_COVERAGE_ENV_VARS` 755-797: `PYCHARM_HOSTED`, `VSCODE_PID`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES` `coverage_env` trip'ler). Her IDE-altı proses self-trip.
- **[LOW]** Watchdog suspend-tespiti clock jump'ta öldürür (`start_watchdog` 976-986: `suspend_limit = max(10*interval, 10.0)`; NTP/VM-clock adımı aşarsa default lethal aksiyon). Availability hazard.

## 5. anti_traceback_analysis.py

- **[MEDIUM]** STRONG `live_format_abuse` pratikte near-unobservable (`_check_live_format_abuse` 223-255). Sinyal, yabancı caller'lı `traceback`-modül frame'ini stack'te CANLI yakalamayı ister — yani microsecond-scale format çağrısı sırasında re-entrant sampling. Meşru `traceback.format_exc()` handling'inden hemen sonra çalışan check hiçbir şey görmez (frame'ler unwind oldu). Kanıt: `try/raise/except → format_exc() → check_all()` → `live_format_abuse: False, verdict: False`. 0.5 sn watchdog poll neredeyse asla denk gelmez → 2 STRONG'dan biri near-dead; verdict `module_pin` + WEAK çiftlerine kalır.
- **[MEDIUM]** `guard()` asla raise etmez (599-616). Kardeş guard'ların aksine sadece `sys.tracebacklimit` snapshot/restore + `check_all()` yield eder. Trip'li halde giriş/çıkış sessiz; caller yield edilen dict'i manuel incelemeli. Kanıt: `with guard() as rep:` trip'li halde sessiz girildi.
- **[MEDIUM]** Watchdog latch'ler ama aksiyon almaz (`_watchdog_loop` 624-635). Trip'te `_watchdog_tripped = True` set edip çıkar. Exit/wipe/callback yok; saldırganın görmezden gelebileceği pasif bayrak (`anti_trace`/`anti_vm` watchdog'ları `os._exit(1)` yaparken).
- **[MEDIUM]** `frame_access` default fail-open (`_check_frame_access` 433-436: `arm_frame_watch()` explicit opt-in olmadan `False`). Default postürde `tb_frame`/`f_code` ile hasat görünmez. Kanıt: `frame_access: False`, `armed: False`.
- **[LOW]** Traceback pin'lerinde import-sırası güveni (`_PIN_FUNCS` 72-90). Post-import shim TESPİT EDİLİR (PoC: swap `format_exc` → `module_pin: True`, restore → `False` — sensör çalışır). Ama modül import'undan ÖNCE kurulan shim genuine yakalanır. `anti_trace` ile aynı yapısal caveat.

## 6. anti_vm.py

- **[HIGH]** `is_virtualized()` hook'a kör — `pinned_mismatch` verdict dışı (1663-1664, `_verdict_from` 1741-1768). `_STRONG_LAYERS`/`_WEAK_LAYERS` `pinned_mismatch` içermez. `time.sleep`, `uuid.getnode`, `re.*`, `subprocess.run` hook'layan saldırgan sadece ayrı `is_environment_tampered()` politikasını değiştirir; VM verdict temiz kalır. Kanıt (win32 bare-metal): hooked `time.sleep` → `tampered: True` ama `virtualized: False`. Sadece `is_virtualized()`/`assert_no_vm()` çağıran her tüketici hook-kör; sadece `guard()` (ikisini de kontrol eder) güvenli.
- **[MEDIUM]** Windows'ta tool-yokluğu fail-open (`_check_cpu` 824-835 win32'de `wmic`+powershell fallback'e dayanır; `_run_capture`/`_tool_path` toolsuz `None` → `False`). `wmic`'siz Win11, kısıtlı PATH, `System32` lockdown CPU katmanını sessizce düşürür. Kanıt: `_tool_path` stub→`None` → `cpu: False, systemd: False, virt: False`.
- **[MEDIUM]** Full-spoof tutarlılığı `cross_validation`'ı yener (`_check_cross_validation` 1562-1591, `_hw_brands`). Trip DMI'a aykırı HW-brand kanıtı ister (`hw` dolu + DMI kayıp/uyumsuz). DMI *VE* MAC/PCI/disk'i tutarlı spoof'layan (aynı marka veya hepsi-temiz) saldırgan `hw==[] → False` alır. Sensör özensiz spoof'u cezalandırır, dikkatli full-stack spoof'u geçirir (kod yolu 1569-1571).
- **[LOW]** Timing katmanı iki yöne de gürültülü (`_check_timing` 1433-1454: 10 ms sleep'in iki ardışık >250 ms aşımı gerekir). Host throttle/NTP gürültüsü double-trip edebilir (FP); `perf_counter`/`sleep` hook'u (yukarıdaki HIGH, verdict-dışı) deterministik öldürür. Bu host'ta `timing: False` gözlendi.
- **[LOW]** Verbose-gating operatörü default kör bırakır (`check_all`/`evidence`/`score` 1641-1656, 1697-1738: `HYPERCIPHER_ANTIVM_VERBOSE=1` olmadan `check_all`/`evidence` sadece `{"virtualized": bool}`, `score()` `(0,0,0)`). Production postüründe triyaj/forensics imkânsız; `set_verbose` proses env'ini side-effect ile mutate eder.

---

# GENEL SİSTEMİK SONUÇLAR (tüm ajanlar)

1. **Watch-then-judge mimarisi**: oracle, side_channel, reflection, introspection, string_extraction, symbol_recovery, module_manipulation(kısmen) — izlemeye alınmamış adversary kodunda temiz rapor verir. "0 açık" iddiası sadece watched set içinde geçerli.
2. **Kimliksiz yönetim düzlemi**: `unpin`/`reseal`/`unwatch`/`unseal()`/`reset_audit_flags`/`reset_counters`/`configure_probe`/`stop_all_watchdogs`/`pin_env` re-pin/`freeze_config` re-freeze — proses-içi herkesçe capability'siz çağrılabilir. Her stateful savunma tek çağrıyla nötr.
3. **Fail-closed terminolojisi ters**: oracle `is_compromised→False`, sandbox `_sensor→False`, profiling unpinned→False, config-tamper `score→(0,0,0)`, error-leakage istisnaları — başlıklar fail-closed iddia ederken exception/deploy-edilmemiş durumlar "temiz" okunur.
4. **Pin-kapsam asimetrisi**: analysis sensor pinler; debug kendi trace globallerini pinlemez; data_flow `sys.modules`'u pinlemez; hook `ctypes`'i pinlemez; tamper bind-fix'siz kısmi rewrite'i yakalar ama full rewrite'i kaçırır.
5. **"Boş = temiz" postürü**: seal/watch/pin/hook kurulmamış deployment'lar yeşil verir — koruma opt-in, raporlama ise koşulsuz yeşil.
6. **Proses-dışı görünmezlik**: offline `.pyc` theft, ayrı-proses decompilation/extraction, yabancı-proses memory okuma, kopya-üzerinde `dis` — runtime tripwire'lar mimari olarak göremez (tehdit modeline yazılmalı).
7. **Baseline-poisoning penceresi**: import'ta snapshot alan her modül (hook, import, trace, traceback, module-manipulation, exception) için ilk import ÖNCESİ ekilen her şey güvenilir baseline olur.
8. **Watchdog polling boşlukları + observe-only watchdogs**: en hızlı default 0.2-0.5 sn; poll-arası geçici saldırılar gözlenmez; emulation/traceback/extraction/instrumentation/memory watchdogs trip'te tepki vermez (sadece flag/log/break).
9. **İsim-tabanlı tespitler**: harness isimleri, hook-modül blocklist, loader `__module__`, finder tag prefix'leri (`mock`, `importlib`, `mock_evil`), oracle fonksiyon isimleri, `check_all` isim pencereleri — hepsi rename/spoof ile atlatılır (çok sayıda PoC).
10. **Kriptografik/sızıntı-özel**: `SecureBuffer`/`SecureCell`/`KeyVault` plaintext `_buf` doğrudan okunabilir (3 bağımsız ajan aynı sınıfı buldu); `read()`/`verify()`/`__str__` silinemez `bytes`/`str` kopyaları üretir; `audit_text` 256 KB cap; error-leakage child-logger bypass; `verify()`+`__len__` guessing oracle.

## Ajan dipnotları (dayanan alanlar)

- analysis `audit_source` direkt concat/chr zincirlerini yakalar; `scan_function` direkt `sys.settrace` ref'ini yakalar.
- bytecode audit-hook liveness probu (`_AUDIT_SEEN`) ve dual-lock naive saldırıya dayanır; `verify()` bozuk kayıtta fail-closed.
- config `_read_nofollow` symlink/size/tail-garbage check'leri ve `pin_env`/`verify_env` round-trip dokümante çalışt.
- debug pinli `perf_counter`/`monotonic`/`os.environ`-kimlik/`gc.get_objects` swap'te fail-closed trip eder; native PEB cross-validation yapısal sağlam.
- fuzzing trip-kural mantığı spesifikasyona uygun; key-extraction küçük-metin `audit_text`, `_looks_secret_shaped`, digest-only registry, `arm_exit_wipe` dokümante çalıştı; memory `__reduce__`/`__copy__` blokları + x64-gate mevcut.
- import canonical-order ve naive meta_path append/remove tespiti çalışır (sadece spoof-kimlikli varyantlar kaçar).

---

## SON KONTROL (2026-09-12) — tamamlık doğrulaması

- 5 task full oturumla yeniden okundu: bg_2290e0b9 (8 mesaj), bg_562146ea (6 mesaj), bg_e567a615 (7 mesaj), bg_cd2598da (6 mesaj), bg_3d2c1bf4 (6 mesaj) — hepsinde Has more: false, kayıp mesaj yok.
- Raporun tamamı baştan sona okundu, ajan çıktılarıyla madde madde karşılaştırıldı.
- Bu turda Edit ile eklenenler: Grup 1 "dayanan alanlar" 5 maddesi + özet sayıların gerçek sayıma çekilmesi (G3: 40, G4: 46, G5: 35, toplam 183 madde / 9 CRITICAL).
- Kayıt: hiçbir ajan dosyayı değiştirmedi; tüm HIGH/CRITICAL bulgular canlı PoC'lu; metod notları (LSP temiz, kapsam-dışı dosyaya dokunulmadı, stil raporlanmadı) 5 ajanda da mevcut.
