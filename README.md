# HYPERCIPHER v5

**2048-bit, donanıma bağlı, rotasyonlu stream cipher**

Kendi şifreleme algoritmamız. AES-256'nın mantığını alıp aşırı buffladık:
2048-bit anahtar uzayı, veri odaklı anahtar rotasyonu, donanım
derinliğinde gizlenen (koda gömülmeyen) anahtar, kurcalamaya karşı HMAC.

> **v5 (2026-08-12):** Zayıf passphrase sorununu kökten çözüyor (3 katman):
> **(1) Keyfile (ikinci faktör)** — age/sympa modeli: passphrase + keyfile
> (≥32 byte) → HKDF-SHA512 → Argon2id. (Referans age/sympa HKDF-SHA256
> kullanır; biz SHA512 — 2048-bit master ailesiyle tutarlı, daha güçlü.)
> Saldırgan zayıf perdeyi bilse bile
> keyfile olmadan HİÇBİR şey yapamaz. Header'a `FLAG_KEYFILE` biti eklendi;
> eski v4 paketler geriye dönük uyumlu açılır. **(2) zxcvbn zorunluluğu**:
> CLI encrypt, `guesses_log10 ≥ 14` (~781 yıl @ 1e4/sn) geçmeyen perdeyi
> REDDEDER (`--allow-weak` açık risk kabulü). **(3) Diceware üret üreteci**:
> `generate-passphrase` → EFF 7776 kelime, 6 kelime ≈ 77.5 bit.
> v4 (2026-08-11): KDF `scrypt` → `Argon2id` (RFC 9106, PHC kazananı
> — GPU/ASIC/trade-off direnci en yüksek parola KDF'si; t=3, p=1,
> memory_cost = kdf_n KiB). v3 (2026-08-11): scrypt, HKDF-SHA512 alt anahtar
> türetimi, nonce 24 byte, header 104 byte.
> **Paket formatı geriye dönük uyumlu DEĞİLDİR** — v3 paketleri v4 ile
> açılamaz (kasıtlı: KDF değişimi formatı yeniledi). v4 paketleri v5 ile
> açılır (VERSION 4 korundu, yalnızca yeni flag biti).

---

## Mimari (4 katman)

```
[L1] MASTER KEY (2048 bit / 256 byte)
     master = Argon2id(passphrase || 0x00 || hardware_fingerprint,
                       salt, time=3, lanes=1, memory_cost=2^17 KiB)
              (memory_cost: kdf_n parametresi, [2^14 .. 2^18], 2'nin kuvveti;
               passphrase ile parmak izi arasinda 0x00 ayrac - kaydirma
               catismasi onlenir: "ab"+"c" != "a"+"bc")
     v5 keyfile: passphrase onceli HKDF-SHA512(salt=keyfile, info="HYPR/keyfile/v1")
                 -> KDF'e ORTUKLU girer (keyfile yoksa acilamaz)
     KDF: Argon2id = PHC kazanani, RFC 9106 — brute-force/GPU/ASIC direnci
          için scrypt'ten üstün. Ölçüm (bu makine): 2^17 KiB ≈ 0.87s.

     Anahtar HİÇBİR YERDE saklanmaz:
     - koda gömülü değil
     - disk'e yazılmıyor (key dosyası yok)
     - her çalıştırmada canlı sistemden sıfırdan türetilir

     Donanım parmak izi kaynakları (canlı sorgu, hepsi):
       MachineGuid (registry) + MAC + volume serial + CPU + hostname

     İki faktör: MAKİNE + PASSphrase. Makine olmadan, insan olmadan yok.

[L2] ROTASYON (her rotation_bytes veride TAZE 2048-bit subkey)
     subkey_i = HKDF-SHA512(master, salt=nonce,
                            info="HYPR/subkey/" || LE64(rot_no) || prev_subkey)
                (ZİNCİRLİ: subkey_0 için prev_subkey = master; her subkey
                 bir öncekinden türetilir. LE64 = uint64 little-endian)

     Zincirli yapı: bir subkey'i kırmak sonrakileri vermez; keystream
     tamamen data-driven üretilir (wall-clock yok) - alıcı/verici asla
     senkronizasyon kaybetmez. rotation_bytes değeri paket header'ında
     saklanır (bkz. güvenlik notu).

[L3] KEYSTREAM (dual-family: keyed BLAKE2b XOR HMAC-SHA512 — AES-CTR mantığı)
     b1 = BLAKE2b-512(key=subkey[:64],
                      data=subkey[64:] || LE64(blok_no) || "HYPR1")
     b2 = HMAC-SHA512(key=subkey, data=LE64(blok_no) || "HYPR2")
     blok = b1 XOR b2                                (64 byte)
     ciphertext = plaintext XOR blok

     İki bağımsız hash ailesi aynı anda çalışır: biri gelecekte kırılırsa
     diğeri keystream'i korur (defense in depth).

[L4] BÜTÜNLÜK (Encrypt-then-MAC)
     auth_key = HKDF-SHA512(master, salt=nonce, info="HYPR/auth")
     tag = HMAC-SHA512(auth_key, header || ciphertext)
     Tek bit kurcalansa bile → "dogrulama basarisiz" hatası.
```

Ek "buff"lar:
- Çift hash ailesi: HMAC-SHA512 (key schedule) + BLAKE2b (keystream) + çift
  keystream içinde yine ikisi birden → bir aile kırılırsa diğeri ayakta
- 32 byte tuz + 24 byte nonce: aynı veri aynı key ile iki kez şifrelense
  bile çıktı farklı. **IC[10]:** salt/nonce artık halka açık API'den
  KALDIRILDI (encrypt/encrypt_file sabit nonce kabul etmez) — her çağrı
  CSPRNG ile yeni nonce üretir; nonce reuse (keystream XOR sızıntısı)
  kullanıcı hatasıyla imkânsız (libsodium secretstream/Tink modeli).
  Deterministik testler iç `_encrypt_deterministic()` kullanır. (V5.3: bu
fonksiyonlar **fail-closed** — `_DETERMINISTIC_MODE` açılmadıkça
`RuntimeError` fırlatır; bayrak yalnızca test ortamında `conftest.py`
tarafından açılır. Üretim kodunda **ASLA** çağırmayın.)
- RAM hijyeni: master/auth anahtar materyali kullanım sonrası sıfırlanıyor
- Argon2id memory_cost sınırı [2^14 .. 2^18]: şişirilmiş header ile KDF'yi
  kilitleyip CPU/bellek DoS yapma girişimleri reddedilir; 2'nin kuvveti
  olmayan değerler de reddedilir (servis bütçesi için
  `HYPERCIPHER_MAX_KDF_N` env ile daha da daraltılabilir)
- ATOMIC yazma: çıktı önce `.hyp-*.tmp` güvenli geçici dosyasına yazılır,
  başarıda os.replace; Windows'ta CreateFileW + protected DACL (yalnız
  kullanıcı) ile oluşturulur;
  hata/kurcalamada yarım dosya asla diske düşmez
- Opsiyonel ISO 7816-4 padding (`--pad-to`): dosya boyutu ciphertext'ten
  birebir okunamaz (metadata sızıntısı kapatılır)

## Paket formatı (104 byte header + ciphertext + 64 byte tag)

**KASITLI OLARAK MAGIC YOK.** Dosya başında formatı tanımlayan sabit bir
byte dizisi (`HYPRC1` gibi) bulunmaz — paket random veri gibi görünür,
hangi cipher olduğuna dair ipucu vermez. Bütünlük doğrulaması tamamen
keyed HMAC-SHA512 tag ile yapılır (sabit string kontrolünden güçlüdür).

| Offset | Alan | Boyut |
|---|---|---|
| 0 | version (4) | 1 |
| 1 | flags (bit0 = donanım bağlı, bit1 = padding, bit2 = keyfile; diğer bitler rezevre — set edilirse paket REDDEDİLİR) | 1 |
| 2 | rotation_bytes (uint16, 0 = eski varsayılan 1024) | 2 |
| 4 | kdf_n (uint32, Argon2id memory_cost KiB, 2'nin kuvveti) | 4 |
| 8 | salt | 32 |
| 40 | nonce | 24 |
| 64 | SHA-256(salt || donanım parmak izi) | 32 |
| 96 | veri uzunluğu (padding dahil olabilir) | 8 |

## Matematik: neden "googol yıl"

- 2048-bit anahtar uzayı: **2^2048 ≈ 3.2×10^616** olasılık
- Dünyadaki tüm bilgisayarlar birleşse bile ulaşılamayacak hız olan
  saniyede 10^30 deneme ile bile: **~10^579 yıl**
- Bir googol = 10^100 yıl. Yani senin tahminin bile mütevazıydı. 😄
- Karşılaştırma: AES-256 = 2^256 ≈ 1.16×10^77 deneme
  → HyperCipher'in anahtar uzayı AES-256'dan **10^539 kat** büyük

## Dürüst limitler (okumadan kullanma)

1. **Rotasyon hızı güvenlik EKLEMEZ.** Tüm subkey'ler master key'den
   türetildiği için güvenlik = master key entropisi. Master key'i bilen,
   tüm "değişen" anahtarları da üretebilir. Rotasyonun kriptografik
   faydası: keystream uzunluğu kısıtı olmaması ve iç yapıya saldırıyı
   zorlaştırması.
2. **Brute-force zaten kırma yöntemi değil.** Gerçek saldırılar:
   zayıf passphrase (kısa/tekrar kullanılan), side-channel'lar,
   implementasyon hataları, phishing. 2048-bit anahtar seni brute-force'tan
   korur; insan hatasından korumaz.
3. **Passphrase'i unutursan veri gider.** Kurtarma yok, backdoor yok.
4. **Bu bir öğrenme/mühendislik projesidir.** Kriptografi topluluğunun
   onayından geçmemiş bir algoritmadır. Gerçek üretim sırları için
   **AES-256-GCM / ChaCha20-Poly1305** kullan (benzer mimari, dünya çapında
   on binlerce kriptanalist tarafından 20+ yıl test edildi).
   HyperCipher'ı öğrenmek, denemek ve geliştirmek için yaptık.

## Güvenlik notları

- **Format magic yok.** Paket `HYPRC1` gibi tanımlayıcı bir sabitle
  başlamaz; şifrelenmiş dosya random veri gibi görünür ve hangi cipher
  olduğunu ele vermez. Doğrulama yalnızca keyed HMAC tag üzerinden yapılır.
- **rotation_bytes header'a gömülüdür** (offset 2, uint16). Decrypt bu
  değeri header'dan okur — `--rotation` hatasıyla sessizce bozuk plaintext
  üretme ihtimali **yoktur** (eski sürümlerde bu açık vardı, kapatıldı).
  Ayrıca rotation_bytes 64'ün katı olmalıdır; değilse paket reddedilir.
- **kdf_n üst sınırı vardır** ([2^14 .. 2^18]): şişirilmiş header ile
  Argon2id'i kilitleyip CPU/bellek DoS yapma girişimleri reddedilir; 2'nin
  kuvveti olmayan değerler de reddedilir. Salt/nonce uzunlukları da
  doğrulanır (kurcalanmış/yabancı format reddedilir).
- **Servis riski (DoS bütçesi)**: Argon2id maliyeti header'dan gelir ve
  saldırgan kendi paketinde 2^18 KiB (256 MiB, ~1s CPU) seçebilir. Tek başına
  zararsızdır, ancak **güvenilmeyen paketleri toplu işleyen bir servis** tek
  paketle saniyelerce CPU + yüzlerce MiB bellek tüketimine zorlanabilir.
  Bu yüzden `HYPERCIPHER_MAX_KDF_N` env değişkeni mevcuttur (rscrypto
  `Argon2VerifyPolicy` deseni): servis operatörü bütçesine göre cap'i
   daraltabilir, örn. `HYPERCIPHER_MAX_KDF_N=131072` (128 MiB). Değer 2'nin
   kuvveti ve [2^14 .. 2^18] aralığında olmalıdır; geçersiz değer fail-closed
   (sessizce genişletilmez, açık hata verir). Cap yalnızca **daraltılabilir**,
   asla 2^18 (256 MiB) üzerine çıkarılamaz.
- **fp_hash tuzludur** (`SHA-256(salt || fp_blob)`): parmak izi özeti her
  dosyada farklı salt ile hesaplanır — aynı makinenin paketleri birbirine
  benzetilerek makineye atıf yapılamaz.
- **Donanım parmak izi ENTROPİ DEĞİLDİR** (V4 zafiyet raporu [2]): fp
  kaynakları yarı-kamusal metaveridir (MachineGuid registry'de okunur; MAC/
  serial/hostname paketler üzerinden sızabilir). fp'nin kriptografik rolü
  yalnızca **sahiplik faktörü** (bu makineden başka yerde açılamaz) ve master
  türetimine ekstra girdidir — gücün kaynağı passphrase + keyfile'dır, fp
  asla "ekstra gizlilik" olarak sayılmaz. fp_hash hesabı tek kaynaktan
  (`fingerprint_digest`) üretilir; _build_header ile formül sapması imkânsızdır
  (V4 zafiyet raporu [4]).
- **Keyfile zorunluluğu simetriktir** (V4 zafiyet raporu [3]): keyfile ile
  şifrelenmiş paket keyfile'sız açılamadığı gibi, **keyfile'sız şifrelenmiş
  pakete keyfile verilirse de CipherError** döner (sessizce yok sayılmaz —
  kullanıcı yanlışlıkla "keyfile korumalı" sanmasın). Decrypt'te zayıf perde
  uyarısı yalnızca keyfile koruması **olmayan** paketlerde gösterilir.
- **Passphrase gücü fail-closed** (V4 zafiyet raporu [1]): zxcvbn kurulu
  değilken `assert_strong_passphrase` HER ZAMAN reddeder (builtin tahmin,
  zxcvbn'in 30k+ kelime/l33t/tarih/klavye analizinin yerini tutamaz); builtin
  fallback ayrıca ardışık dizi, tekrar, klavye satırı ve "abab" dönüşümü
  desenlerini tespit edip tahmini 10^6-10^8'e sabitler. Şifreleme zxcvbn
  kurulumu, `generate-passphrase` (Diceware) veya bilinçli `--allow-weak` ile
  mümkündür.
- **Keyfile entropisi ölçülür** (V4 zafiyet raporu [6]): `_validate_keyfile`
  artık boyutun yanında içerik çeşitliliğini de kontrol eder — <8 farklı bayt
  veya Shannon entropisi <3.0 bit/bayt olan tahmin edilebilir dosyalar ikinci
  faktör olarak REDDEDİLİR (`generate-keyfile` önerilir).
- **HKDF çıktı sınırı** (V4 zafiyet raporu [7]): RFC 5869 tek oktet counter
  sınırı 255×64=16320 byte'tır; `_hkdf` bu sınırı aşan uzatma isteğini açıkça
  ValueError ile reddeder (sessiz truncation yok).
- **Opsiyonel ISO 7816-4 padding** (`--pad-to 512` gibi): veri uzunluğu
  ciphertext'ten birebir okunamaz. Padding, HMAC doğrulaması **geçtikten
  sonra** kaldırılır; bozuk paketin plaintext'i asla diske düşmez.
- Decrypt'te plaintext, HMAC doğrulaması **geçene kadar** diske yazılmaz;
  kurcalanmış paketin kısmi içeriği asla hedef dosyaya düşmez.
- CLI, var olan çıktının üzerine `--force` olmadan yazmaz (veri kaybı
  koruması).
- Sınır 2^64 blok/rotasyonda `struct.pack` taşar (~1 ZiB veri) — pratikte
  ulaşılamaz, kabul edilen bir sınır ([27]).
- Python `bytes` immutable olduğu için subkey'ler silinemez; yalnızca
  master/auth key'leri sıfırlanabilir ([37]).

## Kullanım

```powershell
# makine parmak izini gör
python hcli.py hash

# v5: ikinci faktör keyfile üret (64 byte, üzerine yazmaz)
python hcli.py generate-keyfile anahtar.key

# v5: Diceware passphrase üret (EFF 7776 kelime, 6 kelime ≈ 77.5 bit)
python hcli.py generate-passphrase
python hcli.py generate-passphrase --words 7   # 90 bit

# v5 güvenli akış: keyfile + güçlü perde
python hcli.py encrypt belge.docx --key-file anahtar.key --passphrase-file perde.txt
python hcli.py decrypt belge.docx.hyp --key-file anahtar.key --passphrase-file perde.txt

# şifrele (varsayılan: donanıma bağlı — başka makinede açılamaz)
python hcli.py encrypt belge.docx

# taşınabilir paket (herhangi bir makinede, passphrase ile açılır)
python hcli.py encrypt belge.docx --portable

# KDF gücü (Argon2id memory_cost KiB; varsayılan 131072, aralık 16384..262144)
python hcli.py encrypt belge.docx --kdf-n 262144

# dosya boyutunu gizlemek için padding (16..65536, ISO 7816-4)
python hcli.py encrypt belge.docx --pad-to 512

# zayıf perde zorunluluğu: CLI encrypt, guesses_log10 < 14 şifreleri REDDEDER.
# Script ortamları için açık risk kabulü (ÖNERİLMEZ):
python hcli.py encrypt belge.docx --passphrase-file zayif.txt --allow-weak

# çöz (rotation/kdf_n header'dan otomatik okunur)
python hcli.py decrypt belge.docx.hyp

# hedef dosya varsa üzerine yazmak için --force
python hcli.py encrypt belge.docx --out yedek.hyp --force

# hızlı kendini test (portable + donanım-bağlı + dosya API)
python hcli.py selftest
```

Exit kodları: `0` başarı, `1` çalışma hatası, `2` kullanım hatası.

> **v5 passphrase zorunluluğu (CLI):** `zxcvbn` kuruluysa pattern-aware
> tahmin (30k parola listesi, tarih, klavye, l33t, isim araması); kurulu
> değilse builtin fallback (uzunluk + sınıf + zayıf kalıp cezası) kullanılır.
> Eşik `guesses_log10 ≥ 14` (~781 yıl @ 1e4/sn; Argon2id gerçek hızıyla
> fiilen milyonlarca yıl). Kütüphane API'si **zorlamaz** (eski kod kırılmaz);
> zorunluluk CLI katmanındadır. Decrypt'te **kırmızı bayrak reddedilmez**
> (zaten şifrelenmiş dosya kilitlenmemeli) ama zayıf perdeyle açılan dosyanın
> brute-force'a korumasız olduğu stderr'e **UYARI** olarak basılır.

Python kütüphanesi olarak:

```python
import hyper_cipher as hc

# v5: keyfile (ikinci faktör) — keyfile yoksa age/sympa HKDF katmanı atlanır
paket = hc.encrypt(b"gizli", "passphrase", use_hardware=True,
                   keyfile=open("anahtar.key", "rb").read())
metin = hc.decrypt(paket, "passphrase", keyfile=...)  # yanlış şey → CipherError

# v5: Diceware + zxcvbn (kütüphane zorlamaz; kontrol isteyene açık)
perde = hc.generate_passphrase(6)
guesses, feedback = hc.check_passphrase_strength(perde)
hc.assert_strong_passphrase(perde)   # zayıfsa ValueError

# keyfile üret/oku (sahibi siz; Windows DACL + POSIX 0600, üzerine yazmaz)
hc.generate_keyfile("anahtar.key")
kf = hc.read_keyfile("anahtar.key")   # 32..1048576 byte sınırlı

# dosya API: padding + progress callback + keyfile
hc.encrypt_file("belge.docx", "belge.hyp", "passphrase",
                pad_to=512, keyfile=kf,
                progress=lambda d, t: print(d, "/", t))
```

## Testler

```powershell
python -m unittest discover -v   # 190 test (185 birim/CLI/profesyonel + 5 POSIX)
python -m pytest -q              # 190 test: 185 geçer + 5 POSIX Windows'ta skip
```

**Birim + CLI testleri** (`test_hyper_cipher.py` + `test_hcli.py`):
roundtrip (0 byte → 1 MiB), rotasyon sınırları, yanlış passphrase, 1-bit
kurcalama, tag kurcalama, kesik paket, sona eklenen fazlalık byte reddi,
determinizm, nonce ayrımı, subkey farklılığı, donanım bağı, dosya stream
API, atomicity, progress callback (encrypt+decrypt), padding roundtrip,
KDF/rotation/flag parametre validasyonu, iki-geçişli verify-then-decrypt,
tmp kalıntısı yok (başarı + hata), CLI exit kodları.
**v5 ek testler:** keyfile roundtrip (salt + nonce + ciphertext), header
FLAG_KEYFILE biti, keyfile'sız/yanlış/kısa keyfile reddi, keyfile dosya
üretimi (üzerine yazmaz), dosya API keyfile roundtrip, zxcvbn eşik kontrolü
(güçlü geçer / zayıf reddedilir), `assert_strong_passphrase`, Diceware
(6 kelime, wordlist doğrulaması, çakışmasızlık, sınır dışı reddi), CLI
`generate-keyfile`/`generate-passphrase` exit kodları, CLI zayıf perde reddi,
`--allow-weak` geçişi, CLI keyfile roundtrip ve keyfile'sız red.

**Profesyonel test takımı** (`test_professional.py`):

| Kategori | Test |
|---|---|
| NIST SP800-22 STS | Monobit, Runs, Longest-Run, Serial, Approx-Entropy, Cumulative-Sums (3 farklı nonce keystream'i) |
| Kalibrasyon | AES-256-CTR (deterministik sabit key/nonce) aynı STS motorundan geçer → motor sağlam; HyperCipher keystream'i AES'ten istatistiksel olarak ayırt edilemez |
| İstatistik | chi-square tekdüzelik, min-entropy ≥ 7.9 bit/byte, sıkıştırılamazlık, 64K blok tekrarı yok |
| Avalanche | master/nonce/chain 1-bit değişimi → ~%50 bit flip (büyük örneklem, 5σ) |
| Golden vector | 4289 byte sabit KAT vektörü: 4+ rotasyon zinciri ve yüzlerce keystream bloğu pinler — kod değişikliği çıktıyı bozarsa yakalanır |
| Concurrency | 8 paralel thread roundtrip |
| Cross-API | encrypt() vs encrypt_file() bit-bit aynı |
| Format | v1 reddi, flag kontrolü, her header bölgesi kurcalama, kdf_n/rotation sınırları |
| Atomicity | Başarısız şifreleme/çözme → diskte yarım dosya YOK |

Performans (özel benchmark): ~3.8 MiB/s tek çekirdek, Python stdlib.

## Dosyalar

| Dosya | Görev |
|---|---|
| `hyper_cipher.py` | Çekirdek: Argon2id KDF, parmak izi, HKDF rotasyon, dual keystream, HMAC, stream API, ISO 7816-4 padding, keyfile (HKDF katmanı + FLAG_KEYFILE), zxcvbn eşikli güç kontrolü, Diceware üreteci |
| `hcli.py` | Komut satırı arayüzü (encrypt/decrypt/hash/selftest, generate-keyfile, generate-passphrase, --allow-weak, validasyon, exit kodları) |
| `diceware_words.txt` | EFF geniş Diceware kelime listesi (7776 kelime) — `generate-passphrase` sözlüğü |
| `test_hyper_cipher.py` | Birim + dosya API testleri (keyfile/zxcvbn/Diceware dahil) |
| `test_hcli.py` | CLI subprocess testleri (v5 komutları dahil) |
| `test_professional.py` | Profesyonel testler (STS + istatistik + golden vector) |
| `demo.py` | Canlı demo: şifrele → çöz → kurcalama testi (geçici dizinde, tek seferlik passphrase) |
