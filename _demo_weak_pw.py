# -*- coding: utf-8 -*-
"""DEMO: 2048-bit anahtar AYNI ama zayif passphrase KIRILIR."""
import sys
import time

sys.path.insert(0, ".")
import hyper_cipher as hc

print("=== DEMO: 2048-bit key AYNI ama zayif passphrase KIRILIYOR ===")
print()

# Kurban: sifreleme kusursuz calisiyor, key 2048-bit.
# Ama kullanici perdesi kisa ve tahmin edilebilir.
gercek_pw = "ankara1234"
veri = b"gizli veri - Cline bunu acamaz"
paket = hc.encrypt(veri, gercek_pw, use_hardware=False, kdf_n=1 << 14)
h = hc.parse_header(paket[:hc.HEADER_BYTES])
print(f"kurban: {gercek_pw!r}  -> turetilen key: {hc.KEY_BYTES * 8}-bit "
      f"({hc.KEY_BYTES} byte)")
print(f"header kdf_n: {h.kdf_n} KiB (Argon2id)")
print()

# Saldirgan: 2^2048 key'i denemez. INSAN DILINI dener:
# yaygin kelime + sayi mutasyonlari. Her deneme = Argon2id + HMAC.
kelimeler = ["istanbul", "deneme", "parola", "qwerty", "ankara", "asd123"]


def mutasyon(w):
    return [w, w + "1", w + "12", w + "123", w + "1234", w + "12345", w + "2026"]


denemeler = [m for w in kelimeler for m in mutasyon(w)]
print(f"saldirgan: {len(denemeler)} aday passphrase (kelime+rakam) - "
      f"2^2048 key DENEMIYOR")
print()
t0 = time.time()
kirildi = None
for aday in denemeler:
    try:
        if hc.decrypt(paket, aday) == veri:
            kirildi = aday
            break
    except hc.CipherError:
        continue
gecen = time.time() - t0
if kirildi:
    print(f"SONUC: {kirildi!r} -> KIRILDI ({gecen:.2f}s, {len(denemeler)} "
          f"denemede)")
else:
    print("SONUC: bu wordlist'te bulunamadi (daha buyuk liste lazim)")
print()
print("Anahtar 2048-bit ama sorun anahtar BOYUTU degil,")
print("key'i tureten perde'nin entropisi.")
print("Efektif guvenlik = min(2^2048, perde entropisi).")
