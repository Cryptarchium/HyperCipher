# -*- coding: utf-8 -*-
"""HyperCipher ile EN GÜCLÜ ayarlarla sifreleme: hassas_ayarlar.py -> Hypercipher_şifreledi.

En güclü kombinasyon:
  - use_hardware=True : donanima bagli (bu makinenin disinda acilamaz)
  - keyfile           : ikinci faktor (perde + keyfile BIRLIKTE gerekli)
  - kdf_n varsayilan  : Argon2id 128 MiB (~1 sn/deneme brute-force cezasi)
  - pad_to=65536      : maksimum boyut gizleme (dosya boyu sifirilamaz)
"""

import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import hyper_cipher as hc

DIR = os.path.dirname(os.path.abspath(__file__))
# Opsiyonel argumanlar: python hypercipher_sifrele.py [kaynak] [cikti]
SRC = os.path.join(DIR, sys.argv[1] if len(sys.argv) > 1 else "hassas_ayarlar.py")
OUT = os.path.join(DIR, sys.argv[2] if len(sys.argv) > 2 else "Hypercipher_şifreledi")
KF = os.path.join(DIR, "keyfile.key")

# Rastgele 192-bit perde (bu DEMO'ya ozel; gercek kullanimda kendi perdeni gir)
pw = secrets.token_urlsafe(24)
print(f"[HyperCipher] perde (DEMO-ONLY, sifirla): {pw}")

# Her kosuda TAZE keyfile (demo: onceki duruma bagimlilik yok - perde gibi)
if os.path.exists(KF):
    os.remove(KF)
hc.generate_keyfile(KF)  # protected DACL ile atomik olusturulur
print(f"[HyperCipher] keyfile uretildi: {KF}")
keyfile = hc.read_keyfile(KF)

# --- EN GÜCLÜ sifreleme ---
if os.path.exists(OUT):
    os.remove(OUT)  # onceki kosunun ciktisini temizle
hc.encrypt_file(SRC, OUT, pw, use_hardware=True, keyfile=keyfile, pad_to=65536)
print(f"[HyperCipher] sifrelendi: {OUT} ({os.path.getsize(OUT)} byte)")

# --- Dogrulama: geri coz ve birebir karsilastir ---
with open(OUT, "rb") as f:
    packet = f.read()
with open(SRC, "rb") as f:
    orijinal = f.read()
cozulen = hc.decrypt(packet, pw, keyfile=keyfile)
print(f"[HyperCipher] dogrulama: geri cozuldu, esit mi? -> {cozulen == orijinal}")
