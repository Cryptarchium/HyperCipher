# -*- coding: utf-8 -*-
"""AES-256-CBC 'KOD ENCRYPTION' araci: Python kaynak kodunu sifreler ve
kendini cozen CALISTIRILABILIR dosya uretir.

Cikti dosyasi (AES256CBC_sifrelenmis_kod.py):
  - Kaynak kod DUZ METIN olarak YOKTUR (AES-256-CBC blob gomulu).
  - Calistirildiginda cozulur ve kaynak exec ile calistirilir.
  - Acip bakan kisi sadece sifreli blob gorur; MASTER_KEY/DB_PASS gibi
    hassas degerler okunamaz.

DURUST NOT: Bu bir OBFUSCATION desenidir - anahtar dosyada gomuludur.
Gercek kod korumasi (PyArmor gibi) daha gucludur. Amac: kaynak kodu
duz metin okumayi engellemek.
"""

import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DIR = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(DIR, "hassas_ayarlar.py")
OUT = os.path.join(DIR, "AES256CBC_sifrelenmis_kod.py")

with open(SRC, "rb") as f:
    source = f.read()

key = os.urandom(32)   # 256-bit
iv = os.urandom(16)    # 128-bit

padder = padding.PKCS7(128).padder()
padded = padder.update(source) + padder.finalize()
enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
blob = enc.update(padded) + enc.finalize()

runner = f'''# -*- coding: utf-8 -*-
"""AES-256-CBC ile SIFRELENMIS KOD (kendini cozen calistirici).

Kaynak (hassas_ayarlar.py) bu dosyada DUZ METIN DEGILDIR: AES-256-CBC
ile sifrelenmis gomulu blob'tur. Calistiginda cozulur ve calistirilir.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEY = bytes.fromhex("{key.hex()}")
IV = bytes.fromhex("{iv.hex()}")
BLOB = bytes.fromhex("{blob.hex()}")


def _coz():
    dec = Cipher(algorithms.AES(KEY), modes.CBC(IV)).decryptor()
    pt = dec.update(BLOB) + dec.finalize()
    return pt[:-pt[-1]]  # PKCS7 ac


if __name__ == "__main__":
    kaynak = _coz().decode("utf-8")
    print("[cozucu] Sifreli kod cozuldu ve calistiriliyor...")
    exec(compile(kaynak, "<sifrelenmis-kod>", "exec"))
'''

if os.path.exists(OUT):
    os.remove(OUT)
with open(OUT, "w", encoding="utf-8") as f:
    f.write(runner)

print(f"[AES-256-CBC KOD ENCRYPTION] kaynak sifrelendi: {SRC}")
print(f"[AES-256-CBC KOD ENCRYPTION] cikti          : {OUT} "
      f"({os.path.getsize(OUT)} byte)")
print("[AES-256-CBC KOD ENCRYPTION] MASTER_KEY/DB_PASS/JWT_SECRET "
      "artik dosyada YOK - sadece sifreli blob var.")