# -*- coding: utf-8 -*-
"""HyperCipher canli demo: sifrele -> coz -> dogrula -> kurcalama testi."""

import atexit
import os
import secrets
import shutil
import tempfile

import hyper_cipher as hc

# Zafiyet raporu [34]: demo gecici bir dizinde calisir ve tek seferlik
# random passphrase kullanir. Boylece (a) kill/sigkill durumunda bile
# diskte public-passphrase'li dosya KALMAZ (mkdir temp dizininde, islem
# olunce isletim sistemi temizler), (b) mevcut ornek*.txt/x.txt dosyalari
# asla ezilmez (CLI --force felsefesiyle tutarli).
_TMP = tempfile.mkdtemp(prefix="hypercipher_demo_")
atexit.register(shutil.rmtree, _TMP, ignore_errors=True)
os.chdir(_TMP)

PW = secrets.token_urlsafe(24)
print("=== HYPERCIPHER CANLI DEMO ===\n")
# Zafiyet raporu [7] fix'i: passphrase varsayilan olarak EKRANA BASILMAZ
# (log/ekran kaydi alinan oturumlarda sifir sizintisi). Gorsel denetim
# icin: HYPERCIPHER_DEMO_SHOW_PW=1 python demo.py
if os.environ.get("HYPERCIPHER_DEMO_SHOW_PW") == "1":
    print(f"Bu kosuya ozel passphrase (gorsel denetim): {PW}\n")
print(f"Gecici calisma dizini: {_TMP} (sonunda otomatik silinir)\n")

def main() -> None:
    # 1) Donanim parmak izi (canli sistemden, saklanmiyor)
    digest = hc.fingerprint_digest().hex()
    print(f"[1] Donanim parmak izi SHA-256: {digest[:40]}...")

    # 2) Ornek dosya (~3 KB -> rotasyon sinirini asar)
    data = ("SIFRELI MESAJ - HyperCipher 2048bit rotasyonlu stream cipher. "
            * 60).encode()
    with open("ornek.txt", "wb") as f:
        f.write(data)
    print(f"[2] Ornek dosya: ornek.txt ({len(data)} byte)")

    # 3) Hardware-bound sifreleme
    hc.encrypt_file("ornek.txt", "ornek.txt.hyp", PW, use_hardware=True)
    print(f"[3] Sifrelendi (DONANIMA BAGLI): ornek.txt.hyp "
          f"({os.path.getsize('ornek.txt.hyp')} byte)")

    # 4) Cozme
    hc.decrypt_file("ornek.txt.hyp", "ornek_cozuldu.txt", PW)
    print("[4] Cozuldu: ornek_cozuldu.txt")

    # 5) Byte-level karsilastirma
    a = open("ornek.txt", "rb").read()
    b = open("ornek_cozuldu.txt", "rb").read()
    print(f"[5] Birebir esit mi? -> {a == b}")

    # 6) Yanlis passphrase -> reddedilmeli
    try:
        hc.decrypt_file("ornek.txt.hyp", "x.txt", "YANLIS-passphrase")
        print("[6] HATA: yanlis sifre kabul edildi!")
    except hc.CipherError as e:
        print(f"[6] Yanlis passphrase reddedildi: {e}")

    # 7) Kurcalama (1 bit) -> tespit edilmeli
    with open("ornek.txt.hyp", "rb") as f:
        clean = f.read()
    tampered = bytearray(clean)
    tampered[hc.HEADER_BYTES + 100] ^= 0xFF
    with open("kurcalanmis.hyp", "wb") as f:
        f.write(bytes(tampered))
    try:
        hc.decrypt_file("kurcalanmis.hyp", "x.txt", PW)
        print("[7] HATA: kurcalama tespit edilmedi!")
    except hc.CipherError as e:
        print(f"[7] Kurcalama tespit edildi (1 bit bile): {e}")

    # 8) Ciphertext gorunumu
    with open("ornek.txt.hyp", "rb") as f:
        head = f.read(64)
    print(f"[8] Ciphertext ilk 64 byte: {head.hex()}")

    # 9) Temizlik: kurcalanmis kopyayi sil
    os.remove("kurcalanmis.hyp")
    print("\n[OK] DEMO TAMAM - sifreleme, cozme, dogrulama, kurcalama tespiti.")


if __name__ == "__main__":
    main()
