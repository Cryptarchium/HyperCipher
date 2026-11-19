"""
ornek_kod_v4.py — HyperCipher v4 kullanım örneği (gösterim dosyası)

Bu dosya HyperCipher'in nasıl çalıştığını gösteren örnek bir kod parçasıdır.
Amacı: kütüphanenin şifrelenip çözülmesini uçtan uca test etmek.
"""

import os
import sys

# ornekler/ alt dizininden calistirildiginda ust dizindeki kutuphaneyi bul
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import hyper_cipher as hc


def demo_stream_api(passphrase: str) -> None:
    """Büyük veriyi parça parça birleştirip uçtan uca şifreler ve çözer."""
    parcalar = [b"HyperCipher v4 ", b"Argon2id KDF, ", b"2048-bit anahtar, ",
                b"donanima bagli, rotasyonlu stream cipher."]
    veri = b"".join(parcalar)
    sifreli = hc.encrypt(veri, passphrase, use_hardware=False)
    cozulen = hc.decrypt(sifreli, passphrase)
    assert cozulen == veri, "roundtrip bozuk!"
    print("  [OK] encrypt/decrypt roundtrip basarili")


def demo_hardware_binding(passphrase: str) -> None:
    """Donanım bağlı şifreleme: paket yalnızca bu makinede açılır."""
    veri = b"bu paket yalnizca uretildigi makinada acilir"
    paket = hc.encrypt(veri, passphrase, use_hardware=True)
    assert hc.decrypt(paket, passphrase) == veri
    print("  [OK] donanim bagli encrypt/decrypt basarili")


def demo_avalanche(passphrase: str) -> None:
    """1-byte değişim ~%50 çıktı değiştirmeli (avalans etkisi).

    Büyük veri kullanilir: header'in ~48 byte'i yapisal sabittir
    (version/flags/rotation/kdf_n/fp_hash/data_len); 30 byte veride bu
    sabit kismin ORANI buyuk oldugundan toplam oran ~0.38'e duser.
    4 KiB veride header etkisi ihmal edilir, ciphertext ~0.5 olur.
    """
    veri_a = b"avalanche test verisi 0123456789" * 150   # ~4 KiB
    veri_b = bytearray(veri_a)
    veri_b[512] ^= 0x01  # ayni uzunlukta, tek byte degisti
    p1 = hc.encrypt(bytes(veri_a), passphrase, use_hardware=False)
    p2 = hc.encrypt(bytes(veri_b), passphrase, use_hardware=False)
    fark = sum((a ^ b).bit_count() for a, b in zip(p1, p2))
    oran = fark / (len(p1) * 8)
    assert oran > 0.45, f"avalans zayif: {oran:.2f}"
    print(f"  [OK] avalans etkisi: %{oran * 100:.1f} bit degisti "
          f"({len(veri_a)} byte veri)")


if __name__ == "__main__":
    PW = "ornek-parola-2026"
    print("HyperCipher v4 ornek calismasi:")
    demo_stream_api(PW)
    demo_hardware_binding(PW)
    demo_avalanche(PW)
    print("Tum ornekler basariyla tamamlandi.")
