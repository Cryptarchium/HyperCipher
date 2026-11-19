# -*- coding: utf-8 -*-
"""
GOREV TAKIP UYGULAMASI - HyperCipher ornek dosyasi
====================================================
Tamamen stdlib ile yazilmis, konsol tabanli mini gorev yoneticisi.
Bu dosya, HyperCipher 2048-bit donanima bagli rotasyonlu stream cipher
ile sifrelenmis bir ORNEK Python kodudur.

Kullanim:
    python gorevler.py                 # gorevleri listele
    python gorevler.py ekle "ornek gorev"
    python gorevler.py tamamla 3
    python gorevler.py sil 2
"""

import json
import os
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path

VERI_DOSYASI = Path.home() / ".gorevler.json"


@dataclass
class Gorev:
    """Tek bir gorev kaydi."""
    id: int
    baslik: str
    olusturulma: float
    tamamlandi: bool = False


def yukle() -> list[Gorev]:
    """Kayitli gorevleri diskten okur (dosya yoksa bos liste)."""
    if not VERI_DOSYASI.exists():
        return []
    with open(VERI_DOSYASI, "r", encoding="utf-8") as f:
        return [Gorev(**kayit) for kayit in json.load(f)]


def kaydet(gorevler: list[Gorev]) -> None:
    """Gorev listesini diske yazar (atomik: tmp + replace)."""
    gecici = VERI_DOSYASI.with_suffix(".tmp")
    with open(gecici, "w", encoding="utf-8") as f:
        json.dump([asdict(g) for g in gorevler], f,
                  ensure_ascii=False, indent=2)
    os.replace(gecici, VERI_DOSYASI)


def sonraki_id(gorevler: list[Gorev]) -> int:
    """Yeni gorev icin siradaki benzersiz id numarasini verir."""
    return max((g.id for g in gorevler), default=0) + 1


def listele(gorevler: list[Gorev]) -> None:
    """Gorevleri insan okur formatinda ekrana basar."""
    if not gorevler:
        print("(gorev yok - 'ekle' komutuyla yeni gorev ekleyin)")
        return
    for g in gorevler:
        durum = "[x]" if g.tamamlandi else "[ ]"
        tarih = time.strftime("%d.%m.%Y", time.localtime(g.olusturulma))
        print(f"{g.id:>3}. {durum} {g.baslik}  ({tarih})")


def ekle(gorevler: list[Gorev], baslik: str) -> None:
    """Yeni bir gorev olusturur, listeye ekler ve kaydeder."""
    g = Gorev(sonraki_id(gorevler), baslik, time.time())
    gorevler.append(g)
    kaydet(gorevler)
    print(f"[OK] Gorev eklendi: #{g.id} - {baslik}")


def tamamla(gorevler: list[Gorev], gorev_id: int) -> None:
    """Verilen id'deki gorevi tamamlandi olarak isaretler."""
    for g in gorevler:
        if g.id == gorev_id:
            g.tamamlandi = True
            kaydet(gorevler)
            print(f"[OK] Gorev tamamlandi: #{g.id}")
            return
    print(f"[HATA] #{gorev_id} numarali gorev bulunamadi.")


def sil(gorevler: list[Gorev], gorev_id: int) -> None:
    """Verilen id'deki gorevi listeden kaldirir ve kaydeder."""
    for i, g in enumerate(gorevler):
        if g.id == gorev_id:
            silinen = gorevler.pop(i)
            kaydet(gorevler)
            print(f"[OK] Gorev silindi: #{silinen.id} - {silinen.baslik}")
            return
    print(f"[HATA] #{gorev_id} numarali gorev bulunamadi.")


def ana() -> None:
    """CLI giris noktasi: komutlari ayristirip ilgili islevi calistirir."""
    gorevler = yukle()
    args = sys.argv[1:]
    if not args or args[0] == "listele":
        listele(gorevler)
    elif args[0] == "ekle":
        if len(args) < 2:
            print("Kullanim: gorevler.py ekle <baslik>")
            return
        ekle(gorevler, " ".join(args[1:]))
    elif args[0] == "tamamla":
        if len(args) < 2:
            print("Kullanim: gorevler.py tamamla <id>")
            return
        tamamla(gorevler, int(args[1]))
    elif args[0] == "sil":
        if len(args) < 2:
            print("Kullanim: gorevler.py sil <id>")
            return
        sil(gorevler, int(args[1]))
    else:
        print(f"Bilinmeyen komut: {args[0]}")


if __name__ == "__main__":
    ana()
