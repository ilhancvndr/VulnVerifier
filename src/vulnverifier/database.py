# SQLite veritabani baglantisini guvenli ve ortak bir noktadan yonetir.

import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

VARSAYILAN_VERITABANI_YOLU = Path("vulnverifier.db")
VERITABANI_DOSYASI_IZNI = 0o600
VERITABANI_DIZINI_IZNI = 0o700
VARSAYILAN_BAGLANTI_ZAMAN_ASIMI = 5.0


class VeritabaniHatasi(RuntimeError):
    # Veritabani yolu veya baglanti islemi gecersiz oldugunda olusan hatadir.
    pass


def veritabaniBaglantisiAc(
    dosyaYolu: str | Path = VARSAYILAN_VERITABANI_YOLU,
    zamanAsimi: float = VARSAYILAN_BAGLANTI_ZAMAN_ASIMI,
) -> sqlite3.Connection:
    # SQLite dosyasini hazirlar ve foreign key denetimi acik bir baglanti dondurur.
    dogrulanmisYol = _veritabaniYolunuDogrula(dosyaYolu)
    dogrulanmisZamanAsimi = _zamanAsiminiDogrula(zamanAsimi)
    _veritabaniDizininiHazirla(dogrulanmisYol.parent)
    yeniDosyaMi = not dogrulanmisYol.exists()
    baglanti: sqlite3.Connection | None = None

    try:
        baglanti = sqlite3.connect(dogrulanmisYol, timeout=dogrulanmisZamanAsimi)
        baglanti.row_factory = sqlite3.Row
        baglanti.execute("PRAGMA foreign_keys = ON")
        baglanti.execute(f"PRAGMA busy_timeout = {int(dogrulanmisZamanAsimi * 1000)}")
        foreignKeyAcikMi = baglanti.execute("PRAGMA foreign_keys").fetchone()[0]
        if foreignKeyAcikMi != 1:
            baglanti.close()
            raise VeritabaniHatasi("SQLite foreign key denetimi etkinlestirilemedi.")
        if yeniDosyaMi:
            os.chmod(dogrulanmisYol, VERITABANI_DOSYASI_IZNI)
    except VeritabaniHatasi:
        raise
    except (OSError, sqlite3.Error) as hata:
        if baglanti is not None:
            baglanti.close()
        raise VeritabaniHatasi(
            f"SQLite veritabanina baglanilamadi: {dogrulanmisYol}",
        ) from hata

    return baglanti


@contextmanager
def veritabaniBaglantisi(
    dosyaYolu: str | Path = VARSAYILAN_VERITABANI_YOLU,
    zamanAsimi: float = VARSAYILAN_BAGLANTI_ZAMAN_ASIMI,
) -> Iterator[sqlite3.Connection]:
    # Basarili islemi kaydeder, hata durumunda geri alir ve baglantiyi kapatir.
    baglanti = veritabaniBaglantisiAc(dosyaYolu, zamanAsimi)
    try:
        yield baglanti
    except Exception:
        baglanti.rollback()
        raise
    else:
        baglanti.commit()
    finally:
        baglanti.close()


def _veritabaniYolunuDogrula(dosyaYolu: str | Path) -> Path:
    # Bos, null karakterli, sembolik bag veya dizin olan yollari reddeder.
    if isinstance(dosyaYolu, str):
        if not dosyaYolu or dosyaYolu != dosyaYolu.strip():
            raise VeritabaniHatasi("Veritabani dosya yolu bos olamaz veya boslukla cevrilemez.")
        if "\x00" in dosyaYolu:
            raise VeritabaniHatasi("Veritabani dosya yolu null karakteri iceremez.")
        dogrulanmisYol = Path(dosyaYolu)
    elif isinstance(dosyaYolu, Path):
        dogrulanmisYol = dosyaYolu
    else:
        raise VeritabaniHatasi("Veritabani dosya yolu metin veya Path olmalidir.")

    if dogrulanmisYol.is_symlink():
        raise VeritabaniHatasi("Veritabani dosya yolu sembolik bag olamaz.")
    if dogrulanmisYol.exists() and not dogrulanmisYol.is_file():
        raise VeritabaniHatasi("Veritabani yolu normal bir dosya olmalidir.")
    return dogrulanmisYol


def _zamanAsiminiDogrula(zamanAsimi: float) -> float:
    # SQLite kilit bekleme suresinin pozitif bir sayi olmasini zorunlu tutar.
    if isinstance(zamanAsimi, bool) or not isinstance(zamanAsimi, int | float):
        raise VeritabaniHatasi("Baglanti zaman asimi sayisal olmalidir.")
    if zamanAsimi <= 0:
        raise VeritabaniHatasi("Baglanti zaman asimi sifirdan buyuk olmalidir.")
    return float(zamanAsimi)


def _veritabaniDizininiHazirla(dizinYolu: Path) -> None:
    # Veritabani ust dizinini yalnizca mevcut kullaniciya acik olarak olusturur.
    if dizinYolu.exists() and (dizinYolu.is_symlink() or not dizinYolu.is_dir()):
        raise VeritabaniHatasi("Veritabani ust yolu gercek bir dizin olmalidir.")

    try:
        dizinYolu.mkdir(parents=True, exist_ok=True, mode=VERITABANI_DIZINI_IZNI)
    except OSError as hata:
        raise VeritabaniHatasi(
            f"Veritabani dizini olusturulamadi: {dizinYolu}",
        ) from hata

    if not stat.S_ISDIR(dizinYolu.stat().st_mode):
        raise VeritabaniHatasi("Veritabani ust yolu dizin degildir.")
