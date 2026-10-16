# Metasploit MS17-010 tarayici ciktisini hedef bazinda ayristirir.

import re
from dataclasses import dataclass

from vulnverifier.errors import CiktiAyristirmaHatasi

ANSI_KODU_DESENI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HEDEF_SONUCU_DESENI = re.compile(r"^\s*\[[+*\-]\]\s+(\S+:\d+)\s+-\s+(.+?)\s*$", re.I)
ZAFIYET_MESAJI = "host is likely vulnerable to ms17-010"
GUVENLI_MESAJI = "host does not appear vulnerable"
BELIRSIZ_MESAJLAR = (
    "unable to properly detect if host is vulnerable",
    "an smb login error occurred",
    "connection refused",
    "connection was refused",
    "connection timeout",
    "timed out",
    "connection reset",
    "host unreachable",
)


@dataclass(frozen=True, slots=True)
class Ms17010HedefSonucu:
    # Tek SMB tarama noktasinin zafiyet durumunu ve detayini tasir.
    taramaNoktasi: str
    savunmasizMi: bool | None
    detay: str


@dataclass(frozen=True, slots=True)
class MetasploitMs17010Sonucu:
    # Metasploit tarafindan raporlanan tum MS17-010 sonuclarini tasir.
    hedefSonuclari: tuple[Ms17010HedefSonucu, ...]


def metasploitMs17010CiktisiniAyristir(cikti: str) -> MetasploitMs17010Sonucu:
    # Bilinen modul mesajlarini zafiyet durumlariyla eslestirir.
    if not isinstance(cikti, str) or not cikti.strip():
        raise CiktiAyristirmaHatasi("Metasploit çıktısı boş olamaz.")
    hedefSonuclari: list[Ms17010HedefSonucu] = []
    for hamSatir in cikti.splitlines():
        satir = ANSI_KODU_DESENI.sub("", hamSatir)
        eslesme = HEDEF_SONUCU_DESENI.match(satir)
        if eslesme is None:
            continue
        taramaNoktasi = eslesme.group(1)
        detay = eslesme.group(2).strip()
        durum = _zafiyetDurumunuAyristir(detay)
        if durum is _SONUC_SATIRI_DEGIL:
            continue
        hedefSonuclari.append(Ms17010HedefSonucu(taramaNoktasi, durum, detay))
    if not hedefSonuclari:
        raise CiktiAyristirmaHatasi("Metasploit çıktısında MS17-010 hedef sonucu bulunamadı.")
    return MetasploitMs17010Sonucu(tuple(hedefSonuclari))


_SONUC_SATIRI_DEGIL = object()


def _zafiyetDurumunuAyristir(detay: str) -> bool | None | object:
    # Yalnizca modulun bilinen sonuc mesajlarini kabul eder.
    kucukDetay = detay.casefold()
    if ZAFIYET_MESAJI in kucukDetay:
        return True
    if GUVENLI_MESAJI in kucukDetay:
        return False
    if any(mesaj in kucukDetay for mesaj in BELIRSIZ_MESAJLAR):
        return None
    return _SONUC_SATIRI_DEGIL
