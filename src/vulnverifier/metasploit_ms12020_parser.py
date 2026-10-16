# Metasploit MS12-020 tarayici ciktisini hedef bazinda ayristirir.

import re
from dataclasses import dataclass

from vulnverifier.errors import CiktiAyristirmaHatasi

ANSI_KODU_DESENI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HEDEF_SONUCU_DESENI = re.compile(
    r"^\s*\[[+*\-]\]\s+(\S+:\d+)\s+-\s+(.+?)\s*$",
    re.IGNORECASE,
)
ZAFIYET_MESAJI = "response confirmed vulnerability presence"
GUVENLI_MESAJI = "not vulnerable"
BELIRSIZ_MESAJLAR = (
    "unable to determine ms12-020 vulnerability status",
    "could not connect to rdp",
    "no response to first userrequest",
    "no response to second userrequest",
    "no response to channel request",
)


@dataclass(frozen=True, slots=True)
class Ms12020HedefSonucu:
    # Tek tarama noktasinin zafiyet durumunu ve Metasploit detayini tasir.
    taramaNoktasi: str
    savunmasizMi: bool | None
    detay: str


@dataclass(frozen=True, slots=True)
class MetasploitMs12020Sonucu:
    # Metasploit tarafindan raporlanan tum MS12-020 hedef sonuclarini tasir.
    hedefSonuclari: tuple[Ms12020HedefSonucu, ...]


def metasploitMs12020CiktisiniAyristir(cikti: str) -> MetasploitMs12020Sonucu:
    # Sonuc satirlarini tarar ve her hedefi zafiyet durumuyla birlikte korur.
    if not isinstance(cikti, str) or not cikti.strip():
        raise CiktiAyristirmaHatasi("Metasploit çıktısı boş olamaz.")

    hedefSonuclari: list[Ms12020HedefSonucu] = []
    for hamSatir in cikti.splitlines():
        satir = ANSI_KODU_DESENI.sub("", hamSatir)
        sonucEslesmesi = HEDEF_SONUCU_DESENI.match(satir)
        if sonucEslesmesi is None:
            continue

        taramaNoktasi = sonucEslesmesi.group(1)
        detay = _tekrarlananTaramaNoktasiniKaldir(
            sonucEslesmesi.group(2),
            taramaNoktasi,
        )
        savunmasizMi = _zafiyetDurumunuAyristir(detay)
        if savunmasizMi is _SONUC_SATIRI_DEGIL:
            continue
        hedefSonuclari.append(
            Ms12020HedefSonucu(
                taramaNoktasi=taramaNoktasi,
                savunmasizMi=savunmasizMi,
                detay=detay,
            )
        )

    if not hedefSonuclari:
        raise CiktiAyristirmaHatasi("Metasploit çıktısında MS12-020 hedef sonucu bulunamadı.")
    return MetasploitMs12020Sonucu(hedefSonuclari=tuple(hedefSonuclari))


_SONUC_SATIRI_DEGIL = object()


def _tekrarlananTaramaNoktasiniKaldir(detay: str, taramaNoktasi: str) -> str:
    # Scanner ve modul on eklerinin iki kez yazdigi hedef bilgisini teke indirir.
    temizDetay = detay.strip()
    tekrarlananOnEk = f"{taramaNoktasi} - "
    if temizDetay.startswith(tekrarlananOnEk):
        return temizDetay[len(tekrarlananOnEk) :].strip()
    return temizDetay


def _zafiyetDurumunuAyristir(detay: str) -> bool | None | object:
    # Yalnizca modulun bilinen sonuc mesajlarini hedef sonucu olarak kabul eder.
    kucukDetay = detay.casefold()
    if ZAFIYET_MESAJI in kucukDetay:
        return True
    if GUVENLI_MESAJI in kucukDetay:
        return False
    if any(mesaj in kucukDetay for mesaj in BELIRSIZ_MESAJLAR):
        return None
    return _SONUC_SATIRI_DEGIL
