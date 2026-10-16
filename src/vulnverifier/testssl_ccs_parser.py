# testssl ciktisindan OpenSSL CCS Injection sonuclarini hedef bazinda ayristirir.

import re
from dataclasses import dataclass

from vulnverifier.errors import CiktiAyristirmaHatasi
from vulnverifier.testssl_parser import ANSI_KODU_DESENI, BASLANGIC_SATIRI_DESENI

CCS_SATIRI_DESENI = re.compile(
    r"^\s*CCS\s+\(CVE-2014-0224\)\s+(.+?)\s*$",
    re.I,
)


@dataclass(frozen=True, slots=True)
class CcsDurumu:
    # Tek hedefte CCS Injection sonucunu ve kesinlik bilgisini tasir.
    savunmasizMi: bool | None
    kesinMi: bool
    detay: str


@dataclass(frozen=True, slots=True)
class CcsHedefSonucu:
    # Tek IP veya baglanti noktasi icin CCS Injection sonucunu tasir.
    taramaNoktasi: str
    durum: CcsDurumu | None


@dataclass(frozen=True, slots=True)
class TestsslCcsSonucu:
    # testssl tarafindan taranan tum baglanti noktalarinin sonuclarini tasir.
    hedefSonuclari: tuple[CcsHedefSonucu, ...]


def testsslCcsCiktisiniAyristir(cikti: str) -> TestsslCcsSonucu:
    # Her testssl hedef blogundaki CCS satirini ayri sonuc olarak korur.
    if not isinstance(cikti, str) or not cikti.strip():
        raise CiktiAyristirmaHatasi("testssl CCS çıktısı boş olamaz.")
    hedefSonuclari: list[CcsHedefSonucu] = []
    taramaNoktasi = "bilinmeyen"
    hedefBloguBasladiMi = False
    bulunanDurum: CcsDurumu | None = None
    for hamSatir in cikti.splitlines():
        satir = ANSI_KODU_DESENI.sub("", hamSatir)
        baslangicEslesmesi = BASLANGIC_SATIRI_DESENI.search(satir)
        if baslangicEslesmesi is not None:
            if hedefBloguBasladiMi or bulunanDurum is not None:
                hedefSonuclari.append(CcsHedefSonucu(taramaNoktasi, bulunanDurum))
            taramaNoktasi = _taramaNoktasiniAyristir(baslangicEslesmesi.group(1))
            hedefBloguBasladiMi = True
            bulunanDurum = None
            continue
        ccsEslesmesi = CCS_SATIRI_DESENI.match(satir)
        if ccsEslesmesi is None:
            continue
        detay = ccsEslesmesi.group(1).strip()
        savunmasizMi, kesinMi = _zafiyetDurumunuAyristir(detay)
        bulunanDurum = CcsDurumu(savunmasizMi, kesinMi, detay)
    if hedefBloguBasladiMi or bulunanDurum is not None:
        hedefSonuclari.append(CcsHedefSonucu(taramaNoktasi, bulunanDurum))
    if not hedefSonuclari:
        raise CiktiAyristirmaHatasi("testssl çıktısında CCS Injection sonucu bulunamadı.")
    return TestsslCcsSonucu(tuple(hedefSonuclari))


def _taramaNoktasiniAyristir(hamTaramaNoktasi: str) -> str:
    # Parantez icindeki hostname tekrarini atip IP ve port bilgisini korur.
    return hamTaramaNoktasi.split(" (", maxsplit=1)[0].strip()


def _zafiyetDurumunuAyristir(detay: str) -> tuple[bool | None, bool]:
    # Muhtemel sonuclari kesin sonuclardan ayirarak korumaci degerlendirme saglar.
    kucukDetay = detay.casefold()
    if "likely" in kucukDetay and "not vulnerable" in kucukDetay:
        return False, False
    if "likely" in kucukDetay and "vulnerable" in kucukDetay:
        return True, False
    if "not vulnerable" in kucukDetay:
        return False, True
    if "vulnerable" in kucukDetay:
        return True, True
    return None, False
