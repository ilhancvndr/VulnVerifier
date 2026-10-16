# testssl ciktisindan FREAK durumlarini hedef bazinda ayristirir.

import re
from dataclasses import dataclass

from vulnverifier.errors import CiktiAyristirmaHatasi
from vulnverifier.testssl_parser import ANSI_KODU_DESENI, BASLANGIC_SATIRI_DESENI

FREAK_SATIRI_DESENI = re.compile(
    r"^\s*FREAK\s+\(CVE-2015-0204\)\s+(.+?)\s*$",
    re.I,
)


@dataclass(frozen=True, slots=True)
class FreakDurumu:
    # Tek hedefte FREAK zafiyet durumunu ve testssl detayini tasir.
    savunmasizMi: bool | None
    detay: str


@dataclass(frozen=True, slots=True)
class FreakHedefSonucu:
    # Tek IP veya baglanti noktasi icin FREAK sonucunu tasir.
    taramaNoktasi: str
    durum: FreakDurumu | None


@dataclass(frozen=True, slots=True)
class TestsslFreakSonucu:
    # testssl tarafindan taranan tum baglanti noktalarinin sonuclarini tasir.
    hedefSonuclari: tuple[FreakHedefSonucu, ...]


def testsslFreakCiktisiniAyristir(cikti: str) -> TestsslFreakSonucu:
    # Her testssl hedef blogundaki FREAK satirini ayri sonuc olarak korur.
    if not isinstance(cikti, str) or not cikti.strip():
        raise CiktiAyristirmaHatasi("testssl FREAK çıktısı boş olamaz.")
    hedefSonuclari: list[FreakHedefSonucu] = []
    taramaNoktasi = "bilinmeyen"
    hedefBloguBasladiMi = False
    bulunanDurum: FreakDurumu | None = None
    for hamSatir in cikti.splitlines():
        satir = ANSI_KODU_DESENI.sub("", hamSatir)
        baslangicEslesmesi = BASLANGIC_SATIRI_DESENI.search(satir)
        if baslangicEslesmesi is not None:
            if hedefBloguBasladiMi or bulunanDurum is not None:
                hedefSonuclari.append(FreakHedefSonucu(taramaNoktasi, bulunanDurum))
            taramaNoktasi = _taramaNoktasiniAyristir(baslangicEslesmesi.group(1))
            hedefBloguBasladiMi = True
            bulunanDurum = None
            continue
        freakEslesmesi = FREAK_SATIRI_DESENI.match(satir)
        if freakEslesmesi is None:
            continue
        detay = freakEslesmesi.group(1).strip()
        bulunanDurum = FreakDurumu(_zafiyetDurumunuAyristir(detay), detay)
    if hedefBloguBasladiMi or bulunanDurum is not None:
        hedefSonuclari.append(FreakHedefSonucu(taramaNoktasi, bulunanDurum))
    if not hedefSonuclari:
        raise CiktiAyristirmaHatasi("testssl çıktısında FREAK sonucu bulunamadı.")
    return TestsslFreakSonucu(tuple(hedefSonuclari))


def _taramaNoktasiniAyristir(hamTaramaNoktasi: str) -> str:
    # Parantez icindeki hostname tekrarini atip IP ve port bilgisini korur.
    return hamTaramaNoktasi.split(" (", maxsplit=1)[0].strip()


def _zafiyetDurumunuAyristir(detay: str) -> bool | None:
    # Olumsuz ifade once kontrol edilerek yanlis pozitif engellenir.
    kucukDetay = detay.casefold()
    if "not vulnerable" in kucukDetay:
        return False
    if "vulnerable" in kucukDetay:
        return True
    return None
