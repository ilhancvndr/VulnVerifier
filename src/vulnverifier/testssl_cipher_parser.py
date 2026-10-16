# testssl ciktisindan anonymous TLS cipher durumlarini hedef bazinda ayristirir.

import re
from dataclasses import dataclass

from vulnverifier.errors import CiktiAyristirmaHatasi
from vulnverifier.testssl_parser import ANSI_KODU_DESENI, BASLANGIC_SATIRI_DESENI

ANONYMOUS_CIPHER_SATIRI_DESENI = re.compile(
    r"^\s*Anonymous\s+NULL\s+Ciphers\s+\(no\s+authentication\)\s+(.+?)\s*$",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class AnonymousCipherDurumu:
    # Tek hedefte anonymous cipher sunulma durumunu ve ham detayini tasir.
    sunuluyorMu: bool | None
    detay: str


@dataclass(frozen=True, slots=True)
class AnonymousCipherHedefSonucu:
    # Tek bir IP veya baglanti noktasi icin anonymous cipher sonucunu tasir.
    taramaNoktasi: str
    durum: AnonymousCipherDurumu | None


@dataclass(frozen=True, slots=True)
class TestsslAnonymousCipherSonucu:
    # testssl tarafindan taranan tum baglanti noktalarinin sonuclarini tasir.
    hedefSonuclari: tuple[AnonymousCipherHedefSonucu, ...]


def testsslAnonymousCipherCiktisiniAyristir(cikti: str) -> TestsslAnonymousCipherSonucu:
    # Her testssl hedef blogundaki anonymous cipher satirini ayri sonuc olarak korur.
    if not isinstance(cikti, str) or not cikti.strip():
        raise CiktiAyristirmaHatasi("testssl çıktısı boş olamaz.")

    hedefSonuclari: list[AnonymousCipherHedefSonucu] = []
    taramaNoktasi = "bilinmeyen"
    hedefBloguBasladiMi = False
    bulunanDurum: AnonymousCipherDurumu | None = None

    for hamSatir in cikti.splitlines():
        satir = ANSI_KODU_DESENI.sub("", hamSatir)
        baslangicEslesmesi = BASLANGIC_SATIRI_DESENI.search(satir)
        if baslangicEslesmesi is not None:
            if hedefBloguBasladiMi or bulunanDurum is not None:
                hedefSonuclari.append(
                    AnonymousCipherHedefSonucu(
                        taramaNoktasi=taramaNoktasi,
                        durum=bulunanDurum,
                    )
                )
            taramaNoktasi = _taramaNoktasiniAyristir(baslangicEslesmesi.group(1))
            hedefBloguBasladiMi = True
            bulunanDurum = None
            continue

        cipherEslesmesi = ANONYMOUS_CIPHER_SATIRI_DESENI.match(satir)
        if cipherEslesmesi is None:
            continue

        detay = cipherEslesmesi.group(1).strip()
        bulunanDurum = AnonymousCipherDurumu(
            sunuluyorMu=_sunulmaDurumunuAyristir(detay),
            detay=detay,
        )

    if hedefBloguBasladiMi or bulunanDurum is not None:
        hedefSonuclari.append(
            AnonymousCipherHedefSonucu(
                taramaNoktasi=taramaNoktasi,
                durum=bulunanDurum,
            )
        )
    if not hedefSonuclari:
        raise CiktiAyristirmaHatasi("testssl çıktısında anonymous cipher sonucu bulunamadı.")

    return TestsslAnonymousCipherSonucu(hedefSonuclari=tuple(hedefSonuclari))


def _taramaNoktasiniAyristir(hamTaramaNoktasi: str) -> str:
    # Parantez icindeki hostname tekrarini atip IP ve port bilgisini korur.
    return hamTaramaNoktasi.split(" (", maxsplit=1)[0].strip()


def _sunulmaDurumunuAyristir(detay: str) -> bool | None:
    # Olumsuz ifade once kontrol edilerek "not offered" yanlis pozitifini engeller.
    kucukDetay = detay.casefold()
    if "not offered" in kucukDetay:
        return False
    if re.search(r"\boffered\b", kucukDetay):
        return True
    return None
