# testssl protokol ciktisindan SSLv2, SSLv3 ve modern TLS durumlarini ayristirir.

import re
from dataclasses import dataclass

from vulnverifier.errors import CiktiAyristirmaHatasi

ANSI_KODU_DESENI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
PROTOKOL_SATIRI_DESENI = re.compile(
    r"^\s*(SSLv2|SSLv3|TLS\s*1(?:\.0|\.1|\.2|\.3)?)\s+(.+?)\s*$",
    re.IGNORECASE,
)
BASLANGIC_SATIRI_DESENI = re.compile(
    r"\bStart\b.*?-->>\s+(.+?)\s+<<--",
    re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class ProtokolDurumu:
    # Tek bir protokolun testssl tarafindan bildirilen durumunu tasir.
    protokol: str
    sunuluyorMu: bool | None
    detay: str


@dataclass(frozen=True, slots=True)
class ProtokolHedefSonucu:
    # Tek bir IP veya baglanti noktasi icin ayristirilan protokol durumlarini tasir.
    taramaNoktasi: str
    sslV2: ProtokolDurumu | None
    sslV3: ProtokolDurumu | None
    modernTlsDurumlari: tuple[ProtokolDurumu, ...]


@dataclass(frozen=True, slots=True)
class TestsslProtokolSonucu:
    # testssl tarafindan taranan tum baglanti noktalarinin sonuclarini tasir.
    hedefSonuclari: tuple[ProtokolHedefSonucu, ...]


def testsslProtokolCiktisiniAyristir(cikti: str) -> TestsslProtokolSonucu:
    # Her testssl hedef blogunu kaybetmeden ayri bir standart modele donusturur.
    if not isinstance(cikti, str) or not cikti.strip():
        raise CiktiAyristirmaHatasi("testssl çıktısı boş olamaz.")

    hedefSonuclari: list[ProtokolHedefSonucu] = []
    taramaNoktasi = "bilinmeyen"
    hedefBloguBasladiMi = False
    bulunanDurumlar: dict[str, ProtokolDurumu] = {}
    for hamSatir in cikti.splitlines():
        satir = ANSI_KODU_DESENI.sub("", hamSatir)
        baslangicEslesmesi = BASLANGIC_SATIRI_DESENI.search(satir)
        if baslangicEslesmesi is not None:
            if hedefBloguBasladiMi or bulunanDurumlar:
                _hedefSonucunuEkle(
                    hedefSonuclari,
                    taramaNoktasi,
                    bulunanDurumlar,
                    bosSonucaIzinVer=hedefBloguBasladiMi,
                )
            taramaNoktasi = _taramaNoktasiniAyristir(baslangicEslesmesi.group(1))
            hedefBloguBasladiMi = True
            bulunanDurumlar = {}
            continue

        eslesme = PROTOKOL_SATIRI_DESENI.match(satir)
        if eslesme is None:
            continue

        protokol = _protokolAdiniStandartlastir(eslesme.group(1))
        detay = eslesme.group(2).strip()
        bulunanDurumlar[protokol] = ProtokolDurumu(
            protokol=protokol,
            sunuluyorMu=_sunulmaDurumunuAyristir(detay),
            detay=detay,
        )

    _hedefSonucunuEkle(
        hedefSonuclari,
        taramaNoktasi,
        bulunanDurumlar,
        bosSonucaIzinVer=hedefBloguBasladiMi,
    )
    if not hedefSonuclari:
        raise CiktiAyristirmaHatasi("testssl çıktısında protokol sonucu bulunamadı.")

    return TestsslProtokolSonucu(hedefSonuclari=tuple(hedefSonuclari))


def _hedefSonucunuEkle(
    hedefSonuclari: list[ProtokolHedefSonucu],
    taramaNoktasi: str,
    bulunanDurumlar: dict[str, ProtokolDurumu],
    bosSonucaIzinVer: bool = False,
) -> None:
    # Baslatilan bos hedef blogunu eksik sonuc olarak korur, bos on bilgiyi atlar.
    if not bulunanDurumlar and not bosSonucaIzinVer:
        return
    modernTlsDurumlari = tuple(
        durum for protokol, durum in bulunanDurumlar.items() if protokol.startswith("TLS")
    )
    hedefSonuclari.append(
        ProtokolHedefSonucu(
            taramaNoktasi=taramaNoktasi,
            sslV2=bulunanDurumlar.get("SSLv2"),
            sslV3=bulunanDurumlar.get("SSLv3"),
            modernTlsDurumlari=modernTlsDurumlari,
        )
    )


def _taramaNoktasiniAyristir(hamTaramaNoktasi: str) -> str:
    # Parantez icindeki hostname tekrarini atip IP ve port bilgisini korur.
    return hamTaramaNoktasi.split(" (", maxsplit=1)[0].strip()


def _protokolAdiniStandartlastir(protokol: str) -> str:
    # testssl surumleri arasindaki bosluk ve TLS 1 yazim farklarini giderir.
    kucukAd = re.sub(r"\s+", "", protokol).lower()
    adEslemeleri = {
        "sslv2": "SSLv2",
        "sslv3": "SSLv3",
        "tls1": "TLS1.0",
        "tls1.0": "TLS1.0",
        "tls1.1": "TLS1.1",
        "tls1.2": "TLS1.2",
        "tls1.3": "TLS1.3",
    }
    return adEslemeleri[kucukAd]


def _sunulmaDurumunuAyristir(detay: str) -> bool | None:
    # Olumsuz ifade once kontrol edilerek "not offered" yanlis pozitifini engeller.
    kucukDetay = detay.casefold()
    if "not offered" in kucukDetay:
        return False
    if re.search(r"\boffered\b", kucukDetay):
        return True
    return None
