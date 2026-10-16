# Harici arac surumlerini, timeout degerlerini ve ortak hata durumlarini yonetir.

import re
from dataclasses import dataclass
from enum import StrEnum

from vulnverifier.command_runner import (
    KomutBaslatmaHatasi,
    KomutZamanAsimiHatasi,
    komutuCalistir,
)
from vulnverifier.tool_availability import AracDurumu, araciKontrolEt

NMAP_VARSAYILAN_ZAMAN_ASIMI = 180.0
TESTSSL_VARSAYILAN_ZAMAN_ASIMI = 300.0
METASPLOIT_VARSAYILAN_ZAMAN_ASIMI = 300.0
SURUM_KONTROL_ZAMAN_ASIMI = 30.0
ANSI_KACIS_DESENI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


class AracTuru(StrEnum):
    # Uygulamanin yonettigi harici arac turlerini belirtir.
    NMAP = "nmap"
    TESTSSL = "testssl"
    METASPLOIT = "metasploit"


class AracDurumKodu(StrEnum):
    # Harici arac incelemesinin standart durum kodlarini belirtir.
    READY = "READY"
    MISSING = "MISSING"
    TIMEOUT = "TIMEOUT"
    START_ERROR = "START_ERROR"
    EXIT_ERROR = "EXIT_ERROR"
    VERSION_ERROR = "VERSION_ERROR"


@dataclass(frozen=True, slots=True)
class HariciAracBilgisi:
    # Bir aracin yol, surum, timeout ve standart hata durumunu tasir.
    aracTuru: AracTuru
    aracAdi: str
    durum: AracDurumKodu
    aracYolu: str | None
    surum: str | None
    varsayilanZamanAsimi: float
    hataMesaji: str | None = None


def hariciAraciIncele(aracTuru: AracTuru) -> HariciAracBilgisi:
    # Araci bulur, surum komutunu calistirir ve tum hatalari ortak modele donusturur.
    if not isinstance(aracTuru, AracTuru):
        raise ValueError("Gecerli bir AracTuru gereklidir.")

    aracDurumu = _araciBul(aracTuru)
    varsayilanZamanAsimi = aracZamanAsiminiAl(aracTuru)
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        return HariciAracBilgisi(
            aracTuru=aracTuru,
            aracAdi=aracDurumu.aracAdi,
            durum=AracDurumKodu.MISSING,
            aracYolu=None,
            surum=None,
            varsayilanZamanAsimi=varsayilanZamanAsimi,
            hataMesaji="Araç sistem PATH değeri içinde bulunamadı.",
        )

    komut = _surumKomutunuOlustur(aracTuru, aracDurumu.aracYolu)
    try:
        komutSonucu = komutuCalistir(komut, zamanAsimi=SURUM_KONTROL_ZAMAN_ASIMI)
    except KomutZamanAsimiHatasi:
        return _hataliAracBilgisi(
            aracTuru,
            aracDurumu,
            AracDurumKodu.TIMEOUT,
            varsayilanZamanAsimi,
            f"Sürüm komutu {SURUM_KONTROL_ZAMAN_ASIMI:g} saniyede tamamlanamadı.",
        )
    except KomutBaslatmaHatasi as hata:
        return _hataliAracBilgisi(
            aracTuru,
            aracDurumu,
            AracDurumKodu.START_ERROR,
            varsayilanZamanAsimi,
            str(hata),
        )

    if komutSonucu.cikisKodu != 0:
        hataMetni = _ilkDoluSatiriAl(komutSonucu.standartHata) or (
            f"Sürüm komutu {komutSonucu.cikisKodu} çıkış kodu döndürdü."
        )
        return _hataliAracBilgisi(
            aracTuru,
            aracDurumu,
            AracDurumKodu.EXIT_ERROR,
            varsayilanZamanAsimi,
            hataMetni,
        )

    birlesikCikti = f"{komutSonucu.standartCikti}\n{komutSonucu.standartHata}"
    surum = _surumuAyristir(aracTuru, birlesikCikti)
    if surum is None:
        return _hataliAracBilgisi(
            aracTuru,
            aracDurumu,
            AracDurumKodu.VERSION_ERROR,
            varsayilanZamanAsimi,
            "Araç sürümü çıktıda bulunamadı.",
        )

    return HariciAracBilgisi(
        aracTuru=aracTuru,
        aracAdi=aracDurumu.aracAdi,
        durum=AracDurumKodu.READY,
        aracYolu=aracDurumu.aracYolu,
        surum=surum,
        varsayilanZamanAsimi=varsayilanZamanAsimi,
    )


def tumHariciAraclariIncele() -> tuple[HariciAracBilgisi, ...]:
    # Desteklenen tum araclari biri hata verse bile sirayla inceler.
    return tuple(hariciAraciIncele(aracTuru) for aracTuru in AracTuru)


def aracZamanAsiminiAl(aracTuru: AracTuru) -> float:
    # Arac turune ozel tarama timeout degerini dondurur.
    zamanAsimlari = {
        AracTuru.NMAP: NMAP_VARSAYILAN_ZAMAN_ASIMI,
        AracTuru.TESTSSL: TESTSSL_VARSAYILAN_ZAMAN_ASIMI,
        AracTuru.METASPLOIT: METASPLOIT_VARSAYILAN_ZAMAN_ASIMI,
    }
    try:
        return zamanAsimlari[aracTuru]
    except KeyError as hata:
        raise ValueError("Gecerli bir AracTuru gereklidir.") from hata


def _araciBul(aracTuru: AracTuru) -> AracDurumu:
    # testssl alternatif adlarini, diger araclarin tek komut adini dener.
    adaylar = {
        AracTuru.NMAP: ("nmap",),
        AracTuru.TESTSSL: ("testssl", "testssl.sh"),
        AracTuru.METASPLOIT: ("msfconsole",),
    }[aracTuru]
    for aracAdi in adaylar:
        aracDurumu = araciKontrolEt(aracAdi)
        if aracDurumu.bulunduMu:
            return aracDurumu
    gorunenAd = "testssl/testssl.sh" if aracTuru is AracTuru.TESTSSL else adaylar[0]
    return AracDurumu(gorunenAd, False, None)


def _surumKomutunuOlustur(aracTuru: AracTuru, aracYolu: str) -> tuple[str, ...]:
    # Her arac icin etkilesimsiz surum komutunu olusturur.
    if aracTuru is AracTuru.METASPLOIT:
        return aracYolu, "--version"
    return aracYolu, "--version"


def _surumuAyristir(aracTuru: AracTuru, cikti: str) -> str | None:
    # Bilinen arac surum satirlarini yalnizca surum degerine donusturur.
    desenler = {
        AracTuru.NMAP: r"Nmap version\s+([^\s]+)",
        AracTuru.TESTSSL: r"testssl(?:\.sh)? version\s+([^\s]+)",
        AracTuru.METASPLOIT: r"(?:Framework\s+)?Version:\s*([^\s]+)",
    }
    temizCikti = ANSI_KACIS_DESENI.sub("", cikti)
    eslesme = re.search(desenler[aracTuru], temizCikti, flags=re.IGNORECASE)
    return eslesme.group(1).strip() if eslesme else None


def _hataliAracBilgisi(
    aracTuru: AracTuru,
    aracDurumu: AracDurumu,
    durum: AracDurumKodu,
    varsayilanZamanAsimi: float,
    hataMesaji: str,
) -> HariciAracBilgisi:
    # Ortak hata alanlariyla bir arac bilgisi olusturur.
    return HariciAracBilgisi(
        aracTuru=aracTuru,
        aracAdi=aracDurumu.aracAdi,
        durum=durum,
        aracYolu=aracDurumu.aracYolu,
        surum=None,
        varsayilanZamanAsimi=varsayilanZamanAsimi,
        hataMesaji=hataMesaji,
    )


def _ilkDoluSatiriAl(metin: str) -> str | None:
    # Cok satirli hata ciktisinin ilk anlamli satirini dondurur.
    return next((satir.strip() for satir in metin.splitlines() if satir.strip()), None)
