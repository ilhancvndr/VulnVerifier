# Nmap XML ciktisini host, port ve servis sonuc modellerine donusturur.

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

from vulnverifier.errors import CiktiAyristirmaHatasi

AZAMI_XML_BOYUTU = 10 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class NmapBetikAlani:
    # Bir Nmap NSE betiginin yapilandirilmis tek bir alanini tasir.
    anahtar: str
    deger: str


@dataclass(frozen=True, slots=True)
class NmapBetikSonucu:
    # Bir port uzerinde calisan Nmap NSE betiginin sonucunu tasir.
    kimlik: str
    cikti: str | None = None
    alanlar: tuple[NmapBetikAlani, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class NmapPortSonucu:
    # Bir Nmap port kaydinin durum ve servis bilgilerini tasir.
    port: int
    protokol: str
    durum: str
    servisAdi: str | None = None
    urun: str | None = None
    surum: str | None = None
    betikSonuclari: tuple[NmapBetikSonucu, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class NmapHostSonucu:
    # Bir Nmap host kaydinin durumunu, adreslerini ve portlarini tasir.
    durum: str
    adresler: tuple[str, ...] = field(default_factory=tuple)
    portlar: tuple[NmapPortSonucu, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class NmapTaramaSonucu:
    # Tek bir Nmap XML belgesinden ayristirilan host sonuclarini tasir.
    hostlar: tuple[NmapHostSonucu, ...] = field(default_factory=tuple)


class NmapXmlAyristirmaHatasi(CiktiAyristirmaHatasi):
    # Nmap XML metni gecersiz veya desteklenmeyen yapida oldugunda olusan hatadir.
    pass


def nmapXmliniAyristir(xmlMetni: str) -> NmapTaramaSonucu:
    # Guvenlik denetimlerinden gecen Nmap XML metnini standart modele cevirir.
    _xmlMetniniDogrula(xmlMetni)

    try:
        kokEleman = ElementTree.fromstring(xmlMetni)
    except ElementTree.ParseError as hata:
        raise NmapXmlAyristirmaHatasi("Nmap XML çıktısı geçerli XML değil.") from hata

    if kokEleman.tag != "nmaprun":
        raise NmapXmlAyristirmaHatasi("XML kök elemanı 'nmaprun' olmalıdır.")

    hostlar = tuple(_hostuAyristir(hostElemani) for hostElemani in kokEleman.findall("host"))
    return NmapTaramaSonucu(hostlar=hostlar)


def _xmlMetniniDogrula(xmlMetni: str) -> None:
    # Bos, cok buyuk veya ozel varlik tanimi iceren XML girdilerini reddeder.
    if not isinstance(xmlMetni, str) or not xmlMetni.strip():
        raise NmapXmlAyristirmaHatasi("Nmap XML çıktısı boş olamaz.")
    if len(xmlMetni.encode("utf-8")) > AZAMI_XML_BOYUTU:
        raise NmapXmlAyristirmaHatasi("Nmap XML çıktısı izin verilen boyutu aşıyor.")

    buyukHarfliXml = xmlMetni.upper()
    standartDoctypeHariciXml = re.sub(
        r"<!DOCTYPE\s+NMAPRUN\s*>",
        "",
        buyukHarfliXml,
    )
    if "<!DOCTYPE" in standartDoctypeHariciXml or "<!ENTITY" in buyukHarfliXml:
        raise NmapXmlAyristirmaHatasi(
            "Nmap XML çıktısı standart dışı DOCTYPE veya ENTITY içeremez."
        )


def _hostuAyristir(hostElemani: ElementTree.Element) -> NmapHostSonucu:
    # Bir host elemanini adres ve port bilgileriyle birlikte ayristirir.
    durumElemani = hostElemani.find("status")
    if durumElemani is None:
        raise NmapXmlAyristirmaHatasi("Nmap host kaydında durum bilgisi bulunamadı.")

    durum = _zorunluOzelligiAl(durumElemani, "state", "host durumu")
    adresler = tuple(
        adres
        for adresElemani in hostElemani.findall("address")
        if (adres := _istegeBagliOzelligiAl(adresElemani, "addr")) is not None
    )
    portlar = tuple(
        _portuAyristir(portElemani) for portElemani in hostElemani.findall("ports/port")
    )
    return NmapHostSonucu(durum=durum, adresler=adresler, portlar=portlar)


def _portuAyristir(portElemani: ElementTree.Element) -> NmapPortSonucu:
    # Bir port elemaninin durumunu ve varsa servis bilgilerini ayristirir.
    portMetni = _zorunluOzelligiAl(portElemani, "portid", "port numarası")
    try:
        port = int(portMetni)
    except ValueError as hata:
        raise NmapXmlAyristirmaHatasi("Nmap port numarası geçerli bir tam sayı değil.") from hata
    if not 1 <= port <= 65535:
        raise NmapXmlAyristirmaHatasi("Nmap port numarası 1 ile 65535 arasında olmalıdır.")

    protokol = _zorunluOzelligiAl(portElemani, "protocol", "port protokolü")
    durumElemani = portElemani.find("state")
    if durumElemani is None:
        raise NmapXmlAyristirmaHatasi("Nmap port kaydında durum bilgisi bulunamadı.")
    durum = _zorunluOzelligiAl(durumElemani, "state", "port durumu")
    betikSonuclari = tuple(
        _betikSonucunuAyristir(betikElemani) for betikElemani in portElemani.findall("script")
    )

    servisElemani = portElemani.find("service")
    if servisElemani is None:
        return NmapPortSonucu(
            port=port,
            protokol=protokol,
            durum=durum,
            betikSonuclari=betikSonuclari,
        )

    return NmapPortSonucu(
        port=port,
        protokol=protokol,
        durum=durum,
        servisAdi=_istegeBagliOzelligiAl(servisElemani, "name"),
        urun=_istegeBagliOzelligiAl(servisElemani, "product"),
        surum=_istegeBagliOzelligiAl(servisElemani, "version"),
        betikSonuclari=betikSonuclari,
    )


def _betikSonucunuAyristir(betikElemani: ElementTree.Element) -> NmapBetikSonucu:
    # NSE betiginin kimligini ve dogrudan yapilandirilmis alanlarini ayristirir.
    kimlik = _zorunluOzelligiAl(betikElemani, "id", "NSE betik kimliği")
    alanlar: list[NmapBetikAlani] = []
    for alanElemani in betikElemani.findall("elem"):
        anahtar = _istegeBagliOzelligiAl(alanElemani, "key")
        deger = (alanElemani.text or "").strip()
        if anahtar is not None and deger:
            alanlar.append(NmapBetikAlani(anahtar=anahtar, deger=deger))

    return NmapBetikSonucu(
        kimlik=kimlik,
        cikti=_istegeBagliOzelligiAl(betikElemani, "output"),
        alanlar=tuple(alanlar),
    )


def _zorunluOzelligiAl(
    eleman: ElementTree.Element,
    ozellikAdi: str,
    alanAdi: str,
) -> str:
    # Zorunlu XML ozelligini alir ve bos degeri gecersiz sayar.
    deger = _istegeBagliOzelligiAl(eleman, ozellikAdi)
    if deger is None:
        raise NmapXmlAyristirmaHatasi(f"Nmap XML kaydında {alanAdi} bulunamadı.")
    return deger


def _istegeBagliOzelligiAl(eleman: ElementTree.Element, ozellikAdi: str) -> str | None:
    # Istege bagli XML ozelligini bosluklardan arindirarak dondurur.
    deger = eleman.get(ozellikAdi)
    if deger is None or not deger.strip():
        return None
    return deger.strip()
