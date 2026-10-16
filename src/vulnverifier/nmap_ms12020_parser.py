# Nmap XML ciktisindan MS12-020 NSE sonuclarini ayristirir.

import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

from vulnverifier.nmap_parser import nmapXmliniAyristir

MS12020_BETIK_KIMLIGI = "rdp-vuln-ms12-020"


@dataclass(frozen=True, slots=True)
class NmapMs12020ZafiyetSonucu:
    # Betigin tek CVE icin raporladigi durumu tasir.
    cve: str
    savunmasizMi: bool | None
    detay: str


@dataclass(frozen=True, slots=True)
class NmapMs12020HedefSonucu:
    # Tek RDP hedefinin MS12-020 sonuclarini tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    zafiyetSonuclari: tuple[NmapMs12020ZafiyetSonucu, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class NmapMs12020TaramaSonucu:
    # Nmap XML belgesindeki tum MS12-020 hedef sonuclarini tasir.
    hedefSonuclari: tuple[NmapMs12020HedefSonucu, ...] = field(default_factory=tuple)


def nmapMs12020XmliniAyristir(xmlMetni: str) -> NmapMs12020TaramaSonucu:
    # Guvenlik denetiminden gecen XML icindeki port betigi sonuclarini toplar.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    kokEleman = ElementTree.fromstring(xmlMetni)
    hedefSonuclari: list[NmapMs12020HedefSonucu] = []
    for host, hostElemani in zip(nmapSonucu.hostlar, kokEleman.findall("host"), strict=True):
        portElemanlari = hostElemani.findall("ports/port")
        for port, portElemani in zip(host.portlar, portElemanlari, strict=True):
            betik = next(
                (
                    eleman
                    for eleman in portElemani.findall("script")
                    if eleman.get("id") == MS12020_BETIK_KIMLIGI
                ),
                None,
            )
            hedefSonuclari.append(
                NmapMs12020HedefSonucu(
                    host.durum,
                    host.adresler,
                    port.port,
                    port.durum,
                    port.servisAdi,
                    _zafiyetSonuclariniAyristir(betik),
                )
            )
    return NmapMs12020TaramaSonucu(tuple(hedefSonuclari))


def _zafiyetSonuclariniAyristir(
    betik: ElementTree.Element | None,
) -> tuple[NmapMs12020ZafiyetSonucu, ...]:
    # Her CVE tablosundaki state ve hata ayrintisini korur.
    if betik is None:
        return ()
    sonuclar: list[NmapMs12020ZafiyetSonucu] = []
    for tablo in betik.findall("table"):
        cve = tablo.get("key") or "bilinmeyen"
        durum = _anahtarliElemanMetniniAl(tablo, "state")
        kontrolDetayi = _anahtarliElemanMetniniAl(tablo, "check_results")
        if kontrolDetayi is not None:
            savunmasizMi = None
            detay = kontrolDetayi
        elif durum is not None and durum.upper() == "VULNERABLE":
            savunmasizMi = True
            detay = durum
        elif durum is not None and durum.upper() == "NOT VULNERABLE":
            savunmasizMi = False
            detay = durum
        else:
            savunmasizMi = None
            detay = durum or "NSE betigi kesin bir sonuc uretmedi."
        sonuclar.append(NmapMs12020ZafiyetSonucu(cve, savunmasizMi, detay))
    return tuple(sonuclar)


def _anahtarliElemanMetniniAl(tablo: ElementTree.Element, anahtar: str) -> str | None:
    # Ic ice tablodaki belirtilen anahtarin ilk dolu metnini dondurur.
    return next(
        (
            (eleman.text or "").strip()
            for eleman in tablo.findall(".//elem")
            if eleman.get("key") == anahtar and (eleman.text or "").strip()
        ),
        None,
    )
