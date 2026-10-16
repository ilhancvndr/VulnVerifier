# Nmap XML ciktisindan MS17-010 NSE sonucunu ayristirir.

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

from vulnverifier.nmap_parser import nmapXmliniAyristir

MS17010_BETIK_KIMLIGI = "smb-vuln-ms17-010"
DURUM_DESENI = re.compile(r"State:\s*(NOT VULNERABLE|VULNERABLE)", re.I)


@dataclass(frozen=True, slots=True)
class NmapMs17010HedefSonucu:
    # Tek SMB hedefinin MS17-010 sonucunu tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    savunmasizMi: bool | None = None
    detay: str = "NSE betigi kesin bir sonuc uretmedi."


@dataclass(frozen=True, slots=True)
class NmapMs17010TaramaSonucu:
    # Nmap XML belgesindeki tum MS17-010 sonuclarini tasir.
    hedefSonuclari: tuple[NmapMs17010HedefSonucu, ...] = field(default_factory=tuple)


def nmapMs17010XmliniAyristir(xmlMetni: str) -> NmapMs17010TaramaSonucu:
    # Guvenlik denetiminden gecen XML icindeki host betigi sonucunu portla birlestirir.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    kokEleman = ElementTree.fromstring(xmlMetni)
    hostElemanlari = kokEleman.findall("host")
    hedefSonuclari: list[NmapMs17010HedefSonucu] = []
    for host, hostElemani in zip(nmapSonucu.hostlar, hostElemanlari, strict=True):
        hostBetigi = _betigiBul(hostElemani.findall("hostscript/script"))
        portElemanlari = hostElemani.findall("ports/port")
        for port, portElemani in zip(host.portlar, portElemanlari, strict=True):
            portBetigi = _betigiBul(portElemani.findall("script"))
            betik = portBetigi if portBetigi is not None else hostBetigi
            savunmasizMi, detay = _betikSonucunuAyristir(betik)
            hedefSonuclari.append(
                NmapMs17010HedefSonucu(
                    host.durum,
                    host.adresler,
                    port.port,
                    port.durum,
                    port.servisAdi,
                    savunmasizMi,
                    detay,
                )
            )
    return NmapMs17010TaramaSonucu(tuple(hedefSonuclari))


def _betigiBul(
    betikElemanlari: list[ElementTree.Element],
) -> ElementTree.Element | None:
    # MS17-010 betigini host veya port sonuclari arasinda bulur.
    return next(
        (betik for betik in betikElemanlari if betik.get("id") == MS17010_BETIK_KIMLIGI),
        None,
    )


def _betikSonucunuAyristir(
    betik: ElementTree.Element | None,
) -> tuple[bool | None, str]:
    # Yapilandirilmis state alanini, yoksa insan okunabilir ciktiyi degerlendirir.
    if betik is None:
        return None, "MS17-010 NSE betigi kesin bir sonuc uretmedi."
    durum = next(
        (
            (eleman.text or "").strip().upper()
            for eleman in betik.findall(".//elem")
            if eleman.get("key") == "state" and (eleman.text or "").strip()
        ),
        None,
    )
    cikti = (betik.get("output") or "").strip()
    if durum is None:
        eslesme = DURUM_DESENI.search(cikti)
        durum = eslesme.group(1).upper() if eslesme is not None else None
    detay = _detayiAl(betik, cikti)
    if durum == "VULNERABLE":
        return True, detay
    if durum == "NOT VULNERABLE":
        return False, detay
    return None, detay


def _detayiAl(betik: ElementTree.Element, cikti: str) -> str:
    # Betigin kontrol sonucunu veya ilk anlamli cikti satirini kanit icin alir.
    kontrolSonucu = next(
        (
            (eleman.text or "").strip()
            for eleman in betik.findall(".//elem")
            if eleman.get("key") == "check_results" and (eleman.text or "").strip()
        ),
        None,
    )
    if kontrolSonucu is not None:
        return kontrolSonucu
    satirlar = tuple(satir.strip() for satir in cikti.splitlines() if satir.strip())
    return satirlar[0] if satirlar else "NSE betigi kesin bir sonuc uretmedi."
