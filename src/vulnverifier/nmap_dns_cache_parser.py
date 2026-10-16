# Nmap XML ciktisindan DNS cache snooping sonucunu ayristirir.

import re
from dataclasses import dataclass, field

from vulnverifier.errors import CiktiAyristirmaHatasi
from vulnverifier.nmap_parser import NmapBetikSonucu, nmapXmliniAyristir

DNS_CACHE_BETIK_KIMLIGI = "dns-cache-snoop"
OZET_DESENI = re.compile(r"^(\d+) of (\d+) tested domains are cached\.", re.I)


@dataclass(frozen=True, slots=True)
class DnsCacheHedefSonucu:
    # Tek DNS hedefinin cache snooping sonucunu tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    testEdilenAlanAdiSayisi: int | None = None
    onbellektekiAlanAdlari: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class DnsCacheTaramaSonucu:
    # Nmap XML belgesindeki tum DNS cache sonuclarini tasir.
    hedefSonuclari: tuple[DnsCacheHedefSonucu, ...] = field(default_factory=tuple)


def dnsCacheXmliniAyristir(xmlMetni: str) -> DnsCacheTaramaSonucu:
    # Betik ozetini ve listelenen cache alan adlarini hedef bazinda toplar.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    hedefSonuclari: list[DnsCacheHedefSonucu] = []
    for host in nmapSonucu.hostlar:
        for port in host.portlar:
            betik = _betigiBul(port.betikSonuclari)
            testSayisi, alanAdlari = _betikCiktisiniAyristir(betik)
            hedefSonuclari.append(
                DnsCacheHedefSonucu(
                    host.durum,
                    host.adresler,
                    port.port,
                    port.durum,
                    port.servisAdi,
                    testSayisi,
                    alanAdlari,
                )
            )
    return DnsCacheTaramaSonucu(tuple(hedefSonuclari))


def _betigiBul(betikler: tuple[NmapBetikSonucu, ...]) -> NmapBetikSonucu | None:
    # DNS cache snooping betigini bulur.
    return next((betik for betik in betikler if betik.kimlik == DNS_CACHE_BETIK_KIMLIGI), None)


def _betikCiktisiniAyristir(
    betik: NmapBetikSonucu | None,
) -> tuple[int | None, tuple[str, ...]]:
    # Ozet satirini ve kalan alan adlarini ayristirir.
    if betik is None or betik.cikti is None:
        return None, ()
    satirlar = tuple(satir.strip() for satir in betik.cikti.splitlines() if satir.strip())
    if not satirlar:
        raise CiktiAyristirmaHatasi("DNS cache snooping betik çıktısı boş.")
    eslesme = OZET_DESENI.match(satirlar[0])
    if eslesme is None:
        raise CiktiAyristirmaHatasi("DNS cache snooping özet satırı ayrıştırılamadı.")
    cacheSayisi = int(eslesme.group(1))
    testSayisi = int(eslesme.group(2))
    alanAdlari = satirlar[1:]
    if cacheSayisi != len(alanAdlari):
        raise CiktiAyristirmaHatasi("DNS cache snooping sayısı alan adı listesiyle uyuşmuyor.")
    return testSayisi, alanAdlari
