# Nmap XML ciktisindan HPE iLO urun ve firmware bilgilerini ayristirir.

from dataclasses import dataclass, field

from vulnverifier.nmap_parser import NmapBetikSonucu, nmapXmliniAyristir

HPE_ILO_BETIK_KIMLIGI = "http-hp-ilo-info"


@dataclass(frozen=True, slots=True)
class HpeIloHedefSonucu:
    # Tek host ve port icin ayristirilan HPE iLO bilgilerini tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    iloTuru: str | None = None
    firmwareSurumu: str | None = None
    sunucuTuru: str | None = None
    urunKimligi: str | None = None


@dataclass(frozen=True, slots=True)
class HpeIloTaramaSonucu:
    # Nmap XML belgesindeki tum HPE iLO hedef sonuclarini tasir.
    hedefSonuclari: tuple[HpeIloHedefSonucu, ...] = field(default_factory=tuple)


def hpeIloXmliniAyristir(xmlMetni: str) -> HpeIloTaramaSonucu:
    # Guvenli Nmap ayristiricisini kullanarak iLO alanlarini hedef bazinda toplar.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    hedefSonuclari: list[HpeIloHedefSonucu] = []

    for hostSonucu in nmapSonucu.hostlar:
        for portSonucu in hostSonucu.portlar:
            iloBetigi = _iloBetiginiBul(portSonucu.betikSonuclari)
            betikAlanlari = _betikAlanlariniSozlugeCevir(iloBetigi)
            hedefSonuclari.append(
                HpeIloHedefSonucu(
                    hostDurumu=hostSonucu.durum,
                    adresler=hostSonucu.adresler,
                    port=portSonucu.port,
                    portDurumu=portSonucu.durum,
                    servisAdi=portSonucu.servisAdi,
                    iloTuru=betikAlanlari.get("ILOType"),
                    firmwareSurumu=betikAlanlari.get("ILOFirmware"),
                    sunucuTuru=betikAlanlari.get("ServerType"),
                    urunKimligi=betikAlanlari.get("ProductID"),
                )
            )

    return HpeIloTaramaSonucu(hedefSonuclari=tuple(hedefSonuclari))


def _iloBetiginiBul(betikSonuclari: tuple[NmapBetikSonucu, ...]) -> NmapBetikSonucu | None:
    # Port sonucundaki HPE iLO NSE betigini bulur.
    return next(
        (betik for betik in betikSonuclari if betik.kimlik == HPE_ILO_BETIK_KIMLIGI),
        None,
    )


def _betikAlanlariniSozlugeCevir(betikSonucu: NmapBetikSonucu | None) -> dict[str, str]:
    # Bulunmayan betigi bos alanlarla temsil eder.
    if betikSonucu is None:
        return {}
    return {alan.anahtar: alan.deger for alan in betikSonucu.alanlar}
