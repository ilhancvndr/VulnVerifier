# Nmap XML ciktisindan VMware urun, surum ve build bilgilerini ayristirir.

from dataclasses import dataclass, field

from vulnverifier.nmap_parser import NmapBetikSonucu, nmapXmliniAyristir

VMWARE_SURUM_BETIK_KIMLIGI = "vmware-version"


@dataclass(frozen=True, slots=True)
class VmwareSurumHedefSonucu:
    # Tek host ve port icin ayristirilan VMware surum bilgisini tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    urunAdi: str | None = None
    surum: str | None = None
    build: str | None = None
    localeSurumu: str | None = None
    isletimSistemiTuru: str | None = None
    urunHattiKimligi: str | None = None


@dataclass(frozen=True, slots=True)
class VmwareSurumTaramaSonucu:
    # Nmap XML belgesindeki tum VMware surum sonuclarini tasir.
    hedefSonuclari: tuple[VmwareSurumHedefSonucu, ...] = field(default_factory=tuple)


def vmwareSurumXmliniAyristir(xmlMetni: str) -> VmwareSurumTaramaSonucu:
    # VMware betik alanlarini hedef bazinda normalize eder.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    hedefSonuclari: list[VmwareSurumHedefSonucu] = []
    for hostSonucu in nmapSonucu.hostlar:
        for portSonucu in hostSonucu.portlar:
            betik = _vmwareBetiginiBul(portSonucu.betikSonuclari)
            alanlar = _betikAlanlariniSozlugeCevir(betik)
            urunAdi, surum = _sunucuSurumunuAyristir(alanlar.get("Server version"))
            hedefSonuclari.append(
                VmwareSurumHedefSonucu(
                    hostDurumu=hostSonucu.durum,
                    adresler=hostSonucu.adresler,
                    port=portSonucu.port,
                    portDurumu=portSonucu.durum,
                    servisAdi=portSonucu.servisAdi,
                    urunAdi=urunAdi,
                    surum=surum,
                    build=alanlar.get("Build"),
                    localeSurumu=alanlar.get("Locale version"),
                    isletimSistemiTuru=alanlar.get("OS type"),
                    urunHattiKimligi=alanlar.get("Product Line ID"),
                )
            )
    return VmwareSurumTaramaSonucu(hedefSonuclari=tuple(hedefSonuclari))


def _vmwareBetiginiBul(
    betikSonuclari: tuple[NmapBetikSonucu, ...],
) -> NmapBetikSonucu | None:
    # Port sonucundaki VMware surum betigini bulur.
    return next(
        (betik for betik in betikSonuclari if betik.kimlik == VMWARE_SURUM_BETIK_KIMLIGI),
        None,
    )


def _betikAlanlariniSozlugeCevir(betik: NmapBetikSonucu | None) -> dict[str, str]:
    # Bulunmayan betigi bos alanlarla temsil eder.
    if betik is None:
        return {}
    return {alan.anahtar: alan.deger for alan in betik.alanlar}


def _sunucuSurumunuAyristir(sunucuSurumu: str | None) -> tuple[str | None, str | None]:
    # Son bosluktan onceki bolumu urun, sonraki bolumu surum olarak ayirir.
    if sunucuSurumu is None or " " not in sunucuSurumu:
        return None, None
    urunAdi, surum = sunucuSurumu.rsplit(" ", 1)
    if not urunAdi or not surum:
        return None, None
    return urunAdi, surum
