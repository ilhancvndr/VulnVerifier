# Nmap XML ciktisindan SNMP public community kabul sonucunu ayristirir.

from dataclasses import dataclass, field

from vulnverifier.nmap_parser import NmapBetikSonucu, nmapXmliniAyristir

SNMP_SYS_DESCR_BETIK_KIMLIGI = "snmp-sysdescr"


@dataclass(frozen=True, slots=True)
class SnmpPublicHedefSonucu:
    # Tek host ve UDP portu icin SNMP public community sonucunu tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    publicCommunityKabulEdildiMi: bool | None = None
    sistemAciklamasi: str | None = None


@dataclass(frozen=True, slots=True)
class SnmpPublicTaramaSonucu:
    # Nmap XML belgesindeki tum SNMP public community sonuclarini tasir.
    hedefSonuclari: tuple[SnmpPublicHedefSonucu, ...] = field(default_factory=tuple)


def snmpPublicXmliniAyristir(xmlMetni: str) -> SnmpPublicTaramaSonucu:
    # SNMP betik varligini ve guvenli sistem aciklamasini hedef bazinda toplar.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    hedefSonuclari: list[SnmpPublicHedefSonucu] = []

    for hostSonucu in nmapSonucu.hostlar:
        for portSonucu in hostSonucu.portlar:
            snmpBetigi = _snmpBetiginiBul(portSonucu.betikSonuclari)
            hedefSonuclari.append(
                SnmpPublicHedefSonucu(
                    hostDurumu=hostSonucu.durum,
                    adresler=hostSonucu.adresler,
                    port=portSonucu.port,
                    portDurumu=portSonucu.durum,
                    servisAdi=portSonucu.servisAdi,
                    publicCommunityKabulEdildiMi=(True if snmpBetigi is not None else None),
                    sistemAciklamasi=_sistemAciklamasiniAyristir(snmpBetigi),
                )
            )

    return SnmpPublicTaramaSonucu(hedefSonuclari=tuple(hedefSonuclari))


def _snmpBetiginiBul(
    betikSonuclari: tuple[NmapBetikSonucu, ...],
) -> NmapBetikSonucu | None:
    # Port sonucundaki guvenli SNMP sistem aciklamasi betigini bulur.
    return next(
        (betik for betik in betikSonuclari if betik.kimlik == SNMP_SYS_DESCR_BETIK_KIMLIGI),
        None,
    )


def _sistemAciklamasiniAyristir(betikSonucu: NmapBetikSonucu | None) -> str | None:
    # Calisma suresi satirini cikartip yalnizca sistem aciklamasini dondurur.
    if betikSonucu is None or betikSonucu.cikti is None:
        return None

    aciklamaSatirlari = tuple(
        temizSatir
        for satir in betikSonucu.cikti.splitlines()
        if (temizSatir := satir.strip()) and not temizSatir.casefold().startswith("system uptime:")
    )
    if not aciklamaSatirlari:
        return None
    return " ".join(aciklamaSatirlari)
