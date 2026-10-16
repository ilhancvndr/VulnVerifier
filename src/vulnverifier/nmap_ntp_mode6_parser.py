# Nmap XML ciktisindan NTP Mode 6 READVAR cevabini ayristirir.

from dataclasses import dataclass, field

from vulnverifier.nmap_parser import NmapBetikAlani, NmapBetikSonucu, nmapXmliniAyristir

NTP_INFO_BETIK_KIMLIGI = "ntp-info"
ZAMAN_DAMGASI_ANAHTARI = "receive time stamp"


@dataclass(frozen=True, slots=True)
class NtpMode6HedefSonucu:
    # Tek host ve UDP portu icin Mode 6 cevap durumunu tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    mode6CevabiAlindiMi: bool | None = None
    degiskenler: tuple[NmapBetikAlani, ...] = field(default_factory=tuple)


@dataclass(frozen=True, slots=True)
class NtpMode6TaramaSonucu:
    # Nmap XML belgesindeki tum NTP Mode 6 hedef sonuclarini tasir.
    hedefSonuclari: tuple[NtpMode6HedefSonucu, ...] = field(default_factory=tuple)


def ntpMode6XmliniAyristir(xmlMetni: str) -> NtpMode6TaramaSonucu:
    # ntp-info alanlarindan zaman cevabini ve Mode 6 degiskenlerini ayirir.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    hedefSonuclari: list[NtpMode6HedefSonucu] = []
    for hostSonucu in nmapSonucu.hostlar:
        for portSonucu in hostSonucu.portlar:
            ntpBetigi = _ntpBetiginiBul(portSonucu.betikSonuclari)
            mode6Degiskenleri = _mode6DegiskenleriniAl(ntpBetigi)
            hedefSonuclari.append(
                NtpMode6HedefSonucu(
                    hostDurumu=hostSonucu.durum,
                    adresler=hostSonucu.adresler,
                    port=portSonucu.port,
                    portDurumu=portSonucu.durum,
                    servisAdi=portSonucu.servisAdi,
                    mode6CevabiAlindiMi=_mode6CevapDurumunuBelirle(ntpBetigi, mode6Degiskenleri),
                    degiskenler=mode6Degiskenleri,
                )
            )
    return NtpMode6TaramaSonucu(tuple(hedefSonuclari))


def _ntpBetiginiBul(
    betikSonuclari: tuple[NmapBetikSonucu, ...],
) -> NmapBetikSonucu | None:
    # Port sonucundaki ntp-info betigini bulur.
    return next(
        (betik for betik in betikSonuclari if betik.kimlik == NTP_INFO_BETIK_KIMLIGI),
        None,
    )


def _mode6DegiskenleriniAl(
    ntpBetigi: NmapBetikSonucu | None,
) -> tuple[NmapBetikAlani, ...]:
    # Normal zaman cevabini haric tutup READVAR ile donen alanlari korur.
    if ntpBetigi is None:
        return ()
    return tuple(
        alan for alan in ntpBetigi.alanlar if alan.anahtar.casefold() != ZAMAN_DAMGASI_ANAHTARI
    )


def _mode6CevapDurumunuBelirle(
    ntpBetigi: NmapBetikSonucu | None,
    mode6Degiskenleri: tuple[NmapBetikAlani, ...],
) -> bool | None:
    # Degisken varsa cevap var, yalnizca zaman alani varsa Mode 6 engellidir.
    if mode6Degiskenleri:
        return True
    if ntpBetigi is not None and any(
        alan.anahtar.casefold() == ZAMAN_DAMGASI_ANAHTARI for alan in ntpBetigi.alanlar
    ):
        return False
    return None
