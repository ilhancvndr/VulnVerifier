# Nmap XML ciktisindan SMB kimlik, protokol ve imzalama bilgilerini ayristirir.

import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field

from vulnverifier.nmap_parser import nmapXmliniAyristir

SMB_OS_BETIK_KIMLIGI = "smb-os-discovery"
SMB_PROTOKOL_BETIK_KIMLIGI = "smb-protocols"
SMB_IMZALAMA_BETIK_KIMLIGI = "smb2-security-mode"


@dataclass(frozen=True, slots=True)
class SmbGuvenlikHedefSonucu:
    # Tek hedefin SMB servis ve guvenlik ozelliklerini tasir.
    hostDurumu: str
    adresler: tuple[str, ...]
    port: int
    portDurumu: str
    servisAdi: str | None = None
    bilgisayarAdi: str | None = None
    isletimSistemi: str | None = None
    domain: str | None = None
    fqdn: str | None = None
    smbSurumleri: tuple[str, ...] = field(default_factory=tuple)
    smbV1EtkinMi: bool | None = None
    imzalamaZorunluMu: bool | None = None
    imzalamaEtkinMi: bool | None = None


@dataclass(frozen=True, slots=True)
class SmbGuvenlikTaramaSonucu:
    # Nmap XML belgesindeki SMB guvenlik sonuclarini tasir.
    hedefSonuclari: tuple[SmbGuvenlikHedefSonucu, ...] = field(default_factory=tuple)


def smbGuvenlikXmliniAyristir(xmlMetni: str) -> SmbGuvenlikTaramaSonucu:
    # Guvenlik denetimli XML icindeki SMB betiklerini hedef bazinda birlestirir.
    nmapSonucu = nmapXmliniAyristir(xmlMetni)
    kokEleman = ElementTree.fromstring(xmlMetni)
    hedefSonuclari: list[SmbGuvenlikHedefSonucu] = []
    for host, hostElemani in zip(nmapSonucu.hostlar, kokEleman.findall("host"), strict=True):
        betikler = _betikleriKimligeGoreTopla(hostElemani)
        osAlanlari = _alanlariSozlugeCevir(betikler.get(SMB_OS_BETIK_KIMLIGI))
        smbSurumleri, smbV1EtkinMi = _smbSurumleriniAyristir(
            betikler.get(SMB_PROTOKOL_BETIK_KIMLIGI)
        )
        imzalamaZorunluMu, imzalamaEtkinMi = _imzalamayiAyristir(
            betikler.get(SMB_IMZALAMA_BETIK_KIMLIGI)
        )
        for port in host.portlar:
            hedefSonuclari.append(
                SmbGuvenlikHedefSonucu(
                    hostDurumu=host.durum,
                    adresler=host.adresler,
                    port=port.port,
                    portDurumu=port.durum,
                    servisAdi=port.servisAdi,
                    bilgisayarAdi=_ilkDoluAlan(
                        osAlanlari, "Computer name", "NetBIOS computer name"
                    ),
                    isletimSistemi=_ilkDoluAlan(osAlanlari, "OS"),
                    domain=_ilkDoluAlan(osAlanlari, "Domain name", "Domain", "Workgroup"),
                    fqdn=_ilkDoluAlan(osAlanlari, "FQDN"),
                    smbSurumleri=smbSurumleri,
                    smbV1EtkinMi=smbV1EtkinMi,
                    imzalamaZorunluMu=imzalamaZorunluMu,
                    imzalamaEtkinMi=imzalamaEtkinMi,
                )
            )
    return SmbGuvenlikTaramaSonucu(tuple(hedefSonuclari))


def _betikleriKimligeGoreTopla(
    hostElemani: ElementTree.Element,
) -> dict[str, ElementTree.Element]:
    # Host ve port seviyesindeki ilgili SMB betiklerini tek sozlukte toplar.
    betikler = hostElemani.findall("hostscript/script") + hostElemani.findall("ports/port/script")
    return {
        kimlik: betik
        for betik in betikler
        if (kimlik := betik.get("id"))
        in {SMB_OS_BETIK_KIMLIGI, SMB_PROTOKOL_BETIK_KIMLIGI, SMB_IMZALAMA_BETIK_KIMLIGI}
    }


def _alanlariSozlugeCevir(betik: ElementTree.Element | None) -> dict[str, str]:
    # NSE betiginin ic ice elem alanlarini anahtar ve deger sozlugune cevirir.
    if betik is None:
        return {}
    return {
        anahtar: deger
        for eleman in betik.findall(".//elem")
        if (anahtar := (eleman.get("key") or "").strip()) and (deger := (eleman.text or "").strip())
    }


def _ilkDoluAlan(alanlar: dict[str, str], *anahtarlar: str) -> str | None:
    # Alternatif NSE alan adlarindan ilk bulunan degeri dondurur.
    return next((alanlar[anahtar] for anahtar in anahtarlar if anahtar in alanlar), None)


def _smbSurumleriniAyristir(
    betik: ElementTree.Element | None,
) -> tuple[tuple[str, ...], bool | None]:
    # Sunulan SMB lehcelerini ve SMBv1 durumunu yapilandirilmis degerlere cevirir.
    if betik is None:
        return (), None
    degerler = tuple(
        deger for eleman in betik.findall(".//elem") if (deger := (eleman.text or "").strip())
    )
    if not degerler:
        return (), None
    smbV1EtkinMi = any(
        "smbv1" in deger.lower() or "nt lm 0.12" in deger.lower() for deger in degerler
    )
    return degerler, smbV1EtkinMi


def _imzalamayiAyristir(
    betik: ElementTree.Element | None,
) -> tuple[bool | None, bool | None]:
    # SMB2 security mode metninden zorunluluk ve etkinlik durumlarini ayirir.
    if betik is None:
        return None, None
    parcalar = [betik.get("output") or ""]
    parcalar.extend((eleman.text or "") for eleman in betik.findall(".//elem"))
    metin = " ".join(parcalar).lower()
    if "enabled but not required" in metin or "signing not required" in metin:
        return False, True
    if "disabled" in metin:
        return False, False
    if "enabled and required" in metin or "signing required" in metin:
        return True, True
    return None, None
