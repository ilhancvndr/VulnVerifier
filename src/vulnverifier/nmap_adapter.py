# Nmap port ve servis taramalarini guvenli argumanlarla calistiran adaptoru saglar.

import ipaddress

from vulnverifier.command_runner import (
    KomutIptalDenetimi,
    KomutSonucu,
)
from vulnverifier.command_runner import (
    komutuSonucaDonusturerekCalistir as komutuCalistir,
)
from vulnverifier.port_validation import PortGirdisi, portlariDogrula, portuDogrula
from vulnverifier.target_validation import hedefiDogrula
from vulnverifier.tool_availability import araciKontrolEt
from vulnverifier.tool_management import NMAP_VARSAYILAN_ZAMAN_ASIMI

VARSAYILAN_ILO_PORTU = 443
VARSAYILAN_SNMP_PORTU = 161
VARSAYILAN_VMWARE_PORTU = 443
VARSAYILAN_DNS_PORTU = 53
DNS_CACHE_BETIK_ZAMAN_ASIMI = "45s"
VARSAYILAN_NTP_PORTU = 123
NTP_BETIK_ZAMAN_ASIMI = "20s"
VARSAYILAN_MS17010_PORTU = 445
VARSAYILAN_MS12020_PORTU = 3389
VARSAYILAN_SMB_PORTU = 445


class NmapBulunamadiHatasi(RuntimeError):
    # Nmap sistem PATH degeri icinde bulunamadiginda olusan hatadir.
    pass


class NmapYapilandirmaHatasi(ValueError):
    # Adaptore gecersiz Nmap calistirilabilir dosya yolu verildiginde olusan hatadir.
    pass


class NmapAdaptoru:
    # Tek hedef ve tek port icin Nmap komutunu olusturur ve calistirir.
    def __init__(self, aracYolu: str) -> None:
        if not isinstance(aracYolu, str) or not aracYolu or aracYolu != aracYolu.strip():
            raise NmapYapilandirmaHatasi("Nmap araç yolu boş olamaz veya boşlukla çevrilemez.")
        if "\x00" in aracYolu:
            raise NmapYapilandirmaHatasi("Nmap araç yolu null karakteri içeremez.")

        self._aracYolu = aracYolu

    @classmethod
    def sistemdenOlustur(cls) -> "NmapAdaptoru":
        # PATH icinde bulunan Nmap yoluyla kullanima hazir bir adaptor olusturur.
        aracDurumu = araciKontrolEt("nmap")
        if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
            raise NmapBulunamadiHatasi("Nmap sistem PATH değeri içinde bulunamadı.")
        return cls(aracDurumu.aracYolu)

    def komutOlustur(
        self,
        hedef: str,
        portlar: PortGirdisi = None,
    ) -> tuple[str, ...]:
        # Hedef ve istege bagli portlar icin XML ciktili Nmap komutunu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPortlar = portlariDogrula(portlar)
        komutParcalari = [self._aracYolu]

        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")

        komutParcalari.extend(
            ["-sT", "-sV", "--version-light", "-Pn", "-n", "--noninteractive", "-oX", "-"]
        )
        if standartPortlar:
            komutParcalari.extend(["-p", ",".join(map(str, standartPortlar))])
        komutParcalari.append(standartHedef)
        return tuple(komutParcalari)

    def portServisTaramasiCalistir(
        self,
        hedef: str,
        portlar: PortGirdisi = None,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # Olusturulan Nmap komutunu merkezi komut calistiriciyla yurutur.
        komutParcalari = self.komutOlustur(hedef, portlar)
        return komutuCalistir(
            komutParcalari,
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def hpeIloKomutuOlustur(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_ILO_PORTU,
    ) -> tuple[str, ...]:
        # HPE iLO bilgisini NSE betigiyle XML olarak alacak Nmap komutunu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]

        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")

        komutParcalari.extend(
            [
                "-sT",
                "-sV",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script",
                "http-hp-ilo-info",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def hpeIloTaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_ILO_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # HPE iLO Nmap komutunu merkezi komut calistiriciyla yurutur.
        komutParcalari = self.hpeIloKomutuOlustur(hedef, port)
        return komutuCalistir(
            komutParcalari,
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def snmpPublicCommunityKomutuOlustur(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_SNMP_PORTU,
    ) -> tuple[str, ...]:
        # Public community degerini guvenli SNMP sorgusuyla sinayacak komutu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]

        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")

        komutParcalari.extend(
            [
                "-sU",
                "-sV",
                "--version-light",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script",
                "snmp-sysdescr",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def snmpPublicCommunityTaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_SNMP_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # SNMP public community Nmap komutunu merkezi calistiriciyla yurutur.
        komutParcalari = self.snmpPublicCommunityKomutuOlustur(hedef, port)
        return komutuCalistir(
            komutParcalari,
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def vmwareSurumKomutuOlustur(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_VMWARE_PORTU,
    ) -> tuple[str, ...]:
        # VMware SOAP API surumunu XML olarak alacak guvenli Nmap komutunu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]
        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")
        komutParcalari.extend(
            [
                "-sT",
                "-sV",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script",
                "vmware-version",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def vmwareSurumTaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_VMWARE_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # VMware surum Nmap komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.vmwareSurumKomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def dnsCacheSnoopKomutuOlustur(
        self, hedef: str, port: str | int = VARSAYILAN_DNS_PORTU
    ) -> tuple[str, ...]:
        # DNS cache snooping betigini nonrecursive modda calistiracak komutu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]
        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")
        komutParcalari.extend(
            [
                "-sU",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script-timeout",
                DNS_CACHE_BETIK_ZAMAN_ASIMI,
                "--script",
                "dns-cache-snoop",
                "--script-args",
                "dns-cache-snoop.mode=nonrecursive",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def dnsCacheSnoopTaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_DNS_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # DNS cache snooping komutunu merkezi calistiriciyla yurutur.
        return komutuCalistir(
            self.dnsCacheSnoopKomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def ntpMode6KomutuOlustur(
        self, hedef: str, port: str | int = VARSAYILAN_NTP_PORTU
    ) -> tuple[str, ...]:
        # NTP Mode 6 READVAR sorgusunu sinirli ntp-info betigiyle olusturur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]
        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")
        komutParcalari.extend(
            [
                "-sU",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script-timeout",
                NTP_BETIK_ZAMAN_ASIMI,
                "--script",
                "ntp-info",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def ntpMode6TaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_NTP_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # NTP Mode 6 komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.ntpMode6KomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def ms17010KomutuOlustur(
        self, hedef: str, port: str | int = VARSAYILAN_MS17010_PORTU
    ) -> tuple[str, ...]:
        # MS17-010 durumunu guvenli NSE betigiyle XML olarak alacak komutu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]
        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")
        komutParcalari.extend(
            [
                "-sT",
                "-sV",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script",
                "smb-vuln-ms17-010",
                "--script-args",
                "vulns.showall=1",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def ms17010TaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_MS17010_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # MS17-010 Nmap komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.ms17010KomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def ms12020KomutuOlustur(
        self, hedef: str, port: str | int = VARSAYILAN_MS12020_PORTU
    ) -> tuple[str, ...]:
        # MS12-020 durumunu NSE betigiyle XML olarak alacak komutu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]
        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")
        komutParcalari.extend(
            [
                "-sT",
                "-sV",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script",
                "rdp-vuln-ms12-020",
                "--script-args",
                "vulns.showall=1",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def ms12020TaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_MS12020_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # MS12-020 Nmap komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.ms12020KomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def smbGuvenlikKomutuOlustur(
        self, hedef: str, port: str | int = VARSAYILAN_SMB_PORTU
    ) -> tuple[str, ...]:
        # SMB kimlik, protokol ve imzalama bilgilerini guvenli NSE betikleriyle toplar.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        komutParcalari = [self._aracYolu]
        if _ipv6Mi(standartHedef):
            komutParcalari.append("-6")
        komutParcalari.extend(
            [
                "-sT",
                "-sV",
                "-Pn",
                "-n",
                "--noninteractive",
                "--script",
                "smb-os-discovery,smb-protocols,smb2-security-mode",
                "-oX",
                "-",
                "-p",
                str(standartPort),
                standartHedef,
            ]
        )
        return tuple(komutParcalari)

    def smbGuvenlikTaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_SMB_PORTU,
        zamanAsimi: float | int = NMAP_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # SMB guvenlik kesfi komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.smbGuvenlikKomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )


def _ipv6Mi(hedef: str) -> bool:
    # Standart hedefin IPv6 adresi olup olmadigini belirler.
    try:
        return isinstance(ipaddress.ip_address(hedef), ipaddress.IPv6Address)
    except ValueError:
        return False
