# Metasploit kontrolleri icin guvenli msfconsole komut argumanlarini olusturur.

from vulnverifier.command_runner import (
    KomutIptalDenetimi,
    KomutSonucu,
)
from vulnverifier.command_runner import (
    komutuSonucaDonusturerekCalistir as komutuCalistir,
)
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula
from vulnverifier.tool_availability import araciKontrolEt
from vulnverifier.tool_management import METASPLOIT_VARSAYILAN_ZAMAN_ASIMI

VARSAYILAN_MS12020_PORTU = 3389
MS12020_MODULU = "auxiliary/scanner/rdp/ms12_020_check"
VARSAYILAN_MS17010_PORTU = 445
MS17010_MODULU = "auxiliary/scanner/smb/smb_ms17_010"
VARSAYILAN_IPMI_PORTU = 623
IPMI_HASH_MODULU = "auxiliary/scanner/ipmi/ipmi_dumphashes"
IZINLI_METASPLOIT_MODULLERI = frozenset((MS12020_MODULU, MS17010_MODULU, IPMI_HASH_MODULU))
IZINLI_METASPLOIT_AYARLARI = frozenset(
    (
        "THREADS",
        "CHECK_DOPU",
        "CHECK_ARCH",
        "CHECK_PIPE",
        "CRACK_COMMON",
        "SESSION_MAX_ATTEMPTS",
    )
)


class MetasploitBulunamadiHatasi(RuntimeError):
    # msfconsole sistem PATH degeri icinde bulunamadiginda olusan hatadir.
    pass


class MetasploitYapilandirmaHatasi(ValueError):
    # Adaptore gecersiz msfconsole calistirilabilir dosya yolu verildiginde olusan hatadir.
    pass


class MetasploitGuvenlikHatasi(ValueError):
    # Izin verilmeyen modul veya davranis ayari istendiginde olusan hatadir.
    pass


class MetasploitAdaptoru:
    # Metasploit taramalarinin etkilesimsiz komut argumanlarini olusturur.
    def __init__(self, aracYolu: str) -> None:
        if not isinstance(aracYolu, str) or not aracYolu or aracYolu != aracYolu.strip():
            raise MetasploitYapilandirmaHatasi(
                "msfconsole araç yolu boş olamaz veya boşlukla çevrilemez."
            )
        if "\x00" in aracYolu:
            raise MetasploitYapilandirmaHatasi("msfconsole araç yolu null karakteri içeremez.")
        self._aracYolu = aracYolu

    @classmethod
    def sistemdenOlustur(cls) -> "MetasploitAdaptoru":
        # PATH icinde bulunan msfconsole yoluyla kullanima hazir adaptor olusturur.
        aracDurumu = araciKontrolEt("msfconsole")
        if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
            raise MetasploitBulunamadiHatasi("msfconsole sistem PATH değeri içinde bulunamadı.")
        return cls(aracDurumu.aracYolu)

    def ms12020KomutuOlustur(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_MS12020_PORTU,
    ) -> tuple[str, ...]:
        # MS12-020 tarayicisini tek hedef ve portla etkilesimsiz calistiracak komutu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        konsolKomutu = _guvenliKonsolKomutunuOlustur(
            MS12020_MODULU,
            standartHedef,
            standartPort,
            ("set THREADS 1",),
        )
        return self._aracYolu, "-q", "-x", konsolKomutu

    def ms12020TaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_MS12020_PORTU,
        zamanAsimi: float | int = METASPLOIT_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # MS12-020 komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.ms12020KomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def ms17010KomutuOlustur(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_MS17010_PORTU,
    ) -> tuple[str, ...]:
        # MS17-010 tarayicisini ek sorgular kapali olarak calistiracak komutu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        konsolKomutu = _guvenliKonsolKomutunuOlustur(
            MS17010_MODULU,
            standartHedef,
            standartPort,
            (
                "set THREADS 1",
                "set CHECK_DOPU false",
                "set CHECK_ARCH false",
                "set CHECK_PIPE false",
            ),
        )
        return self._aracYolu, "-q", "-x", konsolKomutu

    def ms17010TaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_MS17010_PORTU,
        zamanAsimi: float | int = METASPLOIT_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # MS17-010 komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.ms17010KomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def ipmiHashKomutuOlustur(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_IPMI_PORTU,
    ) -> tuple[str, ...]:
        # IPMI hash taramasini parola kirma kapali olarak calistiracak komutu dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPort = portuDogrula(port)
        konsolKomutu = _guvenliKonsolKomutunuOlustur(
            IPMI_HASH_MODULU,
            standartHedef,
            standartPort,
            (
                "set THREADS 1",
                "set CRACK_COMMON false",
                "set SESSION_MAX_ATTEMPTS 1",
            ),
        )
        return self._aracYolu, "-q", "-x", konsolKomutu

    def ipmiHashTaramasiCalistir(
        self,
        hedef: str,
        port: str | int = VARSAYILAN_IPMI_PORTU,
        zamanAsimi: float | int = METASPLOIT_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # IPMI hash komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.ipmiHashKomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )


def _guvenliKonsolKomutunuOlustur(
    modul: str,
    hedef: str,
    port: int,
    ekAyarlar: tuple[str, ...],
) -> str:
    # Yalnizca sabit auxiliary modullerini ve guvenli ayarlari calisma komutuna alir.
    if modul not in IZINLI_METASPLOIT_MODULLERI or not modul.startswith("auxiliary/scanner/"):
        raise MetasploitGuvenlikHatasi(
            "Yalnizca izinli auxiliary scanner modulleri kullanilabilir."
        )

    for ayar in ekAyarlar:
        ayarParcalari = ayar.split()
        if len(ayarParcalari) != 3 or ayarParcalari[0] != "set":
            raise MetasploitGuvenlikHatasi("Metasploit ayari guvenli bicimde olusturulamadi.")
        if ayarParcalari[1] not in IZINLI_METASPLOIT_AYARLARI:
            raise MetasploitGuvenlikHatasi(
                f"Metasploit ayarina izin verilmiyor: {ayarParcalari[1]}"
            )

    return "; ".join(
        (
            f"use {modul}",
            f"set RHOSTS {hedef}",
            f"set RPORT {port}",
            *ekAyarlar,
            "run",
            "exit -y",
        )
    )
