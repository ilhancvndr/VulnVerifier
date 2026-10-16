# testssl araciyla SSL ve TLS protokol kontrollerini guvenli bicimde calistirir.

import ipaddress

from vulnverifier.command_runner import (
    KomutIptalDenetimi,
    KomutSonucu,
)
from vulnverifier.command_runner import (
    komutuSonucaDonusturerekCalistir as komutuCalistir,
)
from vulnverifier.port_validation import portlariDogrula
from vulnverifier.target_validation import hedefiDogrula
from vulnverifier.tool_availability import AracDurumu, araciKontrolEt
from vulnverifier.tool_management import TESTSSL_VARSAYILAN_ZAMAN_ASIMI

TESTSSL_ARAC_ADAYLARI = ("testssl", "testssl.sh")
VARSAYILAN_SSL_PORTU = 443


class TestsslBulunamadiHatasi(RuntimeError):
    # Desteklenen testssl komutlarindan hicbiri bulunamadiginda olusan hatadir.
    pass


class TestsslYapilandirmaHatasi(ValueError):
    # Adaptore gecersiz arac yolu veya port verildiginde olusan hatadir.
    pass


def testsslAraciniKontrolEt() -> AracDurumu:
    # Farkli kurulumlarin kullandigi iki komut adini sirayla arar.
    for aracAdi in TESTSSL_ARAC_ADAYLARI:
        aracDurumu = araciKontrolEt(aracAdi)
        if aracDurumu.bulunduMu:
            return aracDurumu
    return AracDurumu("testssl/testssl.sh", False, None)


class TestsslAdaptoru:
    # Tek bir SSL servisi icin protokol tarama komutunu olusturur ve calistirir.
    def __init__(self, aracYolu: str) -> None:
        if not isinstance(aracYolu, str) or not aracYolu or aracYolu != aracYolu.strip():
            raise TestsslYapilandirmaHatasi(
                "testssl araç yolu boş olamaz veya boşlukla çevrilemez."
            )
        if "\x00" in aracYolu:
            raise TestsslYapilandirmaHatasi("testssl araç yolu null karakteri içeremez.")
        self._aracYolu = aracYolu

    @classmethod
    def sistemdenOlustur(cls) -> "TestsslAdaptoru":
        # PATH icindeki desteklenen testssl komutuyla adaptor olusturur.
        aracDurumu = testsslAraciniKontrolEt()
        if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
            raise TestsslBulunamadiHatasi("testssl sistem PATH değeri içinde bulunamadı.")
        return cls(aracDurumu.aracYolu)

    def komutOlustur(self, hedef: str, port: int = VARSAYILAN_SSL_PORTU) -> tuple[str, ...]:
        # Protokol kontrolunu etkilesimsiz ve renksiz calistiracak argumanlari dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPortlar = portlariDogrula(port)
        if len(standartPortlar) != 1:
            raise TestsslYapilandirmaHatasi("SSL protokol kontrolü için tek port gereklidir.")

        hedefMetni = _hedefVePortuBirlestir(standartHedef, standartPortlar[0])
        return (
            self._aracYolu,
            "--protocols",
            "--warnings",
            "batch",
            "--color",
            "0",
            hedefMetni,
        )

    def protokolleriTara(
        self,
        hedef: str,
        port: int = VARSAYILAN_SSL_PORTU,
        zamanAsimi: float | int = TESTSSL_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # Olusturulan testssl komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.komutOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def anonymousCipherKomutuOlustur(
        self,
        hedef: str,
        port: int = VARSAYILAN_SSL_PORTU,
    ) -> tuple[str, ...]:
        # Anonymous cipher kontrolunu etkilesimsiz calistiracak argumanlari dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPortlar = portlariDogrula(port)
        if len(standartPortlar) != 1:
            raise TestsslYapilandirmaHatasi("Anonymous cipher kontrolü için tek port gereklidir.")

        hedefMetni = _hedefVePortuBirlestir(standartHedef, standartPortlar[0])
        return (
            self._aracYolu,
            "-s",
            "--warnings",
            "batch",
            "--color",
            "0",
            hedefMetni,
        )

    def anonymousCipherlariTara(
        self,
        hedef: str,
        port: int = VARSAYILAN_SSL_PORTU,
        zamanAsimi: float | int = TESTSSL_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # Anonymous cipher komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.anonymousCipherKomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def freakKomutuOlustur(
        self,
        hedef: str,
        port: int = VARSAYILAN_SSL_PORTU,
    ) -> tuple[str, ...]:
        # FREAK kontrolunu etkilesimsiz ve renksiz calistiracak argumanlari dondurur.
        standartHedef = hedefiDogrula(hedef)
        standartPortlar = portlariDogrula(port)
        if len(standartPortlar) != 1:
            raise TestsslYapilandirmaHatasi("FREAK doğrulaması için tek port gereklidir.")
        hedefMetni = _hedefVePortuBirlestir(standartHedef, standartPortlar[0])
        return (
            self._aracYolu,
            "--freak",
            "--warnings",
            "batch",
            "--color",
            "0",
            hedefMetni,
        )

    def freakTaramasiCalistir(
        self,
        hedef: str,
        port: int = VARSAYILAN_SSL_PORTU,
        zamanAsimi: float | int = TESTSSL_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # FREAK komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.freakKomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )

    def ccsInjectionKomutuOlustur(
        self,
        hedef: str,
        port: int = VARSAYILAN_SSL_PORTU,
    ) -> tuple[str, ...]:
        # CCS Injection kontrolunu etkilesimsiz ve renksiz calistirir.
        standartHedef = hedefiDogrula(hedef)
        standartPortlar = portlariDogrula(port)
        if len(standartPortlar) != 1:
            raise TestsslYapilandirmaHatasi("CCS Injection doğrulaması için tek port gereklidir.")
        hedefMetni = _hedefVePortuBirlestir(standartHedef, standartPortlar[0])
        return (
            self._aracYolu,
            "--ccs",
            "--warnings",
            "batch",
            "--color",
            "0",
            hedefMetni,
        )

    def ccsInjectionTaramasiCalistir(
        self,
        hedef: str,
        port: int = VARSAYILAN_SSL_PORTU,
        zamanAsimi: float | int = TESTSSL_VARSAYILAN_ZAMAN_ASIMI,
        iptalDenetimi: KomutIptalDenetimi | None = None,
    ) -> KomutSonucu:
        # CCS Injection komutunu merkezi komut calistiriciyla yurutur.
        return komutuCalistir(
            self.ccsInjectionKomutuOlustur(hedef, port),
            zamanAsimi=zamanAsimi,
            iptalDenetimi=iptalDenetimi,
        )


def _hedefVePortuBirlestir(hedef: str, port: int) -> str:
    # IPv6 adreslerini testssl URI kurallarina uygun koseli paranteze alir.
    try:
        adres = ipaddress.ip_address(hedef)
    except ValueError:
        return f"{hedef}:{port}"
    if isinstance(adres, ipaddress.IPv6Address):
        return f"[{hedef}]:{port}"
    return f"{hedef}:{port}"
