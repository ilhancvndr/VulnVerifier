# Dogrulama kontrollerini kaydeden ve kimlikleriyle bulunmasini saglayan katalogu tanimlar.

from vulnverifier.models import CheckDefinition, KontrolEtkisi, RiskLevel


class DuplicateCheckError(ValueError):
    # Ayni kontrol veya bulgu kimligi tekrar eklendiginde olusan hatadir.
    pass


class CheckRegistry:
    # Kontrol tanimlarini eklenme sirasini koruyarak bellekte saklar.
    def __init__(self) -> None:
        self._kimligeGoreKontroller: dict[str, CheckDefinition] = {}
        self._bulguAnahtarinaGoreKontrolKimlikleri: dict[str, list[str]] = {}

    def kontrolEkle(self, kontrolTanimi: CheckDefinition) -> None:
        # Benzersiz bir kontrol tanimini kataloga ekler.
        if kontrolTanimi.kontrolKimligi in self._kimligeGoreKontroller:
            raise DuplicateCheckError(
                f"Kontrol kimliği zaten kayıtlı: {kontrolTanimi.kontrolKimligi}",
            )

        self._kimligeGoreKontroller[kontrolTanimi.kontrolKimligi] = kontrolTanimi
        self._bulguAnahtarinaGoreKontrolKimlikleri.setdefault(
            kontrolTanimi.bulguAnahtari, []
        ).append(kontrolTanimi.kontrolKimligi)

    def kontrolGetir(self, kontrolKimligi: str) -> CheckDefinition | None:
        # Verilen kimlige sahip kontrolu, bulunamazsa `None` degerini dondurur.
        return self._kimligeGoreKontroller.get(kontrolKimligi)

    def kontrolleriListele(self) -> tuple[CheckDefinition, ...]:
        # Kayitli kontrolleri degistirilemeyen bir koleksiyon olarak dondurur.
        return tuple(self._kimligeGoreKontroller.values())

    def bulguAnahtarinaGoreKontrolleriGetir(
        self, bulguAnahtari: str
    ) -> tuple[CheckDefinition, ...]:
        # Ayni bulguyu dogrulayan yontemleri kayit sirasiyla dondurur.
        kontrolKimlikleri = self._bulguAnahtarinaGoreKontrolKimlikleri.get(bulguAnahtari, [])
        return tuple(self._kimligeGoreKontroller[kimlik] for kimlik in kontrolKimlikleri)

    def __len__(self) -> int:
        # Katalogda bulunan kontrol sayisini dondurur.
        return len(self._kimligeGoreKontroller)


def varsayilanKataloguOlustur() -> CheckRegistry:
    # Uygulamanin yerlesik kontrol katalogunu olusturur.
    kontrolKatalogu = CheckRegistry()
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="port-service-discovery",
            bulguAnahtari="open-port-service",
            baslik="Belirli Port ve Servis Keşfi",
            aciklama="Belirtilen hedefteki port durumunu ve servis bilgisini keşfeder.",
            varsayilanPortlar=(),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="sslv2-sslv3-support",
            bulguAnahtari="obsolete-ssl-protocol-support",
            baslik="SSLv2 ve SSLv3 Desteği",
            aciklama="TLS servisinin SSLv2 veya SSLv3 protokollerini sunup sunmadığını doğrular.",
            varsayilanPortlar=(443,),
            gerekliAraclar=("testssl",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="hpe-ilo-version-detection",
            bulguAnahtari="hpe-ilo-version-based-vulnerabilities",
            baslik="HPE iLO Surum Tespiti",
            aciklama="HPE iLO urun ve firmware surum bilgisini tespit eder.",
            varsayilanPortlar=(443,),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="anonymous-cipher-support",
            bulguAnahtari="anonymous-tls-cipher-support",
            baslik="Anonymous TLS Cipher Desteği",
            aciklama="TLS servisinin kimlik doğrulamasız anonymous cipher sunduğunu doğrular.",
            varsayilanPortlar=(443,),
            gerekliAraclar=("testssl",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="ms12-020-metasploit",
            bulguAnahtari="ms12-020-rdp-vulnerability",
            baslik="MS12-020 RDP Kontrolü (Metasploit)",
            aciklama="RDP servisinin MS12-020 zafiyetinden etkilenip etkilenmedigini dogrular.",
            varsayilanPortlar=(3389,),
            gerekliAraclar=("msfconsole",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="snmp-public-community",
            bulguAnahtari="snmp-default-public-community",
            baslik="SNMP Public Community Kontrolu",
            aciklama=(
                "SNMP servisinin varsayilan public community degerini "
                "kabul edip etmedigini dogrular."
            ),
            varsayilanPortlar=(161,),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="vmware-esxi-version-detection",
            bulguAnahtari="vmware-esxi-version-based-vulnerabilities",
            baslik="VMware ESXi Surum Tespiti",
            aciklama=(
                "VMware ESX veya ESXi servisinin urun, surum ve build bilgilerini tespit eder."
            ),
            varsayilanPortlar=(443,),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="ms17-010-metasploit",
            bulguAnahtari="ms17-010-smb-vulnerability",
            baslik="MS17-010 SMB Dogrulamasi (Metasploit)",
            aciklama="SMB servisinin MS17-010 zafiyetinden etkilenip etkilenmedigini dogrular.",
            varsayilanPortlar=(445,),
            gerekliAraclar=("msfconsole",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="dns-cache-snooping",
            bulguAnahtari="dns-cache-snooping-enabled",
            baslik="DNS Cache Snooping Dogrulamasi",
            aciklama="DNS sunucusunun onbelleginin uzaktan sorgulanabildigini dogrular.",
            riskSeviyesi=RiskLevel.INTRUSIVE,
            varsayilanPortlar=(53,),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="ms17-010-nmap",
            bulguAnahtari="ms17-010-smb-vulnerability",
            baslik="MS17-010 SMB Dogrulamasi (Nmap)",
            aciklama="SMB servisinin MS17-010 zafiyetini Nmap NSE ile dogrular.",
            varsayilanPortlar=(445,),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="ms12-020-nmap",
            bulguAnahtari="ms12-020-rdp-vulnerability",
            baslik="MS12-020 RDP Dogrulamasi (Nmap)",
            aciklama="RDP servisinin MS12-020 zafiyetini Nmap NSE ile dogrular.",
            riskSeviyesi=RiskLevel.INTRUSIVE,
            varsayilanPortlar=(3389,),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="ipmi-v2-hash-disclosure",
            bulguAnahtari="ipmi-v2-rakp-hash-disclosure",
            baslik="IPMI 2.0 Password Hash Disclosure",
            aciklama="IPMI 2.0 RAKP uzerinden parola hash bilgisinin alinabildigini dogrular.",
            riskSeviyesi=RiskLevel.INTRUSIVE,
            varsayilanPortlar=(623,),
            gerekliAraclar=("msfconsole",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="freak-export-rsa",
            bulguAnahtari="freak-export-rsa-cve-2015-0204",
            baslik="FREAK EXPORT_RSA Dogrulamasi",
            aciklama=(
                "TLS servisinin FREAK saldirisina acik EXPORT RSA sifrelerini sundugunu dogrular."
            ),
            varsayilanPortlar=(443,),
            gerekliAraclar=("testssl",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="openssl-ccs-injection",
            bulguAnahtari="openssl-ccs-injection-cve-2014-0224",
            baslik="OpenSSL CCS Injection Dogrulamasi",
            aciklama=(
                "TLS servisinin OpenSSL CCS Injection zafiyetinden etkilenip "
                "etkilenmedigini dogrular."
            ),
            riskSeviyesi=RiskLevel.INTRUSIVE,
            varsayilanPortlar=(443,),
            gerekliAraclar=("testssl",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="ntp-mode-6",
            bulguAnahtari="ntp-mode-6-readvar-response",
            baslik="NTP Mode 6 Dogrulamasi",
            aciklama=(
                "NTP servisinin kimlik dogrulamasiz Mode 6 READVAR "
                "sorgularina cevap verdigini dogrular."
            ),
            varsayilanPortlar=(123,),
            gerekliAraclar=("nmap",),
        )
    )
    kontrolKatalogu.kontrolEkle(
        _saltOkunurKontrol(
            kontrolKimligi="smb-security-discovery",
            bulguAnahtari="insecure-smb-configuration",
            baslik="SMB Guvenlik Kesfi",
            aciklama=(
                "SMB servisinin kimlik, protokol ve imzalama yapilandirmasini "
                "guvenli NSE betikleriyle dogrular."
            ),
            varsayilanPortlar=(445,),
            gerekliAraclar=("nmap",),
        )
    )
    return kontrolKatalogu


def _saltOkunurKontrol(
    kontrolKimligi: str,
    bulguAnahtari: str,
    baslik: str,
    aciklama: str,
    riskSeviyesi: RiskLevel = RiskLevel.SAFE,
    varsayilanPortlar: tuple[int, ...] = (),
    gerekliAraclar: tuple[str, ...] = (),
) -> CheckDefinition:
    # Yerlesik kontrolun hedefte degisiklik yapmadigini katalogda acikca tanimlar.
    return CheckDefinition(
        kontrolKimligi=kontrolKimligi,
        bulguAnahtari=bulguAnahtari,
        baslik=baslik,
        aciklama=aciklama,
        riskSeviyesi=riskSeviyesi,
        varsayilanPortlar=varsayilanPortlar,
        gerekliAraclar=gerekliAraclar,
        kontrolEtkisi=KontrolEtkisi.READ_ONLY,
    )


varsayilanKatalog = varsayilanKataloguOlustur()
