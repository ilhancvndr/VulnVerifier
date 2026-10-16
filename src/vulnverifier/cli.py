# VulnVerifier komut satiri arayuzunu ve baslangic komutlarini saglar.

import platform
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Protocol, cast

import typer
from rich.console import Console
from rich.table import Table

from vulnverifier import __version__
from vulnverifier.checks.anonymous_cipher_runner import (
    AnonymousCipherCalismaCiktisi,
    TestsslAnonymousCipherCalistirmaServisi,
)
from vulnverifier.checks.anonymous_cipher_support import (
    KONTROL_KIMLIGI as ANONYMOUS_CIPHER_KONTROL_KIMLIGI,
)
from vulnverifier.checks.dns_cache_runner import (
    DnsCacheCalismaCiktisi,
    NmapDnsCacheCalistirmaServisi,
)
from vulnverifier.checks.dns_cache_snooping import (
    KONTROL_KIMLIGI as DNS_CACHE_KONTROL_KIMLIGI,
)
from vulnverifier.checks.freak_export_rsa import (
    KONTROL_KIMLIGI as FREAK_KONTROL_KIMLIGI,
)
from vulnverifier.checks.freak_runner import (
    FreakCalismaCiktisi,
    TestsslFreakCalistirmaServisi,
)
from vulnverifier.checks.hpe_ilo_runner import (
    HpeIloCalismaCiktisi,
    NmapHpeIloCalistirmaServisi,
)
from vulnverifier.checks.hpe_ilo_version import KONTROL_KIMLIGI as HPE_ILO_KONTROL_KIMLIGI
from vulnverifier.checks.ipmi_hash_disclosure import (
    KONTROL_KIMLIGI as IPMI_HASH_KONTROL_KIMLIGI,
)
from vulnverifier.checks.ipmi_hash_runner import (
    IpmiHashCalismaCiktisi,
    MetasploitIpmiHashCalistirmaServisi,
)
from vulnverifier.checks.ms12020_metasploit import (
    KONTROL_KIMLIGI as MS12020_METASPLOIT_KONTROL_KIMLIGI,
)
from vulnverifier.checks.ms12020_metasploit_runner import (
    MetasploitMs12020CalistirmaServisi,
    Ms12020MetasploitCalismaCiktisi,
)
from vulnverifier.checks.ms12020_nmap import (
    KONTROL_KIMLIGI as MS12020_NMAP_KONTROL_KIMLIGI,
)
from vulnverifier.checks.ms12020_nmap_runner import (
    Ms12020NmapCalismaCiktisi,
    NmapMs12020CalistirmaServisi,
)
from vulnverifier.checks.ms17010_metasploit import (
    KONTROL_KIMLIGI as MS17010_METASPLOIT_KONTROL_KIMLIGI,
)
from vulnverifier.checks.ms17010_metasploit_runner import (
    MetasploitMs17010CalistirmaServisi,
    Ms17010MetasploitCalismaCiktisi,
)
from vulnverifier.checks.ms17010_nmap import (
    KONTROL_KIMLIGI as MS17010_NMAP_KONTROL_KIMLIGI,
)
from vulnverifier.checks.ms17010_nmap_runner import (
    Ms17010NmapCalismaCiktisi,
    NmapMs17010CalistirmaServisi,
)
from vulnverifier.checks.ntp_mode6 import KONTROL_KIMLIGI as NTP_MODE6_KONTROL_KIMLIGI
from vulnverifier.checks.ntp_mode6_runner import (
    NmapNtpMode6CalistirmaServisi,
    NtpMode6CalismaCiktisi,
)
from vulnverifier.checks.openssl_ccs_injection import (
    KONTROL_KIMLIGI as CCS_INJECTION_KONTROL_KIMLIGI,
)
from vulnverifier.checks.openssl_ccs_runner import (
    CcsCalismaCiktisi,
    TestsslCcsCalistirmaServisi,
)
from vulnverifier.checks.port_service_discovery import KONTROL_KIMLIGI
from vulnverifier.checks.port_service_runner import (
    NmapPortServisCalistirmaServisi,
    PortServisCalismaCiktisi,
)
from vulnverifier.checks.snmp_public_community import (
    KONTROL_KIMLIGI as SNMP_PUBLIC_KONTROL_KIMLIGI,
)
from vulnverifier.checks.snmp_public_runner import (
    NmapSnmpPublicCalistirmaServisi,
    SnmpPublicCalismaCiktisi,
)
from vulnverifier.checks.ssl_protocol_runner import (
    SslProtokolCalismaCiktisi,
    TestsslProtokolCalistirmaServisi,
)
from vulnverifier.checks.ssl_protocol_support import KONTROL_KIMLIGI as SSL_KONTROL_KIMLIGI
from vulnverifier.checks.vmware_esxi_runner import (
    NmapVmwareSurumCalistirmaServisi,
    VmwareSurumCalismaCiktisi,
)
from vulnverifier.checks.vmware_esxi_version import (
    KONTROL_KIMLIGI as VMWARE_SURUM_KONTROL_KIMLIGI,
)
from vulnverifier.database import (
    VARSAYILAN_VERITABANI_YOLU,
    VeritabaniHatasi,
    veritabaniBaglantisi,
)
from vulnverifier.database_schema import semayiHazirla
from vulnverifier.evidence_storage import (
    HamCiktiDosyalari,
    KanitDosyasiHatasi,
    KanitDosyasiOzeti,
    KanitManifestoMetadata,
    hassasMetniMaskele,
    kanitManifestosunuKaydet,
)
from vulnverifier.execution_service import eksikAraciStandartlastir
from vulnverifier.metasploit_adapter import MetasploitAdaptoru
from vulnverifier.models import KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import NmapAdaptoru
from vulnverifier.persistence import (
    VARSAYILAN_PROJE_ADI,
    KaliciKayitDeposu,
)
from vulnverifier.port_validation import PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKatalog
from vulnverifier.security_policy import (
    GuvenlikPolitikasiHatasi,
    eszamanliKontroluSinirla,
    guvenlikPolitikasiniDogrula,
)
from vulnverifier.target_validation import TargetValidationError, hedefiDogrula
from vulnverifier.testssl_adapter import TestsslAdaptoru, testsslAraciniKontrolEt
from vulnverifier.tool_availability import araciKontrolEt
from vulnverifier.tool_management import (
    AracDurumKodu,
    AracTuru,
    hariciAraciIncele,
    tumHariciAraclariIncele,
)

ANA_YARDIM_METNI = (
    "Yetkili ortamlarda kanıt odaklı zafiyet doğrulama aracı.\n\n"
    "VulnVerifier; Nmap, testssl.sh ve Metasploit tabanlı kontrolleri çalıştırır, "
    "sonuçları ortak bir durum modeline dönüştürür, evidence dosyalarını oluşturur "
    "ve doğrulama geçmişini SQLite veritabanına kaydeder."
)
ANA_YARDIM_SONU = """
[bold]Güvenlik[/bold]
Bu araç yalnızca açıkça yetkilendirilmiş hedeflerde kullanılmalıdır. Her doğrulamada en az bir
[bold]--allow-target[/bold] belirtilmelidir. Intrusive kontroller ayrıca
[bold]--confirm-intrusive[/bold] gerektirir.

[bold]Hızlı başlangıç[/bold]
  vulnverifier doctor
  vulnverifier list
  vulnverifier verify port-service-discovery \\
    --target 127.0.0.1 \\
    --port 8000 \\
    --allow-target 127.0.0.1

Bir komut hakkında ayrıntılı bilgi: [bold]vulnverifier KOMUT --help[/bold]
"""
LISTE_YARDIM_SONU = """
Her kontrol için kontrol kimliği, başlık, risk seviyesi ve gerekli harici araçlar gösterilir.
Kontrol kimliği [bold]verify[/bold] komutunun ilk argümanı olarak kullanılır.

[bold]Örnek[/bold]
  vulnverifier list
  vulnverifier verify sslv2-sslv3-support \\
    --target example.com \\
    --port 443 \\
    --allow-target example.com
"""
DOCTOR_YARDIM_SONU = """
Python sürümü ile Nmap, testssl.sh ve Metasploit kurulumları, sürümleri ve varsayılan timeout
değerleri kontrol edilir. Bu komut ağ taraması başlatmaz ve hedef parametresi almaz.

[bold]Örnek[/bold]
  vulnverifier doctor
"""
VERITABANI_YARDIM_SONU = """
Komut veritabanını açar veya oluşturur, güncel şemayı uygular, SQLite ve şema sürümlerini
gösterir ve foreign key desteğini kontrol eder.

[bold]Örnekler[/bold]
  vulnverifier database-check
  vulnverifier database-check --database ./data/vulnverifier.db
"""
GECMIS_YARDIM_SONU = """
[bold]Örnekler[/bold]
  vulnverifier history
  vulnverifier history --project musteri-a --limit 20 --database ./data/vulnverifier.db
"""
BULGULAR_YARDIM_SONU = """
Aynı bulguyu doğrulayan farklı yöntemler ortak bulgu anahtarı üzerinden ilişkilendirilir.

[bold]Örnekler[/bold]
  vulnverifier findings
  vulnverifier findings --project musteri-a --limit 20
"""
DOGRULAMA_YARDIM_SONU = """
Kontrol kimliklerini görmek için: [bold]vulnverifier list[/bold]

Her çalıştırmada hedef, [bold]--allow-target[/bold] seçeneklerinden en az biri tarafından
kapsanmalıdır. Intrusive kontroller ayrıca [bold]--confirm-intrusive[/bold] gerektirir. Port
belirtilmezse kontrolün varsayılan portu veya tarama profili kullanılır.

[bold]Güvenli kontrol[/bold]
  vulnverifier verify port-service-discovery \\
    --target 192.0.2.10 \\
    --port 443 \\
    --allow-target 192.0.2.10

[bold]CIDR ile yetkilendirme[/bold]
  vulnverifier verify port-service-discovery \\
    --target 192.0.2.10 \\
    --allow-target 192.0.2.0/24

[bold]Birden fazla port[/bold]
  vulnverifier verify port-service-discovery \\
    --target 192.0.2.10 \\
    --port 80 \\
    --port 443 \\
    --allow-target 192.0.2.10

[bold]Intrusive kontrol[/bold]
  vulnverifier verify dns-cache-snooping \\
    --target 192.0.2.53 \\
    --port 53 \\
    --allow-target 192.0.2.53 \\
    --confirm-intrusive

[bold]Özel kayıt yolları[/bold]
  vulnverifier verify port-service-discovery \\
    --target 127.0.0.1 \\
    --port 8000 \\
    --allow-target 127.0.0.1 \\
    --project yerel-test \\
    --database ./data/vulnverifier.db \\
    --evidence-dir ./data/evidence

[bold]Çıkış kodları[/bold]
   0  Zafiyet doğrulanmadı.
  10  Zafiyet veya potansiyel zafiyet tespit edildi.
  20  Sonuç kesinleştirilemedi.
  30  Kontrol atlandı.
  40  Kontrol hatayla tamamlandı.
   2  Girdi veya güvenlik politikası nedeniyle işlem reddedildi.
"""

uygulama = typer.Typer(
    add_completion=False,
    help=ANA_YARDIM_METNI,
    epilog=ANA_YARDIM_SONU,
    invoke_without_command=True,
    no_args_is_help=True,
    rich_markup_mode="rich",
)
konsol = Console()
VARSAYILAN_KANIT_ANA_DIZINI = Path("evidence")
CIKIS_KODU_TEMIZ = 0
CIKIS_KODU_ZAFIYET = 10
CIKIS_KODU_BELIRSIZ = 20
CIKIS_KODU_ATLANDI = 30
CIKIS_KODU_HATA = 40


class CalismaCiktisiProtokolu(Protocol):
    # Farkli dogrulama ciktisinin ortak evidence alanlarini tanimlar.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


# Kullanilabilir dogrulama kontrollerini listeler.
@uygulama.command(
    "list",
    help="Kullanılabilir doğrulama kontrollerini listeler.",
    epilog=LISTE_YARDIM_SONU,
)
def kontrolleriListele() -> None:
    kayitliKontroller = varsayilanKatalog.kontrolleriListele()
    if not kayitliKontroller:
        konsol.print("[yellow]Henüz doğrulama kontrolü eklenmedi.[/yellow]")
        return

    tablo = Table(title="Kayıtlı doğrulama kontrolleri", show_lines=True)
    tablo.add_column("Kontrol kimliği", min_width=25)
    tablo.add_column("Başlık", max_width=30)
    tablo.add_column("Risk")
    tablo.add_column("Araçlar")

    for kontrolTanimi in kayitliKontroller:
        gerekliAraclar = ", ".join(kontrolTanimi.gerekliAraclar) or "-"
        tablo.add_row(
            kontrolTanimi.kontrolKimligi,
            kontrolTanimi.baslik,
            kontrolTanimi.riskSeviyesi.value,
            gerekliAraclar,
        )

    konsol.print(tablo)


# Calisma ortamini ve planlanan harici araclari kontrol eder.
@uygulama.command(
    "doctor",
    help="Çalışma ortamını ve harici araçları kontrol eder.",
    epilog=DOCTOR_YARDIM_SONU,
)
def ortamKontrolu() -> None:
    tablo = Table(title="VulnVerifier ortam kontrolü")
    tablo.add_column("Bileşen")
    tablo.add_column("Durum")
    tablo.add_column("Sürüm")
    tablo.add_column("Timeout")
    tablo.add_column("Konum / hata", overflow="fold")

    tablo.add_row(
        "Python", "READY", platform.python_version(), "-", platform.python_implementation()
    )
    for aracBilgisi in tumHariciAraclariIncele():
        konumVeyaHata = aracBilgisi.aracYolu or aracBilgisi.hataMesaji or "-"
        if aracBilgisi.aracYolu and aracBilgisi.hataMesaji:
            konumVeyaHata = f"{aracBilgisi.aracYolu} | {aracBilgisi.hataMesaji}"
        durumMetni = (
            "[green]READY[/green]"
            if aracBilgisi.durum is AracDurumKodu.READY
            else f"[yellow]{aracBilgisi.durum.value}[/yellow]"
        )
        tablo.add_row(
            aracBilgisi.aracAdi,
            durumMetni,
            aracBilgisi.surum or "-",
            f"{aracBilgisi.varsayilanZamanAsimi:g} sn",
            konumVeyaHata,
        )

    konsol.print(tablo)


# SQLite dosyasini olusturur ve temel baglanti ayarlarini dogrular.
@uygulama.command(
    "database-check",
    help="SQLite veritabanı bağlantısını ve şemasını kontrol eder.",
    epilog=VERITABANI_YARDIM_SONU,
)
def veritabaniKontrolu(
    veritabaniYolu: Annotated[
        Path,
        typer.Option("--database", help="Kontrol edilecek SQLite dosyasının yolu."),
    ] = VARSAYILAN_VERITABANI_YOLU,
) -> None:
    try:
        with veritabaniBaglantisi(veritabaniYolu) as baglanti:
            semaSurumu = semayiHazirla(baglanti)
            sqliteSurumu = baglanti.execute("SELECT sqlite_version()").fetchone()[0]
            foreignKeyDurumu = baglanti.execute("PRAGMA foreign_keys").fetchone()[0]
    except VeritabaniHatasi as hata:
        konsol.print(f"[red]Veritabanı bağlantı hatası: {hata}[/red]")
        raise typer.Exit(code=1) from hata

    tablo = Table(title="SQLite bağlantı kontrolü")
    tablo.add_column("Alan")
    tablo.add_column("Değer")
    tablo.add_row("Durum", "Hazır")
    tablo.add_row("Dosya", str(veritabaniYolu.resolve()))
    tablo.add_row("SQLite", sqliteSurumu)
    tablo.add_row("Şema sürümü", str(semaSurumu))
    tablo.add_row("Foreign key", "Açık" if foreignKeyDurumu == 1 else "Kapalı")
    konsol.print(tablo)


# SQLite icindeki en yeni dogrulama calismalarini listeler.
@uygulama.command(
    "history",
    help="SQLite veritabanına kaydedilmiş doğrulama çalışmalarını listeler.",
    epilog=GECMIS_YARDIM_SONU,
)
def taramaGecmisiniListele(
    projeAdi: Annotated[
        str | None,
        typer.Option("--project", help="Yalnızca belirtilen projenin kayıtlarını gösterir."),
    ] = None,
    sinir: Annotated[
        int,
        typer.Option("--limit", min=1, max=500, help="Gösterilecek azami kayıt sayısı."),
    ] = 50,
    veritabaniYolu: Annotated[
        Path | None,
        typer.Option("--database", help="Kullanılacak SQLite dosyasının yolu."),
    ] = None,
) -> None:
    etkinVeritabaniYolu = veritabaniYolu or VARSAYILAN_VERITABANI_YOLU
    try:
        kayitlar = KaliciKayitDeposu(etkinVeritabaniYolu).taramaGecmisiniListele(
            projeAdi,
            sinir,
        )
    except VeritabaniHatasi as hata:
        konsol.print(f"[red]Veritabanı hatası: {hata}[/red]")
        raise typer.Exit(code=1) from hata

    if not kayitlar:
        konsol.print("[yellow]Kaydedilmiş doğrulama çalışması bulunamadı.[/yellow]")
        return

    tablo = Table(title="Doğrulama geçmişi", show_lines=True)
    tablo.add_column("Tarama")
    tablo.add_column("Proje")
    tablo.add_column("Hedef")
    tablo.add_column("Kontrol")
    tablo.add_column("Durum")
    tablo.add_column("Evidence")
    tablo.add_column("Bitiş")
    for kayit in kayitlar:
        tablo.add_row(
            str(kayit.taramaKimligi),
            kayit.projeAdi,
            kayit.hedef,
            kayit.kontrolKimligi,
            kayit.durum,
            str(kayit.evidenceSayisi),
            kayit.bitisZamani,
        )
    konsol.print(tablo)


# Ortak bulgu anahtarina gore birlestirilmis son durumlari listeler.
@uygulama.command(
    "findings",
    help="SQLite veritabanındaki birleştirilmiş bulguları listeler.",
    epilog=BULGULAR_YARDIM_SONU,
)
def bulgulariListele(
    projeAdi: Annotated[
        str | None,
        typer.Option("--project", help="Yalnızca belirtilen projenin bulgularını gösterir."),
    ] = None,
    sinir: Annotated[
        int,
        typer.Option("--limit", min=1, max=500, help="Gösterilecek azami bulgu sayısı."),
    ] = 50,
    veritabaniYolu: Annotated[
        Path | None,
        typer.Option("--database", help="Kullanılacak SQLite dosyasının yolu."),
    ] = None,
) -> None:
    etkinVeritabaniYolu = veritabaniYolu or VARSAYILAN_VERITABANI_YOLU
    try:
        bulgular = KaliciKayitDeposu(etkinVeritabaniYolu).bulgulariListele(projeAdi, sinir)
    except VeritabaniHatasi as hata:
        konsol.print(f"[red]Veritabanı hatası: {hata}[/red]")
        raise typer.Exit(code=1) from hata

    if not bulgular:
        konsol.print("[yellow]Kaydedilmiş bulgu bulunamadı.[/yellow]")
        return

    tablo = Table(title="Kaydedilmiş bulgular", show_lines=True)
    tablo.add_column("Bulgu")
    tablo.add_column("Proje")
    tablo.add_column("Hedef")
    tablo.add_column("Bulgu anahtarı")
    tablo.add_column("Durum")
    tablo.add_column("Doğrulama")
    for bulgu in bulgular:
        tablo.add_row(
            str(bulgu.bulguKimligi),
            bulgu.projeAdi,
            bulgu.hedef,
            bulgu.bulguAnahtari,
            bulgu.sonDurum,
            str(bulgu.dogrulamaSayisi),
        )
    konsol.print(tablo)


# Secilen kontrolu gercek motoruyla calistirir ve standart sonucu gosterir.
@uygulama.command(
    "verify",
    help="Seçilen doğrulama kontrolünü yetkili hedefte çalıştırır.",
    epilog=DOGRULAMA_YARDIM_SONU,
)
@eszamanliKontroluSinirla
def dogrula(
    kontrolKimligi: Annotated[
        str,
        typer.Argument(help="Çalıştırılacak kontrol kimliği; seçenekleri görmek için `list`."),
    ],
    hedef: Annotated[
        str,
        typer.Option("--target", "-t", help="Doğrulanacak IP adresi veya hostname."),
    ],
    portlar: Annotated[
        list[str] | None,
        typer.Option(
            "--port",
            "-p",
            help="Doğrulanacak port; desteklenen kontrollerde birden fazla kez kullanılabilir.",
        ),
    ] = None,
    projeAdi: Annotated[
        str,
        typer.Option("--project", help="SQLite kayıtlarının ilişkilendirileceği proje adı."),
    ] = VARSAYILAN_PROJE_ADI,
    veritabaniYolu: Annotated[
        Path | None,
        typer.Option("--database", help="Kullanılacak SQLite veritabanının yolu."),
    ] = None,
    evidenceDizini: Annotated[
        Path | None,
        typer.Option("--evidence-dir", help="Evidence dosyalarının yazılacağı ana dizin."),
    ] = None,
    izinliHedefler: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-target",
            help=(
                "Yetkili IP, hostname veya CIDR; birden fazla kez kullanılabilir ve "
                "hedefi kapsamalıdır."
            ),
        ),
    ] = None,
    intrusiveOnayi: Annotated[
        bool,
        typer.Option(
            "--confirm-intrusive",
            help="Intrusive kontrolün yetkili kapsamda çalıştırılmasını onaylar.",
        ),
    ] = False,
) -> None:
    try:
        standartHedef = hedefiDogrula(hedef)
    except TargetValidationError as hata:
        konsol.print(f"[red]Geçersiz hedef: {hata}[/red]")
        raise typer.Exit(code=2) from hata

    try:
        standartPortlar = portlariDogrula(portlar)
    except PortValidationError as hata:
        konsol.print(f"[red]Geçersiz port: {hata}[/red]")
        raise typer.Exit(code=2) from hata

    kontrolTanimi = varsayilanKatalog.kontrolGetir(kontrolKimligi)
    if kontrolTanimi is None:
        konsol.print(
            f"[red]Kontrol kayıtlı değil: {kontrolKimligi}[/red]",
        )
        raise typer.Exit(code=1)

    konsol.print(
        "[yellow]Uyarı: VulnVerifier yalnızca açıkça yetkilendirilmiş "
        "hedeflerde kullanılmalıdır.[/yellow]"
    )
    try:
        guvenlikPolitikasiniDogrula(
            kontrolTanimi,
            standartHedef,
            izinliHedefler,
            intrusiveOnayi,
        )
    except GuvenlikPolitikasiHatasi as hata:
        konsol.print(f"[red]Güvenlik politikası: {hata}[/red]")
        raise typer.Exit(code=2) from hata

    etkinKanitAnaDizini = evidenceDizini or VARSAYILAN_KANIT_ANA_DIZINI

    if kontrolKimligi == KONTROL_KIMLIGI:
        calismaCiktisi = _portServisKontrolunuCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == SSL_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: SSL protokol kontrolü tek seferde "
                "yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _sslProtokolKontrolunuCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == HPE_ILO_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: HPE iLO kontrolü tek seferde "
                "yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _hpeIloKontrolunuCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == ANONYMOUS_CIPHER_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: Anonymous cipher kontrolü tek seferde "
                "yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _anonymousCipherKontrolunuCalistir(
            standartHedef,
            standartPortlar,
            etkinKanitAnaDizini,
        )
    elif kontrolKimligi == MS12020_METASPLOIT_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: MS12-020 Metasploit kontrolü tek seferde "
                "yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _ms12020MetasploitKontrolunuCalistir(
            standartHedef,
            standartPortlar,
            etkinKanitAnaDizini,
        )
    elif kontrolKimligi == SNMP_PUBLIC_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: SNMP kontrolü tek seferde yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _snmpPublicKontrolunuCalistir(
            standartHedef,
            standartPortlar,
            etkinKanitAnaDizini,
        )
    elif kontrolKimligi == VMWARE_SURUM_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: VMware kontrolü tek seferde yalnızca "
                "bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _vmwareSurumKontrolunuCalistir(
            standartHedef,
            standartPortlar,
            etkinKanitAnaDizini,
        )
    elif kontrolKimligi == MS17010_METASPLOIT_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: MS17-010 doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _ms17010MetasploitDogrulamasiniCalistir(
            standartHedef,
            standartPortlar,
            etkinKanitAnaDizini,
        )
    elif kontrolKimligi == DNS_CACHE_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: DNS cache doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _dnsCacheDogrulamasiniCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == MS17010_NMAP_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: MS17-010 Nmap doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _ms17010NmapDogrulamasiniCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == MS12020_NMAP_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: MS12-020 Nmap doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _ms12020NmapDogrulamasiniCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == IPMI_HASH_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: IPMI hash doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _ipmiHashDogrulamasiniCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == FREAK_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: FREAK doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _freakDogrulamasiniCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == CCS_INJECTION_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: CCS Injection doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _ccsInjectionDogrulamasiniCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    elif kontrolKimligi == NTP_MODE6_KONTROL_KIMLIGI:
        if len(standartPortlar) > 1:
            konsol.print(
                "[red]Geçersiz port: NTP Mode 6 doğrulaması yalnızca bir port kabul eder.[/red]"
            )
            raise typer.Exit(code=2)
        calismaCiktisi = _ntpMode6DogrulamasiniCalistir(
            standartHedef, standartPortlar, etkinKanitAnaDizini
        )
    else:
        konsol.print(f"[yellow]Kontrol motoru henüz hazır değil: {kontrolKimligi}[/yellow]")
        raise typer.Exit(code=1)

    try:
        calismaCiktisi = _evidenceManifestosunuTamamla(calismaCiktisi, kontrolTanimi.gerekliAraclar)
    except KanitDosyasiHatasi as hata:
        konsol.print(f"[red]Evidence manifestosu oluşturulamadı: {hata}[/red]")
        raise typer.Exit(code=CIKIS_KODU_HATA) from hata
    _kontrolSonucunuGoster(calismaCiktisi.kontrolSonucu, calismaCiktisi)
    etkinVeritabaniYolu = veritabaniYolu or VARSAYILAN_VERITABANI_YOLU
    try:
        kayitOzeti = KaliciKayitDeposu(etkinVeritabaniYolu).dogrulamaKaydet(
            projeAdi,
            kontrolTanimi,
            calismaCiktisi.kontrolSonucu,
            standartPortlar,
            calismaCiktisi.kanitDosyasiOzetleri,
        )
    except VeritabaniHatasi as hata:
        konsol.print(f"[red]Doğrulama sonucu veritabanına kaydedilemedi: {hata}[/red]")
        raise typer.Exit(code=CIKIS_KODU_HATA) from hata
    konsol.print(
        f"[dim]SQLite kaydı: proje={projeAdi}, tarama={kayitOzeti.taramaKimligi}, "
        f"bulgu={kayitOzeti.bulguKimligi}[/dim]"
    )
    raise typer.Exit(code=sonucCikisKodunuAl(calismaCiktisi.kontrolSonucu.durum))


def _portServisKontrolunuCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> PortServisCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip ilk kontrolun calisma servisini yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapPortServisCalistirmaServisi(
        NmapAdaptoru(aracDurumu.aracYolu),
        kanitAnaDizini,
    ).calistir(hedef, portlar)


def _sslProtokolKontrolunuCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> SslProtokolCalismaCiktisi:
    # testssl bulunabilirligini denetleyip SSL protokol kontrolunu yurutur.
    aracDurumu = testsslAraciniKontrolEt()
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(SSL_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return TestsslProtokolCalistirmaServisi(
        TestsslAdaptoru(aracDurumu.aracYolu),
        kanitAnaDizini,
    ).calistir(hedef, portlar)


def _hpeIloKontrolunuCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> HpeIloCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip HPE iLO kontrol servisini yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(HPE_ILO_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapHpeIloCalistirmaServisi(
        NmapAdaptoru(aracDurumu.aracYolu),
        kanitAnaDizini,
    ).calistir(hedef, portlar)


def _anonymousCipherKontrolunuCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> AnonymousCipherCalismaCiktisi:
    # testssl bulunabilirligini denetleyip anonymous cipher servisini yurutur.
    aracDurumu = testsslAraciniKontrolEt()
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(
            ANONYMOUS_CIPHER_KONTROL_KIMLIGI,
            hedef,
            aracDurumu,
        )
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return TestsslAnonymousCipherCalistirmaServisi(
        TestsslAdaptoru(aracDurumu.aracYolu),
        kanitAnaDizini,
    ).calistir(hedef, portlar)


def _ms12020MetasploitKontrolunuCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> Ms12020MetasploitCalismaCiktisi:
    # msfconsole bulunabilirligini denetleyip MS12-020 kontrol servisini yurutur.
    aracDurumu = araciKontrolEt("msfconsole")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(
            MS12020_METASPLOIT_KONTROL_KIMLIGI,
            hedef,
            aracDurumu,
        )
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return MetasploitMs12020CalistirmaServisi(
        MetasploitAdaptoru(aracDurumu.aracYolu),
        kanitAnaDizini,
    ).calistir(hedef, portlar)


def _snmpPublicKontrolunuCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> SnmpPublicCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip SNMP public community kontrolunu yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(
            SNMP_PUBLIC_KONTROL_KIMLIGI,
            hedef,
            aracDurumu,
        )
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapSnmpPublicCalistirmaServisi(
        NmapAdaptoru(aracDurumu.aracYolu),
        kanitAnaDizini,
    ).calistir(hedef, portlar)


def _vmwareSurumKontrolunuCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> VmwareSurumCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip VMware surum kontrolunu yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(VMWARE_SURUM_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapVmwareSurumCalistirmaServisi(
        NmapAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _ms17010MetasploitDogrulamasiniCalistir(
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> Ms17010MetasploitCalismaCiktisi:
    # msfconsole bulunabilirligini denetleyip MS17-010 dogrulamasini yurutur.
    aracDurumu = araciKontrolEt("msfconsole")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(MS17010_METASPLOIT_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return MetasploitMs17010CalistirmaServisi(
        MetasploitAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _dnsCacheDogrulamasiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> DnsCacheCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip DNS cache snooping dogrulamasini yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(DNS_CACHE_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapDnsCacheCalistirmaServisi(
        NmapAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _ms17010NmapDogrulamasiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> Ms17010NmapCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip MS17-010 NSE dogrulamasini yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(MS17010_NMAP_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapMs17010CalistirmaServisi(NmapAdaptoru(aracDurumu.aracYolu), kanitAnaDizini).calistir(
        hedef, portlar
    )


def _ms12020NmapDogrulamasiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> Ms12020NmapCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip MS12-020 NSE dogrulamasini yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(MS12020_NMAP_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapMs12020CalistirmaServisi(NmapAdaptoru(aracDurumu.aracYolu), kanitAnaDizini).calistir(
        hedef, portlar
    )


def _ipmiHashDogrulamasiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> IpmiHashCalismaCiktisi:
    # msfconsole bulunabilirligini denetleyip IPMI hash dogrulamasini yurutur.
    aracDurumu = araciKontrolEt("msfconsole")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(IPMI_HASH_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return MetasploitIpmiHashCalistirmaServisi(
        MetasploitAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _freakDogrulamasiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> FreakCalismaCiktisi:
    # testssl bulunabilirligini denetleyip FREAK dogrulamasini yurutur.
    aracDurumu = testsslAraciniKontrolEt()
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(FREAK_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return TestsslFreakCalistirmaServisi(
        TestsslAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _ccsInjectionDogrulamasiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> CcsCalismaCiktisi:
    # testssl bulunabilirligini denetleyip CCS Injection dogrulamasini yurutur.
    aracDurumu = testsslAraciniKontrolEt()
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(CCS_INJECTION_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return TestsslCcsCalistirmaServisi(
        TestsslAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _ntpMode6DogrulamasiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> NtpMode6CalismaCiktisi:
    # Nmap bulunabilirligini denetleyip NTP Mode 6 dogrulamasini yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(NTP_MODE6_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapNtpMode6CalistirmaServisi(
        NmapAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _evidenceManifestosunuTamamla[CalismaCiktisiT: CalismaCiktisiProtokolu](
    calismaCiktisi: CalismaCiktisiT,
    araclar: tuple[str, ...],
) -> CalismaCiktisiT:
    # Calisma ciktisina arac metadata'si ve hash'li manifestoyu ekler.
    aracAdi = araclar[0] if araclar else "bilinmiyor"
    aracSurumu = None
    aracTuru = _aracTurunuAl(aracAdi)
    if aracTuru is not None:
        aracSurumu = hariciAraciIncele(aracTuru).surum

    hamCiktiDosyalari = calismaCiktisi.hamCiktiDosyalari
    komutCikisKodu = hamCiktiDosyalari.cikisKodu if hamCiktiDosyalari is not None else None
    manifestoOzeti = kanitManifestosunuKaydet(
        calismaCiktisi.kanitKlasoru,
        calismaCiktisi.kontrolSonucu,
        calismaCiktisi.kanitDosyasiOzetleri,
        KanitManifestoMetadata(
            aracAdi=aracAdi,
            aracSurumu=aracSurumu,
            komutCikisKodu=komutCikisKodu,
        ),
    )
    return cast(
        CalismaCiktisiT,
        replace(
            calismaCiktisi,
            kanitDosyasiOzetleri=(
                *calismaCiktisi.kanitDosyasiOzetleri,
                manifestoOzeti,
            ),
        ),
    )


def _aracTurunuAl(aracAdi: str) -> AracTuru | None:
    # Katalogdaki arac adini merkezi arac turune donusturur.
    return {
        "nmap": AracTuru.NMAP,
        "testssl": AracTuru.TESTSSL,
        "testssl.sh": AracTuru.TESTSSL,
        "msfconsole": AracTuru.METASPLOIT,
    }.get(aracAdi)


def sonucCikisKodunuAl(durum: ResultStatus) -> int:
    # Standart kontrol durumunu komut satiri cikis koduna donusturur.
    if durum is ResultStatus.NOT_VULNERABLE:
        return CIKIS_KODU_TEMIZ
    if durum in (ResultStatus.VULNERABLE, ResultStatus.POTENTIALLY_VULNERABLE):
        return CIKIS_KODU_ZAFIYET
    if durum is ResultStatus.INCONCLUSIVE:
        return CIKIS_KODU_BELIRSIZ
    if durum is ResultStatus.SKIPPED:
        return CIKIS_KODU_ATLANDI
    return CIKIS_KODU_HATA


def _kontrolSonucunuGoster(
    sonuc: KontrolSonucu,
    calismaCiktisi: (
        PortServisCalismaCiktisi
        | SslProtokolCalismaCiktisi
        | HpeIloCalismaCiktisi
        | AnonymousCipherCalismaCiktisi
        | Ms12020MetasploitCalismaCiktisi
        | SnmpPublicCalismaCiktisi
        | VmwareSurumCalismaCiktisi
        | Ms17010MetasploitCalismaCiktisi
        | DnsCacheCalismaCiktisi
        | Ms17010NmapCalismaCiktisi
        | Ms12020NmapCalismaCiktisi
        | IpmiHashCalismaCiktisi
        | FreakCalismaCiktisi
        | CcsCalismaCiktisi
        | NtpMode6CalismaCiktisi
        | None
    ) = None,
) -> None:
    # Standart sonucu, kanitlari ve evidence yollarini Rich tablolariyla gosterir.
    durumRenkleri = {
        ResultStatus.VULNERABLE: "red",
        ResultStatus.NOT_VULNERABLE: "green",
        ResultStatus.POTENTIALLY_VULNERABLE: "yellow",
        ResultStatus.INCONCLUSIVE: "yellow",
        ResultStatus.SKIPPED: "cyan",
        ResultStatus.ERROR: "red",
    }
    sonucTablosu = Table(title="Doğrulama sonucu")
    sonucTablosu.add_column("Alan")
    sonucTablosu.add_column("Değer")
    sonucTablosu.add_row("Kontrol", sonuc.kontrolKimligi)
    sonucTablosu.add_row("Hedef", hassasMetniMaskele(sonuc.hedef))
    sonucTablosu.add_row("Durum", f"[{durumRenkleri[sonuc.durum]}]{sonuc.durum.value}[/]")
    sonucTablosu.add_row("Özet", hassasMetniMaskele(sonuc.ozet))
    if sonuc.calismaSuresiSaniye is not None:
        sonucTablosu.add_row("Süre", f"{sonuc.calismaSuresiSaniye:.3f} saniye")
    konsol.print(sonucTablosu)

    if sonuc.kanitlar:
        kanitTablosu = Table(title="Yapılandırılmış kanıtlar")
        kanitTablosu.add_column("Anahtar")
        kanitTablosu.add_column("Değer")
        for kanit in sonuc.kanitlar:
            kanitTablosu.add_row(kanit.anahtar, hassasMetniMaskele(kanit.deger))
        konsol.print(kanitTablosu)

    if calismaCiktisi is not None:
        dosyaTablosu = Table(title="Evidence dosyaları")
        dosyaTablosu.add_column("Dosya", overflow="fold")
        dosyaTablosu.add_column("SHA-256", overflow="fold")
        for dosyaOzeti in calismaCiktisi.kanitDosyasiOzetleri:
            dosyaTablosu.add_row(
                hassasMetniMaskele(str(dosyaOzeti.dosyaYolu)),
                dosyaOzeti.sha256,
            )
        konsol.print(dosyaTablosu)


# VulnVerifier CLI komut grubunu baslatir.
@uygulama.callback()
def anaKomut(
    surum: Annotated[
        bool,
        typer.Option("--version", help="Uygulama sürümünü gösterir.", is_eager=True),
    ] = False,
) -> None:
    if surum:
        konsol.print(f"VulnVerifier {__version__}")
        raise typer.Exit()


def uygulamayiCalistir() -> None:
    # Paket giris noktasindan Typer uygulamasini calistirir.
    uygulama()
