# VulnVerifier komut satiri arayuzunu ve baslangic komutlarini saglar.

import platform
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from functools import wraps
from pathlib import Path
from typing import Annotated, Any, Protocol, cast

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer.core import TyperCommand, TyperGroup, TyperOption

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
from vulnverifier.checks.smb_security_discovery import (
    KONTROL_KIMLIGI as SMB_GUVENLIK_KONTROL_KIMLIGI,
)
from vulnverifier.checks.smb_security_runner import (
    NmapSmbGuvenlikCalistirmaServisi,
    SmbGuvenlikCalismaCiktisi,
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
from vulnverifier.command_runner import aktifKomutlariSonlandir
from vulnverifier.control_screenshot_renderer import (
    KESIN_GORSEL_DURUMLARI,
    OZEL_GORSEL_KONTROLLERI,
    ozelTekliEkranGoruntusuOlustur,
    topluKontrolEkranGoruntuleriOlustur,
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
    evidenceDosyalariniAdlandir,
    hassasMetniMaskele,
    kanitManifestosunuKaydet,
)
from vulnverifier.execution_service import eksikAraciStandartlastir
from vulnverifier.metasploit_adapter import MetasploitAdaptoru
from vulnverifier.models import CheckDefinition, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import NmapAdaptoru
from vulnverifier.persistence import (
    VARSAYILAN_PROJE_ADI,
    KaliciKayitDeposu,
)
from vulnverifier.port_validation import PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKatalog
from vulnverifier.screenshot_renderer import (
    ekranGoruntusunuDisaAktar,
    ekranGoruntusuOlustur,
)
from vulnverifier.security_policy import (
    GuvenlikPolitikasiHatasi,
    eszamanliKontroluSinirla,
    guvenlikPolitikasiniDogrula,
)
from vulnverifier.smb_screenshot_renderer import smbTopluEkranGoruntuleriOlustur
from vulnverifier.target_input import (
    HedefGirdisiHatasi,
    HedefGrubu,
    hedefleriGruplariylaHazirla,
)
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
Bu araç yalnızca açıkça yetkilendirilmiş hedeflerde kullanılmalıdır. [bold]--allow-target[/bold]
verilmezse yalnızca [bold]--target[/bold] hedefinin kendisine izin verilir. Intrusive kontroller
ayrıca [bold]--confirm-intrusive[/bold] gerektirir.

[bold]Hızlı başlangıç[/bold]
  vulnverifier doctor
  vulnverifier list
  vulnverifier verify port-service-discovery \\
    --target 127.0.0.1 \\
    --port 8000

Bir komut hakkında ayrıntılı bilgi: [bold]vulnverifier KOMUT --help[/bold]
"""
LISTE_YARDIM_SONU = """
Her kontrol için kontrol kimliği, başlık, varsayılan port, risk seviyesi ve gerekli
harici araçlar gösterilir.
Kontrol kimliği [bold]verify[/bold] komutunun ilk argümanı olarak kullanılır.

[bold]Örnek[/bold]
  vulnverifier list
  vulnverifier verify sslv2-sslv3-support \\
    --target example.com \\
    --port 443
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
Tüm sonuçlar burada tutulur: zafiyet, temiz, keşif, belirsiz, atlanan ve hatalı
çalışmalar. [bold]--database[/bold] verilmezse [bold]./vulnverifier.db[/bold] kullanılır.

[bold]Örnekler[/bold]
  vulnverifier history
  vulnverifier history --project musteri-a --limit 20 --database ./data/vulnverifier.db
"""
BULGULAR_YARDIM_SONU = """
Aynı bulguyu doğrulayan farklı yöntemler ortak bulgu anahtarı üzerinden ilişkilendirilir.
Yalnızca [bold]VULNERABLE[/bold] ve [bold]POTENTIALLY_VULNERABLE[/bold] sonuçları burada
gösterilir. Temiz, keşif, belirsiz, atlanan ve hatalı sonuçlar için
[bold]vulnverifier history[/bold] kullanılır. [bold]--database[/bold] verilmezse
[bold]./vulnverifier.db[/bold] kullanılır.

[bold]Örnekler[/bold]
  vulnverifier findings
  vulnverifier findings --project musteri-a --limit 20
"""


def _kontrolYardimListesiniOlustur() -> str:
    # Verify yardiminda guncel katalogu tek kaynaktan okunabilir bicimde gosterir.
    satirlar = ["[bold]Kullanılabilir kontrol kimlikleri[/bold]"]
    for kontrolTanimi in varsayilanKatalog.kontrolleriListele():
        varsayilanPortlar = ", ".join(str(port) for port in kontrolTanimi.varsayilanPortlar)
        portMetni = varsayilanPortlar or "genel tarama veya --port"
        aracMetni = ", ".join(kontrolTanimi.gerekliAraclar) or "harici araç yok"
        riskMetni = kontrolTanimi.riskSeviyesi.value
        if kontrolTanimi.riskSeviyesi.value == "intrusive":
            riskMetni += " (--confirm-intrusive gerekli)"
        satirlar.extend(
            (
                f"  [bold]{kontrolTanimi.kontrolKimligi}[/bold]",
                f"    {kontrolTanimi.baslik}: {kontrolTanimi.aciklama}",
                f"    Port: {portMetni} | Risk: {riskMetni} | Araç: {aracMetni}",
            )
        )
    return "\n".join(satirlar)


DOGRULAMA_YARDIM_SONU = f"""
{_kontrolYardimListesiniOlustur()}

Kontrol kimliğini [bold]verify[/bold] sonrasında aynen yazın. Kimliklerde alt çizgi değil,
tire kullanılır. Daha kompakt tablo için: [bold]vulnverifier list[/bold]

[bold]--target[/bold] veya [bold]--target-file[/bold] seçeneklerinden en az biri verilmelidir.
Her ikisi birlikte verilirse hedefler birleştirilir ve tekrarlar kaldırılır.

[bold]--allow-target[/bold] verilmezse yalnızca [bold]--target[/bold] değerinin kendisi örtük
yetkili kapsam sayılır. Çoklu kullanımda listedeki her hedef ayrı ayrı yetkili kabul
edilir. Seçenek verilirse hedef IP, hostname veya CIDR kapsamlarından biriyle
eşleşmelidir. Intrusive kontroller ayrıca [bold]--confirm-intrusive[/bold] gerektirir. Port
belirtilmezse kontrolün varsayılan portu veya tarama profili kullanılır.

[bold]Güvenli kontrol[/bold]
  vulnverifier verify port-service-discovery \\
    --target 192.0.2.10 \\
    --port 443

[bold]CIDR ile yetkilendirme[/bold]
  vulnverifier verify port-service-discovery \\
    --target 192.0.2.10 \\
    --allow-target 192.0.2.0/24

[bold]Birden fazla port[/bold]
  vulnverifier verify port-service-discovery \\
    --target 192.0.2.10 \\
    --port 80,443,445

[bold]Çoklu hedef[/bold]
  vulnverifier verify port-service-discovery \\
    --target "10.0.100.0/24, 10.0.101.0/24" \\
    --target-file ./targets.txt

Çoklu hedeflerde varsayılan çıktı kesin [bold]VULNERABLE[/bold] bulguları ve bilgi
amaçlı [bold]DISCOVERED[/bold] sonuçlarını gösterir. Diğer sonuçları da görmek için
[bold]-v[/bold] veya [bold]--verbose[/bold] kullanılır. Sürüm keşfi gerektiren
[bold]POTENTIALLY_VULNERABLE[/bold] sonuçları da varsayılan özette gösterilir.
Paralellik [bold]--workers[/bold] ile 1-16 arasında ayarlanır; varsayılan değer 4'tür.

[bold]Intrusive kontrol[/bold]
  vulnverifier verify dns-cache-snooping \\
    --target 192.0.2.53 \\
    --port 53 \\
    --confirm-intrusive

[bold]Özel kayıt yolları[/bold]
  vulnverifier verify port-service-discovery \\
    --target 127.0.0.1 \\
    --port 8000 \\
    --project yerel-test \\
    --database ./data/vulnverifier.db \\
    --evidence-dir ./data/evidence

[bold]Ekran görüntüsü[/bold]
  vulnverifier verify port-service-discovery \\
    --target 127.0.0.1 \\
    --port 443 \\
    --screenshot

Tek hedefte kontrol türüne uygun sade bir kanıt PNG'si oluşturulur. Çoklu hedeflerde her
CIDR için ayrı, CIDR dışındaki seçili IP'ler için tek toplu özet üretilir. Büyük sonuçlar
otomatik olarak birden fazla PNG sayfasına bölünür. SMB özeti SMBv1 açık ve SMB imzalaması
zorunlu olmayan IP'leri ayrı listeler. [bold]--all-screenshots[/bold] geriye dönük uyumluluk
için ekran görüntüsü üretimini etkinleştirir; toplu özetler zaten tüm kesin sonuçları içerir.
Tarama, evidence ve SQLite kayıtları ekran görüntüsü politikasından etkilenmez.

[bold]Çıkış kodları[/bold]
   0  Zafiyet doğrulanmadı veya keşif tamamlandı.
  10  Zafiyet veya potansiyel zafiyet tespit edildi.
  20  Sonuç kesinleştirilemedi.
  30  Kontrol atlandı.
  40  Kontrol hatayla tamamlandı.
 130  Tarama kullanıcı tarafından Ctrl+C ile iptal edildi.
   2  Girdi veya güvenlik politikası nedeniyle işlem reddedildi.
"""


def _yardimSeceneginiTurkcelestir(yardimSecenegi: TyperOption | None) -> TyperOption | None:
    # Typer tarafindan otomatik eklenen yardim seceneginin metnini Turkcelestirir.
    if yardimSecenegi is not None:
        yardimSecenegi.help = "Bu yardım metnini gösterir ve çıkar."
    return yardimSecenegi


class TurkceYardimKomutu(TyperCommand):
    # Alt komutlarda otomatik --help aciklamasini Turkce gosterir.
    def get_help_option(self, context: Any) -> TyperOption | None:
        return _yardimSeceneginiTurkcelestir(super().get_help_option(context))


class TurkceYardimGrubu(TyperGroup):
    # Ana komutta otomatik --help aciklamasini Turkce gosterir.
    def get_help_option(self, context: Any) -> TyperOption | None:
        return _yardimSeceneginiTurkcelestir(super().get_help_option(context))


uygulama = typer.Typer(
    cls=TurkceYardimGrubu,
    add_completion=False,
    help=ANA_YARDIM_METNI,
    epilog=ANA_YARDIM_SONU,
    invoke_without_command=True,
    no_args_is_help=False,
    rich_markup_mode="rich",
)
konsol = Console()
VARSAYILAN_KANIT_ANA_DIZINI = Path("evidence")
VARSAYILAN_EKRAN_GORUNTUSU_DIZINI = Path("screenshots")
CIKIS_KODU_TEMIZ = 0
CIKIS_KODU_ZAFIYET = 10
CIKIS_KODU_BELIRSIZ = 20
CIKIS_KODU_ATLANDI = 30
CIKIS_KODU_HATA = 40
CIKIS_KODU_IPTAL = 130
VARSAYILAN_IS_PARACIGI_SAYISI = 4
AZAMI_IS_PARACIGI_SAYISI = 16
CIDR_BASINA_EKRAN_GORUNTUSU_SINIRI = 2
KARSILAMA_BASLIGI = "\n".join(
    (
        "__   ___   _ _    _  ___   _____ ___ ___ ___ ___ ___ ___",
        "\\ \\ / / | | | |  | \\| \\ \\ / / __| _ \\_ _| __|_ _| __| _ \\",
        " \\ V /| |_| | |__| .` |\\ V /| _||   /| || _| | || _||   /",
        "  \\_/  \\___/|____|_|\\_| \\_/ |___|_|_\\___|_| |___|___|_|_\\",
    )
)


def kullaniciIptaliniYonet[**ParametrelerT, DonusT](
    fonksiyon: Callable[ParametrelerT, DonusT],
) -> Callable[ParametrelerT, DonusT]:
    # Ctrl+C iptalini traceback yerine standart CLI mesaji ve koduyla sonlandirir.
    @wraps(fonksiyon)
    def iptalYonetimliFonksiyon(
        *args: ParametrelerT.args,
        **kwargs: ParametrelerT.kwargs,
    ) -> DonusT:
        try:
            return fonksiyon(*args, **kwargs)
        except KeyboardInterrupt:
            aktifKomutlariSonlandir()
            konsol.print("[yellow]Tarama kullanıcı tarafından iptal edildi.[/yellow]")
            raise typer.Exit(code=CIKIS_KODU_IPTAL) from None

    return iptalYonetimliFonksiyon


class CalismaCiktisiProtokolu(Protocol):
    # Farkli dogrulama ciktisinin ortak evidence alanlarini tanimlar.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


# Kullanilabilir dogrulama kontrollerini listeler.
@uygulama.command(
    "list",
    cls=TurkceYardimKomutu,
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
    tablo.add_column("Başlık / varsayılan port", max_width=30)
    tablo.add_column("Risk")
    tablo.add_column("Araçlar")

    for kontrolTanimi in kayitliKontroller:
        varsayilanPortlar = ", ".join(str(port) for port in kontrolTanimi.varsayilanPortlar)
        gerekliAraclar = ", ".join(kontrolTanimi.gerekliAraclar) or "-"
        tablo.add_row(
            kontrolTanimi.kontrolKimligi,
            f"{kontrolTanimi.baslik}\nPort: {varsayilanPortlar or 'genel / --port'}",
            kontrolTanimi.riskSeviyesi.value,
            gerekliAraclar,
        )

    konsol.print(tablo)


# Calisma ortamini ve planlanan harici araclari kontrol eder.
@uygulama.command(
    "doctor",
    cls=TurkceYardimKomutu,
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
    cls=TurkceYardimKomutu,
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
    cls=TurkceYardimKomutu,
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
        Path,
        typer.Option("--database", help="Kullanılacak SQLite dosyasının yolu."),
    ] = VARSAYILAN_VERITABANI_YOLU,
) -> None:
    try:
        kayitlar = KaliciKayitDeposu(veritabaniYolu).taramaGecmisiniListele(
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
    cls=TurkceYardimKomutu,
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
        Path,
        typer.Option("--database", help="Kullanılacak SQLite dosyasının yolu."),
    ] = VARSAYILAN_VERITABANI_YOLU,
) -> None:
    try:
        bulgular = KaliciKayitDeposu(veritabaniYolu).bulgulariListele(projeAdi, sinir)
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
    cls=TurkceYardimKomutu,
    help="Seçilen doğrulama kontrolünü yetkili hedefte çalıştırır.",
    epilog=DOGRULAMA_YARDIM_SONU,
)
@kullaniciIptaliniYonet
@eszamanliKontroluSinirla
def dogrula(
    kontrolKimligi: Annotated[
        str,
        typer.Argument(
            metavar="KONTROL_KIMLIGI",
            help="Çalıştırılacak kontrol kimliği; geçerli kimlikler aşağıda listelenir.",
        ),
    ],
    hedef: Annotated[
        str | None,
        typer.Option(
            "--target",
            "-t",
            help="Doğrulanacak IP, hostname, CIDR veya virgülle ayrılmış hedefler.",
        ),
    ] = None,
    hedefDosyasi: Annotated[
        Path | None,
        typer.Option(
            "--target-file",
            help=(
                "Her satırda IP, hostname veya CIDR bulunan UTF-8 hedef dosyası; "
                "boş satırlar ve # yorumları atlanır."
            ),
        ),
    ] = None,
    portlar: Annotated[
        list[str] | None,
        typer.Option(
            "--port",
            "-p",
            help="Doğrulanacak port veya virgülle ayrılmış portlar; örnek: 80,443,445.",
        ),
    ] = None,
    projeAdi: Annotated[
        str,
        typer.Option("--project", help="SQLite kayıtlarının ilişkilendirileceği proje adı."),
    ] = VARSAYILAN_PROJE_ADI,
    veritabaniYolu: Annotated[
        Path,
        typer.Option("--database", help="Kullanılacak SQLite veritabanının yolu."),
    ] = VARSAYILAN_VERITABANI_YOLU,
    evidenceDizini: Annotated[
        Path | None,
        typer.Option("--evidence-dir", help="Evidence dosyalarının yazılacağı ana dizin."),
    ] = None,
    izinliHedefler: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-target",
            help=(
                "İsteğe bağlı yetkili IP, hostname veya CIDR; birden fazla kapsam "
                "için tekrarlanabilir."
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
    ayrintiliCikti: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Çoklu hedeflerde kesin bulgularla birlikte tüm sonuçları gösterir.",
        ),
    ] = False,
    ekranGoruntusu: Annotated[
        bool,
        typer.Option(
            "--screenshot",
            help="Sonucu ./screenshots klasörüne standart PNG olarak kaydeder.",
        ),
    ] = False,
    ekranGoruntusuDizini: Annotated[
        Path | None,
        typer.Option(
            "--screenshot-dir",
            help=(
                "PNG ekran görüntüsünün yazılacağı dizin; bu seçenek tek başına "
                "ekran görüntüsünü etkinleştirir."
            ),
        ),
    ] = None,
    tumEkranGoruntuleri: Annotated[
        bool,
        typer.Option(
            "--all-screenshots",
            help=("PNG üretimini etkinleştirir; toplu özetler tüm kesin sonuçları içerir."),
        ),
    ] = False,
    isParcacigiSayisi: Annotated[
        int,
        typer.Option(
            "--workers",
            min=1,
            max=AZAMI_IS_PARACIGI_SAYISI,
            help="Çoklu hedeflerde eşzamanlı çalışacak azami kontrol sayısı.",
        ),
    ] = VARSAYILAN_IS_PARACIGI_SAYISI,
) -> None:
    try:
        hedefHazirlamaSonucu = hedefleriGruplariylaHazirla(hedef, hedefDosyasi)
        standartHedefler = hedefHazirlamaSonucu.hedefler
    except HedefGirdisiHatasi as hata:
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
    standartHedef = standartHedefler[0]

    konsol.print(
        "[yellow]Uyarı: VulnVerifier yalnızca açıkça yetkilendirilmiş "
        "hedeflerde kullanılmalıdır.[/yellow]"
    )
    for guvenlikHedefi in standartHedefler:
        try:
            guvenlikPolitikasiniDogrula(
                kontrolTanimi,
                guvenlikHedefi,
                izinliHedefler,
                intrusiveOnayi,
            )
        except GuvenlikPolitikasiHatasi as hata:
            konsol.print(f"[red]Güvenlik politikası: {hata}[/red]")
            raise typer.Exit(code=2) from hata

    etkinKanitAnaDizini = evidenceDizini or VARSAYILAN_KANIT_ANA_DIZINI

    if len(standartHedefler) > 1:
        _cokluKontroluCalistir(
            kontrolKimligi,
            standartHedefler,
            standartPortlar,
            etkinKanitAnaDizini,
            veritabaniYolu,
            projeAdi,
            kontrolTanimi,
            ayrintiliCikti,
            ekranGoruntusu or ekranGoruntusuDizini is not None or tumEkranGoruntuleri,
            ekranGoruntusuDizini,
            isParcacigiSayisi,
            hedefHazirlamaSonucu.hedefGruplari,
            tumEkranGoruntuleri,
        )
    calismaCiktisi = _tekHedefKontrolunuCalistir(
        kontrolKimligi,
        standartHedef,
        standartPortlar,
        etkinKanitAnaDizini,
    )

    try:
        calismaCiktisi = _evidenceDosyaAdlariniTamamla(calismaCiktisi)
        if ekranGoruntusu or ekranGoruntusuDizini is not None or tumEkranGoruntuleri:
            calismaCiktisi = _ekranGoruntusunuTamamla(
                calismaCiktisi,
                kontrolTanimi,
                ekranGoruntusuDizini,
            )
        calismaCiktisi = _evidenceManifestosunuTamamla(calismaCiktisi, kontrolTanimi.gerekliAraclar)
    except KanitDosyasiHatasi as hata:
        konsol.print(f"[red]Evidence dosyaları oluşturulamadı: {hata}[/red]")
        raise typer.Exit(code=CIKIS_KODU_HATA) from hata
    _kontrolSonucunuGoster(calismaCiktisi.kontrolSonucu, calismaCiktisi)
    etkinVeritabaniYolu = veritabaniYolu
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
        f"bulgu={kayitOzeti.bulguKimligi or '-'}[/dim]"
    )
    raise typer.Exit(code=sonucCikisKodunuAl(calismaCiktisi.kontrolSonucu.durum))


def _tekHedefKontrolunuCalistir(
    kontrolKimligi: str,
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> CalismaCiktisiProtokolu:
    # Kayitli kontrol motorunu tek hedef icin ortak arayuz uzerinden calistirir.
    if kontrolKimligi != KONTROL_KIMLIGI and len(portlar) > 1:
        konsol.print(
            f"[red]Geçersiz port: {kontrolKimligi} tek seferde yalnızca bir port kabul eder.[/red]"
        )
        raise typer.Exit(code=2)

    calistiricilar = {
        KONTROL_KIMLIGI: _portServisKontrolunuCalistir,
        SSL_KONTROL_KIMLIGI: _sslProtokolKontrolunuCalistir,
        HPE_ILO_KONTROL_KIMLIGI: _hpeIloKontrolunuCalistir,
        ANONYMOUS_CIPHER_KONTROL_KIMLIGI: _anonymousCipherKontrolunuCalistir,
        MS12020_METASPLOIT_KONTROL_KIMLIGI: _ms12020MetasploitKontrolunuCalistir,
        SNMP_PUBLIC_KONTROL_KIMLIGI: _snmpPublicKontrolunuCalistir,
        VMWARE_SURUM_KONTROL_KIMLIGI: _vmwareSurumKontrolunuCalistir,
        MS17010_METASPLOIT_KONTROL_KIMLIGI: _ms17010MetasploitDogrulamasiniCalistir,
        DNS_CACHE_KONTROL_KIMLIGI: _dnsCacheDogrulamasiniCalistir,
        MS17010_NMAP_KONTROL_KIMLIGI: _ms17010NmapDogrulamasiniCalistir,
        MS12020_NMAP_KONTROL_KIMLIGI: _ms12020NmapDogrulamasiniCalistir,
        IPMI_HASH_KONTROL_KIMLIGI: _ipmiHashDogrulamasiniCalistir,
        FREAK_KONTROL_KIMLIGI: _freakDogrulamasiniCalistir,
        CCS_INJECTION_KONTROL_KIMLIGI: _ccsInjectionDogrulamasiniCalistir,
        NTP_MODE6_KONTROL_KIMLIGI: _ntpMode6DogrulamasiniCalistir,
        SMB_GUVENLIK_KONTROL_KIMLIGI: _smbGuvenlikKesfiniCalistir,
    }
    calistirici = calistiricilar.get(kontrolKimligi)
    if calistirici is None:
        konsol.print(f"[yellow]Kontrol motoru henüz hazır değil: {kontrolKimligi}[/yellow]")
        raise typer.Exit(code=1)
    return calistirici(hedef, portlar, kanitAnaDizini)


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


def _smbGuvenlikKesfiniCalistir(
    hedef: str, portlar: tuple[int, ...], kanitAnaDizini: Path
) -> SmbGuvenlikCalismaCiktisi:
    # Nmap bulunabilirligini denetleyip SMB guvenlik kesfini yurutur.
    aracDurumu = araciKontrolEt("nmap")
    if not aracDurumu.bulunduMu or aracDurumu.aracYolu is None:
        sonuc = eksikAraciStandartlastir(SMB_GUVENLIK_KONTROL_KIMLIGI, hedef, aracDurumu)
        _kontrolSonucunuGoster(sonuc)
        raise typer.Exit(code=sonucCikisKodunuAl(sonuc.durum))
    return NmapSmbGuvenlikCalistirmaServisi(
        NmapAdaptoru(aracDurumu.aracYolu), kanitAnaDizini
    ).calistir(hedef, portlar)


def _cokluKontroluCalistir(
    kontrolKimligi: str,
    hedefler: tuple[str, ...],
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
    veritabaniYolu: Path,
    projeAdi: str,
    kontrolTanimi: CheckDefinition,
    ayrintiliCikti: bool = False,
    ekranGoruntusu: bool = False,
    ekranGoruntusuDizini: Path | None = None,
    isParcacigiSayisi: int = VARSAYILAN_IS_PARACIGI_SAYISI,
    hedefGruplari: tuple[HedefGrubu, ...] = (),
    tumEkranGoruntuleri: bool = False,
) -> None:
    # Hedefleri sinirli paralellikle tarar, sirali kaydeder ve birlesik ozet gosterir.
    taramaBaslangici = time.monotonic()
    kayitDeposu = KaliciKayitDeposu(veritabaniYolu)
    try:
        kayitDeposu.hazirla()
        calisanSayisi = min(isParcacigiSayisi, len(hedefler))
        isParcacigiHavuzu = ThreadPoolExecutor(max_workers=calisanSayisi)
        try:
            tumCiktilar = tuple(
                isParcacigiHavuzu.map(
                    lambda hedef: _cokluHedefCiktisiniHazirla(
                        kontrolKimligi,
                        hedef,
                        portlar,
                        kanitAnaDizini,
                    ),
                    hedefler,
                )
            )
        except BaseException:
            aktifKomutlariSonlandir()
            isParcacigiHavuzu.shutdown(wait=True, cancel_futures=True)
            raise
        else:
            isParcacigiHavuzu.shutdown(wait=True)
        taramaSuresi = time.monotonic() - taramaBaslangici

        ekranDosyaSayisi = 0
        ciktiListesi = list(tumCiktilar)
        if ekranGoruntusu:
            if kontrolKimligi == SMB_GUVENLIK_KONTROL_KIMLIGI:
                ciktiListesi, ekranDosyaSayisi = _smbTopluEkranGoruntuleriniTamamla(
                    ciktiListesi,
                    hedefGruplari,
                    ekranGoruntusuDizini,
                )
            else:
                ciktiListesi, ekranDosyaSayisi = _topluKontrolEkranGoruntuleriniTamamla(
                    ciktiListesi,
                    hedefGruplari,
                    kontrolTanimi,
                    ekranGoruntusuDizini,
                )
        tumCiktilar = tuple(
            _evidenceManifestosunuTamamla(calismaCiktisi, kontrolTanimi.gerekliAraclar)
            for calismaCiktisi in ciktiListesi
        )
        for calismaCiktisi in tumCiktilar:
            kayitDeposu.dogrulamaKaydet(
                projeAdi,
                kontrolTanimi,
                calismaCiktisi.kontrolSonucu,
                portlar,
                calismaCiktisi.kanitDosyasiOzetleri,
            )
    except KanitDosyasiHatasi as hata:
        konsol.print(f"[red]Evidence dosyaları oluşturulamadı: {hata}[/red]")
        raise typer.Exit(code=CIKIS_KODU_HATA) from hata
    except VeritabaniHatasi as hata:
        konsol.print(f"[red]Doğrulama sonucu veritabanına kaydedilemedi: {hata}[/red]")
        raise typer.Exit(code=CIKIS_KODU_HATA) from hata

    varsayilanGosterilecekDurumlar = {
        ResultStatus.VULNERABLE,
        ResultStatus.DISCOVERED,
        ResultStatus.POTENTIALLY_VULNERABLE,
    }
    gosterilecekCiktilar = (
        tumCiktilar
        if ayrintiliCikti
        else tuple(
            cikti
            for cikti in tumCiktilar
            if cikti.kontrolSonucu.durum in varsayilanGosterilecekDurumlar
        )
    )
    if not gosterilecekCiktilar:
        konsol.print("[yellow]Kesin doğrulanmış bulgu veya keşif bulunamadı.[/yellow]")
        konsol.print(f"[dim]Tarama süresi: {taramaSuresi:.3f} saniye[/dim]")
    elif kontrolKimligi == SMB_GUVENLIK_KONTROL_KIMLIGI:
        _cokluSmbSonuclariniGoster(gosterilecekCiktilar)
    else:
        _cokluKontrolSonuclariniGoster(gosterilecekCiktilar)
    _taramaOzetiniGoster(tumCiktilar)
    konsol.print(
        f"[dim]SQLite kayıtları: proje={projeAdi}, hedef={len(tumCiktilar)}, "
        f"veritabanı={veritabaniYolu}[/dim]"
    )
    if ekranGoruntusu:
        ciktiDizini = ekranGoruntusuDizini or VARSAYILAN_EKRAN_GORUNTUSU_DIZINI
        konsol.print(f"[dim]Ekran görüntüleri: {ciktiDizini} ({ekranDosyaSayisi} dosya)[/dim]")
    raise typer.Exit(code=_cokluSonucCikisKodunuAl(tumCiktilar))


def _cokluHedefCiktisiniHazirla(
    kontrolKimligi: str,
    hedef: str,
    portlar: tuple[int, ...],
    kanitAnaDizini: Path,
) -> CalismaCiktisiProtokolu:
    # Tek hedefi tarar ve ortak evidence dosya adlarini tamamlar.
    calismaCiktisi = _tekHedefKontrolunuCalistir(
        kontrolKimligi,
        hedef,
        portlar,
        kanitAnaDizini,
    )
    return _evidenceDosyaAdlariniTamamla(calismaCiktisi)


def _ekranGoruntusuHedefleriniSec(
    ciktilar: tuple[CalismaCiktisiProtokolu, ...],
    hedefGruplari: tuple[HedefGrubu, ...],
    ayrintiliCikti: bool,
    tumEkranGoruntuleri: bool,
) -> tuple[tuple[int, ...], tuple[tuple[str, int, int], ...]]:
    # Tekil hedefleri sinirlamaz, CIDR girdilerinde blok basina kota uygular.
    varsayilanDurumlar = {ResultStatus.VULNERABLE, ResultStatus.DISCOVERED}
    hedefIndeksleri = {cikti.kontrolSonucu.hedef: indeks for indeks, cikti in enumerate(ciktilar)}

    def uygunMu(ciktiIndeksi: int) -> bool:
        return ayrintiliCikti or ciktilar[ciktiIndeksi].kontrolSonucu.durum in varsayilanDurumlar

    if not hedefGruplari:
        return tuple(indeks for indeks in range(len(ciktilar)) if uygunMu(indeks)), ()

    secilenIndeksler: set[int] = set()
    cidrOzetleri: list[tuple[str, int, int]] = []
    for hedefGrubu in hedefGruplari:
        uygunIndeksler = [
            hedefIndeksleri[hedef]
            for hedef in hedefGrubu.hedefler
            if hedef in hedefIndeksleri and uygunMu(hedefIndeksleri[hedef])
        ]
        if not hedefGrubu.cidrMi:
            secilenIndeksler.update(uygunIndeksler)
            continue

        # Kesin bulgu ve kesifler, verbose ile gelen diger durumlardan once secilir.
        siraliIndeksler = sorted(
            uygunIndeksler,
            key=lambda indeks: (
                ciktilar[indeks].kontrolSonucu.durum not in varsayilanDurumlar,
                indeks,
            ),
        )
        secilecekIndeksler = (
            siraliIndeksler
            if tumEkranGoruntuleri
            else siraliIndeksler[:CIDR_BASINA_EKRAN_GORUNTUSU_SINIRI]
        )
        secilenIndeksler.update(secilecekIndeksler)
        cidrOzetleri.append((hedefGrubu.kaynakGirdi, len(uygunIndeksler), len(secilecekIndeksler)))

    return tuple(sorted(secilenIndeksler)), tuple(cidrOzetleri)


def _smbTopluEkranGoruntuleriniTamamla(
    ciktilar: list[CalismaCiktisiProtokolu],
    hedefGruplari: tuple[HedefGrubu, ...],
    ekranGoruntusuDizini: Path | None,
) -> tuple[list[CalismaCiktisiProtokolu], int]:
    # SMB bulgularini kapsam bazinda toplar ve her kapsam icin ozet PNG uretir.
    ciktiDizini = ekranGoruntusuDizini or VARSAYILAN_EKRAN_GORUNTUSU_DIZINI
    uretilenDosyaSayisi = 0
    for kapsam, ciktiIndeksleri in _topluEkranGoruntusuGruplariniOlustur(
        tuple(ciktilar),
        hedefGruplari,
    ):
        kesinBulguIndeksleri = tuple(
            indeks
            for indeks in ciktiIndeksleri
            if _smbKesinBulgusuVarMi(ciktilar[indeks].kontrolSonucu)
        )
        if not kesinBulguIndeksleri:
            continue

        baglanacakIndeks = kesinBulguIndeksleri[0]
        baglanacakCikti = ciktilar[baglanacakIndeks]
        topluSonuc = smbTopluEkranGoruntuleriOlustur(
            baglanacakCikti.kanitKlasoru,
            kapsam,
            tuple(ciktilar[indeks].kontrolSonucu for indeks in ciktiIndeksleri),
        )
        for dosyaOzeti in topluSonuc.dosyaOzetleri:
            ekranGoruntusunuDisaAktar(
                dosyaOzeti.dosyaYolu,
                ciktiDizini,
                baglanacakCikti.kanitKlasoru.name,
            )
        ciktilar[baglanacakIndeks] = cast(
            CalismaCiktisiProtokolu,
            replace(
                baglanacakCikti,
                kanitDosyasiOzetleri=(
                    *baglanacakCikti.kanitDosyasiOzetleri,
                    *topluSonuc.dosyaOzetleri,
                ),
            ),
        )
        uretilenDosyaSayisi += len(topluSonuc.dosyaOzetleri)
    return ciktilar, uretilenDosyaSayisi


def _topluKontrolEkranGoruntuleriniTamamla(
    ciktilar: list[CalismaCiktisiProtokolu],
    hedefGruplari: tuple[HedefGrubu, ...],
    kontrolTanimi: CheckDefinition,
    ekranGoruntusuDizini: Path | None,
) -> tuple[list[CalismaCiktisiProtokolu], int]:
    # SMB disindaki kesin sonuclari kapsam bazli toplu PNG ozetlerine donusturur.
    ciktiDizini = ekranGoruntusuDizini or VARSAYILAN_EKRAN_GORUNTUSU_DIZINI
    uretilenDosyaSayisi = 0
    for kapsam, ciktiIndeksleri in _topluEkranGoruntusuGruplariniOlustur(
        tuple(ciktilar),
        hedefGruplari,
    ):
        kesinSonucIndeksleri = tuple(
            indeks
            for indeks in ciktiIndeksleri
            if ciktilar[indeks].kontrolSonucu.durum in KESIN_GORSEL_DURUMLARI
        )
        if not kesinSonucIndeksleri:
            continue

        baglanacakIndeks = kesinSonucIndeksleri[0]
        baglanacakCikti = ciktilar[baglanacakIndeks]
        topluSonuc = topluKontrolEkranGoruntuleriOlustur(
            baglanacakCikti.kanitKlasoru,
            kapsam,
            kontrolTanimi,
            tuple(ciktilar[indeks].kontrolSonucu for indeks in ciktiIndeksleri),
        )
        for dosyaOzeti in topluSonuc.dosyaOzetleri:
            ekranGoruntusunuDisaAktar(
                dosyaOzeti.dosyaYolu,
                ciktiDizini,
                baglanacakCikti.kanitKlasoru.name,
            )
        ciktilar[baglanacakIndeks] = cast(
            CalismaCiktisiProtokolu,
            replace(
                baglanacakCikti,
                kanitDosyasiOzetleri=(
                    *baglanacakCikti.kanitDosyasiOzetleri,
                    *topluSonuc.dosyaOzetleri,
                ),
            ),
        )
        uretilenDosyaSayisi += len(topluSonuc.dosyaOzetleri)
    return ciktilar, uretilenDosyaSayisi


def _topluEkranGoruntusuGruplariniOlustur(
    ciktilar: tuple[CalismaCiktisiProtokolu, ...],
    hedefGruplari: tuple[HedefGrubu, ...],
) -> tuple[tuple[str, tuple[int, ...]], ...]:
    # Her CIDR'yi ayri, CIDR disindaki hedefleri tek toplu kapsam olarak gruplar.
    hedefIndeksleri = {cikti.kontrolSonucu.hedef: indeks for indeks, cikti in enumerate(ciktilar)}
    if not hedefGruplari:
        return (("Seçili hedefler", tuple(range(len(ciktilar)))),)

    gruplar: list[tuple[str, tuple[int, ...]]] = []
    tekilIndeksler: list[int] = []
    kullanilanIndeksler: set[int] = set()
    for hedefGrubu in hedefGruplari:
        grupIndeksleri = tuple(
            hedefIndeksleri[hedef]
            for hedef in hedefGrubu.hedefler
            if hedef in hedefIndeksleri and hedefIndeksleri[hedef] not in kullanilanIndeksler
        )
        kullanilanIndeksler.update(grupIndeksleri)
        if not grupIndeksleri:
            continue
        if hedefGrubu.cidrMi:
            gruplar.append((hedefGrubu.kaynakGirdi, grupIndeksleri))
        else:
            tekilIndeksler.extend(grupIndeksleri)

    tekilIndeksler.extend(
        indeks for indeks in range(len(ciktilar)) if indeks not in kullanilanIndeksler
    )
    if tekilIndeksler:
        gruplar.append(("Seçili hedefler", tuple(tekilIndeksler)))
    return tuple(gruplar)


def _smbKesinBulgusuVarMi(kontrolSonucu: KontrolSonucu) -> bool:
    # SMBv1 acikligini veya imzalama zorunlulugu eksikligini kesin bulgu sayar.
    kanitlar = _kanitlariSozlugeCevir(kontrolSonucu)
    return kanitlar.get("smbV1") == "true" or kanitlar.get("imzalamaZorunlu") == "false"


def _cidrEkranGoruntusuOzetiniGoster(
    cidrOzetleri: tuple[tuple[str, int, int], ...],
    tumEkranGoruntuleri: bool,
) -> None:
    # CIDR basina uygun, uretilen ve kota nedeniyle atlanan PNG sayilarini gosterir.
    if not cidrOzetleri or not any(uretilenSayisi for _, _, uretilenSayisi in cidrOzetleri):
        return
    tablo = Table(title="CIDR ekran görüntüsü özeti")
    tablo.add_column("CIDR")
    tablo.add_column("Uygun")
    tablo.add_column("Üretilen")
    tablo.add_column("Sınır nedeniyle atlanan")
    for kaynakGirdi, uygunSayisi, uretilenSayisi in cidrOzetleri:
        tablo.add_row(
            kaynakGirdi,
            str(uygunSayisi),
            str(uretilenSayisi),
            str(uygunSayisi - uretilenSayisi),
        )
    konsol.print(tablo)
    if tumEkranGoruntuleri:
        konsol.print("[dim]--all-screenshots: CIDR başına PNG sınırı kaldırıldı.[/dim]")


def _taramaOzetiniGoster(ciktilar: tuple[CalismaCiktisiProtokolu, ...]) -> None:
    # Tum sonuclari durum gruplarina ayirip gizlenen kayitlari da sayisal olarak bildirir.
    durumlar = tuple(cikti.kontrolSonucu.durum for cikti in ciktilar)
    kesinBulguSayisi = durumlar.count(ResultStatus.VULNERABLE)
    temizSayisi = durumlar.count(ResultStatus.NOT_VULNERABLE)
    kesifSayisi = durumlar.count(ResultStatus.DISCOVERED)
    bulunamayanSayisi = durumlar.count(ResultStatus.NOT_FOUND)
    belirsizSayisi = sum(
        durum in {ResultStatus.POTENTIALLY_VULNERABLE, ResultStatus.INCONCLUSIVE}
        for durum in durumlar
    )
    hataSayisi = sum(durum in {ResultStatus.SKIPPED, ResultStatus.ERROR} for durum in durumlar)
    konsol.print(
        "[bold]Tarama özeti:[/bold] "
        f"taranan={len(ciktilar)}, kesin bulgu={kesinBulguSayisi}, "
        f"keşif={kesifSayisi}, bulunamadı={bulunamayanSayisi}, temiz={temizSayisi}, "
        f"belirsiz={belirsizSayisi}, hata/atlanan={hataSayisi}"
    )


def _cokluKontrolSonuclariniGoster(
    ciktilar: tuple[CalismaCiktisiProtokolu, ...],
) -> None:
    # Kontrol bagimsiz coklu hedef sonuclarini tek ozet tabloda gosterir.
    durumRenkleri = {
        ResultStatus.VULNERABLE: "red",
        ResultStatus.NOT_VULNERABLE: "green",
        ResultStatus.POTENTIALLY_VULNERABLE: "yellow",
        ResultStatus.INCONCLUSIVE: "yellow",
        ResultStatus.SKIPPED: "cyan",
        ResultStatus.ERROR: "red",
        ResultStatus.DISCOVERED: "blue",
        ResultStatus.NOT_FOUND: "cyan",
    }
    tablo = Table(title="Çoklu hedef doğrulama özeti", show_lines=True)
    tablo.add_column("Hedef", no_wrap=True)
    tablo.add_column("Durum", no_wrap=True)
    tablo.add_column("Özet", overflow="fold")
    tablo.add_column("Süre", no_wrap=True)
    for cikti in ciktilar:
        sonuc = cikti.kontrolSonucu
        sure = f"{sonuc.calismaSuresiSaniye:.3f} sn" if sonuc.calismaSuresiSaniye else "-"
        tablo.add_row(
            hassasMetniMaskele(sonuc.hedef),
            f"[{durumRenkleri[sonuc.durum]}]{sonuc.durum.value}[/]",
            hassasMetniMaskele(sonuc.ozet),
            sure,
        )
    konsol.print(tablo)
    _cokluEvidenceKlasorleriniGoster(ciktilar)


def _cokluSmbSonuclariniGoster(
    ciktilar: tuple[CalismaCiktisiProtokolu, ...],
) -> None:
    # Coklu SMB sonuclarini ekran goruntusune uygun tek bir tabloda gosterir.
    durumRenkleri = {
        ResultStatus.VULNERABLE: "red",
        ResultStatus.NOT_VULNERABLE: "green",
        ResultStatus.POTENTIALLY_VULNERABLE: "yellow",
        ResultStatus.INCONCLUSIVE: "yellow",
        ResultStatus.SKIPPED: "cyan",
        ResultStatus.ERROR: "red",
        ResultStatus.DISCOVERED: "blue",
        ResultStatus.NOT_FOUND: "cyan",
    }
    tablo = Table(title="SMB çoklu hedef özeti", show_lines=False)
    tablo.add_column("IP", no_wrap=True)
    tablo.add_column("Port", no_wrap=True)
    tablo.add_column("Host")
    tablo.add_column("OS", overflow="fold")
    tablo.add_column("Domain")
    tablo.add_column("Sign")
    tablo.add_column("SMBv1")
    tablo.add_column("Durum", no_wrap=True)
    for cikti in ciktilar:
        sonuc = cikti.kontrolSonucu
        kanitlar = _kanitlariSozlugeCevir(sonuc)
        tablo.add_row(
            hassasMetniMaskele(sonuc.hedef),
            kanitlar.get("port", "-"),
            hassasMetniMaskele(kanitlar.get("bilgisayarAdi", "-")),
            hassasMetniMaskele(kanitlar.get("isletimSistemi", "-")),
            hassasMetniMaskele(kanitlar.get("domain", "-")),
            _booleanGorunumunuOlustur(kanitlar.get("imzalamaZorunlu")),
            _booleanGorunumunuOlustur(kanitlar.get("smbV1")),
            f"[{durumRenkleri[sonuc.durum]}]{sonuc.durum.value}[/]",
        )
    konsol.print(tablo)

    _cokluEvidenceKlasorleriniGoster(ciktilar)


def _cokluEvidenceKlasorleriniGoster(
    ciktilar: tuple[CalismaCiktisiProtokolu, ...],
) -> None:
    # Her hedefin ayri evidence klasorunu kompakt bir tabloda gosterir.
    evidenceTablosu = Table(title="Hedef evidence klasörleri", show_lines=False)
    evidenceTablosu.add_column("Hedef", no_wrap=True)
    evidenceTablosu.add_column("Evidence klasörü", overflow="fold")
    for cikti in ciktilar:
        evidenceTablosu.add_row(
            hassasMetniMaskele(cikti.kontrolSonucu.hedef),
            hassasMetniMaskele(str(cikti.kanitKlasoru)),
        )
    konsol.print(evidenceTablosu)


def _kanitlariSozlugeCevir(sonuc: KontrolSonucu) -> dict[str, str]:
    # Tekil SMB kanitlarini ozet tablo icin anahtar deger yapisina cevirir.
    return {kanit.anahtar: kanit.deger for kanit in sonuc.kanitlar}


def _booleanGorunumunuOlustur(deger: str | None) -> str:
    # Kanit boolean degerini NetExec benzeri buyuk harfli gorunume cevirir.
    return {"true": "True", "false": "False", "unknown": "?"}.get(deger or "", "?")


def _cokluSonucCikisKodunuAl(
    ciktilar: tuple[CalismaCiktisiProtokolu, ...],
) -> int:
    # Coklu taramanin en onemli durumunu tek surec cikis koduna cevirir.
    durumlar = {cikti.kontrolSonucu.durum for cikti in ciktilar}
    if ResultStatus.ERROR in durumlar:
        return CIKIS_KODU_HATA
    if durumlar & {ResultStatus.VULNERABLE, ResultStatus.POTENTIALLY_VULNERABLE}:
        return CIKIS_KODU_ZAFIYET
    if ResultStatus.INCONCLUSIVE in durumlar:
        return CIKIS_KODU_BELIRSIZ
    if ResultStatus.SKIPPED in durumlar:
        return CIKIS_KODU_ATLANDI
    return CIKIS_KODU_TEMIZ


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


def _evidenceDosyaAdlariniTamamla[CalismaCiktisiT: CalismaCiktisiProtokolu](
    calismaCiktisi: CalismaCiktisiT,
) -> CalismaCiktisiT:
    # Gecici evidence adlarini hedef, kontrol, durum ve zaman iceren adlara cevirir.
    adlandirilmisDosyalar = evidenceDosyalariniAdlandir(
        calismaCiktisi.kanitKlasoru,
        calismaCiktisi.kontrolSonucu,
        calismaCiktisi.hamCiktiDosyalari,
        calismaCiktisi.normalizeKanitYolu,
        calismaCiktisi.kanitDosyasiOzetleri,
    )
    return cast(
        CalismaCiktisiT,
        replace(
            calismaCiktisi,
            kanitKlasoru=adlandirilmisDosyalar.kanitKlasoru,
            hamCiktiDosyalari=adlandirilmisDosyalar.hamCiktiDosyalari,
            normalizeKanitYolu=adlandirilmisDosyalar.normalizeKanitYolu,
            kanitDosyasiOzetleri=adlandirilmisDosyalar.kanitDosyasiOzetleri,
        ),
    )


def _ekranGoruntusunuTamamla[CalismaCiktisiT: CalismaCiktisiProtokolu](
    calismaCiktisi: CalismaCiktisiT,
    kontrolTanimi: CheckDefinition,
    ekranGoruntusuDizini: Path | None,
    yoluGoster: bool = True,
) -> CalismaCiktisiT:
    # PNG kanitini evidence listesine ekler ve secilen cikti dizinine kopyalar.
    if kontrolTanimi.kontrolKimligi in OZEL_GORSEL_KONTROLLERI:
        ekranGoruntusuOzeti = ozelTekliEkranGoruntusuOlustur(
            calismaCiktisi.kanitKlasoru,
            kontrolTanimi,
            calismaCiktisi.kontrolSonucu,
        )
    else:
        ekranGoruntusuOzeti = ekranGoruntusuOlustur(
            calismaCiktisi.kanitKlasoru,
            kontrolTanimi,
            calismaCiktisi.kontrolSonucu,
        )
    ciktiDizini = ekranGoruntusuDizini or VARSAYILAN_EKRAN_GORUNTUSU_DIZINI
    disariAktarilanYol = ekranGoruntusunuDisaAktar(
        ekranGoruntusuOzeti.dosyaYolu,
        ciktiDizini,
        calismaCiktisi.kanitKlasoru.name,
    )
    if yoluGoster:
        konsol.print(f"[dim]Ekran görüntüsü: {disariAktarilanYol}[/dim]")
    return cast(
        CalismaCiktisiT,
        replace(
            calismaCiktisi,
            kanitDosyasiOzetleri=(
                *calismaCiktisi.kanitDosyasiOzetleri,
                ekranGoruntusuOzeti,
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
    if durum in {
        ResultStatus.NOT_VULNERABLE,
        ResultStatus.DISCOVERED,
        ResultStatus.NOT_FOUND,
    }:
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
        | SmbGuvenlikCalismaCiktisi
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
        ResultStatus.DISCOVERED: "blue",
        ResultStatus.NOT_FOUND: "cyan",
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


def _karsilamaEkraniniGoster() -> None:
    # Parametresiz calistirmada kisa urun tanitimini ve yonlendirmeleri gosterir.
    icerik = Text(justify="center")
    icerik.append(KARSILAMA_BASLIGI, style="bold #ff8c1a")
    icerik.append("\n\nKanıt odaklı zafiyet doğrulama aracı", style="bold")
    icerik.append(
        "\nYetkili hedeflerde ağ ve güvenlik kontrollerini çalıştırır; "
        "sonuçları evidence dosyalarına ve SQLite veritabanına kaydeder."
    )
    icerik.append(
        f"\n\nSürüm: {__version__}  |  Kontrol sayısı: {len(varsayilanKatalog)}  |  Arayüz: CLI",
        style="bold #c55a11",
    )
    icerik.append("\n\nKomutlar ve seçenekler: ", style="dim")
    icerik.append("vulnverifier --help", style="bold cyan")
    icerik.append("\nKontrol listesini göster: ", style="dim")
    icerik.append("vulnverifier list", style="bold cyan")
    konsol.print(Panel.fit(icerik, border_style="#ff9d1d", padding=(1, 2)))


# VulnVerifier CLI komut grubunu baslatir.
@uygulama.callback()
def anaKomut(
    context: typer.Context,
    surum: Annotated[
        bool,
        typer.Option("--version", help="Uygulama sürümünü gösterir.", is_eager=True),
    ] = False,
) -> None:
    if surum:
        konsol.print(f"VulnVerifier {__version__}")
        raise typer.Exit()
    if context.invoked_subcommand is None:
        _karsilamaEkraniniGoster()


def uygulamayiCalistir() -> None:
    # Paket giris noktasindan Typer uygulamasini calistirir.
    uygulama()
