# SMB disindaki kontroller icin tekli ve toplu rapor PNG'leri uretir.

import math
import textwrap
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from vulnverifier.artifact_naming import (
    TURKIYE_SAAT_DILIMI,
    dosyaAdiParcasiniGuvenliYap,
)
from vulnverifier.evidence_storage import (
    KanitDosyasiOzeti,
    hassasMetniMaskele,
    kanitDosyasiOzetiniHesapla,
)
from vulnverifier.models import CheckDefinition, KontrolSonucu, ResultStatus
from vulnverifier.screenshot_renderer import (
    ARKA_PLAN_RENGI,
    DURUM_RENKLERI,
    GORUNTU_GENISLIGI,
    IKINCIL_METIN_RENGI,
    KENAR_RENGI,
    METIN_RENGI,
    YATAY_BOSLUK,
    EkranGoruntusuHatasi,
    _pngDosyasiniAtomikOlustur,
    _vurguSeridiniCiz,
    _yaziTipiniYukle,
    ekranGoruntusuDosyaAdiniOlustur,
)

PORT_KONTROLU = "port-service-discovery"
TLS_PROTOKOL_KONTROLU = "sslv2-sslv3-support"
SURUM_KONTROLLERI = {
    "hpe-ilo-version-detection",
    "vmware-esxi-version-detection",
}
SMB_KONTROLU = "smb-security-discovery"
OZEL_GORSEL_KONTROLLERI = {
    PORT_KONTROLU,
    TLS_PROTOKOL_KONTROLU,
    *SURUM_KONTROLLERI,
    "anonymous-cipher-support",
    "ms12-020-metasploit",
    "snmp-public-community",
    "ms17-010-metasploit",
    "dns-cache-snooping",
    "ms17-010-nmap",
    "ms12-020-nmap",
    "ipmi-v2-hash-disclosure",
    "freak-export-rsa",
    "openssl-ccs-injection",
    "ntp-mode-6",
}
KESIN_GORSEL_DURUMLARI = {
    ResultStatus.VULNERABLE,
    ResultStatus.DISCOVERED,
    ResultStatus.POTENTIALLY_VULNERABLE,
}
SATIR_RENGI = "#fff4e6"
VURGU_RENGI = "#f05a28"
ACIK_VURGU_RENGI = "#fff4e6"
TABLO_SAYFA_SATIRI = 12
LISTE_SAYFA_HEDEFI = 25
LISTE_SATIR_HEDEFI = 5


@dataclass(frozen=True, slots=True)
class TopluEkranGoruntusuSonucu:
    # Uretilen toplu kontrol sayfalarini ve kesin sonuc sayisini tasir.

    dosyaOzetleri: tuple[KanitDosyasiOzeti, ...]
    kesinSonucSayisi: int


def ozelTekliEkranGoruntusuOlustur(
    kanitKlasoru: str | Path,
    kontrolTanimi: CheckDefinition,
    kontrolSonucu: KontrolSonucu,
) -> KanitDosyasiOzeti:
    # Kontrol turune uygun sade tek hedef PNG'sini evidence klasorune yazar.
    klasorYolu = Path(kanitKlasoru)
    _girdiDogrula(klasorYolu, kontrolTanimi, (kontrolSonucu,))
    if kontrolTanimi.kontrolKimligi not in OZEL_GORSEL_KONTROLLERI:
        raise EkranGoruntusuHatasi("Bu kontrol için özel tekli ekran görüntüsü tanımlı değil.")

    if kontrolTanimi.kontrolKimligi == PORT_KONTROLU:
        goruntu = _tekliPortGoruntusunuCiz(kontrolTanimi, kontrolSonucu)
    elif kontrolTanimi.kontrolKimligi == TLS_PROTOKOL_KONTROLU:
        goruntu = _tekliTlsGoruntusunuCiz(kontrolTanimi, kontrolSonucu)
    elif kontrolTanimi.kontrolKimligi in SURUM_KONTROLLERI:
        goruntu = _tekliSurumGoruntusunuCiz(kontrolTanimi, kontrolSonucu)
    else:
        goruntu = _tekliBulguGoruntusunuCiz(kontrolTanimi, kontrolSonucu)

    dosyaYolu = klasorYolu / ekranGoruntusuDosyaAdiniOlustur(kontrolSonucu)
    _pngDosyasiniAtomikOlustur(goruntu, dosyaYolu)
    return kanitDosyasiOzetiniHesapla(dosyaYolu)


def topluKontrolEkranGoruntuleriOlustur(
    kanitKlasoru: str | Path,
    kapsam: str,
    kontrolTanimi: CheckDefinition,
    kontrolSonuclari: tuple[KontrolSonucu, ...],
    zaman: datetime | None = None,
) -> TopluEkranGoruntusuSonucu:
    # Ayni kontrolun kesin coklu hedef sonuclarini kapsam bazli PNG ozetlerine cevirir.
    klasorYolu = Path(kanitKlasoru)
    _girdiDogrula(klasorYolu, kontrolTanimi, kontrolSonuclari)
    if not kapsam.strip():
        raise EkranGoruntusuHatasi("Toplu ekran görüntüsü kapsamı boş olamaz.")
    if kontrolTanimi.kontrolKimligi not in OZEL_GORSEL_KONTROLLERI:
        raise EkranGoruntusuHatasi("Bu kontrol için özel toplu ekran görüntüsü tanımlı değil.")

    kesinSonuclar = tuple(
        sonuc for sonuc in kontrolSonuclari if sonuc.durum in KESIN_GORSEL_DURUMLARI
    )
    if not kesinSonuclar:
        return TopluEkranGoruntusuSonucu((), 0)

    if kontrolTanimi.kontrolKimligi == PORT_KONTROLU:
        sayfalar = _topluPortSayfalariniCiz(
            kapsam,
            kontrolTanimi,
            kontrolSonuclari,
            kesinSonuclar,
            zaman,
        )
    elif kontrolTanimi.kontrolKimligi == TLS_PROTOKOL_KONTROLU:
        sayfalar = _topluTlsSayfalariniCiz(
            kapsam,
            kontrolTanimi,
            kontrolSonuclari,
            kesinSonuclar,
            zaman,
        )
    elif kontrolTanimi.kontrolKimligi in SURUM_KONTROLLERI:
        sayfalar = _topluSurumSayfalariniCiz(
            kapsam,
            kontrolTanimi,
            kontrolSonuclari,
            kesinSonuclar,
            zaman,
        )
    else:
        sayfalar = _topluBulguSayfalariniCiz(
            kapsam,
            kontrolTanimi,
            kontrolSonuclari,
            kesinSonuclar,
            zaman,
        )

    dosyaOzetleri: list[KanitDosyasiOzeti] = []
    for sayfaNumarasi, goruntu in enumerate(sayfalar, start=1):
        dosyaYolu = klasorYolu / _topluDosyaAdiniOlustur(
            kapsam,
            kontrolTanimi.kontrolKimligi,
            sayfaNumarasi,
            len(sayfalar),
            zaman,
        )
        _pngDosyasiniAtomikOlustur(goruntu, dosyaYolu)
        dosyaOzetleri.append(kanitDosyasiOzetiniHesapla(dosyaYolu))
    return TopluEkranGoruntusuSonucu(tuple(dosyaOzetleri), len(kesinSonuclar))


def _girdiDogrula(
    klasorYolu: Path,
    kontrolTanimi: CheckDefinition,
    kontrolSonuclari: tuple[KontrolSonucu, ...],
) -> None:
    # Renderer girdilerinin ayni kontrolu ve gercek evidence klasorunu kullandigini denetler.
    if klasorYolu.is_symlink() or not klasorYolu.is_dir():
        raise EkranGoruntusuHatasi("Ekran görüntüsü için gerçek bir evidence klasörü gerekir.")
    if not kontrolSonuclari:
        raise EkranGoruntusuHatasi("Ekran görüntüsü için en az bir kontrol sonucu gerekir.")
    if any(sonuc.kontrolKimligi != kontrolTanimi.kontrolKimligi for sonuc in kontrolSonuclari):
        raise EkranGoruntusuHatasi("Kontrol tanımı ile ekran görüntüsü sonuçları uyuşmuyor.")


def _tekliPortGoruntusunuCiz(
    kontrolTanimi: CheckDefinition,
    sonuc: KontrolSonucu,
) -> Image.Image:
    # Tek hedefteki acik port ve servisleri sade tabloya donusturur.
    portSatirlari = _portSatirlariniOlustur(sonuc)
    if not portSatirlari:
        return _tekliBulguGoruntusunuCiz(kontrolTanimi, sonuc)
    goruntuYuksekligi = 548 + (len(portSatirlari) * 60) + 130
    goruntu, cizim, yaziTipleri = _tekliTemeliniCiz(
        kontrolTanimi,
        sonuc,
        "PORT VE SERVİS · TEK HEDEF",
        goruntuYuksekligi,
        "TARANAN PORT",
        str(_istenenPortSayisiniAl(sonuc, portSatirlari)),
        "AÇIK PORT",
        str(len(portSatirlari)),
    )
    tabloAltSiniri = _tabloyuCiz(
        cizim,
        318,
        (("PORT", 92), ("DURUM", 330), ("SERVİS", 590), ("ÜRÜN / SÜRÜM", 900)),
        tuple((port, "AÇIK", servis, urun) for port, servis, urun in portSatirlari),
        yaziTipleri[0],
        yaziTipleri[1],
    )
    _altBilgiyiCiz(
        cizim,
        tabloAltSiniri + 42,
        "Yalnızca açık olduğu doğrulanan portlar gösterilmiştir.",
        yaziTipleri[0],
        yaziTipleri[1],
    )
    return goruntu


def _tekliTlsGoruntusunuCiz(
    kontrolTanimi: CheckDefinition,
    sonuc: KontrolSonucu,
) -> Image.Image:
    # Tek hedefteki TLS protokol durumlarini protokol tablosunda gosterir.
    protokolSatirlari = _tlsProtokolSatirlariniOlustur(sonuc)
    if not protokolSatirlari:
        return _tekliBulguGoruntusunuCiz(kontrolTanimi, sonuc)
    goruntuYuksekligi = 548 + (len(protokolSatirlari) * 60) + 130
    bulguSayisi = sum(
        1
        for protokol, durum, _ in protokolSatirlari
        if protokol in {"SSLv2", "SSLv3"} and durum == "Sunuluyor"
    )
    goruntu, cizim, yaziTipleri = _tekliTemeliniCiz(
        kontrolTanimi,
        sonuc,
        "TLS PROTOKOLLERİ · TEK HEDEF",
        goruntuYuksekligi,
        "PORT",
        _ilkKanitDegeriniAl(sonuc, "port") or "443",
        "DOĞRULANAN BULGU",
        str(bulguSayisi),
    )
    tabloAltSiniri = _tabloyuCiz(
        cizim,
        318,
        (("PROTOKOL", 92), ("SUNUCU DESTEĞİ", 470), ("SONUÇ", 930)),
        tuple(protokolSatirlari),
        yaziTipleri[0],
        yaziTipleri[1],
    )
    _altBilgiyiCiz(
        cizim,
        tabloAltSiniri + 42,
        hassasMetniMaskele(sonuc.ozet),
        yaziTipleri[0],
        yaziTipleri[1],
    )
    return goruntu


def _tekliSurumGoruntusunuCiz(
    kontrolTanimi: CheckDefinition,
    sonuc: KontrolSonucu,
) -> Image.Image:
    # Tek hedefte bulunan urun ve surum alanlarini tek kartta gosterir.
    goruntu, cizim, yaziTipleri = _tekliTemeliniCiz(
        kontrolTanimi,
        sonuc,
        "SÜRÜM KEŞFİ · TEK HEDEF",
        760,
        "PORT",
        _ilkKanitDegeriniAl(sonuc, "port") or "-",
        "SONUÇ",
        _durumEtiketiniAl(sonuc.durum),
    )
    cizim.rounded_rectangle(
        (YATAY_BOSLUK, 318, GORUNTU_GENISLIGI - YATAY_BOSLUK, 552),
        radius=14,
        outline=KENAR_RENGI,
        width=2,
    )
    cizim.text((92, 344), "DOĞRULANAN CİHAZ BİLGİLERİ", font=yaziTipleri[2], fill=METIN_RENGI)
    urun, surum, ekBilgi = _surumAlanlariniAl(sonuc)
    for etiket, deger, xKonumu in (
        ("ÜRÜN", urun, 92),
        ("SÜRÜM / FIRMWARE", surum, 500),
        ("EK BİLGİ", ekBilgi, 930),
    ):
        cizim.text((xKonumu, 416), etiket, font=yaziTipleri[1], fill=IKINCIL_METIN_RENGI)
        cizim.text((xKonumu, 462), _metniKisalt(deger, 34), font=yaziTipleri[0], fill=METIN_RENGI)
    _altBilgiyiCiz(
        cizim,
        600,
        "Bu çıktı bir zafiyet kararı değil, doğrulanmış ürün ve sürüm keşfidir.",
        yaziTipleri[0],
        yaziTipleri[1],
    )
    return goruntu


def _tekliBulguGoruntusunuCiz(
    kontrolTanimi: CheckDefinition,
    sonuc: KontrolSonucu,
) -> Image.Image:
    # Tek sonuclu kontrolleri kisa ozet ve sonuc etiketiyle gosterir.
    ozetSatirlari = tuple(textwrap.wrap(hassasMetniMaskele(sonuc.ozet), width=90)) or ("-",)
    goruntuYuksekligi = 660 + max(0, len(ozetSatirlari) - 1) * 32
    goruntu, cizim, yaziTipleri = _tekliTemeliniCiz(
        kontrolTanimi,
        sonuc,
        "DOĞRULAMA KANITI · TEK HEDEF",
        goruntuYuksekligi,
        "PORT",
        _portMetniniOlustur(sonuc),
        "KONTROL",
        sonuc.kontrolKimligi,
    )
    kartAltSiniri = 484 + max(0, len(ozetSatirlari) - 1) * 32
    cizim.rounded_rectangle(
        (YATAY_BOSLUK, 318, GORUNTU_GENISLIGI - YATAY_BOSLUK, kartAltSiniri),
        radius=14,
        outline=KENAR_RENGI,
        width=2,
    )
    cizim.text((92, 344), "KONTROL SONUCU", font=yaziTipleri[1], fill=METIN_RENGI)
    for sira, satir in enumerate(ozetSatirlari):
        cizim.text((92, 400 + sira * 32), satir, font=yaziTipleri[0], fill=IKINCIL_METIN_RENGI)
    durumRengi = DURUM_RENKLERI[sonuc.durum]
    cizim.rounded_rectangle((1080, 368, 1348, 436), radius=12, fill="#fff4e6")
    cizim.text(
        (1214, 402),
        _durumEtiketiniAl(sonuc.durum),
        font=yaziTipleri[1],
        fill=durumRengi,
        anchor="mm",
    )
    _altBilgiyiCiz(
        cizim,
        kartAltSiniri + 42,
        "Kontrol sonucu ve temel hedef bilgileri rapor kullanımı için sadeleştirilmiştir.",
        yaziTipleri[0],
        yaziTipleri[1],
    )
    return goruntu


def _tekliTemeliniCiz(
    kontrolTanimi: CheckDefinition,
    sonuc: KontrolSonucu,
    sagBaslik: str,
    goruntuYuksekligi: int,
    ikinciEtiket: str,
    ikinciDeger: str,
    ucuncuEtiket: str,
    ucuncuDeger: str,
) -> tuple[
    Image.Image,
    ImageDraw.ImageDraw,
    tuple[ImageFont.FreeTypeFont | ImageFont.ImageFont, ...],
]:
    # Tekli sablonun marka, baslik ve hedef bilgi alanlarini ortak bicimde cizer.
    normalYazi = _yaziTipiniYukle(22)
    kucukYazi = _yaziTipiniYukle(18, kalin=True)
    bolumYazisi = _yaziTipiniYukle(22, kalin=True)
    baslikYazisi = _yaziTipiniYukle(38, kalin=True)
    altBaslikYazisi = _yaziTipiniYukle(28, kalin=True)
    goruntu = Image.new("RGB", (GORUNTU_GENISLIGI, goruntuYuksekligi), ARKA_PLAN_RENGI)
    cizim = ImageDraw.Draw(goruntu)
    _basligiCiz(cizim, sagBaslik, kontrolTanimi.baslik, baslikYazisi, kucukYazi, altBaslikYazisi)
    for etiket, deger, xKonumu in (
        ("HEDEF", hassasMetniMaskele(sonuc.hedef), YATAY_BOSLUK),
        (ikinciEtiket, hassasMetniMaskele(ikinciDeger), 470),
        (ucuncuEtiket, hassasMetniMaskele(ucuncuDeger), 930),
    ):
        cizim.text((xKonumu, 212), etiket, font=kucukYazi, fill=IKINCIL_METIN_RENGI)
        cizim.text((xKonumu, 248), _metniKisalt(deger, 34), font=normalYazi, fill=METIN_RENGI)
    return goruntu, cizim, (normalYazi, kucukYazi, bolumYazisi)


def _topluPortSayfalariniCiz(
    kapsam: str,
    kontrolTanimi: CheckDefinition,
    tumSonuclar: tuple[KontrolSonucu, ...],
    kesinSonuclar: tuple[KontrolSonucu, ...],
    zaman: datetime | None,
) -> tuple[Image.Image, ...]:
    # Acik portlari hedef, servis ve urun bilgileriyle sayfali tabloya donusturur.
    satirlar = tuple(
        (sonuc.hedef, port, servis, urun)
        for sonuc in kesinSonuclar
        for port, servis, urun in _portSatirlariniOlustur(sonuc)
    )
    if not satirlar:
        satirlar = tuple((sonuc.hedef, "-", "-", "-") for sonuc in kesinSonuclar)
    sayfaSayisi = max(1, math.ceil(len(satirlar) / TABLO_SAYFA_SATIRI))
    sayfalar: list[Image.Image] = []
    for sayfaSirasi in range(sayfaSayisi):
        sayfaSatirlari = satirlar[
            sayfaSirasi * TABLO_SAYFA_SATIRI : (sayfaSirasi + 1) * TABLO_SAYFA_SATIRI
        ]
        goruntuYuksekligi = 548 + len(sayfaSatirlari) * 60 + 130
        goruntu, cizim, yaziTipleri = _topluTemeliniCiz(
            kapsam,
            kontrolTanimi,
            tumSonuclar,
            kesinSonuclar,
            "PORT VE SERVİS · TOPLU ÖZET",
            "KEŞİF",
            goruntuYuksekligi,
        )
        tabloAltSiniri = _tabloyuCiz(
            cizim,
            318,
            (("HEDEF", 92), ("AÇIK PORT", 380), ("SERVİS", 630), ("ÜRÜN / SÜRÜM", 900)),
            sayfaSatirlari,
            yaziTipleri[0],
            yaziTipleri[1],
        )
        _topluAltBilgiyiCiz(
            cizim,
            tabloAltSiniri + 42,
            "Yalnızca açık port ve servis keşfi yapılan hedefler listelenmiştir.",
            sayfaSirasi + 1,
            sayfaSayisi,
            yaziTipleri[0],
            yaziTipleri[1],
            zaman,
        )
        sayfalar.append(goruntu)
    return tuple(sayfalar)


def _topluTlsSayfalariniCiz(
    kapsam: str,
    kontrolTanimi: CheckDefinition,
    tumSonuclar: tuple[KontrolSonucu, ...],
    kesinSonuclar: tuple[KontrolSonucu, ...],
    zaman: datetime | None,
) -> tuple[Image.Image, ...]:
    # SSLv2 ve SSLv3 sunan hedefleri ayri bolumlerde sayfalayarak gosterir.
    sslV2Hedefleri = tuple(
        sonuc.hedef for sonuc in kesinSonuclar if _tlsSunuluyorMu(sonuc, "SSLv2")
    )
    sslV3Hedefleri = tuple(
        sonuc.hedef for sonuc in kesinSonuclar if _tlsSunuluyorMu(sonuc, "SSLv3")
    )
    sayfaSayisi = max(
        1,
        math.ceil(len(sslV2Hedefleri) / LISTE_SAYFA_HEDEFI),
        math.ceil(len(sslV3Hedefleri) / LISTE_SAYFA_HEDEFI),
    )
    sayfalar: list[Image.Image] = []
    for sayfaSirasi in range(sayfaSayisi):
        sslV2Sayfasi = _listeSayfasiniAl(sslV2Hedefleri, sayfaSirasi)
        sslV3Sayfasi = _listeSayfasiniAl(sslV3Hedefleri, sayfaSirasi)
        ilkKartYuksekligi = _hedefKartYuksekliginiHesapla(sslV2Sayfasi)
        ikinciKartYuksekligi = _hedefKartYuksekliginiHesapla(sslV3Sayfasi)
        goruntuYuksekligi = 520 + ilkKartYuksekligi + ikinciKartYuksekligi
        goruntu, cizim, yaziTipleri = _topluTemeliniCiz(
            kapsam,
            kontrolTanimi,
            tumSonuclar,
            kesinSonuclar,
            "TLS PROTOKOLLERİ · TOPLU ÖZET",
            "KESİN BULGU",
            goruntuYuksekligi,
        )
        yKonumu = _hedefBolumunuCiz(
            cizim,
            318,
            "SSLv2 SUNAN HEDEFLER",
            sslV2Sayfasi,
            len(sslV2Hedefleri),
            ilkKartYuksekligi,
            yaziTipleri[0],
            yaziTipleri[1],
            yaziTipleri[2],
        )
        yKonumu = _hedefBolumunuCiz(
            cizim,
            yKonumu + 28,
            "SSLv3 SUNAN HEDEFLER",
            sslV3Sayfasi,
            len(sslV3Hedefleri),
            ikinciKartYuksekligi,
            yaziTipleri[0],
            yaziTipleri[1],
            yaziTipleri[2],
        )
        _topluAltBilgiyiCiz(
            cizim,
            yKonumu + 42,
            "Yalnızca eski TLS protokol desteği kesin olarak doğrulanan hedefler listelenmiştir.",
            sayfaSirasi + 1,
            sayfaSayisi,
            yaziTipleri[0],
            yaziTipleri[1],
            zaman,
        )
        sayfalar.append(goruntu)
    return tuple(sayfalar)


def _topluSurumSayfalariniCiz(
    kapsam: str,
    kontrolTanimi: CheckDefinition,
    tumSonuclar: tuple[KontrolSonucu, ...],
    kesinSonuclar: tuple[KontrolSonucu, ...],
    zaman: datetime | None,
) -> tuple[Image.Image, ...]:
    # Urun ve surum kesiflerini hedef bazli sayfali tabloya donusturur.
    satirlar = tuple((sonuc.hedef, *_surumAlanlariniAl(sonuc)) for sonuc in kesinSonuclar)
    sayfaSayisi = max(1, math.ceil(len(satirlar) / TABLO_SAYFA_SATIRI))
    sayfalar: list[Image.Image] = []
    for sayfaSirasi in range(sayfaSayisi):
        sayfaSatirlari = satirlar[
            sayfaSirasi * TABLO_SAYFA_SATIRI : (sayfaSirasi + 1) * TABLO_SAYFA_SATIRI
        ]
        goruntuYuksekligi = 548 + len(sayfaSatirlari) * 60 + 130
        goruntu, cizim, yaziTipleri = _topluTemeliniCiz(
            kapsam,
            kontrolTanimi,
            tumSonuclar,
            kesinSonuclar,
            "SÜRÜM KEŞFİ · TOPLU ÖZET",
            "KEŞİF",
            goruntuYuksekligi,
        )
        tabloAltSiniri = _tabloyuCiz(
            cizim,
            318,
            (("HEDEF", 92), ("ÜRÜN", 400), ("SÜRÜM / FIRMWARE", 760), ("EK BİLGİ", 1080)),
            tuple(tuple(_metniKisalt(deger, 29) for deger in satir) for satir in sayfaSatirlari),
            yaziTipleri[0],
            yaziTipleri[1],
        )
        _topluAltBilgiyiCiz(
            cizim,
            tabloAltSiniri + 42,
            "Bu çıktı bir zafiyet kararı değil, doğrulanmış ürün ve sürüm keşfidir.",
            sayfaSirasi + 1,
            sayfaSayisi,
            yaziTipleri[0],
            yaziTipleri[1],
            zaman,
        )
        sayfalar.append(goruntu)
    return tuple(sayfalar)


def _topluBulguSayfalariniCiz(
    kapsam: str,
    kontrolTanimi: CheckDefinition,
    tumSonuclar: tuple[KontrolSonucu, ...],
    kesinSonuclar: tuple[KontrolSonucu, ...],
    zaman: datetime | None,
) -> tuple[Image.Image, ...]:
    # Tek tip bulgu kontrollerinin kesin hedeflerini IP listesi olarak sayfalar.
    hedefler = tuple(sonuc.hedef for sonuc in kesinSonuclar)
    sayfaSayisi = max(1, math.ceil(len(hedefler) / LISTE_SAYFA_HEDEFI))
    sayfalar: list[Image.Image] = []
    for sayfaSirasi in range(sayfaSayisi):
        sayfaHedefleri = _listeSayfasiniAl(hedefler, sayfaSirasi)
        kartYuksekligi = _hedefKartYuksekliginiHesapla(sayfaHedefleri)
        goruntuYuksekligi = 470 + kartYuksekligi
        goruntu, cizim, yaziTipleri = _topluTemeliniCiz(
            kapsam,
            kontrolTanimi,
            tumSonuclar,
            kesinSonuclar,
            "DOĞRULAMA · TOPLU ÖZET",
            "KESİN BULGU",
            goruntuYuksekligi,
        )
        yKonumu = _hedefBolumunuCiz(
            cizim,
            318,
            _topluBolumBasliginiAl(kontrolTanimi.kontrolKimligi),
            sayfaHedefleri,
            len(hedefler),
            kartYuksekligi,
            yaziTipleri[0],
            yaziTipleri[1],
            yaziTipleri[2],
        )
        _topluAltBilgiyiCiz(
            cizim,
            yKonumu + 42,
            "Yalnızca kontrol sonucu kesin olarak doğrulanan hedefler listelenmiştir.",
            sayfaSirasi + 1,
            sayfaSayisi,
            yaziTipleri[0],
            yaziTipleri[1],
            zaman,
        )
        sayfalar.append(goruntu)
    return tuple(sayfalar)


def _topluTemeliniCiz(
    kapsam: str,
    kontrolTanimi: CheckDefinition,
    tumSonuclar: tuple[KontrolSonucu, ...],
    kesinSonuclar: tuple[KontrolSonucu, ...],
    sagBaslik: str,
    sonucEtiketi: str,
    goruntuYuksekligi: int,
) -> tuple[
    Image.Image,
    ImageDraw.ImageDraw,
    tuple[ImageFont.FreeTypeFont | ImageFont.ImageFont, ...],
]:
    # Toplu sablonlarin ortak marka, kapsam ve sayac alanlarini cizer.
    normalYazi = _yaziTipiniYukle(22)
    kucukYazi = _yaziTipiniYukle(18, kalin=True)
    bolumYazisi = _yaziTipiniYukle(22, kalin=True)
    baslikYazisi = _yaziTipiniYukle(38, kalin=True)
    altBaslikYazisi = _yaziTipiniYukle(28, kalin=True)
    goruntu = Image.new("RGB", (GORUNTU_GENISLIGI, goruntuYuksekligi), ARKA_PLAN_RENGI)
    cizim = ImageDraw.Draw(goruntu)
    _basligiCiz(cizim, sagBaslik, kontrolTanimi.baslik, baslikYazisi, kucukYazi, altBaslikYazisi)
    for etiket, deger, xKonumu in (
        ("KAPSAM", hassasMetniMaskele(kapsam), YATAY_BOSLUK),
        ("TARANAN HEDEF", str(len(tumSonuclar)), 470),
        (sonucEtiketi, str(len(kesinSonuclar)), 930),
    ):
        cizim.text((xKonumu, 212), etiket, font=kucukYazi, fill=IKINCIL_METIN_RENGI)
        cizim.text((xKonumu, 248), _metniKisalt(deger, 36), font=normalYazi, fill=METIN_RENGI)
    return goruntu, cizim, (normalYazi, kucukYazi, bolumYazisi)


def _basligiCiz(
    cizim: ImageDraw.ImageDraw,
    sagBaslik: str,
    kontrolBasligi: str,
    baslikYazisi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    altBaslikYazisi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> None:
    # Ortak marka ve kontrol basligini cizer.
    cizim.text((YATAY_BOSLUK, 52), "VulnVerifier", font=baslikYazisi, fill=METIN_RENGI)
    cizim.text(
        (GORUNTU_GENISLIGI - YATAY_BOSLUK, 66),
        sagBaslik,
        font=kucukYazi,
        fill=METIN_RENGI,
        anchor="ra",
    )
    _vurguSeridiniCiz(cizim, 124)
    cizim.text(
        (YATAY_BOSLUK, 162),
        hassasMetniMaskele(kontrolBasligi),
        font=altBaslikYazisi,
        fill=METIN_RENGI,
    )


def _tabloyuCiz(
    cizim: ImageDraw.ImageDraw,
    yKonumu: int,
    basliklar: tuple[tuple[str, int], ...],
    satirlar: tuple[tuple[str, ...], ...],
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> int:
    # Sutun basliklari ve zebra satirlari olan teknik tabloyu cizer.
    tabloAltSiniri = yKonumu + 62 + len(satirlar) * 60
    cizim.rounded_rectangle(
        (YATAY_BOSLUK, yKonumu, GORUNTU_GENISLIGI - YATAY_BOSLUK, tabloAltSiniri),
        radius=14,
        outline=KENAR_RENGI,
        width=2,
    )
    for baslik, xKonumu in basliklar:
        cizim.text((xKonumu, yKonumu + 20), baslik, font=kucukYazi, fill=IKINCIL_METIN_RENGI)
    satirYKonumu = yKonumu + 62
    for sira, satir in enumerate(satirlar):
        if sira % 2 == 0:
            cizim.rectangle(
                (
                    YATAY_BOSLUK + 1,
                    satirYKonumu,
                    GORUNTU_GENISLIGI - YATAY_BOSLUK - 1,
                    satirYKonumu + 60,
                ),
                fill=SATIR_RENGI,
            )
        for deger, (_, xKonumu) in zip(satir, basliklar, strict=True):
            cizim.text(
                (xKonumu, satirYKonumu + 18),
                _metniKisalt(hassasMetniMaskele(deger), 38),
                font=normalYazi,
                fill=METIN_RENGI,
            )
        satirYKonumu += 60
    return tabloAltSiniri


def _hedefBolumunuCiz(
    cizim: ImageDraw.ImageDraw,
    yKonumu: int,
    baslik: str,
    hedefler: tuple[str, ...],
    toplamHedefSayisi: int,
    kartYuksekligi: int,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    bolumYazisi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> int:
    # Bir bulgu turundeki hedefleri rozetler halinde cizer.
    kartAltSiniri = yKonumu + kartYuksekligi
    cizim.rounded_rectangle(
        (YATAY_BOSLUK, yKonumu, GORUNTU_GENISLIGI - YATAY_BOSLUK, kartAltSiniri),
        radius=14,
        outline=KENAR_RENGI,
        width=2,
    )
    cizim.text((92, yKonumu + 26), baslik, font=bolumYazisi, fill=METIN_RENGI)
    cizim.rounded_rectangle(
        (GORUNTU_GENISLIGI - 174, yKonumu + 20, GORUNTU_GENISLIGI - 92, yKonumu + 58),
        radius=19,
        fill=ACIK_VURGU_RENGI,
    )
    cizim.text(
        (GORUNTU_GENISLIGI - 133, yKonumu + 39),
        str(toplamHedefSayisi),
        font=kucukYazi,
        fill=VURGU_RENGI,
        anchor="mm",
    )
    if not hedefler:
        cizim.text((92, yKonumu + 92), "Bulunmadı", font=normalYazi, fill=IKINCIL_METIN_RENGI)
        return kartAltSiniri
    for sira, hedef in enumerate(hedefler):
        satir = sira // LISTE_SATIR_HEDEFI
        sutun = sira % LISTE_SATIR_HEDEFI
        xKonumu = 92 + sutun * 250
        hedefYKonumu = yKonumu + 82 + satir * 62
        cizim.rounded_rectangle(
            (xKonumu, hedefYKonumu, xKonumu + 222, hedefYKonumu + 46),
            radius=8,
            fill=ACIK_VURGU_RENGI,
        )
        cizim.text(
            (xKonumu + 16, hedefYKonumu + 23),
            _metniKisalt(hassasMetniMaskele(hedef), 24),
            font=normalYazi,
            fill=METIN_RENGI,
            anchor="lm",
        )
    return kartAltSiniri


def _altBilgiyiCiz(
    cizim: ImageDraw.ImageDraw,
    yKonumu: int,
    aciklama: str,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    zaman: datetime | None = None,
) -> None:
    # Aciklama ve Turkiye saatini gorselin altinda gosterir.
    aciklamaSatirlari = tuple(textwrap.wrap(aciklama, width=105)) or ("-",)
    for sira, satir in enumerate(aciklamaSatirlari):
        cizim.text(
            (YATAY_BOSLUK, yKonumu + sira * 30),
            satir,
            font=normalYazi,
            fill=IKINCIL_METIN_RENGI,
        )
    turkiyeZamani = (zaman or datetime.now(TURKIYE_SAAT_DILIMI)).astimezone(TURKIYE_SAAT_DILIMI)
    cizim.text(
        (YATAY_BOSLUK, yKonumu + len(aciklamaSatirlari) * 30 + 34),
        f"Oluşturma zamanı: {turkiyeZamani:%d.%m.%Y %H:%M:%S} (TR)",
        font=kucukYazi,
        fill=IKINCIL_METIN_RENGI,
    )


def _topluAltBilgiyiCiz(
    cizim: ImageDraw.ImageDraw,
    yKonumu: int,
    aciklama: str,
    sayfaNumarasi: int,
    sayfaSayisi: int,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    zaman: datetime | None,
) -> None:
    # Cok sayfali toplu goruntulere sayfa bilgisini ekler.
    if sayfaSayisi > 1:
        aciklama = f"{aciklama}  Sayfa {sayfaNumarasi}/{sayfaSayisi}."
    _altBilgiyiCiz(cizim, yKonumu, aciklama, normalYazi, kucukYazi, zaman)


def _portSatirlariniOlustur(sonuc: KontrolSonucu) -> tuple[tuple[str, str, str], ...]:
    # Port kanitlarini port, servis ve urun metnine donusturur.
    satirlar: list[tuple[str, str, str]] = []
    for deger in _kanitDegerleriniAl(sonuc, "tcpPort"):
        parcalar = deger.split("|")
        if len(parcalar) < 2 or parcalar[1].lower() != "open":
            continue
        servis = parcalar[2] if len(parcalar) > 2 and parcalar[2] else "-"
        urunParcalari = tuple(parca for parca in parcalar[3:5] if parca)
        satirlar.append((f"{parcalar[0]}/TCP", servis, " ".join(urunParcalari) or "-"))
    if satirlar:
        return tuple(satirlar)
    portDurumu = (_ilkKanitDegeriniAl(sonuc, "portDurumu") or "").lower()
    if portDurumu != "open":
        return ()
    port = _ilkKanitDegeriniAl(sonuc, "port") or "-"
    servis = _ilkKanitDegeriniAl(sonuc, "servis") or "-"
    urun = (
        " ".join(
            deger
            for deger in (
                _ilkKanitDegeriniAl(sonuc, "urun"),
                _ilkKanitDegeriniAl(sonuc, "surum"),
            )
            if deger
        )
        or "-"
    )
    return ((f"{port}/TCP", servis, urun),)


def _istenenPortSayisiniAl(
    sonuc: KontrolSonucu,
    portSatirlari: tuple[tuple[str, str, str], ...],
) -> int:
    # Kullanici port listesini veya eldeki satir sayisini taranan port sayisi olarak dondurur.
    istenenPortlar = _ilkKanitDegeriniAl(sonuc, "istenenPortlar")
    if istenenPortlar:
        return len(tuple(port for port in istenenPortlar.split(",") if port.strip()))
    return max(1, len(portSatirlari))


def _tlsProtokolSatirlariniOlustur(sonuc: KontrolSonucu) -> tuple[tuple[str, str, str], ...]:
    # Tekrarli testssl protokol kanitlarini protokol bazinda tekillestirir.
    satirlar: list[tuple[str, str, str]] = []
    gorulenler: set[tuple[str, str]] = set()
    for deger in _kanitDegerleriniAl(sonuc, "protokol"):
        parcalar = deger.split("|")
        if len(parcalar) < 3:
            continue
        protokol = parcalar[-3]
        hamDurum = parcalar[-2]
        sunuluyorMu = hamDurum == "offered"
        anahtar = (protokol, hamDurum)
        if anahtar in gorulenler:
            continue
        gorulenler.add(anahtar)
        if protokol in {"SSLv2", "SSLv3"} and sunuluyorMu:
            sonucMetni = "BULGU"
        else:
            sonucMetni = "AKTİF" if sunuluyorMu else "TEMİZ"
        satirlar.append((protokol, "Sunuluyor" if sunuluyorMu else "Sunulmuyor", sonucMetni))
    return tuple(satirlar)


def _tlsSunuluyorMu(sonuc: KontrolSonucu, arananProtokol: str) -> bool:
    # Belirtilen eski protokolun en az bir tarama noktasinda sunuldugunu denetler.
    return any(
        len(parcalar := deger.split("|")) >= 3
        and parcalar[-3] == arananProtokol
        and parcalar[-2] == "offered"
        for deger in _kanitDegerleriniAl(sonuc, "protokol")
    )


def _surumAlanlariniAl(sonuc: KontrolSonucu) -> tuple[str, str, str]:
    # HPE iLO veya VMware kanitlarini ortak urun, surum ve ek bilgi alanlarina cevirir.
    if sonuc.kontrolKimligi == "hpe-ilo-version-detection":
        return (
            _ilkKanitDegeriniAl(sonuc, "iloTuru") or "HPE iLO",
            _ilkKanitDegeriniAl(sonuc, "firmwareSurumu") or "-",
            _ilkKanitDegeriniAl(sonuc, "sunucuTuru")
            or _ilkKanitDegeriniAl(sonuc, "urunKimligi")
            or "-",
        )
    surum = _ilkKanitDegeriniAl(sonuc, "surum") or "-"
    build = _ilkKanitDegeriniAl(sonuc, "build")
    return (
        _ilkKanitDegeriniAl(sonuc, "urun") or "VMware ESXi",
        f"{surum}{f' build {build}' if build else ''}",
        _ilkKanitDegeriniAl(sonuc, "isletimSistemiTuru")
        or _ilkKanitDegeriniAl(sonuc, "urunHattiKimligi")
        or "-",
    )


def _topluBolumBasliginiAl(kontrolKimligi: str) -> str:
    # Kontrol kimligini raporda kullanilacak kesin hedef listesi basligina cevirir.
    return {
        "anonymous-cipher-support": "ANONYMOUS TLS CIPHER SUNAN HEDEFLER",
        "ms12-020-metasploit": "MS12-020 DOĞRULANAN HEDEFLER",
        "snmp-public-community": "PUBLIC COMMUNITY KABUL EDEN HEDEFLER",
        "ms17-010-metasploit": "MS17-010 DOĞRULANAN HEDEFLER",
        "dns-cache-snooping": "DNS CACHE SNOOPING DOĞRULANAN HEDEFLER",
        "ms17-010-nmap": "MS17-010 DOĞRULANAN HEDEFLER",
        "ms12-020-nmap": "MS12-020 DOĞRULANAN HEDEFLER",
        "ipmi-v2-hash-disclosure": "IPMI HASH DISCLOSURE DOĞRULANAN HEDEFLER",
        "freak-export-rsa": "FREAK ZAFİYETİ DOĞRULANAN HEDEFLER",
        "openssl-ccs-injection": "CCS INJECTION DOĞRULANAN HEDEFLER",
        "ntp-mode-6": "MODE 6 READVAR CEVABI VEREN HEDEFLER",
    }.get(kontrolKimligi, "KESİN SONUÇ ALINAN HEDEFLER")


def _durumEtiketiniAl(durum: ResultStatus) -> str:
    # Teknik durum kodunu raporda okunabilir kisa etikete cevirir.
    return {
        ResultStatus.VULNERABLE: "DOĞRULANDI",
        ResultStatus.NOT_VULNERABLE: "TEMİZ",
        ResultStatus.DISCOVERED: "KEŞFEDİLDİ",
        ResultStatus.NOT_FOUND: "BULUNAMADI",
        ResultStatus.POTENTIALLY_VULNERABLE: "İNCELEME GEREKLİ",
        ResultStatus.INCONCLUSIVE: "BELİRSİZ",
        ResultStatus.SKIPPED: "ATLANDI",
        ResultStatus.ERROR: "HATA",
    }[durum]


def _portMetniniOlustur(sonuc: KontrolSonucu) -> str:
    # Port ve protokol kanitlarini ust bilgi icin birlestirir.
    port = _ilkKanitDegeriniAl(sonuc, "port") or "-"
    protokol = (_ilkKanitDegeriniAl(sonuc, "protokol") or "tcp").upper()
    return f"{port}/{protokol}"


def _kanitDegerleriniAl(sonuc: KontrolSonucu, anahtar: str) -> tuple[str, ...]:
    # Ayni anahtara sahip tum evidence degerlerini sirayla dondurur.
    return tuple(kanit.deger for kanit in sonuc.kanitlar if kanit.anahtar == anahtar)


def _ilkKanitDegeriniAl(sonuc: KontrolSonucu, anahtar: str) -> str | None:
    # Istenen anahtarin ilk evidence degerini veya None dondurur.
    return next((kanit.deger for kanit in sonuc.kanitlar if kanit.anahtar == anahtar), None)


def _hedefKartYuksekliginiHesapla(hedefler: tuple[str, ...]) -> int:
    # Hedef rozetlerinin satir sayisina gore kart yuksekligini hesaplar.
    satirSayisi = max(1, math.ceil(len(hedefler) / LISTE_SATIR_HEDEFI))
    return 112 + satirSayisi * 62


def _listeSayfasiniAl(hedefler: tuple[str, ...], sayfaSirasi: int) -> tuple[str, ...]:
    # Hedef listesinden sabit boyutlu sayfa parcasini alir.
    baslangic = sayfaSirasi * LISTE_SAYFA_HEDEFI
    return hedefler[baslangic : baslangic + LISTE_SAYFA_HEDEFI]


def _metniKisalt(metin: str, azamiUzunluk: int) -> str:
    # Uzun tablo degerlerini hucre disina tasmadan kisaltir.
    return metin if len(metin) <= azamiUzunluk else f"{metin[: azamiUzunluk - 3]}..."


def _topluDosyaAdiniOlustur(
    kapsam: str,
    kontrolKimligi: str,
    sayfaNumarasi: int,
    sayfaSayisi: int,
    zaman: datetime | None,
) -> str:
    # Kapsam, kontrol, ozet ve Turkiye zamanini toplu PNG dosya adinda birlestirir.
    turkiyeZamani = (zaman or datetime.now(TURKIYE_SAAT_DILIMI)).astimezone(TURKIYE_SAAT_DILIMI)
    temelAd = (
        f"{dosyaAdiParcasiniGuvenliYap(kapsam, 80)}-"
        f"{dosyaAdiParcasiniGuvenliYap(kontrolKimligi, 60)}-"
        f"SUMMARY-{turkiyeZamani:%Y%m%d-%H%M}"
    )
    if sayfaSayisi > 1:
        temelAd += f"-sayfa-{sayfaNumarasi}"
    return f"{temelAd}.png"
