# Coklu SMB sonuclarini bulgu turune gore gruplanmis PNG ozetlerine donusturur.

import math
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
from vulnverifier.models import KontrolSonucu
from vulnverifier.screenshot_renderer import (
    ARKA_PLAN_RENGI,
    GORUNTU_GENISLIGI,
    IKINCIL_METIN_RENGI,
    KENAR_RENGI,
    METIN_RENGI,
    YATAY_BOSLUK,
    EkranGoruntusuHatasi,
    _pngDosyasiniAtomikOlustur,
    _vurguSeridiniCiz,
    _yaziTipiniYukle,
)

SAYFA_BASINA_BOLUM_HEDEF_SAYISI = 25
SATIR_BASINA_HEDEF_SAYISI = 5
HEDEF_KUTUSU_YUKSEKLIGI = 46
HEDEF_SATIR_BOSLUGU = 12
KART_IC_BOSLUGU = 28
ACIK_VURGU_RENGI = "#fff4e6"
VURGU_RENGI = "#f05a28"


@dataclass(frozen=True, slots=True)
class SmbTopluEkranGoruntusuSonucu:
    # Uretilen toplu SMB sayfalarinin evidence ozetlerini tasir.

    dosyaOzetleri: tuple[KanitDosyasiOzeti, ...]
    smbV1HedefSayisi: int
    imzalamaZorunluOlmayanHedefSayisi: int


def smbTopluEkranGoruntuleriOlustur(
    kanitKlasoru: str | Path,
    kapsam: str,
    kontrolSonuclari: tuple[KontrolSonucu, ...],
    zaman: datetime | None = None,
) -> SmbTopluEkranGoruntusuSonucu:
    # Bir kapsamdaki kesin SMB bulgularini bir veya daha cok ozet PNG sayfasina donusturur.
    klasorYolu = Path(kanitKlasoru)
    if klasorYolu.is_symlink() or not klasorYolu.is_dir():
        raise EkranGoruntusuHatasi(
            "Toplu SMB ekran görüntüsü için gerçek bir evidence klasörü gerekir."
        )
    if not kapsam.strip():
        raise EkranGoruntusuHatasi("Toplu SMB ekran görüntüsü kapsamı boş olamaz.")
    if not kontrolSonuclari:
        raise EkranGoruntusuHatasi("Toplu SMB ekran görüntüsü için en az bir sonuç gerekir.")
    if any(sonuc.kontrolKimligi != "smb-security-discovery" for sonuc in kontrolSonuclari):
        raise EkranGoruntusuHatasi("Toplu SMB ekran görüntüsü yalnızca SMB sonuçlarını kabul eder.")

    smbV1Hedefleri = _kanitDegerineGoreHedefleriAl(kontrolSonuclari, "smbV1", "true")
    imzalamaHedefleri = _kanitDegerineGoreHedefleriAl(
        kontrolSonuclari,
        "imzalamaZorunlu",
        "false",
    )
    sayfaSayisi = max(
        1,
        math.ceil(len(smbV1Hedefleri) / SAYFA_BASINA_BOLUM_HEDEF_SAYISI),
        math.ceil(len(imzalamaHedefleri) / SAYFA_BASINA_BOLUM_HEDEF_SAYISI),
    )
    dosyaOzetleri: list[KanitDosyasiOzeti] = []
    for sayfaSirasi in range(sayfaSayisi):
        smbV1Sayfasi = _sayfaParcasiniAl(smbV1Hedefleri, sayfaSirasi)
        imzalamaSayfasi = _sayfaParcasiniAl(imzalamaHedefleri, sayfaSirasi)
        goruntu = _smbTopluSayfasiniCiz(
            kapsam,
            kontrolSonuclari,
            smbV1Sayfasi,
            imzalamaSayfasi,
            len(smbV1Hedefleri),
            len(imzalamaHedefleri),
            sayfaSirasi + 1,
            sayfaSayisi,
            zaman,
        )
        dosyaYolu = klasorYolu / _smbTopluDosyaAdiniOlustur(
            kapsam,
            sayfaSirasi + 1,
            sayfaSayisi,
            zaman,
        )
        _pngDosyasiniAtomikOlustur(goruntu, dosyaYolu)
        dosyaOzetleri.append(kanitDosyasiOzetiniHesapla(dosyaYolu))

    return SmbTopluEkranGoruntusuSonucu(
        tuple(dosyaOzetleri),
        len(smbV1Hedefleri),
        len(imzalamaHedefleri),
    )


def _smbTopluSayfasiniCiz(
    kapsam: str,
    kontrolSonuclari: tuple[KontrolSonucu, ...],
    smbV1Hedefleri: tuple[str, ...],
    imzalamaHedefleri: tuple[str, ...],
    toplamSmbV1Sayisi: int,
    toplamImzalamaSayisi: int,
    sayfaNumarasi: int,
    sayfaSayisi: int,
    zaman: datetime | None,
) -> Image.Image:
    # Tek toplu SMB ozet sayfasinin baslik, kapsam ve bulgu kartlarini cizer.
    normalYazi = _yaziTipiniYukle(22)
    kucukYazi = _yaziTipiniYukle(18, kalin=True)
    baslikYazisi = _yaziTipiniYukle(38, kalin=True)
    altBaslikYazisi = _yaziTipiniYukle(28, kalin=True)
    bolumYazisi = _yaziTipiniYukle(22, kalin=True)
    smbV1KartYuksekligi = _hedefKartYuksekliginiHesapla(smbV1Hedefleri)
    imzalamaKartYuksekligi = _hedefKartYuksekliginiHesapla(imzalamaHedefleri)
    goruntuYuksekligi = 520 + smbV1KartYuksekligi + imzalamaKartYuksekligi

    goruntu = Image.new("RGB", (GORUNTU_GENISLIGI, goruntuYuksekligi), ARKA_PLAN_RENGI)
    cizim = ImageDraw.Draw(goruntu)
    cizim.text((YATAY_BOSLUK, 52), "VulnVerifier", font=baslikYazisi, fill=METIN_RENGI)
    cizim.text(
        (GORUNTU_GENISLIGI - YATAY_BOSLUK, 66),
        "SMB GÜVENLİK ÖZETİ",
        font=kucukYazi,
        fill=METIN_RENGI,
        anchor="ra",
    )
    _vurguSeridiniCiz(cizim, 124)
    cizim.text(
        (YATAY_BOSLUK, 162),
        "SMB Güvenlik Keşfi",
        font=altBaslikYazisi,
        fill=METIN_RENGI,
    )
    _ustBilgiyiCiz(
        cizim,
        kapsam,
        kontrolSonuclari,
        kucukYazi,
        normalYazi,
    )

    yKonumu = _hedefBolumunuCiz(
        cizim,
        318,
        "SMBv1 AÇIK OLAN HEDEFLER",
        smbV1Hedefleri,
        toplamSmbV1Sayisi,
        smbV1KartYuksekligi,
        normalYazi,
        bolumYazisi,
        kucukYazi,
    )
    yKonumu = _hedefBolumunuCiz(
        cizim,
        yKonumu + 28,
        "SMB İMZALAMASI ZORUNLU OLMAYAN HEDEFLER",
        imzalamaHedefleri,
        toplamImzalamaSayisi,
        imzalamaKartYuksekligi,
        normalYazi,
        bolumYazisi,
        kucukYazi,
    )
    altBilgi = "Yalnızca kesin doğrulanan SMB güvenlik bulguları listelenmiştir."
    if sayfaSayisi > 1:
        altBilgi += f"  Sayfa {sayfaNumarasi}/{sayfaSayisi}."
    cizim.text(
        (YATAY_BOSLUK, yKonumu + 42),
        altBilgi,
        font=normalYazi,
        fill=IKINCIL_METIN_RENGI,
    )
    olusturmaZamani = (zaman or datetime.now(TURKIYE_SAAT_DILIMI)).astimezone(TURKIYE_SAAT_DILIMI)
    cizim.text(
        (YATAY_BOSLUK, yKonumu + 96),
        f"Oluşturma zamanı: {olusturmaZamani:%d.%m.%Y %H:%M:%S} (TR)",
        font=kucukYazi,
        fill=IKINCIL_METIN_RENGI,
    )
    return goruntu


def _ustBilgiyiCiz(
    cizim: ImageDraw.ImageDraw,
    kapsam: str,
    kontrolSonuclari: tuple[KontrolSonucu, ...],
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> None:
    # Kapsam, taranan hedef ve benzersiz kesin bulgu sayisini baslik altinda gosterir.
    kesinHedefler = {
        sonuc.hedef
        for sonuc in kontrolSonuclari
        if _kanitDegeriniAl(sonuc, "smbV1") == "true"
        or _kanitDegeriniAl(sonuc, "imzalamaZorunlu") == "false"
    }
    alanlar = (
        ("KAPSAM", hassasMetniMaskele(kapsam), YATAY_BOSLUK),
        ("TARANAN HEDEF", str(len(kontrolSonuclari)), 470),
        ("KESİN BULGU", str(len(kesinHedefler)), 930),
    )
    for etiket, deger, xKonumu in alanlar:
        cizim.text((xKonumu, 212), etiket, font=kucukYazi, fill=IKINCIL_METIN_RENGI)
        cizim.text((xKonumu, 244), deger, font=normalYazi, fill=METIN_RENGI)


def _hedefBolumunuCiz(
    cizim: ImageDraw.ImageDraw,
    yKonumu: int,
    baslik: str,
    hedefler: tuple[str, ...],
    toplamHedefSayisi: int,
    kartYuksekligi: int,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kalinYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> int:
    # Bir SMB bulgu turundeki hedefleri satir ve sutunlara bolerek kartta gosterir.
    kartAltSiniri = yKonumu + kartYuksekligi
    cizim.rounded_rectangle(
        (YATAY_BOSLUK, yKonumu, GORUNTU_GENISLIGI - YATAY_BOSLUK, kartAltSiniri),
        radius=14,
        fill=ARKA_PLAN_RENGI,
        outline=KENAR_RENGI,
        width=2,
    )
    cizim.text(
        (YATAY_BOSLUK + KART_IC_BOSLUGU, yKonumu + 24),
        baslik,
        font=kalinYazi,
        fill=METIN_RENGI,
    )
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
        cizim.text(
            (YATAY_BOSLUK + KART_IC_BOSLUGU, yKonumu + 88),
            "Bulunmadı",
            font=normalYazi,
            fill=IKINCIL_METIN_RENGI,
        )
        return kartAltSiniri

    kutuGenisligi = 218
    for hedefSirasi, hedef in enumerate(hedefler):
        satir = hedefSirasi // SATIR_BASINA_HEDEF_SAYISI
        sutun = hedefSirasi % SATIR_BASINA_HEDEF_SAYISI
        xKonumu = YATAY_BOSLUK + KART_IC_BOSLUGU + sutun * 238
        hedefYKonumu = yKonumu + 86 + satir * (HEDEF_KUTUSU_YUKSEKLIGI + HEDEF_SATIR_BOSLUGU)
        cizim.rounded_rectangle(
            (
                xKonumu,
                hedefYKonumu,
                xKonumu + kutuGenisligi,
                hedefYKonumu + HEDEF_KUTUSU_YUKSEKLIGI,
            ),
            radius=8,
            fill=ACIK_VURGU_RENGI,
        )
        cizim.text(
            (xKonumu + 18, hedefYKonumu + HEDEF_KUTUSU_YUKSEKLIGI / 2),
            hassasMetniMaskele(hedef),
            font=normalYazi,
            fill=METIN_RENGI,
            anchor="lm",
        )
    return kartAltSiniri


def _hedefKartYuksekliginiHesapla(hedefler: tuple[str, ...]) -> int:
    # Bos ve dolu hedef listeleri icin gerekli kart yuksekligini hesaplar.
    if not hedefler:
        return 146
    satirSayisi = math.ceil(len(hedefler) / SATIR_BASINA_HEDEF_SAYISI)
    return 106 + satirSayisi * (HEDEF_KUTUSU_YUKSEKLIGI + HEDEF_SATIR_BOSLUGU)


def _kanitDegerineGoreHedefleriAl(
    kontrolSonuclari: tuple[KontrolSonucu, ...],
    anahtar: str,
    beklenenDeger: str,
) -> tuple[str, ...]:
    # Kesin kanit degeri eslesen hedefleri tarama sirasini koruyarak listeler.
    return tuple(
        sonuc.hedef
        for sonuc in kontrolSonuclari
        if _kanitDegeriniAl(sonuc, anahtar) == beklenenDeger
    )


def _kanitDegeriniAl(kontrolSonucu: KontrolSonucu, anahtar: str) -> str | None:
    # Tekrarsiz SMB boolean kanitinin degerini sonuc nesnesinden alir.
    return next(
        (kanit.deger for kanit in kontrolSonucu.kanitlar if kanit.anahtar == anahtar),
        None,
    )


def _sayfaParcasiniAl(hedefler: tuple[str, ...], sayfaSirasi: int) -> tuple[str, ...]:
    # Hedef listesinden istenen sayfanin sabit boyutlu parcasini alir.
    baslangic = sayfaSirasi * SAYFA_BASINA_BOLUM_HEDEF_SAYISI
    bitis = baslangic + SAYFA_BASINA_BOLUM_HEDEF_SAYISI
    return hedefler[baslangic:bitis]


def _smbTopluDosyaAdiniOlustur(
    kapsam: str,
    sayfaNumarasi: int,
    sayfaSayisi: int,
    zaman: datetime | None,
) -> str:
    # Kapsam, kontrol, ozet durumu ve Turkiye zamanini dosya adinda birlestirir.
    turkiyeZamani = (zaman or datetime.now(TURKIYE_SAAT_DILIMI)).astimezone(TURKIYE_SAAT_DILIMI)
    guvenliKapsam = dosyaAdiParcasiniGuvenliYap(kapsam, 80)
    temelAd = f"{guvenliKapsam}-smb-security-discovery-SUMMARY-{turkiyeZamani:%Y%m%d-%H%M}"
    if sayfaSayisi > 1:
        temelAd += f"-sayfa-{sayfaNumarasi}"
    return f"{temelAd}.png"
