# Dogrulama sonuclarindan rapora uygun, standart PNG kanit goruntuleri uretir.

import os
import shutil
import textwrap
import uuid
from datetime import datetime
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from vulnverifier.artifact_naming import (
    TURKIYE_SAAT_DILIMI,
    artifactDosyaAdiTemeliniOlustur,
)
from vulnverifier.evidence_storage import (
    HAM_CIKTI_DOSYASI_IZNI,
    KanitDosyasiHatasi,
    KanitDosyasiOzeti,
    hassasMetniMaskele,
    kanitDosyasiOzetiniHesapla,
)
from vulnverifier.models import CheckDefinition, KontrolSonucu, ResultStatus

GORUNTU_GENISLIGI = 1440
YATAY_BOSLUK = 64
DIKEY_BOSLUK = 52
SATIR_BOSLUGU = 12
AZAMI_KANIT_SAYISI = 80
AZAMI_DEGER_UZUNLUGU = 600
ARKA_PLAN_RENGI = "#ffffff"
KART_RENGI = "#ffffff"
ALTERNATIF_SATIR_RENGI = "#fff4e6"
KENAR_RENGI = "#e8c598"
METIN_RENGI = "#000000"
IKINCIL_METIN_RENGI = "#000000"
DURUM_RENKLERI = {
    ResultStatus.VULNERABLE: "#f05a28",
    ResultStatus.NOT_VULNERABLE: "#2e9b62",
    ResultStatus.DISCOVERED: "#2878b5",
    ResultStatus.NOT_FOUND: "#607d8b",
    ResultStatus.POTENTIALLY_VULNERABLE: "#ff9f1c",
    ResultStatus.INCONCLUSIVE: "#d88a18",
    ResultStatus.SKIPPED: "#8c7a65",
    ResultStatus.ERROR: "#cf3f32",
}


class EkranGoruntusuHatasi(KanitDosyasiHatasi):
    # PNG olusturma veya kaydetme hatalarini evidence hatasi olarak bildirir.
    pass


def ekranGoruntusuOlustur(
    kanitKlasoru: str | Path,
    kontrolTanimi: CheckDefinition,
    kontrolSonucu: KontrolSonucu,
) -> KanitDosyasiOzeti:
    # Ortak kontrol sonucunu acik temali ve okunabilir bir PNG dosyasina donusturur.
    klasorYolu = Path(kanitKlasoru)
    if klasorYolu.is_symlink() or not klasorYolu.is_dir():
        raise EkranGoruntusuHatasi("Ekran görüntüsü için gerçek bir evidence klasörü gerekir.")
    if kontrolTanimi.kontrolKimligi != kontrolSonucu.kontrolKimligi:
        raise EkranGoruntusuHatasi("Kontrol tanımı ile ekran görüntüsü sonucu uyuşmuyor.")

    normalYazi = _yaziTipiniYukle(22)
    kucukYazi = _yaziTipiniYukle(18, kalin=True)
    baslikYazisi = _yaziTipiniYukle(38, kalin=True)
    altBaslikYazisi = _yaziTipiniYukle(26, kalin=True)
    satirlar = _goruntuSatirlariniOlustur(kontrolTanimi, kontrolSonucu)
    ozetSatirlari = _ozetSatirlariniOlustur(kontrolSonucu)
    goruntuYuksekligi = _goruntuYuksekliginiHesapla(satirlar, ozetSatirlari)

    goruntu = Image.new("RGB", (GORUNTU_GENISLIGI, goruntuYuksekligi), ARKA_PLAN_RENGI)
    cizim = ImageDraw.Draw(goruntu)
    yKonumu = DIKEY_BOSLUK
    cizim.text((YATAY_BOSLUK, yKonumu), "Vuln", font=baslikYazisi, fill=METIN_RENGI)
    vulnGenisligi = cizim.textlength("Vuln", font=baslikYazisi)
    cizim.text(
        (YATAY_BOSLUK + vulnGenisligi, yKonumu),
        "Verifier",
        font=baslikYazisi,
        fill=METIN_RENGI,
    )
    cizim.text(
        (GORUNTU_GENISLIGI - YATAY_BOSLUK, yKonumu + 8),
        "DOĞRULAMA KANITI",
        font=kucukYazi,
        fill=IKINCIL_METIN_RENGI,
        anchor="ra",
    )
    yKonumu += 72
    _vurguSeridiniCiz(cizim, yKonumu)
    yKonumu += 34

    cizim.text(
        (YATAY_BOSLUK, yKonumu),
        hassasMetniMaskele(kontrolTanimi.baslik),
        font=altBaslikYazisi,
        fill=METIN_RENGI,
    )
    yKonumu += 50
    yKonumu = _bilgiKartiniCiz(cizim, kontrolSonucu, yKonumu, normalYazi, kucukYazi)
    yKonumu += 30
    yKonumu = _ozetKartiniCiz(cizim, ozetSatirlari, yKonumu, normalYazi, kucukYazi)
    yKonumu += 30
    _kanitTablosunuCiz(cizim, satirlar, yKonumu, normalYazi, kucukYazi)

    dosyaYolu = klasorYolu / ekranGoruntusuDosyaAdiniOlustur(kontrolSonucu)
    _pngDosyasiniAtomikOlustur(goruntu, dosyaYolu)
    return kanitDosyasiOzetiniHesapla(dosyaYolu)


def ekranGoruntusunuDisaAktar(
    ekranGoruntusuYolu: str | Path,
    hedefDizin: str | Path,
    calismaKimligi: str,
) -> Path:
    # Manifestoya bagli PNG'yi aciklayici bir dosya adiyla kullanici dizinine kopyalar.
    kaynakYolu = Path(ekranGoruntusuYolu)
    dizinYolu = Path(hedefDizin)
    if dizinYolu.exists() and (dizinYolu.is_symlink() or not dizinYolu.is_dir()):
        raise EkranGoruntusuHatasi("Ekran görüntüsü çıktı yolu gerçek bir dizin olmalıdır.")
    try:
        dizinYolu.mkdir(parents=True, exist_ok=True, mode=0o700)
        hedefYolu = dizinYolu / kaynakYolu.name
        if hedefYolu.exists():
            guvenliCalismaKimligi = calismaKimligi[:8]
            hedefYolu = hedefYolu.with_stem(f"{hedefYolu.stem}-{guvenliCalismaKimligi}")
        with kaynakYolu.open("rb") as kaynak, hedefYolu.open("xb") as hedef:
            os.chmod(hedefYolu, HAM_CIKTI_DOSYASI_IZNI)
            shutil.copyfileobj(kaynak, hedef)
            hedef.flush()
            os.fsync(hedef.fileno())
    except (OSError, ValueError) as hata:
        raise EkranGoruntusuHatasi(
            f"Ekran görüntüsü seçilen dizine aktarılamadı: {dizinYolu}"
        ) from hata
    return hedefYolu


def ekranGoruntusuDosyaAdiniOlustur(
    kontrolSonucu: KontrolSonucu,
    zaman: datetime | None = None,
) -> str:
    # Ortak artifact temelini PNG uzantisiyla kullanir.
    return f"{artifactDosyaAdiTemeliniOlustur(kontrolSonucu, zaman)}.png"


def _goruntuSatirlariniOlustur(
    kontrolTanimi: CheckDefinition,
    kontrolSonucu: KontrolSonucu,
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    # Kanitlari sinirlayip uzun degerleri goruntu genisligine gore satirlara boler.
    satirlar: list[tuple[str, tuple[str, ...]]] = []
    for kanit in kontrolSonucu.kanitlar[:AZAMI_KANIT_SAYISI]:
        anahtar = hassasMetniMaskele(kanit.anahtar)
        deger = hassasMetniMaskele(kanit.deger)
        if len(deger) > AZAMI_DEGER_UZUNLUGU:
            deger = f"{deger[:AZAMI_DEGER_UZUNLUGU]}..."
        satirlar.append((anahtar, tuple(textwrap.wrap(deger, width=78)) or ("-",)))
    if len(kontrolSonucu.kanitlar) > AZAMI_KANIT_SAYISI:
        kalan = len(kontrolSonucu.kanitlar) - AZAMI_KANIT_SAYISI
        satirlar.append(
            ("bilgi", (f"{kalan} ek kanit normalize evidence JSON dosyasinda saklandi.",))
        )
    if not satirlar:
        satirlar.append(("bilgi", ("Yapilandirilmis kanit bulunmuyor.",)))
    return tuple(satirlar)


def _ozetSatirlariniOlustur(kontrolSonucu: KontrolSonucu) -> tuple[str, ...]:
    # Uzun ozetleri sinirlayip sabit goruntu genisligine uygun satirlara boler.
    ozet = hassasMetniMaskele(kontrolSonucu.ozet)
    if len(ozet) > AZAMI_DEGER_UZUNLUGU:
        ozet = f"{ozet[:AZAMI_DEGER_UZUNLUGU]}..."
    return tuple(textwrap.wrap(ozet, width=92)) or ("-",)


def _goruntuYuksekliginiHesapla(
    satirlar: tuple[tuple[str, tuple[str, ...]], ...],
    ozetSatirlari: tuple[str, ...],
) -> int:
    # Baslik, kartlar, kanit satirlari ve alt bilgi icin gereken tuval yuksekligini hesaplar.
    kanitYuksekligi = sum(max(54, 28 * len(degerSatirlari) + 24) for _, degerSatirlari in satirlar)
    ekOzetYuksekligi = max(0, len(ozetSatirlari) - 1) * 31
    return 520 + ekOzetYuksekligi + kanitYuksekligi + 100


def _bilgiKartiniCiz(
    cizim: ImageDraw.ImageDraw,
    sonuc: KontrolSonucu,
    yKonumu: int,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> int:
    # Hedef, kontrol kimligi, sure ve durum bilgisini ust bilgi kartinda gosterir.
    kartAltSiniri = yKonumu + 146
    cizim.rounded_rectangle(
        (YATAY_BOSLUK, yKonumu, GORUNTU_GENISLIGI - YATAY_BOSLUK, kartAltSiniri),
        radius=14,
        fill=KART_RENGI,
        outline=KENAR_RENGI,
        width=2,
    )
    alanlar = (
        ("HEDEF", hassasMetniMaskele(sonuc.hedef), YATAY_BOSLUK + 28),
        ("KONTROL", sonuc.kontrolKimligi, 470),
        ("SURE", _sureMetniniOlustur(sonuc), 930),
    )
    for etiket, deger, xKonumu in alanlar:
        cizim.text((xKonumu, yKonumu + 28), etiket, font=kucukYazi, fill=IKINCIL_METIN_RENGI)
        cizim.text((xKonumu, yKonumu + 66), deger, font=normalYazi, fill=METIN_RENGI)

    durumRengi = DURUM_RENKLERI[sonuc.durum]
    cizim.rounded_rectangle(
        (1110, yKonumu + 46, GORUNTU_GENISLIGI - YATAY_BOSLUK - 28, yKonumu + 105),
        radius=14,
        fill=durumRengi,
    )
    cizim.text(
        ((1110 + GORUNTU_GENISLIGI - YATAY_BOSLUK - 28) / 2, yKonumu + 75),
        sonuc.durum.value,
        font=kucukYazi,
        fill="#ffffff",
        anchor="mm",
    )
    return kartAltSiniri


def _ozetKartiniCiz(
    cizim: ImageDraw.ImageDraw,
    ozetSatirlari: tuple[str, ...],
    yKonumu: int,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> int:
    # Sonuc ozetini uzun metinleri katlayarak ayri bir kartta gosterir.
    kartYuksekligi = 72 + len(ozetSatirlari) * 31
    cizim.rounded_rectangle(
        (
            YATAY_BOSLUK,
            yKonumu,
            GORUNTU_GENISLIGI - YATAY_BOSLUK,
            yKonumu + kartYuksekligi,
        ),
        radius=14,
        fill=KART_RENGI,
        outline=KENAR_RENGI,
        width=2,
    )
    cizim.text((YATAY_BOSLUK + 28, yKonumu + 22), "OZET", font=kucukYazi, fill=IKINCIL_METIN_RENGI)
    for sira, satir in enumerate(ozetSatirlari):
        cizim.text(
            (YATAY_BOSLUK + 28, yKonumu + 56 + sira * 31),
            satir,
            font=normalYazi,
            fill=METIN_RENGI,
        )
    return yKonumu + kartYuksekligi


def _kanitTablosunuCiz(
    cizim: ImageDraw.ImageDraw,
    satirlar: tuple[tuple[str, tuple[str, ...]], ...],
    yKonumu: int,
    normalYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    kucukYazi: ImageFont.FreeTypeFont | ImageFont.ImageFont,
) -> None:
    # Anahtar ve deger kanitlarini tekrarli anahtarlari koruyan bir tabloda cizer.
    cizim.text(
        (YATAY_BOSLUK, yKonumu),
        "YAPILANDIRILMIS KANITLAR",
        font=kucukYazi,
        fill=IKINCIL_METIN_RENGI,
    )
    yKonumu += 42
    for sira, (anahtar, degerSatirlari) in enumerate(satirlar):
        satirYuksekligi = max(54, 28 * len(degerSatirlari) + 24)
        if sira % 2 == 0:
            cizim.rectangle(
                (
                    YATAY_BOSLUK,
                    yKonumu,
                    GORUNTU_GENISLIGI - YATAY_BOSLUK,
                    yKonumu + satirYuksekligi,
                ),
                fill=ALTERNATIF_SATIR_RENGI,
            )
        cizim.text((YATAY_BOSLUK + 22, yKonumu + 15), anahtar, font=normalYazi, fill=METIN_RENGI)
        for degerSirasi, degerSatiri in enumerate(degerSatirlari):
            cizim.text(
                (390, yKonumu + 15 + degerSirasi * 28),
                degerSatiri,
                font=normalYazi,
                fill=METIN_RENGI,
            )
        yKonumu += satirYuksekligi
    cizim.text(
        (YATAY_BOSLUK, yKonumu + 36),
        _olusturmaZamaniMetniniOlustur(),
        font=kucukYazi,
        fill=IKINCIL_METIN_RENGI,
    )


def _sureMetniniOlustur(sonuc: KontrolSonucu) -> str:
    # Eksik sure bilgisini tireyle, mevcut sureyi uc ondalik basamakla gosterir.
    if sonuc.calismaSuresiSaniye is None:
        return "-"
    return f"{sonuc.calismaSuresiSaniye:.3f} sn"


def _olusturmaZamaniMetniniOlustur(zaman: datetime | None = None) -> str:
    # Verilen zamani veya simdiki ani Turkiye saatine cevirip okunabilir bicimde gosterir.
    turkiyeZamani = (zaman or datetime.now(TURKIYE_SAAT_DILIMI)).astimezone(TURKIYE_SAAT_DILIMI)
    return f"Olusturma zamani: {turkiyeZamani:%d.%m.%Y %H:%M:%S} (TR)"


def _vurguSeridiniCiz(cizim: ImageDraw.ImageDraw, yKonumu: int) -> None:
    # Logo renklerini soldan saga yumusak gecisli ince bir seritte birlestirir.
    baslangic = (255, 122, 24)
    bitis = (255, 173, 31)
    genislik = GORUNTU_GENISLIGI - 2 * YATAY_BOSLUK
    for ofset in range(genislik):
        oran = ofset / max(1, genislik - 1)
        renk = tuple(
            round(sol + (sag - sol) * oran) for sol, sag in zip(baslangic, bitis, strict=True)
        )
        xKonumu = YATAY_BOSLUK + ofset
        cizim.line((xKonumu, yKonumu, xKonumu, yKonumu + 3), fill=renk)


def _yaziTipiniYukle(
    boyut: int,
    *,
    kalin: bool = False,
) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    # Calibri veya metrik uyumlu Carlito ailesini, basliklarda kalin kullanir.
    if kalin:
        adaylar = (
            "/Library/Fonts/Calibri Bold.ttf",
            "/System/Library/Fonts/Supplemental/Calibri Bold.ttf",
            "/Applications/LibreOffice.app/Contents/Resources/fonts/truetype/Carlito-Bold.ttf",
            "/usr/share/fonts/truetype/crosextra/Carlito-Bold.ttf",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        )
    else:
        adaylar = (
            "/Library/Fonts/Calibri.ttf",
            "/System/Library/Fonts/Supplemental/Calibri.ttf",
            "/Applications/LibreOffice.app/Contents/Resources/fonts/truetype/Carlito-Regular.ttf",
            "/usr/share/fonts/truetype/crosextra/Carlito-Regular.ttf",
            "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        )
    for aday in adaylar:
        if Path(aday).is_file():
            return ImageFont.truetype(aday, boyut)
    return ImageFont.load_default(size=boyut)


def _pngDosyasiniAtomikOlustur(goruntu: Image.Image, dosyaYolu: Path) -> None:
    # PNG verisini sinirli izinli gecici dosyaya yazip hedefi ezmeden yayinlar.
    geciciYol = dosyaYolu.with_name(f".{dosyaYolu.name}.{uuid.uuid4().hex}.tmp")
    acmaBayraklari = os.O_RDWR | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        acmaBayraklari |= os.O_NOFOLLOW
    try:
        dosyaTanimi = os.open(geciciYol, acmaBayraklari, HAM_CIKTI_DOSYASI_IZNI)
        with os.fdopen(dosyaTanimi, "w+b") as dosya:
            goruntu.save(dosya, format="PNG", optimize=True)
            dosya.flush()
            os.fsync(dosya.fileno())
        os.link(geciciYol, dosyaYolu)
    except (OSError, ValueError) as hata:
        raise EkranGoruntusuHatasi(f"Ekran görüntüsü kaydedilemedi: {dosyaYolu}") from hata
    finally:
        geciciYol.unlink(missing_ok=True)
