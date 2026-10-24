# Dogrulama calismalari icin benzersiz ve sinirli erisimli kanit klasorleri olusturur.

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vulnverifier.artifact_naming import artifactDosyaAdiTemeliniOlustur
from vulnverifier.command_runner import KomutSonucu
from vulnverifier.models import KontrolSonucu

KANIT_KLASORU_IZNI = 0o700
HAM_CIKTI_DOSYASI_IZNI = 0o600
STANDART_CIKTI_DOSYA_ADI = "stdout.txt"
STANDART_HATA_DOSYA_ADI = "stderr.txt"
NORMALIZE_KANIT_DOSYA_ADI = "evidence.json"
KANIT_MANIFESTO_DOSYA_ADI = "manifest.json"
KANIT_SEMA_SURUMU = 2
MANIFESTO_SEMA_SURUMU = 1
HASH_OKUMA_PARCA_BOYUTU = 64 * 1024
AZAMI_HAM_CIKTI_BAYT = 5 * 1024 * 1024
KISALTMA_BILDIRIMI = "\n[VulnVerifier: cikti boyut siniri nedeniyle kisaltildi]\n"
MASKELI_DEGER = "[MASKELENDI]"
HASSAS_DEGER_DESENLERI = (
    re.compile(r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret)\b(\s*[:=]\s*)([^\s,;]+)"),
    re.compile(r"(?i)\b(authorization\s*:\s*(?:basic|bearer)\s+)([^\s]+)"),
)


@dataclass(frozen=True, slots=True)
class HamCiktiDosyalari:
    # Kaydedilen standart cikti ve standart hata dosyalarinin yollarini tasir.
    standartCiktiYolu: Path
    standartHataYolu: Path
    cikisKodu: int | None = None


@dataclass(frozen=True, slots=True)
class KanitDosyasiOzeti:
    # Bir evidence dosyasinin yolunu ve SHA-256 butunluk ozetini tasir.
    dosyaYolu: Path
    sha256: str


@dataclass(frozen=True, slots=True)
class KanitManifestoMetadata:
    # Manifestoya yazilacak arac ve komut sonuc bilgilerini tasir.
    aracAdi: str
    aracSurumu: str | None
    komutCikisKodu: int | None


@dataclass(frozen=True, slots=True)
class AdlandirilmisKanitDosyalari:
    # Yeni adlara tasinan ham ve normalize evidence yollarini birlikte tasir.
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class KanitKlasoruHatasi(OSError):
    # Kanit klasoru olusturulamadiginda olusan hatadir.
    pass


class KanitDosyasiHatasi(OSError):
    # Ham arac ciktisi dosyalara kaydedilemediginde olusan hatadir.
    pass


def kanitKlasoruOlustur(anaDizin: str | Path) -> Path:
    # Ana dizin altinda rastgele kimlikli yeni bir kanit klasoru olusturur.
    dogrulanmisAnaDizin = _anaDiziniDogrula(anaDizin)
    klasorYolu = dogrulanmisAnaDizin / uuid.uuid4().hex

    try:
        dogrulanmisAnaDizin.mkdir(parents=True, exist_ok=True)
        klasorYolu.mkdir(mode=KANIT_KLASORU_IZNI, exist_ok=False)
    except OSError as hata:
        raise KanitKlasoruHatasi(
            f"Kanıt klasörü oluşturulamadı: {klasorYolu}",
        ) from hata

    return klasorYolu


def hamAracCiktisiniKaydet(
    kanitKlasoru: str | Path,
    komutSonucu: KomutSonucu,
) -> HamCiktiDosyalari:
    # Komutun stdout ve stderr metinlerini yeni, sinirli erisimli dosyalara kaydeder.
    dogrulanmisKlasor = _kanitKlasorunuDogrula(kanitKlasoru)
    if not isinstance(komutSonucu, KomutSonucu):
        raise KanitDosyasiHatasi("Ham çıktı için geçerli bir KomutSonucu gereklidir.")

    standartCiktiYolu = dogrulanmisKlasor / STANDART_CIKTI_DOSYA_ADI
    standartHataYolu = dogrulanmisKlasor / STANDART_HATA_DOSYA_ADI
    olusturulanDosyalar: list[Path] = []
    try:
        standartCikti = _hamCiktiyiGuvenliHaleGetir(komutSonucu.standartCikti)
        standartHata = _hamCiktiyiGuvenliHaleGetir(komutSonucu.standartHata)
        _metinDosyasiniAtomikOlustur(standartCiktiYolu, standartCikti)
        olusturulanDosyalar.append(standartCiktiYolu)
        _metinDosyasiniAtomikOlustur(standartHataYolu, standartHata)
        olusturulanDosyalar.append(standartHataYolu)
    except (OSError, UnicodeError) as hata:
        for dosyaYolu in olusturulanDosyalar:
            dosyaYolu.unlink(missing_ok=True)
        raise KanitDosyasiHatasi(
            f"Ham araç çıktısı kaydedilemedi: {dogrulanmisKlasor}",
        ) from hata

    return HamCiktiDosyalari(
        standartCiktiYolu=standartCiktiYolu,
        standartHataYolu=standartHataYolu,
        cikisKodu=komutSonucu.cikisKodu,
    )


def normalizeEdilmisKanitiKaydet(
    kanitKlasoru: str | Path,
    kontrolSonucu: KontrolSonucu,
) -> Path:
    # Standart kontrol sonucunu surumlu ve okunabilir bir JSON dosyasina kaydeder.
    dogrulanmisKlasor = _kanitKlasorunuDogrula(kanitKlasoru)
    if not isinstance(kontrolSonucu, KontrolSonucu):
        raise KanitDosyasiHatasi("Normalize kanıt için geçerli bir KontrolSonucu gereklidir.")

    kanitVerisi = {
        "semaSurumu": KANIT_SEMA_SURUMU,
        "calismaKimligi": dogrulanmisKlasor.name,
        "kontrolKimligi": kontrolSonucu.kontrolKimligi,
        "hedef": kontrolSonucu.hedef,
        "durum": kontrolSonucu.durum.value,
        "ozet": hassasMetniMaskele(kontrolSonucu.ozet),
        "kanitlar": [
            {"anahtar": kanit.anahtar, "deger": hassasMetniMaskele(kanit.deger)}
            for kanit in kontrolSonucu.kanitlar
        ],
    }
    jsonMetni = json.dumps(kanitVerisi, ensure_ascii=False, indent=2) + "\n"
    dosyaYolu = dogrulanmisKlasor / NORMALIZE_KANIT_DOSYA_ADI

    try:
        _metinDosyasiniAtomikOlustur(dosyaYolu, jsonMetni)
    except (OSError, UnicodeError) as hata:
        raise KanitDosyasiHatasi(
            f"Normalize kanıt kaydedilemedi: {dosyaYolu}",
        ) from hata

    return dosyaYolu


def evidenceDosyalariniAdlandir(
    kanitKlasoru: str | Path,
    kontrolSonucu: KontrolSonucu,
    hamCiktiDosyalari: HamCiktiDosyalari | None,
    normalizeKanitYolu: str | Path,
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...],
) -> AdlandirilmisKanitDosyalari:
    # Gecici evidence adlarini sonuc bilgisi iceren ortak adlara guvenle tasir.
    dogrulanmisKlasor = _kanitKlasorunuDogrula(kanitKlasoru)
    normalizeYolu = _dosyaYolunuDogrula(normalizeKanitYolu)
    dosyaAdiTemeli = artifactDosyaAdiTemeliniOlustur(kontrolSonucu)
    tasimaPlani: list[tuple[Path, Path]] = [
        (normalizeYolu, dogrulanmisKlasor / f"{dosyaAdiTemeli}-evidence.json")
    ]
    yeniHamDosyalar: HamCiktiDosyalari | None = None
    if hamCiktiDosyalari is not None:
        yeniStandartCiktiYolu = dogrulanmisKlasor / f"{dosyaAdiTemeli}-stdout.txt"
        yeniStandartHataYolu = dogrulanmisKlasor / f"{dosyaAdiTemeli}-stderr.txt"
        tasimaPlani.extend(
            (
                (hamCiktiDosyalari.standartCiktiYolu, yeniStandartCiktiYolu),
                (hamCiktiDosyalari.standartHataYolu, yeniStandartHataYolu),
            )
        )
        yeniHamDosyalar = HamCiktiDosyalari(
            standartCiktiYolu=yeniStandartCiktiYolu,
            standartHataYolu=yeniStandartHataYolu,
            cikisKodu=hamCiktiDosyalari.cikisKodu,
        )

    _evidenceDosyalariniGuvenleTasi(dogrulanmisKlasor, tuple(tasimaPlani))
    yolEslemeleri = {eskiYol: yeniYol for eskiYol, yeniYol in tasimaPlani}
    yeniOzetler = tuple(
        KanitDosyasiOzeti(
            dosyaYolu=yolEslemeleri.get(dosyaOzeti.dosyaYolu, dosyaOzeti.dosyaYolu),
            sha256=dosyaOzeti.sha256,
        )
        for dosyaOzeti in kanitDosyasiOzetleri
    )
    return AdlandirilmisKanitDosyalari(
        hamCiktiDosyalari=yeniHamDosyalar,
        normalizeKanitYolu=tasimaPlani[0][1],
        kanitDosyasiOzetleri=yeniOzetler,
    )


def kanitManifestosunuKaydet(
    kanitKlasoru: str | Path,
    kontrolSonucu: KontrolSonucu,
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...],
    metadata: KanitManifestoMetadata,
) -> KanitDosyasiOzeti:
    # Bir calismadaki dosya, arac, zaman ve butunluk bilgilerini manifestoda toplar.
    dogrulanmisKlasor = _kanitKlasorunuDogrula(kanitKlasoru)
    if not isinstance(kontrolSonucu, KontrolSonucu):
        raise KanitDosyasiHatasi("Manifesto için geçerli bir KontrolSonucu gereklidir.")
    if not isinstance(metadata, KanitManifestoMetadata):
        raise KanitDosyasiHatasi("Manifesto için geçerli metadata gereklidir.")

    dosyaKayitlari = []
    for dosyaOzeti in kanitDosyasiOzetleri:
        dosyaYolu = _dosyaYolunuDogrula(dosyaOzeti.dosyaYolu)
        if dosyaYolu.parent.resolve() != dogrulanmisKlasor.resolve():
            raise KanitDosyasiHatasi("Manifestoya yalnızca aynı çalışmanın dosyaları eklenebilir.")
        dosyaKayitlari.append(
            {
                "dosyaAdi": dosyaYolu.name,
                "boyutBayt": dosyaYolu.stat().st_size,
                "sha256": dosyaOzeti.sha256,
            }
        )

    manifestoVerisi = {
        "semaSurumu": MANIFESTO_SEMA_SURUMU,
        "calismaKimligi": dogrulanmisKlasor.name,
        "kontrolKimligi": kontrolSonucu.kontrolKimligi,
        "arac": {
            "ad": metadata.aracAdi,
            "surum": metadata.aracSurumu,
            "komutCikisKodu": metadata.komutCikisKodu,
        },
        "zaman": {
            "baslangic": _zamanDegeriniMetneDonustur(kontrolSonucu.baslangicZamani),
            "bitis": _zamanDegeriniMetneDonustur(kontrolSonucu.bitisZamani),
            "sureSaniye": kontrolSonucu.calismaSuresiSaniye,
            "manifestoOlusturma": datetime.now(UTC).isoformat(),
        },
        "dosyalar": dosyaKayitlari,
    }
    dosyaAdiTemeli = artifactDosyaAdiTemeliniOlustur(kontrolSonucu)
    manifestoYolu = dogrulanmisKlasor / f"{dosyaAdiTemeli}-{KANIT_MANIFESTO_DOSYA_ADI}"
    manifestoMetni = json.dumps(manifestoVerisi, ensure_ascii=False, indent=2) + "\n"
    try:
        _metinDosyasiniAtomikOlustur(manifestoYolu, manifestoMetni)
    except (OSError, UnicodeError) as hata:
        raise KanitDosyasiHatasi(
            f"Evidence manifestosu kaydedilemedi: {manifestoYolu}",
        ) from hata
    return kanitDosyasiOzetiniHesapla(manifestoYolu)


def kanitDosyasiOzetiniHesapla(dosyaYolu: str | Path) -> KanitDosyasiOzeti:
    # Normal bir dosyayi parcalar halinde okuyarak SHA-256 ozetini hesaplar.
    dogrulanmisDosyaYolu = _dosyaYolunuDogrula(dosyaYolu)
    acmaBayraklari = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        acmaBayraklari |= os.O_NOFOLLOW

    try:
        dosyaTanimi = os.open(dogrulanmisDosyaYolu, acmaBayraklari)
        with os.fdopen(dosyaTanimi, "rb") as dosya:
            if not stat.S_ISREG(os.fstat(dosya.fileno()).st_mode):
                raise KanitDosyasiHatasi("SHA-256 özeti yalnızca normal dosyalar için hesaplanır.")

            ozetHesaplayici = hashlib.sha256()
            while parca := dosya.read(HASH_OKUMA_PARCA_BOYUTU):
                ozetHesaplayici.update(parca)
    except KanitDosyasiHatasi:
        raise
    except OSError as hata:
        raise KanitDosyasiHatasi(
            f"Evidence dosyası SHA-256 özeti hesaplanamadı: {dogrulanmisDosyaYolu}",
        ) from hata

    return KanitDosyasiOzeti(
        dosyaYolu=dogrulanmisDosyaYolu,
        sha256=ozetHesaplayici.hexdigest(),
    )


def _anaDiziniDogrula(anaDizin: str | Path) -> Path:
    # Bos veya null karakterli ana dizin girdilerini reddeder.
    if isinstance(anaDizin, str):
        if not anaDizin or anaDizin != anaDizin.strip():
            raise KanitKlasoruHatasi("Kanıt ana dizini boş olamaz veya boşlukla çevrilemez.")
        if "\x00" in anaDizin:
            raise KanitKlasoruHatasi("Kanıt ana dizini null karakteri içeremez.")
        return Path(anaDizin)

    if isinstance(anaDizin, Path):
        return anaDizin

    raise KanitKlasoruHatasi("Kanıt ana dizini metin veya Path olmalıdır.")


def _kanitKlasorunuDogrula(kanitKlasoru: str | Path) -> Path:
    # Ham cikti icin var olan ve sembolik bag olmayan bir klasor gerektirir.
    if isinstance(kanitKlasoru, str):
        if not kanitKlasoru or kanitKlasoru != kanitKlasoru.strip():
            raise KanitDosyasiHatasi("Kanıt klasörü boş olamaz veya boşlukla çevrilemez.")
        if "\x00" in kanitKlasoru:
            raise KanitDosyasiHatasi("Kanıt klasörü null karakteri içeremez.")
        klasorYolu = Path(kanitKlasoru)
    elif isinstance(kanitKlasoru, Path):
        klasorYolu = kanitKlasoru
    else:
        raise KanitDosyasiHatasi("Kanıt klasörü metin veya Path olmalıdır.")

    if klasorYolu.is_symlink() or not klasorYolu.is_dir():
        raise KanitDosyasiHatasi("Kanıt klasörü mevcut bir gerçek dizin olmalıdır.")
    return klasorYolu


def _dosyaYolunuDogrula(dosyaYolu: str | Path) -> Path:
    # SHA-256 hesabi icin bos veya null karakterli dosya yollarini reddeder.
    if isinstance(dosyaYolu, str):
        if not dosyaYolu or dosyaYolu != dosyaYolu.strip():
            raise KanitDosyasiHatasi("Evidence dosya yolu boş olamaz veya boşlukla çevrilemez.")
        if "\x00" in dosyaYolu:
            raise KanitDosyasiHatasi("Evidence dosya yolu null karakteri içeremez.")
        return Path(dosyaYolu)

    if isinstance(dosyaYolu, Path):
        return dosyaYolu

    raise KanitDosyasiHatasi("Evidence dosya yolu metin veya Path olmalıdır.")


def _hamCiktiyiGuvenliHaleGetir(metin: str) -> str:
    # Bilinen hassas degerleri maskeler ve UTF-8 ciktisini bayt sinirinda kisaltir.
    maskeliMetin = hassasMetniMaskele(metin)
    kodlanmisMetin = maskeliMetin.encode("utf-8")
    if len(kodlanmisMetin) <= AZAMI_HAM_CIKTI_BAYT:
        return maskeliMetin
    bildirim = KISALTMA_BILDIRIMI.encode("utf-8")
    izinVerilenBoyut = AZAMI_HAM_CIKTI_BAYT - len(bildirim)
    kisaltilmisMetin = kodlanmisMetin[:izinVerilenBoyut].decode("utf-8", errors="ignore")
    return kisaltilmisMetin + KISALTMA_BILDIRIMI


def hassasMetniMaskele(metin: str) -> str:
    # Bilinen parola, token ve yetkilendirme kaliplarini guvenli degerle degistirir.
    maskeliMetin = metin
    for sira, desen in enumerate(HASSAS_DEGER_DESENLERI):
        if sira == 0:
            maskeliMetin = desen.sub(rf"\1\2{MASKELI_DEGER}", maskeliMetin)
        else:
            maskeliMetin = desen.sub(rf"\1{MASKELI_DEGER}", maskeliMetin)
    return maskeliMetin


def _zamanDegeriniMetneDonustur(zamanDegeri: datetime | None) -> str | None:
    # Zaman degerini tasinabilir ISO 8601 metnine donusturur.
    return zamanDegeri.isoformat() if zamanDegeri is not None else None


def _evidenceDosyalariniGuvenleTasi(
    kanitKlasoru: Path,
    tasimaPlani: tuple[tuple[Path, Path], ...],
) -> None:
    # Tum yeni baglantilari olusturmadan eski adlari silmeyerek kismi tasimayi engeller.
    for kaynakYolu, hedefYolu in tasimaPlani:
        dogrulanmisKaynak = _dosyaYolunuDogrula(kaynakYolu)
        if dogrulanmisKaynak.parent.resolve() != kanitKlasoru.resolve():
            raise KanitDosyasiHatasi("Yalnızca aynı çalışmanın evidence dosyaları taşınabilir.")
        if dogrulanmisKaynak.is_symlink() or not dogrulanmisKaynak.is_file():
            raise KanitDosyasiHatasi("Taşınacak evidence yolu normal bir dosya olmalıdır.")
        if hedefYolu.exists() or hedefYolu.is_symlink():
            raise KanitDosyasiHatasi(f"Evidence hedef dosyası zaten mevcut: {hedefYolu}")

    olusturulanHedefler: list[Path] = []
    try:
        for kaynakYolu, hedefYolu in tasimaPlani:
            os.link(kaynakYolu, hedefYolu, follow_symlinks=False)
            olusturulanHedefler.append(hedefYolu)
    except OSError as hata:
        for hedefYolu in olusturulanHedefler:
            hedefYolu.unlink(missing_ok=True)
        raise KanitDosyasiHatasi("Evidence dosyaları açıklayıcı adlara taşınamadı.") from hata

    for kaynakYolu, _ in tasimaPlani:
        kaynakYolu.unlink()


def _metinDosyasiniAtomikOlustur(dosyaYolu: Path, metin: str) -> None:
    # Gecici dosyayi diske yazip hedefi uzerine yazmadan atomik olarak yayinlar.
    geciciDosyaYolu = dosyaYolu.with_name(f".{dosyaYolu.name}.{uuid.uuid4().hex}.tmp")
    acmaBayraklari = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        acmaBayraklari |= os.O_NOFOLLOW

    try:
        dosyaTanimi = os.open(geciciDosyaYolu, acmaBayraklari, HAM_CIKTI_DOSYASI_IZNI)
        with os.fdopen(dosyaTanimi, "w", encoding="utf-8", newline="") as dosya:
            dosya.write(metin)
            dosya.flush()
            os.fsync(dosya.fileno())
        os.link(geciciDosyaYolu, dosyaYolu)
    finally:
        geciciDosyaYolu.unlink(missing_ok=True)
