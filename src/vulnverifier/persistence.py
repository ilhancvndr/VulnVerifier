# Dogrulama sonuclarini ve evidence baglantilarini SQLite icinde kalici olarak saklar.

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vulnverifier.database import VeritabaniHatasi, veritabaniBaglantisi
from vulnverifier.database_schema import semayiHazirla
from vulnverifier.evidence_storage import KanitDosyasiOzeti
from vulnverifier.models import CheckDefinition, KontrolSonucu, ResultStatus

VARSAYILAN_PROJE_ADI = "default"
AZAMI_PROJE_ADI_UZUNLUGU = 100
AZAMI_GECMIS_KAYDI = 500


@dataclass(frozen=True, slots=True)
class DogrulamaKayitOzeti:
    # Yeni kaydedilen tarama ve bagli satirlarin kimliklerini tasir.
    projeKimligi: int
    hedefKimligi: int
    taramaKimligi: int
    bulguKimligi: int | None
    kontrolSonucuKimligi: int


@dataclass(frozen=True, slots=True)
class TaramaGecmisiKaydi:
    # CLI gecmis listesinde gosterilecek tek bir dogrulama kaydini tasir.
    taramaKimligi: int
    projeAdi: str
    hedef: str
    kontrolKimligi: str
    durum: str
    ozet: str
    bitisZamani: str
    evidenceSayisi: int


@dataclass(frozen=True, slots=True)
class BulguKaydi:
    # Bir hedefte ayni bulgu anahtari altinda birlesen son durumu tasir.
    bulguKimligi: int
    projeAdi: str
    hedef: str
    bulguAnahtari: str
    baslik: str
    sonDurum: str
    dogrulamaSayisi: int
    sonGorulmeZamani: str


class KaliciKayitDeposu:
    # SQLite semasini ve dogrulama kayit islemlerini tek servis altinda toplar.
    def __init__(self, veritabaniYolu: str | Path) -> None:
        self._veritabaniYolu = veritabaniYolu

    def hazirla(self) -> int:
        # Veritabani semasini guncel surume getirir.
        with veritabaniBaglantisi(self._veritabaniYolu) as baglanti:
            return semayiHazirla(baglanti)

    def dogrulamaKaydet(
        self,
        projeAdi: str,
        kontrolTanimi: CheckDefinition,
        kontrolSonucu: KontrolSonucu,
        istenenPortlar: tuple[int, ...],
        evidenceDosyalari: tuple[KanitDosyasiOzeti, ...] = (),
    ) -> DogrulamaKayitOzeti:
        # Bir dogrulamayi tum bagli kayitlariyla tek transaction icinde saklar.
        standartProjeAdi = projeAdiniDogrula(projeAdi)
        _kayitGirdileriniDogrula(kontrolTanimi, kontrolSonucu, evidenceDosyalari)
        baslangicZamani, bitisZamani = _sonucZamanlariniAl(kontrolSonucu)

        try:
            with veritabaniBaglantisi(self._veritabaniYolu) as baglanti:
                semayiHazirla(baglanti)
                projeKimligi = _projeyiGetirVeyaOlustur(baglanti, standartProjeAdi)
                hedefKimligi = _hedefiGetirVeyaOlustur(
                    baglanti,
                    projeKimligi,
                    kontrolSonucu.hedef,
                )
                bulguKimligi = _bulguyuGetirVeyaGuncelle(
                    baglanti,
                    projeKimligi,
                    hedefKimligi,
                    kontrolTanimi,
                    kontrolSonucu,
                    bitisZamani,
                )
                taramaKimligi = _taramaEkle(
                    baglanti,
                    projeKimligi,
                    hedefKimligi,
                    baslangicZamani,
                    bitisZamani,
                    istenenPortlar,
                )
                kontrolSonucuKimligi = _kontrolSonucuEkle(
                    baglanti,
                    taramaKimligi,
                    bulguKimligi,
                    kontrolSonucu,
                    baslangicZamani,
                    bitisZamani,
                )
                _yapilandirilmisKanitlariEkle(
                    baglanti,
                    kontrolSonucuKimligi,
                    kontrolSonucu,
                )
                _evidenceDosyalariniEkle(
                    baglanti,
                    kontrolSonucuKimligi,
                    evidenceDosyalari,
                )
        except VeritabaniHatasi:
            raise
        except sqlite3.Error as hata:
            raise VeritabaniHatasi("Dogrulama sonucu SQLite veritabanina kaydedilemedi.") from hata

        return DogrulamaKayitOzeti(
            projeKimligi=projeKimligi,
            hedefKimligi=hedefKimligi,
            taramaKimligi=taramaKimligi,
            bulguKimligi=bulguKimligi,
            kontrolSonucuKimligi=kontrolSonucuKimligi,
        )

    def taramaGecmisiniListele(
        self,
        projeAdi: str | None = None,
        sinir: int = 50,
    ) -> tuple[TaramaGecmisiKaydi, ...]:
        # En yeni taramalari proje filtresiyle birlikte listeler.
        standartProjeAdi = projeAdiniDogrula(projeAdi) if projeAdi is not None else None
        standartSinir = kayitSiniriniDogrula(sinir)
        with veritabaniBaglantisi(self._veritabaniYolu) as baglanti:
            semayiHazirla(baglanti)
            kosul = "WHERE p.ad = ? COLLATE NOCASE" if standartProjeAdi else ""
            parametreler: tuple[object, ...] = (
                (standartProjeAdi, standartSinir) if standartProjeAdi else (standartSinir,)
            )
            satirlar = baglanti.execute(
                f"""
                SELECT t.kimlik, p.ad, h.adres, ks.kontrol_kimligi, ks.durum,
                       ks.ozet, t.bitis_zamani, COUNT(ed.kimlik) AS evidence_sayisi
                FROM tarama_calismalari AS t
                JOIN projeler AS p ON p.kimlik = t.proje_kimligi
                JOIN hedefler AS h ON h.kimlik = t.hedef_kimligi
                JOIN kontrol_sonuclari AS ks ON ks.tarama_kimligi = t.kimlik
                LEFT JOIN evidence_dosyalari AS ed
                    ON ed.kontrol_sonucu_kimligi = ks.kimlik
                {kosul}
                GROUP BY t.kimlik, ks.kimlik
                ORDER BY t.kimlik DESC
                LIMIT ?
                """,
                parametreler,
            ).fetchall()
        return tuple(
            TaramaGecmisiKaydi(
                taramaKimligi=satir[0],
                projeAdi=satir[1],
                hedef=satir[2],
                kontrolKimligi=satir[3],
                durum=satir[4],
                ozet=satir[5],
                bitisZamani=satir[6],
                evidenceSayisi=satir[7],
            )
            for satir in satirlar
        )

    def bulgulariListele(
        self,
        projeAdi: str | None = None,
        sinir: int = 50,
    ) -> tuple[BulguKaydi, ...]:
        # Ayni bulguya baglanan tum dogrulama yontemlerini tek satirda listeler.
        standartProjeAdi = projeAdiniDogrula(projeAdi) if projeAdi is not None else None
        standartSinir = kayitSiniriniDogrula(sinir)
        with veritabaniBaglantisi(self._veritabaniYolu) as baglanti:
            semayiHazirla(baglanti)
            kosul = "WHERE p.ad = ? COLLATE NOCASE" if standartProjeAdi else ""
            parametreler: tuple[object, ...] = (
                (standartProjeAdi, standartSinir) if standartProjeAdi else (standartSinir,)
            )
            satirlar = baglanti.execute(
                f"""
                SELECT b.kimlik, p.ad, h.adres, b.bulgu_anahtari, b.baslik,
                       b.son_durum, COUNT(ks.kimlik), b.son_gorulme_zamani
                FROM bulgular AS b
                JOIN projeler AS p ON p.kimlik = b.proje_kimligi
                JOIN hedefler AS h ON h.kimlik = b.hedef_kimligi
                LEFT JOIN kontrol_sonuclari AS ks ON ks.bulgu_kimligi = b.kimlik
                {kosul}
                GROUP BY b.kimlik
                ORDER BY b.son_gorulme_zamani DESC, b.kimlik DESC
                LIMIT ?
                """,
                parametreler,
            ).fetchall()
        return tuple(
            BulguKaydi(
                bulguKimligi=satir[0],
                projeAdi=satir[1],
                hedef=satir[2],
                bulguAnahtari=satir[3],
                baslik=satir[4],
                sonDurum=satir[5],
                dogrulamaSayisi=satir[6],
                sonGorulmeZamani=satir[7],
            )
            for satir in satirlar
        )


def projeAdiniDogrula(projeAdi: str) -> str:
    # Bos, cevresinde bosluk veya cok uzun proje adlarini reddeder.
    if not isinstance(projeAdi, str):
        raise VeritabaniHatasi("Proje adi metin olmalidir.")
    if not projeAdi or projeAdi != projeAdi.strip():
        raise VeritabaniHatasi("Proje adi bos olamaz veya boslukla cevrilemez.")
    if "\x00" in projeAdi:
        raise VeritabaniHatasi("Proje adi null karakteri iceremez.")
    if len(projeAdi) > AZAMI_PROJE_ADI_UZUNLUGU:
        raise VeritabaniHatasi(
            f"Proje adi en fazla {AZAMI_PROJE_ADI_UZUNLUGU} karakter olabilir.",
        )
    return projeAdi


def kayitSiniriniDogrula(sinir: int) -> int:
    # Gecmis sorgusu satir sinirini guvenli aralikta tutar.
    if (
        isinstance(sinir, bool)
        or not isinstance(sinir, int)
        or not 1 <= sinir <= AZAMI_GECMIS_KAYDI
    ):
        raise VeritabaniHatasi(
            f"Kayit siniri 1 ile {AZAMI_GECMIS_KAYDI} arasinda olmalidir.",
        )
    return sinir


def _kayitGirdileriniDogrula(
    kontrolTanimi: CheckDefinition,
    kontrolSonucu: KontrolSonucu,
    evidenceDosyalari: tuple[KanitDosyasiOzeti, ...],
) -> None:
    # Kontrol tanimi, sonuc ve evidence ozetlerinin birbiriyle uyumunu denetler.
    if not isinstance(kontrolTanimi, CheckDefinition):
        raise VeritabaniHatasi("Gecerli bir kontrol tanimi gereklidir.")
    if not isinstance(kontrolSonucu, KontrolSonucu):
        raise VeritabaniHatasi("Gecerli bir kontrol sonucu gereklidir.")
    if kontrolTanimi.kontrolKimligi != kontrolSonucu.kontrolKimligi:
        raise VeritabaniHatasi("Kontrol tanimi ile sonuc kimligi uyusmuyor.")
    if not isinstance(evidenceDosyalari, tuple) or not all(
        isinstance(dosya, KanitDosyasiOzeti) for dosya in evidenceDosyalari
    ):
        raise VeritabaniHatasi("Evidence dosyalari gecerli bir tuple olmalidir.")


def _sonucZamanlariniAl(kontrolSonucu: KontrolSonucu) -> tuple[str, str]:
    # Eksik zamanlari UTC simdi degeriyle tamamlayip ISO-8601 metnine donusturur.
    simdi = datetime.now(UTC)
    baslangic = kontrolSonucu.baslangicZamani or simdi
    bitis = kontrolSonucu.bitisZamani or simdi
    return _utcMetnineDonustur(baslangic), _utcMetnineDonustur(bitis)


def _utcMetnineDonustur(zaman: datetime) -> str:
    # Zaman dilimsiz degerleri UTC kabul eder ve tutarli ISO-8601 metni uretir.
    if zaman.tzinfo is None:
        zaman = zaman.replace(tzinfo=UTC)
    return zaman.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _projeyiGetirVeyaOlustur(baglanti: sqlite3.Connection, projeAdi: str) -> int:
    # Projeyi varsa getirir, yoksa olusturur.
    baglanti.execute(
        "INSERT INTO projeler (ad, olusturma_zamani) VALUES (?, ?) ON CONFLICT(ad) DO NOTHING",
        (projeAdi, _utcMetnineDonustur(datetime.now(UTC))),
    )
    return int(
        baglanti.execute(
            "SELECT kimlik FROM projeler WHERE ad = ? COLLATE NOCASE",
            (projeAdi,),
        ).fetchone()[0]
    )


def _hedefiGetirVeyaOlustur(
    baglanti: sqlite3.Connection,
    projeKimligi: int,
    hedef: str,
) -> int:
    # Proje icindeki hedefi varsa getirir, yoksa olusturur.
    baglanti.execute(
        "INSERT INTO hedefler (proje_kimligi, adres, olusturma_zamani) VALUES (?, ?, ?) "
        "ON CONFLICT(proje_kimligi, adres) DO NOTHING",
        (projeKimligi, hedef, _utcMetnineDonustur(datetime.now(UTC))),
    )
    return int(
        baglanti.execute(
            "SELECT kimlik FROM hedefler WHERE proje_kimligi = ? AND adres = ?",
            (projeKimligi, hedef),
        ).fetchone()[0]
    )


def _bulguyuGetirVeyaGuncelle(
    baglanti: sqlite3.Connection,
    projeKimligi: int,
    hedefKimligi: int,
    kontrolTanimi: CheckDefinition,
    kontrolSonucu: KontrolSonucu,
    bitisZamani: str,
) -> int | None:
    # Yalnizca gercek veya olasi zafiyet sonuclarini bulgu olarak gunceller.
    bulguDurumlari = {
        ResultStatus.VULNERABLE,
        ResultStatus.POTENTIALLY_VULNERABLE,
    }
    if kontrolSonucu.durum not in bulguDurumlari:
        return None

    baglanti.execute(
        """
        INSERT INTO bulgular (
            proje_kimligi, hedef_kimligi, bulgu_anahtari, baslik,
            son_durum, ilk_gorulme_zamani, son_gorulme_zamani
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(proje_kimligi, hedef_kimligi, bulgu_anahtari) DO UPDATE SET
            baslik = excluded.baslik,
            son_durum = excluded.son_durum,
            son_gorulme_zamani = excluded.son_gorulme_zamani
        """,
        (
            projeKimligi,
            hedefKimligi,
            kontrolTanimi.bulguAnahtari,
            kontrolTanimi.baslik,
            kontrolSonucu.durum.value,
            bitisZamani,
            bitisZamani,
        ),
    )
    return int(
        baglanti.execute(
            """
            SELECT kimlik FROM bulgular
            WHERE proje_kimligi = ? AND hedef_kimligi = ? AND bulgu_anahtari = ?
            """,
            (projeKimligi, hedefKimligi, kontrolTanimi.bulguAnahtari),
        ).fetchone()[0]
    )


def _taramaEkle(
    baglanti: sqlite3.Connection,
    projeKimligi: int,
    hedefKimligi: int,
    baslangicZamani: str,
    bitisZamani: str,
    istenenPortlar: tuple[int, ...],
) -> int:
    # Tek CLI dogrulamasini tarama calismasi olarak kaydeder.
    imlec = baglanti.execute(
        """
        INSERT INTO tarama_calismalari (
            proje_kimligi, hedef_kimligi, baslangic_zamani,
            bitis_zamani, istenen_portlar
        ) VALUES (?, ?, ?, ?, ?)
        """,
        (
            projeKimligi,
            hedefKimligi,
            baslangicZamani,
            bitisZamani,
            json.dumps(istenenPortlar),
        ),
    )
    return int(imlec.lastrowid)


def _kontrolSonucuEkle(
    baglanti: sqlite3.Connection,
    taramaKimligi: int,
    bulguKimligi: int | None,
    kontrolSonucu: KontrolSonucu,
    baslangicZamani: str,
    bitisZamani: str,
) -> int:
    # Standart kontrol sonucunu tarama ve ortak bulgu kaydina baglar.
    imlec = baglanti.execute(
        """
        INSERT INTO kontrol_sonuclari (
            tarama_kimligi, bulgu_kimligi, kontrol_kimligi, durum, ozet,
            calisma_suresi_saniye, baslangic_zamani, bitis_zamani
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            taramaKimligi,
            bulguKimligi,
            kontrolSonucu.kontrolKimligi,
            kontrolSonucu.durum.value,
            kontrolSonucu.ozet,
            kontrolSonucu.calismaSuresiSaniye,
            baslangicZamani,
            bitisZamani,
        ),
    )
    return int(imlec.lastrowid)


def _yapilandirilmisKanitlariEkle(
    baglanti: sqlite3.Connection,
    kontrolSonucuKimligi: int,
    kontrolSonucu: KontrolSonucu,
) -> None:
    # Sonucun anahtar ve deger kanitlarini tekrarli sirayi koruyarak ekler.
    baglanti.executemany(
        """
        INSERT INTO yapilandirilmis_kanitlar (
            kontrol_sonucu_kimligi, anahtar, deger
        ) VALUES (?, ?, ?)
        """,
        ((kontrolSonucuKimligi, kanit.anahtar, kanit.deger) for kanit in kontrolSonucu.kanitlar),
    )


def _evidenceDosyalariniEkle(
    baglanti: sqlite3.Connection,
    kontrolSonucuKimligi: int,
    evidenceDosyalari: tuple[KanitDosyasiOzeti, ...],
) -> None:
    # Evidence yollarini, turlerini ve SHA-256 degerlerini veritabanina baglar.
    baglanti.executemany(
        """
        INSERT INTO evidence_dosyalari (
            kontrol_sonucu_kimligi, dosya_yolu, sha256, dosya_turu
        ) VALUES (?, ?, ?, ?)
        """,
        (
            (
                kontrolSonucuKimligi,
                str(dosya.dosyaYolu.resolve()),
                dosya.sha256,
                _evidenceTurunuAl(dosya.dosyaYolu),
            )
            for dosya in evidenceDosyalari
        ),
    )


def _evidenceTurunuAl(dosyaYolu: Path) -> str:
    # Eski ve aciklayici evidence dosya adlarini ortak tur degerlerine donusturur.
    ad = dosyaYolu.name
    turler = (
        ("stdout.txt", "stdout"),
        ("stderr.txt", "stderr"),
        ("evidence.json", "normalized"),
        ("manifest.json", "manifest"),
        (".png", "screenshot"),
    )
    for sonek, evidenceTuru in turler:
        if ad == sonek or ad.endswith(f"-{sonek}") or (sonek == ".png" and ad.endswith(sonek)):
            return evidenceTuru
    return "other"
