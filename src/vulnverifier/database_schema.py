# SQLite semasini surumlu migration adimlariyla olusturur ve dogrular.

import sqlite3
from collections.abc import Sequence

from vulnverifier.database import VeritabaniHatasi

GUNCEL_SEMA_SURUMU = 1

ILK_SEMA_SQL: tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS sema_migrationlari (
        surum INTEGER PRIMARY KEY,
        uygulama_zamani TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE projeler (
        kimlik INTEGER PRIMARY KEY,
        ad TEXT NOT NULL COLLATE NOCASE UNIQUE,
        olusturma_zamani TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE hedefler (
        kimlik INTEGER PRIMARY KEY,
        proje_kimligi INTEGER NOT NULL REFERENCES projeler(kimlik) ON DELETE CASCADE,
        adres TEXT NOT NULL,
        olusturma_zamani TEXT NOT NULL,
        UNIQUE (proje_kimligi, adres)
    )
    """,
    """
    CREATE TABLE bulgular (
        kimlik INTEGER PRIMARY KEY,
        proje_kimligi INTEGER NOT NULL REFERENCES projeler(kimlik) ON DELETE CASCADE,
        hedef_kimligi INTEGER NOT NULL REFERENCES hedefler(kimlik) ON DELETE CASCADE,
        bulgu_anahtari TEXT NOT NULL,
        baslik TEXT NOT NULL,
        son_durum TEXT NOT NULL CHECK (
            son_durum IN (
                'VULNERABLE', 'NOT_VULNERABLE', 'POTENTIALLY_VULNERABLE',
                'INCONCLUSIVE', 'SKIPPED', 'ERROR'
            )
        ),
        ilk_gorulme_zamani TEXT NOT NULL,
        son_gorulme_zamani TEXT NOT NULL,
        UNIQUE (proje_kimligi, hedef_kimligi, bulgu_anahtari)
    )
    """,
    """
    CREATE TABLE tarama_calismalari (
        kimlik INTEGER PRIMARY KEY,
        proje_kimligi INTEGER NOT NULL REFERENCES projeler(kimlik) ON DELETE CASCADE,
        hedef_kimligi INTEGER NOT NULL REFERENCES hedefler(kimlik) ON DELETE CASCADE,
        baslangic_zamani TEXT NOT NULL,
        bitis_zamani TEXT NOT NULL,
        istenen_portlar TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE kontrol_sonuclari (
        kimlik INTEGER PRIMARY KEY,
        tarama_kimligi INTEGER NOT NULL
            REFERENCES tarama_calismalari(kimlik) ON DELETE CASCADE,
        bulgu_kimligi INTEGER NOT NULL REFERENCES bulgular(kimlik) ON DELETE CASCADE,
        kontrol_kimligi TEXT NOT NULL,
        durum TEXT NOT NULL CHECK (
            durum IN (
                'VULNERABLE', 'NOT_VULNERABLE', 'POTENTIALLY_VULNERABLE',
                'INCONCLUSIVE', 'SKIPPED', 'ERROR'
            )
        ),
        ozet TEXT NOT NULL,
        calisma_suresi_saniye REAL,
        baslangic_zamani TEXT NOT NULL,
        bitis_zamani TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE yapilandirilmis_kanitlar (
        kimlik INTEGER PRIMARY KEY,
        kontrol_sonucu_kimligi INTEGER NOT NULL
            REFERENCES kontrol_sonuclari(kimlik) ON DELETE CASCADE,
        anahtar TEXT NOT NULL,
        deger TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE evidence_dosyalari (
        kimlik INTEGER PRIMARY KEY,
        kontrol_sonucu_kimligi INTEGER NOT NULL
            REFERENCES kontrol_sonuclari(kimlik) ON DELETE CASCADE,
        dosya_yolu TEXT NOT NULL,
        sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
        dosya_turu TEXT NOT NULL,
        UNIQUE (kontrol_sonucu_kimligi, dosya_yolu)
    )
    """,
    "CREATE INDEX idx_hedefler_proje ON hedefler(proje_kimligi)",
    "CREATE INDEX idx_bulgular_hedef ON bulgular(hedef_kimligi)",
    "CREATE INDEX idx_bulgular_anahtar ON bulgular(bulgu_anahtari)",
    "CREATE INDEX idx_taramalar_proje_zaman ON tarama_calismalari(proje_kimligi, kimlik DESC)",
    "CREATE INDEX idx_taramalar_hedef ON tarama_calismalari(hedef_kimligi)",
    "CREATE INDEX idx_sonuclar_tarama ON kontrol_sonuclari(tarama_kimligi)",
    "CREATE INDEX idx_sonuclar_bulgu ON kontrol_sonuclari(bulgu_kimligi)",
    "CREATE INDEX idx_kanitlar_sonuc ON yapilandirilmis_kanitlar(kontrol_sonucu_kimligi)",
    "CREATE INDEX idx_evidence_sonuc ON evidence_dosyalari(kontrol_sonucu_kimligi)",
)


def semayiHazirla(baglanti: sqlite3.Connection) -> int:
    # Eksik migration adimlarini sirasiyla uygular ve guncel sema surumunu dondurur.
    mevcutSurum = _semaSurumunuAl(baglanti)
    if mevcutSurum > GUNCEL_SEMA_SURUMU:
        raise VeritabaniHatasi(
            f"Veritabani semasi uygulamadan daha yeni: {mevcutSurum} > {GUNCEL_SEMA_SURUMU}",
        )

    migrationlar: dict[int, Sequence[str]] = {1: ILK_SEMA_SQL}
    for surum in range(mevcutSurum + 1, GUNCEL_SEMA_SURUMU + 1):
        _migrationUygula(baglanti, surum, migrationlar[surum])
    return GUNCEL_SEMA_SURUMU


def _semaSurumunuAl(baglanti: sqlite3.Connection) -> int:
    # SQLite user_version degerini okur.
    try:
        return int(baglanti.execute("PRAGMA user_version").fetchone()[0])
    except sqlite3.Error as hata:
        raise VeritabaniHatasi("SQLite sema surumu okunamadi.") from hata


def _migrationUygula(
    baglanti: sqlite3.Connection,
    surum: int,
    sqlKomutlari: Sequence[str],
) -> None:
    # Bir migration adimini savepoint icinde atomik olarak uygular.
    savepointAdi = f"migration_{surum}"
    try:
        baglanti.execute(f"SAVEPOINT {savepointAdi}")
        for sqlKomutu in sqlKomutlari:
            baglanti.execute(sqlKomutu)
        baglanti.execute(
            "INSERT INTO sema_migrationlari (surum, uygulama_zamani) "
            "VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))",
            (surum,),
        )
        baglanti.execute(f"PRAGMA user_version = {surum}")
        baglanti.execute(f"RELEASE SAVEPOINT {savepointAdi}")
    except sqlite3.Error as hata:
        try:
            baglanti.execute(f"ROLLBACK TO SAVEPOINT {savepointAdi}")
            baglanti.execute(f"RELEASE SAVEPOINT {savepointAdi}")
        except sqlite3.Error:
            pass
        raise VeritabaniHatasi(f"SQLite sema migration adimi uygulanamadi: {surum}") from hata
