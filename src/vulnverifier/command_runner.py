# Harici komutlari shell kullanmadan guvenli arguman listesiyle calistirir.

import math
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

VARSAYILAN_ZAMAN_ASIMI = 120.0
IPTAL_KONTROL_ARALIGI = 0.05
SONLANDIRMA_BEKLEME_SURESI = 1.0


@dataclass(frozen=True, slots=True)
class KomutSonucu:
    # Tamamlanan bir komutun cikis kodunu ve yakalanan ciktilarini tasir.
    cikisKodu: int
    standartCikti: str
    standartHata: str


class KomutDogrulamaHatasi(ValueError):
    # Gecersiz komut veya arguman listesi verildiginde olusan hatadir.
    pass


class KomutZamanAsimiHatasi(TimeoutError):
    # Komut belirlenen surede tamamlanmadiginda olusan hatadir.
    def __init__(self, komutParcalari: tuple[str, ...], zamanAsimi: float) -> None:
        self.komutParcalari = komutParcalari
        self.zamanAsimi = zamanAsimi
        super().__init__(f"Komut {zamanAsimi:g} saniye içinde tamamlanamadı.")


class KomutIptalHatasi(RuntimeError):
    # Komut kullanici istegiyle iptal edildiginde olusan hatadir.
    def __init__(self, komutParcalari: tuple[str, ...]) -> None:
        self.komutParcalari = komutParcalari
        super().__init__("Komut çalışırken iptal edildi.")


class KomutBaslatmaHatasi(RuntimeError):
    # Calistirilabilir dosya baslatilamadiginda ortak hata bilgisi tasir.
    def __init__(self, komutParcalari: tuple[str, ...], neden: str) -> None:
        self.komutParcalari = komutParcalari
        self.neden = neden
        super().__init__(f"Komut başlatılamadı: {neden}")


class KomutIptalDenetimi:
    # Farkli bir calisma akisindan guvenli bicimde iptal istegi iletir.
    def __init__(self) -> None:
        self._iptalOlayi = threading.Event()

    def iptalEt(self) -> None:
        self._iptalOlayi.set()

    def iptalIstendiMi(self) -> bool:
        return self._iptalOlayi.is_set()


def komutuCalistir(
    komutParcalari: Sequence[str],
    zamanAsimi: float | int = VARSAYILAN_ZAMAN_ASIMI,
    iptalDenetimi: KomutIptalDenetimi | None = None,
) -> KomutSonucu:
    # Komutu shell yorumlamasi olmadan calistirir ve standart sonucu dondurur.
    dogrulanmisParcalar = _komutParcalariniDogrula(komutParcalari)
    dogrulanmisZamanAsimi = _zamanAsiminiDogrula(zamanAsimi)
    if iptalDenetimi is not None and iptalDenetimi.iptalIstendiMi():
        raise KomutIptalHatasi(dogrulanmisParcalar)

    try:
        surec = subprocess.Popen(
            dogrulanmisParcalar,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as hata:
        raise KomutBaslatmaHatasi(dogrulanmisParcalar, str(hata)) from hata
    baslangicZamani = time.monotonic()

    while True:
        if iptalDenetimi is not None and iptalDenetimi.iptalIstendiMi():
            _sureciSonlandir(surec)
            raise KomutIptalHatasi(dogrulanmisParcalar)

        kalanSure = dogrulanmisZamanAsimi - (time.monotonic() - baslangicZamani)
        if kalanSure <= 0:
            _sureciSonlandir(surec)
            raise KomutZamanAsimiHatasi(
                komutParcalari=dogrulanmisParcalar,
                zamanAsimi=dogrulanmisZamanAsimi,
            )

        try:
            standartCikti, standartHata = surec.communicate(
                timeout=min(IPTAL_KONTROL_ARALIGI, kalanSure),
            )
            return KomutSonucu(
                cikisKodu=surec.wait(),
                standartCikti=standartCikti,
                standartHata=standartHata,
            )
        except subprocess.TimeoutExpired:
            continue


def komutuSonucaDonusturerekCalistir(
    komutParcalari: Sequence[str],
    zamanAsimi: float | int = VARSAYILAN_ZAMAN_ASIMI,
    iptalDenetimi: KomutIptalDenetimi | None = None,
) -> KomutSonucu:
    # Baslatma hatasini ortak cikis kodlu sonuca donusturur, timeout ve iptali korur.
    try:
        return komutuCalistir(komutParcalari, zamanAsimi, iptalDenetimi)
    except KomutBaslatmaHatasi as hata:
        return KomutSonucu(
            cikisKodu=126,
            standartCikti="",
            standartHata=str(hata),
        )


def _sureciSonlandir(surec: subprocess.Popen[str]) -> None:
    # Once normal sonlandirma dener, surec yanit vermezse zorla kapatir.
    if surec.poll() is not None:
        return

    surec.terminate()
    try:
        surec.communicate(timeout=SONLANDIRMA_BEKLEME_SURESI)
    except subprocess.TimeoutExpired:
        surec.kill()
        surec.communicate()


def _komutParcalariniDogrula(komutParcalari: Sequence[str]) -> tuple[str, ...]:
    # Ham komut metnini reddeder ve her argumanin guvenli aktarilabilir oldugunu denetler.
    if isinstance(komutParcalari, (str, bytes)):
        raise KomutDogrulamaHatasi("Komut, metin yerine argüman listesi olarak verilmelidir.")

    dogrulanmisParcalar = tuple(komutParcalari)
    if not dogrulanmisParcalar:
        raise KomutDogrulamaHatasi("Komut argüman listesi boş olamaz.")

    for parca in dogrulanmisParcalar:
        if not isinstance(parca, str):
            raise KomutDogrulamaHatasi("Bütün komut argümanları metin olmalıdır.")
        if "\x00" in parca:
            raise KomutDogrulamaHatasi("Komut argümanları null karakteri içeremez.")

    if not dogrulanmisParcalar[0]:
        raise KomutDogrulamaHatasi("Çalıştırılacak program adı boş olamaz.")

    return dogrulanmisParcalar


def _zamanAsiminiDogrula(zamanAsimi: float | int) -> float:
    # Zaman asiminin pozitif ve sonlu bir sayi oldugunu denetler.
    if isinstance(zamanAsimi, bool) or not isinstance(zamanAsimi, (int, float)):
        raise KomutDogrulamaHatasi("Zaman aşımı sayısal bir değer olmalıdır.")

    dogrulanmisZamanAsimi = float(zamanAsimi)
    if not math.isfinite(dogrulanmisZamanAsimi) or dogrulanmisZamanAsimi <= 0:
        raise KomutDogrulamaHatasi("Zaman aşımı sıfırdan büyük ve sonlu olmalıdır.")

    return dogrulanmisZamanAsimi
