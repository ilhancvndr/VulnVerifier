# Harici komutlari shell kullanmadan guvenli arguman listesiyle calistirir.

import math
import os
import signal
import subprocess
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

VARSAYILAN_ZAMAN_ASIMI = 120.0
IPTAL_KONTROL_ARALIGI = 0.05
SONLANDIRMA_BEKLEME_SURESI = 1.0
_aktifSurecler: set[subprocess.Popen[str]] = set()
_aktifSurecKilidi = threading.Lock()


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
            start_new_session=os.name == "posix",
        )
    except OSError as hata:
        raise KomutBaslatmaHatasi(dogrulanmisParcalar, str(hata)) from hata
    with _aktifSurecKilidi:
        _aktifSurecler.add(surec)
    baslangicZamani = time.monotonic()

    try:
        while True:
            if iptalDenetimi is not None and iptalDenetimi.iptalIstendiMi():
                raise KomutIptalHatasi(dogrulanmisParcalar)

            kalanSure = dogrulanmisZamanAsimi - (time.monotonic() - baslangicZamani)
            if kalanSure <= 0:
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
    except BaseException:
        _sureciSonlandir(surec)
        raise
    finally:
        with _aktifSurecKilidi:
            _aktifSurecler.discard(surec)


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


def aktifKomutlariSonlandir() -> None:
    # Paralel taramalarda pipe'lara dokunmadan tum surec gruplarini kapatir.
    with _aktifSurecKilidi:
        surecler = tuple(_aktifSurecler)
    for surec in surecler:
        if _surecCalisiyorMu(surec):
            _surecSinyaliGonder(surec, signal.SIGTERM)

    sonlandirmaSonu = time.monotonic() + SONLANDIRMA_BEKLEME_SURESI
    while any(_surecCalisiyorMu(surec) for surec in surecler):
        if time.monotonic() >= sonlandirmaSonu:
            break
        time.sleep(IPTAL_KONTROL_ARALIGI)

    for surec in surecler:
        if _surecCalisiyorMu(surec):
            _surecSinyaliGonder(surec, signal.SIGKILL)


def _sureciSonlandir(surec: subprocess.Popen[str]) -> None:
    # Once surec grubunu sonlandirir, yanit gelmezse grubu zorla kapatir.
    if not _surecCalisiyorMu(surec):
        return

    _surecSinyaliGonder(surec, signal.SIGTERM)
    try:
        surec.communicate(timeout=SONLANDIRMA_BEKLEME_SURESI)
    except subprocess.TimeoutExpired:
        _surecSinyaliGonder(surec, signal.SIGKILL)
        try:
            surec.communicate()
        except (OSError, ValueError):
            pass
    except (OSError, ValueError):
        pass


def _surecCalisiyorMu(surec: subprocess.Popen[str]) -> bool:
    # Eszamanli kapanmis sureclerde poll hatasini calisiyor olarak yorumlamaz.
    try:
        return surec.poll() is None
    except OSError:
        return False


def _surecSinyaliGonder(surec: subprocess.Popen[str], sinyal: signal.Signals) -> None:
    # POSIX ortaminda tum surec grubuna, diger ortamlarda ana surece sinyal yollar.
    try:
        if os.name == "posix":
            os.killpg(os.getpgid(surec.pid), sinyal)
        elif sinyal is signal.SIGTERM:
            surec.terminate()
        else:
            surec.kill()
    except OSError:
        pass


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
