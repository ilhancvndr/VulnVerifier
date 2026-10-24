# Kontrol katalogu ile kontrol calistiricilari arasindaki ortak yonetim katmanini saglar.

import time
from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime

from vulnverifier.command_runner import (
    KomutIptalHatasi,
    KomutSonucu,
    KomutZamanAsimiHatasi,
)
from vulnverifier.errors import CiktiAyristirmaHatasi
from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.port_validation import PortGirdisi, portlariDogrula
from vulnverifier.registry import CheckRegistry
from vulnverifier.target_validation import hedefiDogrula
from vulnverifier.tool_availability import AracDurumu

type KontrolCalistirici = Callable[[str, tuple[int, ...]], KontrolSonucu]
type BasariliAracSonucuDonusturucu = Callable[[KomutSonucu], KontrolSonucu]

NMAP_YETKI_HATASI_IPUCLARI = (
    "requires root privileges",
    "couldn't open a raw socket",
    "failed to open device",
)


class KontrolBulunamadiHatasi(LookupError):
    # Istenen kontrol katalogda bulunamadiginda olusan hatadir.
    pass


class KontrolCalistiricisiBulunamadiHatasi(LookupError):
    # Katalogdaki kontrol icin calistirici kaydedilmediginde olusan hatadir.
    pass


class KontrolCalistiriciKayitHatasi(ValueError):
    # Gecersiz veya yinelenen kontrol calistiricisi kaydinda olusan hatadir.
    pass


class KontrolCalistirmaHatasi(RuntimeError):
    # Calistirici ortak servis sozlesmesine uymayan sonuc dondurdugunde olusan hatadir.
    pass


def aracSonucunuStandartlastir(
    kontrolKimligi: str,
    hedef: str,
    komutSonucu: KomutSonucu,
    basariliSonucDonusturucu: BasariliAracSonucuDonusturucu,
) -> KontrolSonucu:
    # Harici arac sonucunu ortak kontrol sonucu sozlesmesine donusturur.
    standartHedef = hedefiDogrula(hedef)
    if not isinstance(komutSonucu, KomutSonucu):
        raise KontrolCalistirmaHatasi("Geçerli bir KomutSonucu sağlanmalıdır.")
    if not callable(basariliSonucDonusturucu):
        raise KontrolCalistirmaHatasi("Başarılı sonuç dönüştürücüsü çağrılabilir olmalıdır.")

    if komutSonucu.cikisKodu != 0:
        if _nmapYetkiHatasiMi(komutSonucu.standartHata):
            return KontrolSonucu(
                kontrolKimligi=kontrolKimligi,
                hedef=standartHedef,
                durum=ResultStatus.ERROR,
                ozet="Nmap taraması yönetici veya gerekli ağ yetkileriyle çalıştırılmalıdır.",
                kanitlar=(
                    KanitBilgisi(
                        anahtar="aracCikisKodu",
                        deger=str(komutSonucu.cikisKodu),
                    ),
                    KanitBilgisi(anahtar="hataTuru", deger="nmapYetkiEksikligi"),
                ),
            )
        return KontrolSonucu(
            kontrolKimligi=kontrolKimligi,
            hedef=standartHedef,
            durum=ResultStatus.ERROR,
            ozet=f"Harici araç {komutSonucu.cikisKodu} çıkış koduyla tamamlandı.",
            kanitlar=(
                KanitBilgisi(
                    anahtar="aracCikisKodu",
                    deger=str(komutSonucu.cikisKodu),
                ),
            ),
        )

    sonuc = basariliSonucDonusturucu(komutSonucu)
    _kontrolSonucunuDogrula(sonuc, kontrolKimligi, standartHedef)
    return sonuc


def _nmapYetkiHatasiMi(standartHata: str) -> bool:
    # Nmap ham paket taramalarinda gorulen bilinen yetki hatalarini tanir.
    kucukHata = standartHata.casefold()
    return any(ipucu in kucukHata for ipucu in NMAP_YETKI_HATASI_IPUCLARI)


def zamanAsimiHatasiniStandartlastir(
    kontrolKimligi: str,
    hedef: str,
    zamanAsimiHatasi: KomutZamanAsimiHatasi,
) -> KontrolSonucu:
    # Komut zaman asimini ortak hata sonucuna donusturur.
    standartHedef = hedefiDogrula(hedef)
    if not isinstance(zamanAsimiHatasi, KomutZamanAsimiHatasi):
        raise KontrolCalistirmaHatasi("Geçerli bir KomutZamanAsimiHatasi sağlanmalıdır.")

    zamanAsimi = f"{zamanAsimiHatasi.zamanAsimi:g}"
    return KontrolSonucu(
        kontrolKimligi=kontrolKimligi,
        hedef=standartHedef,
        durum=ResultStatus.ERROR,
        ozet=f"Harici araç {zamanAsimi} saniye içinde tamamlanamadı.",
        kanitlar=(KanitBilgisi(anahtar="zamanAsimiSaniye", deger=zamanAsimi),),
    )


def iptalHatasiniStandartlastir(
    kontrolKimligi: str,
    hedef: str,
    iptalHatasi: KomutIptalHatasi,
) -> KontrolSonucu:
    # Kullanici iptalini atlanan standart kontrol sonucuna donusturur.
    standartHedef = hedefiDogrula(hedef)
    if not isinstance(iptalHatasi, KomutIptalHatasi):
        raise KontrolCalistirmaHatasi("Geçerli bir KomutIptalHatasi sağlanmalıdır.")

    return KontrolSonucu(
        kontrolKimligi=kontrolKimligi,
        hedef=standartHedef,
        durum=ResultStatus.SKIPPED,
        ozet="Kontrol kullanıcı tarafından iptal edildi.",
        kanitlar=(KanitBilgisi(anahtar="iptalNedeni", deger="kullanici"),),
    )


def ayristirmaHatasiniStandartlastir(
    kontrolKimligi: str,
    hedef: str,
    ayristirmaHatasi: CiktiAyristirmaHatasi,
) -> KontrolSonucu:
    # Arac ciktisi ayristirma hatasini ortak hata sonucuna donusturur.
    standartHedef = hedefiDogrula(hedef)
    if not isinstance(ayristirmaHatasi, CiktiAyristirmaHatasi):
        raise KontrolCalistirmaHatasi("Geçerli bir CiktiAyristirmaHatasi sağlanmalıdır.")

    return KontrolSonucu(
        kontrolKimligi=kontrolKimligi,
        hedef=standartHedef,
        durum=ResultStatus.ERROR,
        ozet="Harici araç çıktısı ayrıştırılamadı.",
        kanitlar=(
            KanitBilgisi(
                anahtar="ayristirmaHatasi",
                deger=str(ayristirmaHatasi),
            ),
        ),
    )


def eksikAraciStandartlastir(
    kontrolKimligi: str,
    hedef: str,
    aracDurumu: AracDurumu,
) -> KontrolSonucu:
    # Bulunamayan harici araci atlanan standart kontrol sonucuna donusturur.
    standartHedef = hedefiDogrula(hedef)
    if not isinstance(aracDurumu, AracDurumu):
        raise KontrolCalistirmaHatasi("Geçerli bir AracDurumu sağlanmalıdır.")
    if aracDurumu.bulunduMu:
        raise KontrolCalistirmaHatasi("Bulunan bir araç eksik olarak işaretlenemez.")

    return KontrolSonucu(
        kontrolKimligi=kontrolKimligi,
        hedef=standartHedef,
        durum=ResultStatus.SKIPPED,
        ozet=f"Gerekli harici araç bulunamadı: {aracDurumu.aracAdi}",
        kanitlar=(KanitBilgisi(anahtar="eksikArac", deger=aracDurumu.aracAdi),),
    )


def _kontrolSonucunuDogrula(
    sonuc: object,
    kontrolKimligi: str,
    hedef: str,
) -> None:
    # Standart sonucun tip, kontrol kimligi ve hedef sozlesmesini denetler.
    if not isinstance(sonuc, KontrolSonucu):
        raise KontrolCalistirmaHatasi("Çalıştırıcı geçerli bir KontrolSonucu döndürmedi.")
    if sonuc.kontrolKimligi != kontrolKimligi:
        raise KontrolCalistirmaHatasi("Çalıştırıcı farklı bir kontrol kimliği döndürdü.")
    if sonuc.hedef != hedef:
        raise KontrolCalistirmaHatasi("Çalıştırıcı farklı bir hedef döndürdü.")


class KontrolCalistirmaServisi:
    # Kontrol kimliklerini calistiricilarla eslestirir ve standart sonucu dogrular.
    def __init__(self, kontrolKatalogu: CheckRegistry) -> None:
        self._kontrolKatalogu = kontrolKatalogu
        self._calistiricilar: dict[str, KontrolCalistirici] = {}

    def calistiriciEkle(
        self,
        kontrolKimligi: str,
        calistirici: KontrolCalistirici,
    ) -> None:
        # Katalogda bulunan bir kontrol icin benzersiz calistirici kaydeder.
        if self._kontrolKatalogu.kontrolGetir(kontrolKimligi) is None:
            raise KontrolBulunamadiHatasi(f"Kontrol katalogda bulunamadı: {kontrolKimligi}")
        if kontrolKimligi in self._calistiricilar:
            raise KontrolCalistiriciKayitHatasi(
                f"Kontrol çalıştırıcısı zaten kayıtlı: {kontrolKimligi}",
            )
        if not callable(calistirici):
            raise KontrolCalistiriciKayitHatasi("Kontrol çalıştırıcısı çağrılabilir olmalıdır.")

        self._calistiricilar[kontrolKimligi] = calistirici

    def kontroluCalistir(
        self,
        kontrolKimligi: str,
        hedef: str,
        portlar: PortGirdisi = None,
    ) -> KontrolSonucu:
        # Girdileri dogrular, kayitli calistiriciyi secer ve standart sonucu dondurur.
        if self._kontrolKatalogu.kontrolGetir(kontrolKimligi) is None:
            raise KontrolBulunamadiHatasi(f"Kontrol katalogda bulunamadı: {kontrolKimligi}")

        calistirici = self._calistiricilar.get(kontrolKimligi)
        if calistirici is None:
            raise KontrolCalistiricisiBulunamadiHatasi(
                f"Kontrol çalıştırıcısı bulunamadı: {kontrolKimligi}",
            )

        standartHedef = hedefiDogrula(hedef)
        standartPortlar = portlariDogrula(portlar)
        baslangicZamani = datetime.now(UTC)
        baslangicOlcumu = time.monotonic()
        sonuc = calistirici(standartHedef, standartPortlar)
        calismaSuresi = time.monotonic() - baslangicOlcumu
        bitisZamani = datetime.now(UTC)
        _kontrolSonucunuDogrula(sonuc, kontrolKimligi, standartHedef)
        return replace(
            sonuc,
            baslangicZamani=baslangicZamani,
            bitisZamani=bitisZamani,
            calismaSuresiSaniye=calismaSuresi,
        )
