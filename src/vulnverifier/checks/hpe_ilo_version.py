# HPE iLO urun ve firmware tespitini standart kontrol sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_ILO_PORTU
from vulnverifier.nmap_ilo_parser import HpeIloHedefSonucu, HpeIloTaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "hpe-ilo-version-detection"


class HpeIloDegerlendirmeHatasi(ValueError):
    # Degerlendirme islevine gecersiz iLO tarama sonucu verildiginde olusan hatadir.
    pass


def hpeIloSonucunuOlustur(
    taramaSonucu: HpeIloTaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_ILO_PORTU,
) -> KontrolSonucu:
    # Ayristirilmis iLO bilgisini korumaci kurallarla standart sonuca cevirir.
    if not isinstance(taramaSonucu, HpeIloTaramaSonucu):
        raise HpeIloDegerlendirmeHatasi("Geçerli bir HpeIloTaramaSonucu gereklidir.")

    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenSonuclar = tuple(
        hedefSonucu
        for hedefSonucu in taramaSonucu.hedefSonuclari
        if hedefSonucu.port == standartPort
    )

    if len(eslesenSonuclar) != 1:
        return _belirsizSonucOlustur(
            standartHedef,
            f"Nmap çıktısında {standartPort}/tcp için tek bir hedef sonucu bulunamadı.",
            (
                KanitBilgisi(anahtar="port", deger=str(standartPort)),
                KanitBilgisi(anahtar="eslesenSonucSayisi", deger=str(len(eslesenSonuclar))),
            ),
        )

    hedefSonucu = eslesenSonuclar[0]
    kanitlar = _kanitlariOlustur(hedefSonucu)
    if hedefSonucu.hostDurumu != "up":
        return _belirsizSonucOlustur(
            standartHedef,
            f"Hedef host durumu '{hedefSonucu.hostDurumu}' olduğu için iLO doğrulanamadı.",
            kanitlar,
        )

    if hedefSonucu.portDurumu != "open":
        return _belirsizSonucOlustur(
            standartHedef,
            (
                f"{standartPort}/tcp port durumu '{hedefSonucu.portDurumu}' olduğu için "
                "iLO bilgisi alınamadı."
            ),
            kanitlar,
        )

    if hedefSonucu.iloTuru is None or hedefSonucu.firmwareSurumu is None:
        return _belirsizSonucOlustur(
            standartHedef,
            "HPE iLO türü ve firmware sürümü birlikte doğrulanamadı.",
            kanitlar,
        )

    return KontrolSonucu(
        kontrolKimligi=KONTROL_KIMLIGI,
        hedef=standartHedef,
        durum=ResultStatus.POTENTIALLY_VULNERABLE,
        ozet=(
            f"{hedefSonucu.iloTuru} firmware {hedefSonucu.firmwareSurumu} tespit edildi; "
            "sürüm tabanlı güvenlik incelemesi gerekiyor."
        ),
        kanitlar=kanitlar,
    )


def _kanitlariOlustur(hedefSonucu: HpeIloHedefSonucu) -> tuple[KanitBilgisi, ...]:
    # Host, port ve iLO surum alanlarini yapilandirilmis kanitlara cevirir.
    kanitlar = [
        KanitBilgisi(anahtar="hostDurumu", deger=hedefSonucu.hostDurumu),
        KanitBilgisi(anahtar="port", deger=str(hedefSonucu.port)),
        KanitBilgisi(anahtar="portDurumu", deger=hedefSonucu.portDurumu),
    ]
    if hedefSonucu.adresler:
        kanitlar.append(KanitBilgisi(anahtar="adresler", deger=",".join(hedefSonucu.adresler)))

    istegeBagliAlanlar = (
        ("servis", hedefSonucu.servisAdi),
        ("iloTuru", hedefSonucu.iloTuru),
        ("firmwareSurumu", hedefSonucu.firmwareSurumu),
        ("sunucuTuru", hedefSonucu.sunucuTuru),
        ("urunKimligi", hedefSonucu.urunKimligi),
    )
    kanitlar.extend(
        KanitBilgisi(anahtar=anahtar, deger=deger)
        for anahtar, deger in istegeBagliAlanlar
        if deger is not None
    )
    return tuple(kanitlar)


def _belirsizSonucOlustur(
    hedef: str,
    ozet: str,
    kanitlar: tuple[KanitBilgisi, ...],
) -> KontrolSonucu:
    # Eksik veya kesin olmayan iLO tespitleri icin ortak sonuc olusturur.
    return KontrolSonucu(
        kontrolKimligi=KONTROL_KIMLIGI,
        hedef=hedef,
        durum=ResultStatus.INCONCLUSIVE,
        ozet=ozet,
        kanitlar=kanitlar,
    )
