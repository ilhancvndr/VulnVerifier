# SNMP public community tarama sonucunu standart kontrol sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_SNMP_PORTU
from vulnverifier.nmap_snmp_parser import SnmpPublicHedefSonucu, SnmpPublicTaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "snmp-public-community"


class SnmpPublicDegerlendirmeHatasi(ValueError):
    # Degerlendirme islevine gecersiz SNMP tarama sonucu verildiginde olusan hatadir.
    pass


def snmpPublicSonucunuOlustur(
    taramaSonucu: SnmpPublicTaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_SNMP_PORTU,
) -> KontrolSonucu:
    # Ayristirilmis SNMP sonucunu korumaci kurallarla standart sonuca cevirir.
    if not isinstance(taramaSonucu, SnmpPublicTaramaSonucu):
        raise SnmpPublicDegerlendirmeHatasi("Geçerli bir SnmpPublicTaramaSonucu gereklidir.")

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
            f"Nmap çıktısında {standartPort}/udp için tek bir hedef sonucu bulunamadı.",
            (
                KanitBilgisi(anahtar="port", deger=str(standartPort)),
                KanitBilgisi(anahtar="eslesenSonucSayisi", deger=str(len(eslesenSonuclar))),
            ),
        )

    hedefSonucu = eslesenSonuclar[0]
    kanitlar = _kanitlariOlustur(hedefSonucu)
    if hedefSonucu.publicCommunityKabulEdildiMi is True:
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=standartHedef,
            durum=ResultStatus.VULNERABLE,
            ozet=f"{standartPort}/udp üzerinde SNMP public community kabul edildi.",
            kanitlar=kanitlar,
        )

    return _belirsizSonucOlustur(
        standartHedef,
        (f"{standartPort}/udp üzerinde SNMP public community kabulü kesin olarak doğrulanamadı."),
        kanitlar,
    )


def _kanitlariOlustur(hedefSonucu: SnmpPublicHedefSonucu) -> tuple[KanitBilgisi, ...]:
    # Host, port ve public community alanlarini yapilandirilmis kanitlara cevirir.
    kanitlar = [
        KanitBilgisi(anahtar="hostDurumu", deger=hedefSonucu.hostDurumu),
        KanitBilgisi(anahtar="port", deger=str(hedefSonucu.port)),
        KanitBilgisi(anahtar="protokol", deger="udp"),
        KanitBilgisi(anahtar="portDurumu", deger=hedefSonucu.portDurumu),
        KanitBilgisi(
            anahtar="publicCommunity",
            deger=("accepted" if hedefSonucu.publicCommunityKabulEdildiMi is True else "unknown"),
        ),
    ]
    if hedefSonucu.adresler:
        kanitlar.append(KanitBilgisi(anahtar="adresler", deger=",".join(hedefSonucu.adresler)))
    istegeBagliAlanlar = (
        ("servis", hedefSonucu.servisAdi),
        ("sistemAciklamasi", hedefSonucu.sistemAciklamasi),
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
    # Kesin olarak dogrulanamayan SNMP sonuclari icin ortak sonuc olusturur.
    return KontrolSonucu(
        kontrolKimligi=KONTROL_KIMLIGI,
        hedef=hedef,
        durum=ResultStatus.INCONCLUSIVE,
        ozet=ozet,
        kanitlar=kanitlar,
    )
