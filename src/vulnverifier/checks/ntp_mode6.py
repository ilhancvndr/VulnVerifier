# NTP Mode 6 READVAR sonucunu standart dogrulama sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_NTP_PORTU
from vulnverifier.nmap_ntp_mode6_parser import NtpMode6HedefSonucu, NtpMode6TaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "ntp-mode-6"


def ntpMode6SonucunuOlustur(
    taramaSonucu: NtpMode6TaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_NTP_PORTU,
) -> KontrolSonucu:
    # Mode 6 cevabini port durumuyla birlikte korumaci bicimde degerlendirir.
    if not isinstance(taramaSonucu, NtpMode6TaramaSonucu):
        raise ValueError("Geçerli bir NtpMode6TaramaSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenler = tuple(sonuc for sonuc in taramaSonucu.hedefSonuclari if sonuc.port == standartPort)
    if len(eslesenler) != 1:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.INCONCLUSIVE,
            "NTP Mode 6 için tek bir hedef sonucu bulunamadı.",
            (KanitBilgisi("eslesenSonucSayisi", str(len(eslesenler))),),
        )

    hedefSonucu = eslesenler[0]
    kanitlar = _kanitlariOlustur(hedefSonucu)
    if hedefSonucu.mode6CevabiAlindiMi is True:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            f"{standartPort}/udp NTP servisi Mode 6 READVAR sorgusuna cevap verdi.",
            kanitlar,
        )
    if hedefSonucu.mode6CevabiAlindiMi is False or hedefSonucu.portDurumu == "closed":
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.NOT_VULNERABLE,
            f"{standartPort}/udp üzerinde NTP Mode 6 READVAR cevabı alınmadı.",
            kanitlar,
        )
    return KontrolSonucu(
        KONTROL_KIMLIGI,
        standartHedef,
        ResultStatus.INCONCLUSIVE,
        "NTP Mode 6 cevap durumu kesin olarak belirlenemedi.",
        kanitlar,
    )


def _kanitlariOlustur(hedefSonucu: NtpMode6HedefSonucu) -> tuple[KanitBilgisi, ...]:
    # Port ve READVAR alanlarini yapilandirilmis kanitlara cevirir.
    cevapDurumu = {
        True: "received",
        False: "notReceived",
        None: "unknown",
    }[hedefSonucu.mode6CevabiAlindiMi]
    kanitlar = [
        KanitBilgisi("hostDurumu", hedefSonucu.hostDurumu),
        KanitBilgisi("port", str(hedefSonucu.port)),
        KanitBilgisi("protokol", "udp"),
        KanitBilgisi("portDurumu", hedefSonucu.portDurumu),
        KanitBilgisi("mode6Readvar", cevapDurumu),
    ]
    if hedefSonucu.adresler:
        kanitlar.append(KanitBilgisi("adresler", ",".join(hedefSonucu.adresler)))
    kanitlar.extend(
        KanitBilgisi("ntpDegiskeni", f"{alan.anahtar}={alan.deger}")
        for alan in hedefSonucu.degiskenler
    )
    return tuple(kanitlar)
