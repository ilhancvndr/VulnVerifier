# FREAK sonucunu standart dogrulama sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula
from vulnverifier.testssl_adapter import VARSAYILAN_SSL_PORTU
from vulnverifier.testssl_freak_parser import TestsslFreakSonucu

KONTROL_KIMLIGI = "freak-export-rsa"


def freakSonucunuOlustur(
    taramaSonucu: TestsslFreakSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_SSL_PORTU,
) -> KontrolSonucu:
    # Coklu IP sonuclarini en riskli sonucu koruyacak bicimde birlestirir.
    if not isinstance(taramaSonucu, TestsslFreakSonucu):
        raise ValueError("Geçerli bir TestsslFreakSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    kanitlar = [KanitBilgisi("port", str(standartPort))]
    for hedefSonucu in taramaSonucu.hedefSonuclari:
        if hedefSonucu.durum is None:
            kanitDegeri = f"{hedefSonucu.taramaNoktasi}|unknown|sonuc bulunamadi"
        else:
            durumMetni = {
                True: "vulnerable",
                False: "notVulnerable",
                None: "unknown",
            }[hedefSonucu.durum.savunmasizMi]
            kanitDegeri = f"{hedefSonucu.taramaNoktasi}|{durumMetni}|{hedefSonucu.durum.detay}"
        kanitlar.append(KanitBilgisi("freak", kanitDegeri))
    savunmasizlar = tuple(
        hedefSonucu.taramaNoktasi
        for hedefSonucu in taramaSonucu.hedefSonuclari
        if hedefSonucu.durum is not None and hedefSonucu.durum.savunmasizMi is True
    )
    if savunmasizlar:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            f"FREAK zafiyeti doğrulandı: {', '.join(savunmasizlar)}.",
            tuple(kanitlar),
        )
    tumuGuvenliMi = bool(taramaSonucu.hedefSonuclari) and all(
        hedefSonucu.durum is not None and hedefSonucu.durum.savunmasizMi is False
        for hedefSonucu in taramaSonucu.hedefSonuclari
    )
    if tumuGuvenliMi:
        hedefSayisi = len(taramaSonucu.hedefSonuclari)
        ozet = "TLS servisi FREAK zafiyetinden etkilenmiyor."
        if hedefSayisi > 1:
            ozet = f"{hedefSayisi} tarama noktası FREAK zafiyetinden etkilenmiyor."
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.NOT_VULNERABLE,
            ozet,
            tuple(kanitlar),
        )
    return KontrolSonucu(
        KONTROL_KIMLIGI,
        standartHedef,
        ResultStatus.INCONCLUSIVE,
        "FREAK zafiyet durumu kesin olarak belirlenemedi.",
        tuple(kanitlar),
    )
