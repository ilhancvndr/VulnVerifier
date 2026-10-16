# OpenSSL CCS Injection sonucunu standart dogrulama sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula
from vulnverifier.testssl_adapter import VARSAYILAN_SSL_PORTU
from vulnverifier.testssl_ccs_parser import CcsHedefSonucu, TestsslCcsSonucu

KONTROL_KIMLIGI = "openssl-ccs-injection"


def ccsInjectionSonucunuOlustur(
    taramaSonucu: TestsslCcsSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_SSL_PORTU,
) -> KontrolSonucu:
    # Coklu IP sonuclarini en riskli ve en kesin sonucu koruyarak birlestirir.
    if not isinstance(taramaSonucu, TestsslCcsSonucu):
        raise ValueError("Geçerli bir TestsslCcsSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    kanitlar = [KanitBilgisi("port", str(standartPort))]
    for hedefSonucu in taramaSonucu.hedefSonuclari:
        kanitlar.append(KanitBilgisi("ccsInjection", _kanitDegeriniOlustur(hedefSonucu)))

    kesinSavunmasizlar = tuple(
        sonuc.taramaNoktasi
        for sonuc in taramaSonucu.hedefSonuclari
        if sonuc.durum is not None and sonuc.durum.savunmasizMi is True and sonuc.durum.kesinMi
    )
    if kesinSavunmasizlar:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            f"OpenSSL CCS Injection zafiyeti doğrulandı: {', '.join(kesinSavunmasizlar)}.",
            tuple(kanitlar),
        )

    olasiSavunmasizlar = tuple(
        sonuc.taramaNoktasi
        for sonuc in taramaSonucu.hedefSonuclari
        if sonuc.durum is not None and sonuc.durum.savunmasizMi is True and not sonuc.durum.kesinMi
    )
    if olasiSavunmasizlar:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.POTENTIALLY_VULNERABLE,
            f"OpenSSL CCS Injection zafiyeti olası görünüyor: {', '.join(olasiSavunmasizlar)}.",
            tuple(kanitlar),
        )

    tumuKesinGuvenliMi = bool(taramaSonucu.hedefSonuclari) and all(
        sonuc.durum is not None and sonuc.durum.savunmasizMi is False and sonuc.durum.kesinMi
        for sonuc in taramaSonucu.hedefSonuclari
    )
    if tumuKesinGuvenliMi:
        hedefSayisi = len(taramaSonucu.hedefSonuclari)
        ozet = "TLS servisi OpenSSL CCS Injection zafiyetinden etkilenmiyor."
        if hedefSayisi > 1:
            ozet = f"{hedefSayisi} tarama noktası CCS Injection zafiyetinden etkilenmiyor."
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
        "OpenSSL CCS Injection zafiyet durumu kesin olarak belirlenemedi.",
        tuple(kanitlar),
    )


def _kanitDegeriniOlustur(hedefSonucu: CcsHedefSonucu) -> str:
    # Hedef sonucunu hassas veri icermeyen tek satirlik kanita donusturur.
    taramaNoktasi = hedefSonucu.taramaNoktasi
    durum = hedefSonucu.durum
    if durum is None:
        return f"{taramaNoktasi}|unknown|sonuc bulunamadi"
    if durum.savunmasizMi is True:
        durumMetni = "vulnerable" if durum.kesinMi else "potentiallyVulnerable"
    elif durum.savunmasizMi is False and durum.kesinMi:
        durumMetni = "notVulnerable"
    else:
        durumMetni = "unknown"
    return f"{taramaNoktasi}|{durumMetni}|{durum.detay}"
