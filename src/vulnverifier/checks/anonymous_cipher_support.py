# Anonymous TLS cipher sonucunu standart kontrol sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula
from vulnverifier.testssl_adapter import VARSAYILAN_SSL_PORTU
from vulnverifier.testssl_cipher_parser import TestsslAnonymousCipherSonucu

KONTROL_KIMLIGI = "anonymous-cipher-support"


class AnonymousCipherDegerlendirmeHatasi(ValueError):
    # Degerlendirme islevine gecersiz tarama sonucu verildiginde olusan hatadir.
    pass


def anonymousCipherSonucunuOlustur(
    taramaSonucu: TestsslAnonymousCipherSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_SSL_PORTU,
) -> KontrolSonucu:
    # Tum IP sonuclarini korumaci kuralla birlestirip tek kontrol sonucu uretir.
    if not isinstance(taramaSonucu, TestsslAnonymousCipherSonucu):
        raise AnonymousCipherDegerlendirmeHatasi(
            "Geçerli bir TestsslAnonymousCipherSonucu gereklidir."
        )

    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    kanitlar = [KanitBilgisi(anahtar="port", deger=str(standartPort))]
    for hedefSonucu in taramaSonucu.hedefSonuclari:
        if hedefSonucu.durum is None:
            kanitDegeri = f"{hedefSonucu.taramaNoktasi}|unknown|sonuc bulunamadi"
        else:
            durumMetni = {
                True: "offered",
                False: "notOffered",
                None: "unknown",
            }[hedefSonucu.durum.sunuluyorMu]
            kanitDegeri = f"{hedefSonucu.taramaNoktasi}|{durumMetni}|{hedefSonucu.durum.detay}"
        kanitlar.append(KanitBilgisi(anahtar="anonymousCipher", deger=kanitDegeri))

    sunulanHedefler = tuple(
        hedefSonucu.taramaNoktasi
        for hedefSonucu in taramaSonucu.hedefSonuclari
        if hedefSonucu.durum is not None and hedefSonucu.durum.sunuluyorMu is True
    )
    if sunulanHedefler:
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=standartHedef,
            durum=ResultStatus.VULNERABLE,
            ozet=(f"Anonymous TLS cipher desteği tespit edildi: {', '.join(sunulanHedefler)}."),
            kanitlar=tuple(kanitlar),
        )

    tumSonuclarKesinVeKapaliMi = bool(taramaSonucu.hedefSonuclari) and all(
        hedefSonucu.durum is not None and hedefSonucu.durum.sunuluyorMu is False
        for hedefSonucu in taramaSonucu.hedefSonuclari
    )
    if tumSonuclarKesinVeKapaliMi:
        hedefSayisi = len(taramaSonucu.hedefSonuclari)
        ozet = "Anonymous TLS cipher desteği sunulmuyor."
        if hedefSayisi > 1:
            ozet = f"{hedefSayisi} tarama noktasında anonymous TLS cipher desteği sunulmuyor."
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=standartHedef,
            durum=ResultStatus.NOT_VULNERABLE,
            ozet=ozet,
            kanitlar=tuple(kanitlar),
        )

    return KontrolSonucu(
        kontrolKimligi=KONTROL_KIMLIGI,
        hedef=standartHedef,
        durum=ResultStatus.INCONCLUSIVE,
        ozet="Anonymous TLS cipher desteği kesin olarak doğrulanamadı.",
        kanitlar=tuple(kanitlar),
    )
