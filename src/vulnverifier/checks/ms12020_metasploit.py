# Metasploit MS12-020 tarama sonucunu standart kontrol sonucuna donusturur.

from vulnverifier.metasploit_adapter import VARSAYILAN_MS12020_PORTU
from vulnverifier.metasploit_ms12020_parser import MetasploitMs12020Sonucu
from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "ms12-020-metasploit"


class Ms12020MetasploitDegerlendirmeHatasi(ValueError):
    # Degerlendirme islevine gecersiz tarama sonucu verildiginde olusan hatadir.
    pass


def ms12020MetasploitSonucunuOlustur(
    taramaSonucu: MetasploitMs12020Sonucu,
    hedef: str,
    port: str | int = VARSAYILAN_MS12020_PORTU,
) -> KontrolSonucu:
    # Hedef sonuclarini korumaci kuralla birlestirip tek kontrol sonucu uretir.
    if not isinstance(taramaSonucu, MetasploitMs12020Sonucu):
        raise Ms12020MetasploitDegerlendirmeHatasi(
            "Geçerli bir MetasploitMs12020Sonucu gereklidir."
        )

    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    kanitlar = [KanitBilgisi(anahtar="port", deger=str(standartPort))]
    durumMetinleri = {True: "vulnerable", False: "notVulnerable", None: "unknown"}
    kanitlar.extend(
        KanitBilgisi(
            anahtar="ms12020",
            deger=(
                f"{hedefSonucu.taramaNoktasi}|"
                f"{durumMetinleri[hedefSonucu.savunmasizMi]}|{hedefSonucu.detay}"
            ),
        )
        for hedefSonucu in taramaSonucu.hedefSonuclari
    )

    savunmasizHedefler = tuple(
        hedefSonucu.taramaNoktasi
        for hedefSonucu in taramaSonucu.hedefSonuclari
        if hedefSonucu.savunmasizMi is True
    )
    if savunmasizHedefler:
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=standartHedef,
            durum=ResultStatus.VULNERABLE,
            ozet=f"MS12-020 zafiyeti doğrulandı: {', '.join(savunmasizHedefler)}.",
            kanitlar=tuple(kanitlar),
        )

    tumSonuclarGuvenliMi = bool(taramaSonucu.hedefSonuclari) and all(
        hedefSonucu.savunmasizMi is False for hedefSonucu in taramaSonucu.hedefSonuclari
    )
    if tumSonuclarGuvenliMi:
        hedefSayisi = len(taramaSonucu.hedefSonuclari)
        ozet = "Hedef MS12-020 zafiyetinden etkilenmiyor."
        if hedefSayisi > 1:
            ozet = f"{hedefSayisi} tarama noktası MS12-020 zafiyetinden etkilenmiyor."
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
        ozet="MS12-020 zafiyet durumu kesin olarak belirlenemedi.",
        kanitlar=tuple(kanitlar),
    )
