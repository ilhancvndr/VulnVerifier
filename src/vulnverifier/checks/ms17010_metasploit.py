# Metasploit MS17-010 sonucunu standart dogrulama sonucuna donusturur.

from vulnverifier.metasploit_adapter import VARSAYILAN_MS17010_PORTU
from vulnverifier.metasploit_ms17010_parser import MetasploitMs17010Sonucu
from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "ms17-010-metasploit"


def ms17010MetasploitSonucunuOlustur(
    taramaSonucu: MetasploitMs17010Sonucu,
    hedef: str,
    port: str | int = VARSAYILAN_MS17010_PORTU,
) -> KontrolSonucu:
    # Hedef sonuclarini korumaci kuralla birlestirir.
    if not isinstance(taramaSonucu, MetasploitMs17010Sonucu):
        raise ValueError("Geçerli bir MetasploitMs17010Sonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    durumMetinleri = {True: "vulnerable", False: "notVulnerable", None: "unknown"}
    kanitlar = [KanitBilgisi("port", str(standartPort))]
    kanitlar.extend(
        KanitBilgisi(
            "ms17010",
            f"{sonuc.taramaNoktasi}|{durumMetinleri[sonuc.savunmasizMi]}|{sonuc.detay}",
        )
        for sonuc in taramaSonucu.hedefSonuclari
    )
    savunmasizlar = tuple(
        sonuc.taramaNoktasi for sonuc in taramaSonucu.hedefSonuclari if sonuc.savunmasizMi is True
    )
    if savunmasizlar:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            f"MS17-010 zafiyeti doğrulandı: {', '.join(savunmasizlar)}.",
            tuple(kanitlar),
        )
    if taramaSonucu.hedefSonuclari and all(
        sonuc.savunmasizMi is False for sonuc in taramaSonucu.hedefSonuclari
    ):
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.NOT_VULNERABLE,
            "Hedef MS17-010 zafiyetinden etkilenmiyor.",
            tuple(kanitlar),
        )
    return KontrolSonucu(
        KONTROL_KIMLIGI,
        standartHedef,
        ResultStatus.INCONCLUSIVE,
        "MS17-010 zafiyet durumu kesin olarak belirlenemedi.",
        tuple(kanitlar),
    )
