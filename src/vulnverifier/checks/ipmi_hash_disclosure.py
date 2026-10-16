# IPMI RAKP hash sonucunu standart dogrulama sonucuna donusturur.

import hashlib

from vulnverifier.metasploit_adapter import VARSAYILAN_IPMI_PORTU
from vulnverifier.metasploit_ipmi_hash_parser import MetasploitIpmiHashSonucu
from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "ipmi-v2-hash-disclosure"


def ipmiHashSonucunuOlustur(
    taramaSonucu: MetasploitIpmiHashSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_IPMI_PORTU,
) -> KontrolSonucu:
    # Hash bulunursa zafiyeti dogrular, hash bulunmamasini temiz sonuc saymaz.
    if not isinstance(taramaSonucu, MetasploitIpmiHashSonucu):
        raise ValueError("Geçerli bir MetasploitIpmiHashSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenHashler = tuple(
        kayit for kayit in taramaSonucu.hashKayitlari if kayit.port == standartPort
    )
    kanitlar = [
        KanitBilgisi("port", str(standartPort)),
        KanitBilgisi("protokol", "udp"),
    ]
    for kayit in eslesenHashler:
        parmakIzi = hashlib.sha256(f"{kayit.salt}:{kayit.sha1Hash}".encode()).hexdigest()
        kullaniciAdi = kayit.kullaniciAdi or "<bos>"
        kanitlar.append(
            KanitBilgisi(
                "ipmiHash",
                f"{kayit.taramaNoktasi}:{kayit.port}|{kullaniciAdi}|sha256:{parmakIzi}",
            )
        )
    kanitlar.extend(KanitBilgisi("detay", detay) for detay in taramaSonucu.detaylar)
    if eslesenHashler:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            f"{len(eslesenHashler)} IPMI 2.0 RAKP parola hash kaydı alındı.",
            tuple(kanitlar),
        )
    return KontrolSonucu(
        KONTROL_KIMLIGI,
        standartHedef,
        ResultStatus.INCONCLUSIVE,
        "IPMI 2.0 RAKP hash disclosure durumu kesin olarak belirlenemedi.",
        tuple(kanitlar),
    )
