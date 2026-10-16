# Nmap MS17-010 sonucunu standart dogrulama sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_MS17010_PORTU
from vulnverifier.nmap_ms17010_parser import NmapMs17010TaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "ms17-010-nmap"


def ms17010NmapSonucunuOlustur(
    taramaSonucu: NmapMs17010TaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_MS17010_PORTU,
) -> KontrolSonucu:
    # NSE sonucunu kesinlik durumuna gore korumaci bicimde siniflandirir.
    if not isinstance(taramaSonucu, NmapMs17010TaramaSonucu):
        raise ValueError("Geçerli bir NmapMs17010TaramaSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenler = tuple(sonuc for sonuc in taramaSonucu.hedefSonuclari if sonuc.port == standartPort)
    kanitlar = [KanitBilgisi("port", str(standartPort))]
    if len(eslesenler) != 1:
        kanitlar.append(KanitBilgisi("eslesenSonucSayisi", str(len(eslesenler))))
        return _belirsizSonuc(standartHedef, tuple(kanitlar))
    sonuc = eslesenler[0]
    kanitlar.extend(
        [
            KanitBilgisi("portDurumu", sonuc.portDurumu),
            KanitBilgisi("adresler", ",".join(sonuc.adresler) or "-"),
            KanitBilgisi(
                "ms17010",
                f"{standartHedef}:{standartPort}|{_durumMetni(sonuc.savunmasizMi)}|{sonuc.detay}",
            ),
        ]
    )
    if sonuc.savunmasizMi is True:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            "MS17-010 zafiyeti Nmap NSE ile doğrulandı.",
            tuple(kanitlar),
        )
    if sonuc.savunmasizMi is False:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.NOT_VULNERABLE,
            "Nmap NSE sonucuna göre hedef MS17-010 zafiyetinden etkilenmiyor.",
            tuple(kanitlar),
        )
    return _belirsizSonuc(standartHedef, tuple(kanitlar))


def _durumMetni(savunmasizMi: bool | None) -> str:
    # Uc durumlu sonucu evidence icin sabit metne cevirir.
    return {True: "vulnerable", False: "notVulnerable", None: "unknown"}[savunmasizMi]


def _belirsizSonuc(hedef: str, kanitlar: tuple[KanitBilgisi, ...]) -> KontrolSonucu:
    # Kesin NSE sonucu bulunmayan hedefi temiz kabul etmez.
    return KontrolSonucu(
        KONTROL_KIMLIGI,
        hedef,
        ResultStatus.INCONCLUSIVE,
        "MS17-010 zafiyet durumu Nmap NSE ile kesin olarak belirlenemedi.",
        kanitlar,
    )
