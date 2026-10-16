# Nmap MS12-020 sonucunu standart dogrulama sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_MS12020_PORTU
from vulnverifier.nmap_ms12020_parser import NmapMs12020TaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "ms12-020-nmap"


def ms12020NmapSonucunuOlustur(
    taramaSonucu: NmapMs12020TaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_MS12020_PORTU,
) -> KontrolSonucu:
    # NSE sonuclarini korumaci kuralla tek dogrulama sonucunda birlestirir.
    if not isinstance(taramaSonucu, NmapMs12020TaramaSonucu):
        raise ValueError("Geçerli bir NmapMs12020TaramaSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenler = tuple(sonuc for sonuc in taramaSonucu.hedefSonuclari if sonuc.port == standartPort)
    kanitlar = [KanitBilgisi("port", str(standartPort))]
    if len(eslesenler) != 1:
        kanitlar.append(KanitBilgisi("eslesenSonucSayisi", str(len(eslesenler))))
        return _belirsizSonuc(standartHedef, tuple(kanitlar))
    hedefSonucu = eslesenler[0]
    kanitlar.extend(
        [
            KanitBilgisi("portDurumu", hedefSonucu.portDurumu),
            KanitBilgisi("adresler", ",".join(hedefSonucu.adresler) or "-"),
        ]
    )
    for zafiyetSonucu in hedefSonucu.zafiyetSonuclari:
        kanitlar.append(
            KanitBilgisi(
                "ms12020",
                f"{zafiyetSonucu.cve}|{_durumMetni(zafiyetSonucu.savunmasizMi)}|"
                f"{zafiyetSonucu.detay}",
            )
        )
    if any(sonuc.savunmasizMi is True for sonuc in hedefSonucu.zafiyetSonuclari):
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            "MS12-020 zafiyeti Nmap NSE ile doğrulandı.",
            tuple(kanitlar),
        )
    if hedefSonucu.zafiyetSonuclari and all(
        sonuc.savunmasizMi is False for sonuc in hedefSonucu.zafiyetSonuclari
    ):
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.NOT_VULNERABLE,
            "Nmap NSE sonucuna göre hedef MS12-020 zafiyetinden etkilenmiyor.",
            tuple(kanitlar),
        )
    return _belirsizSonuc(standartHedef, tuple(kanitlar))


def _durumMetni(savunmasizMi: bool | None) -> str:
    # Uc durumlu sonucu evidence icin sabit metne cevirir.
    return {True: "vulnerable", False: "notVulnerable", None: "unknown"}[savunmasizMi]


def _belirsizSonuc(hedef: str, kanitlar: tuple[KanitBilgisi, ...]) -> KontrolSonucu:
    # Eksik veya guvenilmez NSE sonucunu temiz kabul etmez.
    return KontrolSonucu(
        KONTROL_KIMLIGI,
        hedef,
        ResultStatus.INCONCLUSIVE,
        "MS12-020 zafiyet durumu Nmap NSE ile kesin olarak belirlenemedi.",
        kanitlar,
    )
