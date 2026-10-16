# DNS cache snooping sonucunu standart dogrulama sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_DNS_PORTU
from vulnverifier.nmap_dns_cache_parser import DnsCacheTaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "dns-cache-snooping"


def dnsCacheSonucunuOlustur(
    taramaSonucu: DnsCacheTaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_DNS_PORTU,
) -> KontrolSonucu:
    # Cache alan adi bulunursa zafiyeti dogrular, diger durumlari belirsiz birakir.
    if not isinstance(taramaSonucu, DnsCacheTaramaSonucu):
        raise ValueError("Geçerli bir DnsCacheTaramaSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenler = tuple(sonuc for sonuc in taramaSonucu.hedefSonuclari if sonuc.port == standartPort)
    if len(eslesenler) != 1:
        return _belirsizSonuc(
            standartHedef,
            "DNS cache snooping için tek bir hedef sonucu bulunamadı.",
            (KanitBilgisi("eslesenSonucSayisi", str(len(eslesenler))),),
        )
    sonuc = eslesenler[0]
    kanitlar = [
        KanitBilgisi("port", str(sonuc.port)),
        KanitBilgisi("protokol", "udp"),
        KanitBilgisi("portDurumu", sonuc.portDurumu),
    ]
    if sonuc.testEdilenAlanAdiSayisi is not None:
        kanitlar.append(KanitBilgisi("testEdilenAlanAdiSayisi", str(sonuc.testEdilenAlanAdiSayisi)))
    kanitlar.extend(
        KanitBilgisi("cacheAlanAdi", alanAdi) for alanAdi in sonuc.onbellektekiAlanAdlari
    )
    if sonuc.onbellektekiAlanAdlari:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            f"DNS önbelleğinde {len(sonuc.onbellektekiAlanAdlari)} alan adı uzaktan doğrulandı.",
            tuple(kanitlar),
        )
    return _belirsizSonuc(
        standartHedef,
        "DNS cache snooping kesin olarak doğrulanamadı.",
        tuple(kanitlar),
    )


def _belirsizSonuc(hedef: str, ozet: str, kanitlar: tuple[KanitBilgisi, ...]) -> KontrolSonucu:
    # Kesin olmayan DNS cache sonuclari icin ortak sonuc olusturur.
    return KontrolSonucu(KONTROL_KIMLIGI, hedef, ResultStatus.INCONCLUSIVE, ozet, kanitlar)
