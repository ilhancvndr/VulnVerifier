# VMware ESXi surum tespitini standart kontrol sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_VMWARE_PORTU
from vulnverifier.nmap_vmware_parser import VmwareSurumHedefSonucu, VmwareSurumTaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "vmware-esxi-version-detection"


def vmwareSurumSonucunuOlustur(
    taramaSonucu: VmwareSurumTaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_VMWARE_PORTU,
) -> KontrolSonucu:
    # VMware surum bilgisini kesin zafiyet saymadan standart sonuca cevirir.
    if not isinstance(taramaSonucu, VmwareSurumTaramaSonucu):
        raise ValueError("Geçerli bir VmwareSurumTaramaSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenler = tuple(sonuc for sonuc in taramaSonucu.hedefSonuclari if sonuc.port == standartPort)
    if len(eslesenler) != 1:
        return _belirsizSonuc(
            standartHedef,
            f"Nmap çıktısında {standartPort}/tcp için tek bir hedef sonucu bulunamadı.",
            (KanitBilgisi("eslesenSonucSayisi", str(len(eslesenler))),),
        )
    hedefSonucu = eslesenler[0]
    kanitlar = _kanitlariOlustur(hedefSonucu)
    if hedefSonucu.portDurumu != "open":
        return _belirsizSonuc(
            standartHedef,
            f"{standartPort}/tcp port durumu '{hedefSonucu.portDurumu}'.",
            kanitlar,
        )
    if hedefSonucu.urunAdi is None or hedefSonucu.surum is None:
        return _belirsizSonuc(
            standartHedef,
            "VMware ürün ve sürüm bilgisi birlikte doğrulanamadı.",
            kanitlar,
        )
    return KontrolSonucu(
        kontrolKimligi=KONTROL_KIMLIGI,
        hedef=standartHedef,
        durum=ResultStatus.POTENTIALLY_VULNERABLE,
        ozet=(
            f"{hedefSonucu.urunAdi} {hedefSonucu.surum}"
            f" build {hedefSonucu.build or 'bilinmiyor'} tespit edildi; "
            "sürüm tabanlı güvenlik incelemesi gerekiyor."
        ),
        kanitlar=kanitlar,
    )


def _kanitlariOlustur(hedefSonucu: VmwareSurumHedefSonucu) -> tuple[KanitBilgisi, ...]:
    # VMware hedef alanlarini yapilandirilmis kanitlara cevirir.
    alanlar = [
        KanitBilgisi("hostDurumu", hedefSonucu.hostDurumu),
        KanitBilgisi("port", str(hedefSonucu.port)),
        KanitBilgisi("portDurumu", hedefSonucu.portDurumu),
    ]
    if hedefSonucu.adresler:
        alanlar.append(KanitBilgisi("adresler", ",".join(hedefSonucu.adresler)))
    for anahtar, deger in (
        ("servis", hedefSonucu.servisAdi),
        ("urun", hedefSonucu.urunAdi),
        ("surum", hedefSonucu.surum),
        ("build", hedefSonucu.build),
        ("localeSurumu", hedefSonucu.localeSurumu),
        ("isletimSistemiTuru", hedefSonucu.isletimSistemiTuru),
        ("urunHattiKimligi", hedefSonucu.urunHattiKimligi),
    ):
        if deger is not None:
            alanlar.append(KanitBilgisi(anahtar, deger))
    return tuple(alanlar)


def _belirsizSonuc(
    hedef: str,
    ozet: str,
    kanitlar: tuple[KanitBilgisi, ...],
) -> KontrolSonucu:
    # Kesin olmayan VMware tespitleri icin ortak sonuc olusturur.
    return KontrolSonucu(KONTROL_KIMLIGI, hedef, ResultStatus.INCONCLUSIVE, ozet, kanitlar)
