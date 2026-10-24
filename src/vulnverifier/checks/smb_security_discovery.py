# SMBv1 ve SMB imzalama kesif sonucunu standart kontrol sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_adapter import VARSAYILAN_SMB_PORTU
from vulnverifier.nmap_smb_security_parser import (
    SmbGuvenlikHedefSonucu,
    SmbGuvenlikTaramaSonucu,
)
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "smb-security-discovery"


def smbGuvenlikSonucunuOlustur(
    taramaSonucu: SmbGuvenlikTaramaSonucu,
    hedef: str,
    port: str | int = VARSAYILAN_SMB_PORTU,
) -> KontrolSonucu:
    # SMBv1 ve imzalama durumunu korumaci bir karar kuralina gore siniflandirir.
    if not isinstance(taramaSonucu, SmbGuvenlikTaramaSonucu):
        raise ValueError("Geçerli bir SmbGuvenlikTaramaSonucu gereklidir.")
    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)
    eslesenler = tuple(sonuc for sonuc in taramaSonucu.hedefSonuclari if sonuc.port == standartPort)
    if len(eslesenler) != 1:
        return _belirsizSonuc(
            standartHedef,
            "Nmap çıktısında SMB hedef sonucu tekilleştirilemedi.",
            (KanitBilgisi("eslesenSonucSayisi", str(len(eslesenler))),),
        )
    sonuc = eslesenler[0]
    kanitlar = _kanitlariOlustur(sonuc)
    if sonuc.portDurumu == "closed":
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.NOT_VULNERABLE,
            f"{standartPort}/tcp portu kapalı; SMB servisi erişilebilir değil.",
            kanitlar,
        )
    if sonuc.portDurumu != "open":
        return _belirsizSonuc(
            standartHedef,
            f"{standartPort}/tcp port durumu '{sonuc.portDurumu}'.",
            kanitlar,
        )
    zayifliklar = _zayifliklariBul(sonuc)
    if zayifliklar:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.VULNERABLE,
            "SMB güvenlik zayıflığı tespit edildi: " + "; ".join(zayifliklar) + ".",
            kanitlar,
        )
    if sonuc.smbV1EtkinMi is False and sonuc.imzalamaZorunluMu is True:
        return KontrolSonucu(
            KONTROL_KIMLIGI,
            standartHedef,
            ResultStatus.NOT_VULNERABLE,
            "SMBv1 sunulmuyor ve SMB imzalama zorunlu.",
            kanitlar,
        )
    return _belirsizSonuc(
        standartHedef,
        "SMBv1 ve SMB imzalama durumu birlikte kesinleştirilemedi.",
        kanitlar,
    )


def _zayifliklariBul(sonuc: SmbGuvenlikHedefSonucu) -> tuple[str, ...]:
    # Kesin olarak gozlenen SMB guvenlik zayifliklarini listeler.
    zayifliklar: list[str] = []
    if sonuc.smbV1EtkinMi is True:
        zayifliklar.append("SMBv1 etkin")
    if sonuc.imzalamaZorunluMu is False:
        zayifliklar.append("SMB imzalama zorunlu değil")
    return tuple(zayifliklar)


def _kanitlariOlustur(sonuc: SmbGuvenlikHedefSonucu) -> tuple[KanitBilgisi, ...]:
    # SMB kesif alanlarini CLI ve evidence icin ortak kanitlara cevirir.
    kanitlar = [
        KanitBilgisi("hostDurumu", sonuc.hostDurumu),
        KanitBilgisi("adresler", ",".join(sonuc.adresler) or "-"),
        KanitBilgisi("port", str(sonuc.port)),
        KanitBilgisi("portDurumu", sonuc.portDurumu),
    ]
    for anahtar, deger in (
        ("servis", sonuc.servisAdi),
        ("bilgisayarAdi", sonuc.bilgisayarAdi),
        ("isletimSistemi", sonuc.isletimSistemi),
        ("domain", sonuc.domain),
        ("fqdn", sonuc.fqdn),
    ):
        if deger is not None:
            kanitlar.append(KanitBilgisi(anahtar, deger))
    kanitlar.append(KanitBilgisi("smbV1", _ucDurumluMetin(sonuc.smbV1EtkinMi)))
    kanitlar.append(KanitBilgisi("imzalamaZorunlu", _ucDurumluMetin(sonuc.imzalamaZorunluMu)))
    kanitlar.append(KanitBilgisi("imzalamaEtkin", _ucDurumluMetin(sonuc.imzalamaEtkinMi)))
    for surum in sonuc.smbSurumleri:
        kanitlar.append(KanitBilgisi("smbSurumu", surum))
    return tuple(kanitlar)


def _ucDurumluMetin(deger: bool | None) -> str:
    # True, false ve bilinmeyen degerlerini sabit kanit metnine cevirir.
    return {True: "true", False: "false", None: "unknown"}[deger]


def _belirsizSonuc(
    hedef: str,
    ozet: str,
    kanitlar: tuple[KanitBilgisi, ...],
) -> KontrolSonucu:
    # Eksik veya kesin olmayan SMB bulgularini temiz kabul etmez.
    return KontrolSonucu(KONTROL_KIMLIGI, hedef, ResultStatus.INCONCLUSIVE, ozet, kanitlar)
