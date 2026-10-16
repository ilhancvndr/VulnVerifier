# SSLv2 ve SSLv3 protokol destegi bulgusunu standart kontrol sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.testssl_adapter import VARSAYILAN_SSL_PORTU
from vulnverifier.testssl_parser import (
    ProtokolDurumu,
    ProtokolHedefSonucu,
    TestsslProtokolSonucu,
)

KONTROL_KIMLIGI = "sslv2-sslv3-support"


def sslProtokolSonucunuOlustur(
    taramaSonucu: TestsslProtokolSonucu,
    hedef: str,
    port: int = VARSAYILAN_SSL_PORTU,
) -> KontrolSonucu:
    # Tum IP sonuclarini korumaci kuralla birlestirip tek kontrol sonucu uretir.
    kanitlar = [KanitBilgisi("port", str(port))]
    for hedefSonucu in taramaSonucu.hedefSonuclari:
        eskiProtokoller = tuple(
            durum for durum in (hedefSonucu.sslV2, hedefSonucu.sslV3) if durum is not None
        )
        kanitlar.extend(_protokolKanitlariniOlustur(hedefSonucu.taramaNoktasi, eskiProtokoller))
        kanitlar.extend(
            _protokolKanitlariniOlustur(
                hedefSonucu.taramaNoktasi,
                hedefSonucu.modernTlsDurumlari,
            )
        )

    sunulanEskiProtokoller = tuple(
        (hedefSonucu.taramaNoktasi, durum.protokol)
        for hedefSonucu in taramaSonucu.hedefSonuclari
        for durum in (hedefSonucu.sslV2, hedefSonucu.sslV3)
        if durum is not None and durum.sunuluyorMu is True
    )
    if sunulanEskiProtokoller:
        protokolMetni = ", ".join(
            f"{protokol} ({taramaNoktasi})" for taramaNoktasi, protokol in sunulanEskiProtokoller
        )
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=hedef,
            durum=ResultStatus.VULNERABLE,
            ozet=f"Güvenli olmayan protokol desteği tespit edildi: {protokolMetni}.",
            kanitlar=tuple(kanitlar),
        )

    if taramaSonucu.hedefSonuclari and all(
        _hedefSonucuTemizMi(hedefSonucu) for hedefSonucu in taramaSonucu.hedefSonuclari
    ):
        hedefSayisi = len(taramaSonucu.hedefSonuclari)
        ozet = "SSLv2 ve SSLv3 sunulmuyor; TLS servisi doğrulandı."
        if hedefSayisi > 1:
            ozet = (
                f"{hedefSayisi} tarama noktasında SSLv2 ve SSLv3 sunulmuyor; "
                "TLS servisleri doğrulandı."
            )
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=hedef,
            durum=ResultStatus.NOT_VULNERABLE,
            ozet=ozet,
            kanitlar=tuple(kanitlar),
        )

    return KontrolSonucu(
        kontrolKimligi=KONTROL_KIMLIGI,
        hedef=hedef,
        durum=ResultStatus.INCONCLUSIVE,
        ozet="SSLv2 ve SSLv3 desteği kesin olarak doğrulanamadı.",
        kanitlar=tuple(kanitlar),
    )


def _protokolKanitlariniOlustur(
    taramaNoktasi: str,
    protokolDurumlari: tuple[ProtokolDurumu, ...],
) -> tuple[KanitBilgisi, ...]:
    # Protokol durumunu tarandigi IP veya baglanti noktasiyla birlikte kanita cevirir.
    durumMetinleri = {True: "offered", False: "notOffered", None: "unknown"}
    return tuple(
        KanitBilgisi(
            anahtar="protokol",
            deger=(
                f"{taramaNoktasi}|{durum.protokol}|"
                f"{durumMetinleri[durum.sunuluyorMu]}|{durum.detay}"
            ),
        )
        for durum in protokolDurumlari
    )


def _hedefSonucuTemizMi(hedefSonucu: ProtokolHedefSonucu) -> bool:
    # Eksik eski protokol veya dogrulanmamis TLS servisini temiz saymaz.
    eskiProtokoller = (hedefSonucu.sslV2, hedefSonucu.sslV3)
    eskiDurumlarKesinMi = all(
        durum is not None and durum.sunuluyorMu is False for durum in eskiProtokoller
    )
    modernTlsSunuluyorMu = any(
        durum.sunuluyorMu is True for durum in hedefSonucu.modernTlsDurumlari
    )
    return eskiDurumlarKesinMi and modernTlsSunuluyorMu
