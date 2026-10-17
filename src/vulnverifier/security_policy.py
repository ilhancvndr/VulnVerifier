# Hedef kapsami, kontrol riski ve eszamanlilik icin merkezi guvenlik politikasini uygular.

import ipaddress
import threading
from collections.abc import Callable, Sequence
from functools import wraps

from vulnverifier.models import CheckDefinition, KontrolEtkisi, RiskLevel
from vulnverifier.target_validation import TargetValidationError, hedefiDogrula

AZAMI_ESZAMANLI_KONTROL = 1
AZAMI_KAPSAM_GIRDISI = 256
_kontrolSemaforu = threading.BoundedSemaphore(AZAMI_ESZAMANLI_KONTROL)


class GuvenlikPolitikasiHatasi(ValueError):
    # Hedef veya kontrol merkezi guvenlik politikasina uymadiginda olusan hatadir.
    pass


def guvenlikPolitikasiniDogrula(
    kontrolTanimi: CheckDefinition,
    hedef: str,
    izinliHedefler: Sequence[str] | None,
    intrusiveOnayi: bool,
) -> None:
    # Kontrolu yalnizca izinli hedefte, salt okunur etkide ve gerekli onayla calistirir.
    if not isinstance(kontrolTanimi, CheckDefinition):
        raise GuvenlikPolitikasiHatasi("Gecerli bir kontrol tanimi gereklidir.")

    try:
        standartHedef = hedefiDogrula(hedef)
    except TargetValidationError as hata:
        raise GuvenlikPolitikasiHatasi("Guvenlik politikasi gecersiz hedefi reddetti.") from hata
    if isinstance(izinliHedefler, (str, bytes)):
        raise GuvenlikPolitikasiHatasi("Allowlist bir hedef listesi olarak verilmelidir.")
    etkinIzinliHedefler = tuple(izinliHedefler) if izinliHedefler else (standartHedef,)
    if len(etkinIzinliHedefler) > AZAMI_KAPSAM_GIRDISI:
        raise GuvenlikPolitikasiHatasi(
            f"En fazla {AZAMI_KAPSAM_GIRDISI} allowlist girdisi kullanilabilir."
        )
    kapsamSonuclari = tuple(
        _hedefKapsamdaMi(standartHedef, kapsam) for kapsam in etkinIzinliHedefler
    )
    if not any(kapsamSonuclari):
        raise GuvenlikPolitikasiHatasi(f"Hedef izinli kapsam listesinde degil: {standartHedef}")

    if kontrolTanimi.kontrolEtkisi is not KontrolEtkisi.READ_ONLY:
        raise GuvenlikPolitikasiHatasi(
            f"Hedefte degisiklik, DoS veya exploit etkili kontrol engellendi: "
            f"{kontrolTanimi.kontrolKimligi}"
        )
    if kontrolTanimi.riskSeviyesi is RiskLevel.INTRUSIVE and intrusiveOnayi is not True:
        raise GuvenlikPolitikasiHatasi(
            "Intrusive kontrol varsayilan olarak kapalidir; calistirmak icin "
            "--confirm-intrusive gereklidir."
        )


def eszamanliKontroluSinirla[**ParametrelerT, DonusT](
    fonksiyon: Callable[ParametrelerT, DonusT],
) -> Callable[ParametrelerT, DonusT]:
    # Ayni uygulama surecinde ayni anda yalnizca sinirli sayida kontrol calistirir.
    @wraps(fonksiyon)
    def sinirliFonksiyon(*args: ParametrelerT.args, **kwargs: ParametrelerT.kwargs) -> DonusT:
        with _kontrolSemaforu:
            return fonksiyon(*args, **kwargs)

    return sinirliFonksiyon


def _hedefKapsamdaMi(standartHedef: str, kapsam: str) -> bool:
    # Tek hedefi tam eslesmeyle, IP adresini ayrica CIDR uyeligiyle denetler.
    if not isinstance(kapsam, str) or not kapsam or kapsam != kapsam.strip():
        raise GuvenlikPolitikasiHatasi("Allowlist girdisi bos veya boslukla cevrili olamaz.")

    if "/" not in kapsam:
        try:
            return hedefiDogrula(kapsam) == standartHedef
        except TargetValidationError as hata:
            raise GuvenlikPolitikasiHatasi(f"Gecersiz allowlist hedefi: {kapsam}") from hata

    try:
        ag = ipaddress.ip_network(kapsam, strict=False)
    except ValueError as hata:
        raise GuvenlikPolitikasiHatasi(f"Gecersiz allowlist CIDR degeri: {kapsam}") from hata
    try:
        hedefAdresi = ipaddress.ip_address(standartHedef)
    except ValueError:
        return False
    return hedefAdresi.version == ag.version and hedefAdresi in ag
