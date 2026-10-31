# Virgullu komut satiri ve metin dosyasi hedeflerini guvenli bicimde hazirlar.

import ipaddress
import stat
from dataclasses import dataclass
from itertools import islice
from pathlib import Path

from vulnverifier.target_validation import TargetValidationError, hedefiDogrula

AZAMI_HEDEF_GIRDISI = 256
AZAMI_HEDEF_SAYISI = 4096
AZAMI_HEDEF_DOSYASI_BOYUTU = 1024 * 1024


class HedefGirdisiHatasi(ValueError):
    # Coklu hedef girdisi gecersiz veya guvensiz oldugunda olusan hatadir.
    pass


@dataclass(frozen=True, slots=True)
class HedefGrubu:
    # Bir ham girdinin tekil hedef mi yoksa CIDR blogu mu oldugunu korur.

    kaynakGirdi: str
    cidrMi: bool
    hedefler: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HedefHazirlamaSonucu:
    # Tekillestirilmis hedefleri ve kaynak gruplarini birlikte tasir.

    hedefler: tuple[str, ...]
    hedefGruplari: tuple[HedefGrubu, ...]


def hedefleriHazirla(
    hedefMetni: str | None,
    hedefDosyasi: str | Path | None = None,
) -> tuple[str, ...]:
    # Komut satiri ve dosya hedeflerini dogrular, birlestirir ve tekillestirir.
    return hedefleriGruplariylaHazirla(hedefMetni, hedefDosyasi).hedefler


def hedefleriGruplariylaHazirla(
    hedefMetni: str | None,
    hedefDosyasi: str | Path | None = None,
) -> HedefHazirlamaSonucu:
    # Hedefleri kaynak girdileriyle birlikte dogrular ve tekillestirir.
    hamHedefler: list[str] = []
    if hedefMetni is not None:
        hamHedefler.extend(_virgulluMetniAyir(hedefMetni, "--target"))
    if hedefDosyasi is not None:
        hamHedefler.extend(_hedefDosyasiniOku(hedefDosyasi))
    if not hamHedefler:
        raise HedefGirdisiHatasi("En az bir --target veya --target-file verilmelidir.")
    if len(hamHedefler) > AZAMI_HEDEF_GIRDISI:
        raise HedefGirdisiHatasi(f"En fazla {AZAMI_HEDEF_GIRDISI} hedef girdisi kullanılabilir.")

    standartHedefler: list[str] = []
    gorulenHedefler: set[str] = set()
    hedefGruplari: list[HedefGrubu] = []
    for hamHedef in hamHedefler:
        genisletilmisHedefler = _hedefGirdisiniGenislet(hamHedef)
        grupHedefleri: list[str] = []
        for standartHedef in genisletilmisHedefler:
            if standartHedef not in gorulenHedefler:
                standartHedefler.append(standartHedef)
                grupHedefleri.append(standartHedef)
                gorulenHedefler.add(standartHedef)
            if len(standartHedefler) > AZAMI_HEDEF_SAYISI:
                raise HedefGirdisiHatasi(
                    f"CIDR açılımı sonrası en fazla {AZAMI_HEDEF_SAYISI} hedef kullanılabilir."
                )
        hedefGruplari.append(
            HedefGrubu(
                kaynakGirdi=_hedefGrubuKaynaginiStandartlastir(hamHedef, genisletilmisHedefler),
                cidrMi="/" in hamHedef,
                hedefler=tuple(grupHedefleri),
            )
        )
    return HedefHazirlamaSonucu(tuple(standartHedefler), tuple(hedefGruplari))


def _hedefGrubuKaynaginiStandartlastir(
    hamHedef: str,
    genisletilmisHedefler: tuple[str, ...],
) -> str:
    # Ozetlerde kullanilacak tekil hedef veya CIDR metnini standartlastirir.
    if "/" in hamHedef:
        return str(ipaddress.ip_network(hamHedef, strict=True))
    return genisletilmisHedefler[0]


def _hedefGirdisiniGenislet(hamHedef: str) -> tuple[str, ...]:
    # Tek hedefi dogrular veya CIDR blogunu kullanilabilir IP adreslerine genisletir.
    if "/" not in hamHedef:
        try:
            return (hedefiDogrula(hamHedef),)
        except TargetValidationError as hata:
            raise HedefGirdisiHatasi(f"Geçersiz hedef '{hamHedef}': {hata}") from hata

    try:
        agBlogu = ipaddress.ip_network(hamHedef, strict=True)
    except ValueError as hata:
        raise HedefGirdisiHatasi(f"Geçersiz CIDR '{hamHedef}': {hata}") from hata

    adresler = tuple(islice(agBlogu.hosts(), AZAMI_HEDEF_SAYISI + 1))
    if len(adresler) > AZAMI_HEDEF_SAYISI:
        raise HedefGirdisiHatasi(
            f"CIDR açılımı sonrası en fazla {AZAMI_HEDEF_SAYISI} hedef kullanılabilir."
        )
    return tuple(adres.compressed for adres in adresler)


def _virgulluMetniAyir(metin: str, kaynak: str) -> tuple[str, ...]:
    # Virgulle ayrilmis hedefleri cevre bosluklarini temizleyerek ayirir.
    if not isinstance(metin, str) or not metin.strip():
        raise HedefGirdisiHatasi(f"{kaynak} değeri boş olamaz.")
    parcalar = tuple(parca.strip() for parca in metin.split(","))
    if any(not parca for parca in parcalar):
        raise HedefGirdisiHatasi(f"{kaynak} içinde boş hedef bulunamaz.")
    return parcalar


def _hedefDosyasiniOku(dosyaYolu: str | Path) -> tuple[str, ...]:
    # Normal ve sinirli boyuttaki metin dosyasindan hedefleri okur.
    yol = Path(dosyaYolu)
    try:
        dosyaBilgisi = yol.lstat()
    except OSError as hata:
        raise HedefGirdisiHatasi(f"Hedef dosyası okunamadı: {yol}") from hata
    if stat.S_ISLNK(dosyaBilgisi.st_mode) or not stat.S_ISREG(dosyaBilgisi.st_mode):
        raise HedefGirdisiHatasi(
            "Hedef dosyası sembolik bağlantı olmayan normal bir dosya olmalıdır."
        )
    if dosyaBilgisi.st_size > AZAMI_HEDEF_DOSYASI_BOYUTU:
        raise HedefGirdisiHatasi("Hedef dosyası izin verilen boyutu aşıyor.")
    try:
        satirlar = yol.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as hata:
        raise HedefGirdisiHatasi(f"Hedef dosyası UTF-8 olarak okunamadı: {yol}") from hata

    hedefler: list[str] = []
    for satirNumarasi, satir in enumerate(satirlar, start=1):
        temizSatir = satir.strip()
        if not temizSatir or temizSatir.startswith("#"):
            continue
        hedefler.extend(_virgulluMetniAyir(temizSatir, f"Hedef dosyası satır {satirNumarasi}"))
    return tuple(hedefler)
