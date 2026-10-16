# Harici araclarin calistirilabilir dosya yolunu sistem PATH degeri uzerinden bulur.

import shutil
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AracDurumu:
    # Bir harici aracin bulunma durumunu ve calistirilabilir dosya yolunu tasir.
    aracAdi: str
    bulunduMu: bool
    aracYolu: str | None


class AracDogrulamaHatasi(ValueError):
    # Gecersiz arac adi verildiginde olusan hatadir.
    pass


def araciKontrolEt(aracAdi: str) -> AracDurumu:
    # Araci PATH icinde arar ve sonucu standart bir modelle dondurur.
    if not isinstance(aracAdi, str) or not aracAdi or aracAdi != aracAdi.strip():
        raise AracDogrulamaHatasi("Araç adı boş olamaz veya çevresinde boşluk içeremez.")
    if "\x00" in aracAdi:
        raise AracDogrulamaHatasi("Araç adı null karakteri içeremez.")

    aracYolu = shutil.which(aracAdi)
    return AracDurumu(
        aracAdi=aracAdi,
        bulunduMu=aracYolu is not None,
        aracYolu=aracYolu,
    )
