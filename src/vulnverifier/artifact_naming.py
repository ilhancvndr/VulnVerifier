# Evidence ve ekran goruntusu dosyalari icin ortak, guvenli adlar olusturur.

import re
from datetime import datetime
from zoneinfo import ZoneInfo

from vulnverifier.models import KontrolSonucu

TURKIYE_SAAT_DILIMI = ZoneInfo("Europe/Istanbul")
AZAMI_HEDEF_PARCA_UZUNLUGU = 80
AZAMI_KONTROL_PARCA_UZUNLUGU = 60


def artifactDosyaAdiTemeliniOlustur(
    kontrolSonucu: KontrolSonucu,
    zaman: datetime | None = None,
) -> str:
    # Hedef, kontrol, durum, tarih ve dakikayi ortak dosya adi temelinde birlestirir.
    kaynakZaman = (
        zaman
        or kontrolSonucu.bitisZamani
        or kontrolSonucu.baslangicZamani
        or datetime.now(TURKIYE_SAAT_DILIMI)
    )
    turkiyeZamani = kaynakZaman.astimezone(TURKIYE_SAAT_DILIMI)
    tarihSaat = turkiyeZamani.strftime("%Y%m%d-%H%M")
    hedef = dosyaAdiParcasiniGuvenliYap(
        kontrolSonucu.hedef,
        AZAMI_HEDEF_PARCA_UZUNLUGU,
    )
    kontrol = dosyaAdiParcasiniGuvenliYap(
        kontrolSonucu.kontrolKimligi,
        AZAMI_KONTROL_PARCA_UZUNLUGU,
    )
    durum = dosyaAdiParcasiniGuvenliYap(kontrolSonucu.durum.value, 40)
    return f"{hedef}-{kontrol}-{durum}-{tarihSaat}"


def dosyaAdiParcasiniGuvenliYap(deger: str, azamiUzunluk: int = 120) -> str:
    # Dosya sisteminde riskli karakterleri tireye cevirip parca uzunlugunu sinirlar.
    temizDeger = re.sub(r"[^A-Za-z0-9_-]+", "-", deger.strip())
    temizDeger = re.sub(r"-+", "-", temizDeger).strip("-_")
    return temizDeger[:azamiUzunluk].rstrip("-_") or "bilinmeyen"
