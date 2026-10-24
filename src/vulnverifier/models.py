# Dogrulama kontrollerinin paylasacagi temel veri tiplerini tanimlar.

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class ResultStatus(StrEnum):
    # Bir dogrulama calismasinin standart sonuc durumlarini belirtir.
    VULNERABLE = "VULNERABLE"
    NOT_VULNERABLE = "NOT_VULNERABLE"
    DISCOVERED = "DISCOVERED"
    NOT_FOUND = "NOT_FOUND"
    POTENTIALLY_VULNERABLE = "POTENTIALLY_VULNERABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class RiskLevel(StrEnum):
    # Bir kontrolun hedef uzerinde olusturabilecegi etki seviyesini belirtir.
    SAFE = "safe"
    INTRUSIVE = "intrusive"


class KontrolEtkisi(StrEnum):
    # Kontrolun hedef sistem uzerinde olusturabilecegi islemsel etkiyi belirtir.
    UNKNOWN = "unknown"
    READ_ONLY = "read_only"
    STATE_CHANGE = "state_change"
    DENIAL_OF_SERVICE = "denial_of_service"
    EXPLOIT = "exploit"


@dataclass(frozen=True, slots=True)
class KanitBilgisi:
    # Bir kontrol sonucundaki yapilandirilmis tek bir kanit alanini tasir.
    anahtar: str
    deger: str


@dataclass(frozen=True, slots=True)
class KontrolSonucu:
    # Bir kontrolun standart durumunu, kanitlarini ve calisma zamanlarini tasir.
    kontrolKimligi: str
    hedef: str
    durum: ResultStatus
    ozet: str
    kanitlar: tuple[KanitBilgisi, ...] = field(default_factory=tuple)
    baslangicZamani: datetime | None = None
    bitisZamani: datetime | None = None
    calismaSuresiSaniye: float | None = None


@dataclass(frozen=True, slots=True)
class CheckDefinition:
    # Katalogda gosterilecek bir dogrulama kontrolunun sabit bilgilerini tasir.
    kontrolKimligi: str
    bulguAnahtari: str
    baslik: str
    aciklama: str
    riskSeviyesi: RiskLevel = RiskLevel.SAFE
    varsayilanPortlar: tuple[int, ...] = field(default_factory=tuple)
    gerekliAraclar: tuple[str, ...] = field(default_factory=tuple)
    kontrolEtkisi: KontrolEtkisi = KontrolEtkisi.UNKNOWN
