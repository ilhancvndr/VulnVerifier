# Metasploit IPMI hash disclosure ciktisini ayristirir.

import re
from dataclasses import dataclass, field

from vulnverifier.errors import CiktiAyristirmaHatasi

ANSI_KODU_DESENI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
HASH_DESENI = re.compile(
    r"^\s*\[\+\]\s+(.+):(\d+)\s+-\s+IPMI\s+-\s+Hash found:\s*"
    r"([^:]*):([0-9a-f]+):([0-9a-f]{40})\s*$",
    re.I,
)
HATA_DESENI = re.compile(r"^\s*\[-\]\s+(.+):(\d+)\s+-\s+IPMI\s+-\s+(.+?)\s*$", re.I)
TAMAMLANDI_DESENI = re.compile(r"^\s*\[\*\]\s+Scanned\s+\d+\s+of\s+\d+\s+hosts", re.I)


@dataclass(frozen=True, slots=True)
class IpmiHashKaydi:
    # Tek kullanici icin alinan RAKP hash parcalarini tasir.
    taramaNoktasi: str
    port: int
    kullaniciAdi: str
    salt: str
    sha1Hash: str


@dataclass(frozen=True, slots=True)
class MetasploitIpmiHashSonucu:
    # Metasploit tarafindan raporlanan hash ve tanisal mesajlari tasir.
    hashKayitlari: tuple[IpmiHashKaydi, ...] = field(default_factory=tuple)
    detaylar: tuple[str, ...] = field(default_factory=tuple)


def metasploitIpmiHashCiktisiniAyristir(cikti: str) -> MetasploitIpmiHashSonucu:
    # Hash satirlarini ve sonuc alinamamasini aciklayan hata satirlarini toplar.
    if not isinstance(cikti, str) or not cikti.strip():
        raise CiktiAyristirmaHatasi("Metasploit IPMI çıktısı boş olamaz.")
    hashKayitlari: list[IpmiHashKaydi] = []
    detaylar: list[str] = []
    taramaTamamlandiMi = False
    for hamSatir in cikti.splitlines():
        satir = ANSI_KODU_DESENI.sub("", hamSatir)
        hashEslesmesi = HASH_DESENI.match(satir)
        if hashEslesmesi is not None:
            hashKayitlari.append(
                IpmiHashKaydi(
                    hashEslesmesi.group(1),
                    int(hashEslesmesi.group(2)),
                    hashEslesmesi.group(3),
                    hashEslesmesi.group(4).lower(),
                    hashEslesmesi.group(5).lower(),
                )
            )
            continue
        hataEslesmesi = HATA_DESENI.match(satir)
        if hataEslesmesi is not None:
            detaylar.append(hataEslesmesi.group(3).strip())
            continue
        if TAMAMLANDI_DESENI.match(satir):
            taramaTamamlandiMi = True
    if not hashKayitlari and not detaylar and not taramaTamamlandiMi:
        raise CiktiAyristirmaHatasi("Metasploit çıktısında IPMI tarama sonucu bulunamadı.")
    if not hashKayitlari and not detaylar:
        detaylar.append("Tarama tamamlandı ancak IPMI RAKP hash kaydı bulunamadı.")
    return MetasploitIpmiHashSonucu(tuple(hashKayitlari), tuple(detaylar))
