# DNS cache snooping dogrulamasini calistirip evidence dosyalarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.dns_cache_snooping import KONTROL_KIMLIGI, dnsCacheSonucunuOlustur
from vulnverifier.command_runner import (
    KomutIptalHatasi,
    KomutSonucu,
    KomutZamanAsimiHatasi,
)
from vulnverifier.errors import CiktiAyristirmaHatasi
from vulnverifier.evidence_storage import (
    HamCiktiDosyalari,
    KanitDosyasiOzeti,
    hamAracCiktisiniKaydet,
    kanitDosyasiOzetiniHesapla,
    kanitKlasoruOlustur,
    normalizeEdilmisKanitiKaydet,
)
from vulnverifier.execution_service import (
    KontrolCalistirmaServisi,
    aracSonucunuStandartlastir,
    ayristirmaHatasiniStandartlastir,
    iptalHatasiniStandartlastir,
    zamanAsimiHatasiniStandartlastir,
)
from vulnverifier.models import KontrolSonucu
from vulnverifier.nmap_adapter import VARSAYILAN_DNS_PORTU, NmapAdaptoru
from vulnverifier.nmap_dns_cache_parser import dnsCacheXmliniAyristir
from vulnverifier.nmap_parser import NmapXmlAyristirmaHatasi
from vulnverifier.port_validation import PortGirdisi, PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKataloguOlustur
from vulnverifier.tool_management import NMAP_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI


@dataclass(frozen=True, slots=True)
class DnsCacheCalismaCiktisi:
    # Standart sonucu ve evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class NmapDnsCacheCalistirmaServisi:
    # Nmap, parser, siniflandirma ve evidence akislarini birlestirir.
    def __init__(
        self,
        nmapAdaptoru: NmapAdaptoru,
        kanitAnaDizini: str | Path,
        zamanAsimi: float | int = VARSAYILAN_ZAMAN_ASIMI,
    ) -> None:
        if not isinstance(nmapAdaptoru, NmapAdaptoru):
            raise TypeError("Geçerli bir NmapAdaptoru sağlanmalıdır.")
        self._nmapAdaptoru = nmapAdaptoru
        self._kanitAnaDizini = kanitAnaDizini
        self._zamanAsimi = zamanAsimi

    def calistir(self, hedef: str, portlar: PortGirdisi = None) -> DnsCacheCalismaCiktisi:
        # Tek taramayi standart sonuca ve evidence dosyalarina donusturur.
        standartPortlar = portlariDogrula(portlar)
        if len(standartPortlar) > 1:
            raise PortValidationError("DNS cache doğrulaması yalnızca bir port kabul eder.")
        secilenPort = standartPortlar[0] if standartPortlar else VARSAYILAN_DNS_PORTU
        uretilenler: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def dogrulamayiCalistir(standartHedef: str, _portlar: tuple[int, ...]) -> KontrolSonucu:
            klasor = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._nmapAdaptoru.dnsCacheSnoopTaramasiCalistir(
                    standartHedef, secilenPort, zamanAsimi=self._zamanAsimi
                )
                hamDosyalar = hamAracCiktisiniKaydet(klasor, komutSonucu)
                kontrolSonucu = self._komutSonucunuDonustur(standartHedef, secilenPort, komutSonucu)
            except KomutZamanAsimiHatasi as hata:
                kontrolSonucu = zamanAsimiHatasiniStandartlastir(
                    KONTROL_KIMLIGI, standartHedef, hata
                )
            except KomutIptalHatasi as hata:
                kontrolSonucu = iptalHatasiniStandartlastir(KONTROL_KIMLIGI, standartHedef, hata)
            normalizeYolu = normalizeEdilmisKanitiKaydet(klasor, kontrolSonucu)
            uretilenler.append((klasor, hamDosyalar, normalizeYolu))
            return kontrolSonucu

        servis = KontrolCalistirmaServisi(varsayilanKataloguOlustur())
        servis.calistiriciEkle(KONTROL_KIMLIGI, dogrulamayiCalistir)
        kontrolSonucu = servis.kontroluCalistir(KONTROL_KIMLIGI, hedef, (secilenPort,))
        klasor, hamDosyalar, normalizeYolu = uretilenler[0]
        dosyalar = [normalizeYolu]
        if hamDosyalar is not None:
            dosyalar[0:0] = [hamDosyalar.standartCiktiYolu, hamDosyalar.standartHataYolu]
        return DnsCacheCalismaCiktisi(
            kontrolSonucu,
            klasor,
            hamDosyalar,
            normalizeYolu,
            tuple(kanitDosyasiOzetiniHesapla(yol) for yol in dosyalar),
        )

    def _komutSonucunuDonustur(
        self, hedef: str, port: int, komutSonucu: KomutSonucu
    ) -> KontrolSonucu:
        # Arac ve parser sonuclarini ortak modele donusturur.
        def basariliSonuc(hamSonuc: KomutSonucu) -> KontrolSonucu:
            return dnsCacheSonucunuOlustur(
                dnsCacheXmliniAyristir(hamSonuc.standartCikti), hedef, port
            )

        try:
            return aracSonucunuStandartlastir(KONTROL_KIMLIGI, hedef, komutSonucu, basariliSonuc)
        except (NmapXmlAyristirmaHatasi, CiktiAyristirmaHatasi) as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
