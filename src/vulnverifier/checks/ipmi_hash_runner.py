# IPMI hash disclosure dogrulamasini calistirip evidence dosyalarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.ipmi_hash_disclosure import KONTROL_KIMLIGI, ipmiHashSonucunuOlustur
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
from vulnverifier.metasploit_adapter import VARSAYILAN_IPMI_PORTU, MetasploitAdaptoru
from vulnverifier.metasploit_ipmi_hash_parser import metasploitIpmiHashCiktisiniAyristir
from vulnverifier.models import KontrolSonucu
from vulnverifier.port_validation import PortGirdisi, PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKataloguOlustur
from vulnverifier.tool_management import (
    METASPLOIT_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI,
)


@dataclass(frozen=True, slots=True)
class IpmiHashCalismaCiktisi:
    # Standart sonucu ve evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class MetasploitIpmiHashCalistirmaServisi:
    # Metasploit, parser, siniflandirma ve evidence akislarini birlestirir.
    def __init__(
        self,
        metasploitAdaptoru: MetasploitAdaptoru,
        kanitAnaDizini: str | Path,
        zamanAsimi: float | int = VARSAYILAN_ZAMAN_ASIMI,
    ) -> None:
        if not isinstance(metasploitAdaptoru, MetasploitAdaptoru):
            raise TypeError("Geçerli bir MetasploitAdaptoru sağlanmalıdır.")
        self._metasploitAdaptoru = metasploitAdaptoru
        self._kanitAnaDizini = kanitAnaDizini
        self._zamanAsimi = zamanAsimi

    def calistir(self, hedef: str, portlar: PortGirdisi = None) -> IpmiHashCalismaCiktisi:
        # Tek IPMI taramasini standart sonuca ve evidence dosyalarina donusturur.
        standartPortlar = portlariDogrula(portlar)
        if len(standartPortlar) > 1:
            raise PortValidationError("IPMI hash doğrulaması yalnızca bir port kabul eder.")
        secilenPort = standartPortlar[0] if standartPortlar else VARSAYILAN_IPMI_PORTU
        uretilenler: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def dogrulamayiCalistir(standartHedef: str, _portlar: tuple[int, ...]) -> KontrolSonucu:
            klasor = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._metasploitAdaptoru.ipmiHashTaramasiCalistir(
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
        return IpmiHashCalismaCiktisi(
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
            return ipmiHashSonucunuOlustur(
                metasploitIpmiHashCiktisiniAyristir(hamSonuc.standartCikti), hedef, port
            )

        try:
            return aracSonucunuStandartlastir(KONTROL_KIMLIGI, hedef, komutSonucu, basariliSonuc)
        except CiktiAyristirmaHatasi as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
