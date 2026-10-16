# VMware ESXi surum tespitini calistirip ham ve normalize kanitlarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.vmware_esxi_version import (
    KONTROL_KIMLIGI,
    vmwareSurumSonucunuOlustur,
)
from vulnverifier.command_runner import (
    KomutIptalHatasi,
    KomutSonucu,
    KomutZamanAsimiHatasi,
)
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
from vulnverifier.nmap_adapter import VARSAYILAN_VMWARE_PORTU, NmapAdaptoru
from vulnverifier.nmap_parser import NmapXmlAyristirmaHatasi
from vulnverifier.nmap_vmware_parser import vmwareSurumXmliniAyristir
from vulnverifier.port_validation import PortGirdisi, PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKataloguOlustur
from vulnverifier.tool_management import NMAP_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI


@dataclass(frozen=True, slots=True)
class VmwareSurumCalismaCiktisi:
    # Standart sonucu ve ayni calismada uretilen evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class NmapVmwareSurumCalistirmaServisi:
    # Nmap, XML, siniflandirma ve evidence akislarini birlestirir.
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

    def calistir(
        self,
        hedef: str,
        portlar: PortGirdisi = None,
    ) -> VmwareSurumCalismaCiktisi:
        # Tek VMware taramasini standart sonuca ve evidence dosyalarina donusturur.
        standartPortlar = portlariDogrula(portlar)
        if len(standartPortlar) > 1:
            raise PortValidationError("VMware kontrolü tek seferde yalnızca bir port kabul eder.")
        secilenPort = standartPortlar[0] if standartPortlar else VARSAYILAN_VMWARE_PORTU
        uretilenDosyalar: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def vmwareKontrolunuCalistir(
            standartHedef: str,
            _standartPortlar: tuple[int, ...],
        ) -> KontrolSonucu:
            kanitKlasoru = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._nmapAdaptoru.vmwareSurumTaramasiCalistir(
                    standartHedef,
                    secilenPort,
                    zamanAsimi=self._zamanAsimi,
                )
                hamDosyalar = hamAracCiktisiniKaydet(kanitKlasoru, komutSonucu)
                kontrolSonucu = self._komutSonucunuDonustur(
                    standartHedef,
                    secilenPort,
                    komutSonucu,
                )
            except KomutZamanAsimiHatasi as hata:
                kontrolSonucu = zamanAsimiHatasiniStandartlastir(
                    KONTROL_KIMLIGI, standartHedef, hata
                )
            except KomutIptalHatasi as hata:
                kontrolSonucu = iptalHatasiniStandartlastir(KONTROL_KIMLIGI, standartHedef, hata)
            normalizeKanitYolu = normalizeEdilmisKanitiKaydet(kanitKlasoru, kontrolSonucu)
            uretilenDosyalar.append((kanitKlasoru, hamDosyalar, normalizeKanitYolu))
            return kontrolSonucu

        ortakServis = KontrolCalistirmaServisi(varsayilanKataloguOlustur())
        ortakServis.calistiriciEkle(KONTROL_KIMLIGI, vmwareKontrolunuCalistir)
        kontrolSonucu = ortakServis.kontroluCalistir(KONTROL_KIMLIGI, hedef, (secilenPort,))
        kanitKlasoru, hamCiktiDosyalari, normalizeKanitYolu = uretilenDosyalar[0]
        kanitDosyaYollari = [normalizeKanitYolu]
        if hamCiktiDosyalari is not None:
            kanitDosyaYollari[0:0] = [
                hamCiktiDosyalari.standartCiktiYolu,
                hamCiktiDosyalari.standartHataYolu,
            ]
        return VmwareSurumCalismaCiktisi(
            kontrolSonucu,
            kanitKlasoru,
            hamCiktiDosyalari,
            normalizeKanitYolu,
            tuple(kanitDosyasiOzetiniHesapla(yol) for yol in kanitDosyaYollari),
        )

    def _komutSonucunuDonustur(
        self, hedef: str, port: int, komutSonucu: KomutSonucu
    ) -> KontrolSonucu:
        # Arac ve XML sonuclarini ortak modele donusturur.
        def basariliSonucuDonustur(hamSonuc: KomutSonucu) -> KontrolSonucu:
            return vmwareSurumSonucunuOlustur(
                vmwareSurumXmliniAyristir(hamSonuc.standartCikti), hedef, port
            )

        try:
            return aracSonucunuStandartlastir(
                KONTROL_KIMLIGI, hedef, komutSonucu, basariliSonucuDonustur
            )
        except NmapXmlAyristirmaHatasi as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
