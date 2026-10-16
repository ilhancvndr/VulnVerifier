# FREAK dogrulamasini calistirip evidence dosyalarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.freak_export_rsa import KONTROL_KIMLIGI, freakSonucunuOlustur
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
from vulnverifier.port_validation import PortGirdisi, PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKataloguOlustur
from vulnverifier.testssl_adapter import VARSAYILAN_SSL_PORTU, TestsslAdaptoru
from vulnverifier.testssl_freak_parser import testsslFreakCiktisiniAyristir
from vulnverifier.tool_management import (
    TESTSSL_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI,
)


@dataclass(frozen=True, slots=True)
class FreakCalismaCiktisi:
    # Standart sonucu ve evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class TestsslFreakCalistirmaServisi:
    # testssl, parser, siniflandirma ve evidence akislarini birlestirir.
    def __init__(
        self,
        testsslAdaptoru: TestsslAdaptoru,
        kanitAnaDizini: str | Path,
        zamanAsimi: float | int = VARSAYILAN_ZAMAN_ASIMI,
    ) -> None:
        if not isinstance(testsslAdaptoru, TestsslAdaptoru):
            raise TypeError("Geçerli bir TestsslAdaptoru sağlanmalıdır.")
        self._testsslAdaptoru = testsslAdaptoru
        self._kanitAnaDizini = kanitAnaDizini
        self._zamanAsimi = zamanAsimi

    def calistir(self, hedef: str, portlar: PortGirdisi = None) -> FreakCalismaCiktisi:
        # Tek FREAK taramasini standart sonuca ve evidence dosyalarina donusturur.
        standartPortlar = portlariDogrula(portlar)
        if len(standartPortlar) > 1:
            raise PortValidationError("FREAK doğrulaması yalnızca bir port kabul eder.")
        secilenPort = standartPortlar[0] if standartPortlar else VARSAYILAN_SSL_PORTU
        uretilenler: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def dogrulamayiCalistir(standartHedef: str, _portlar: tuple[int, ...]) -> KontrolSonucu:
            klasor = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._testsslAdaptoru.freakTaramasiCalistir(
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
        return FreakCalismaCiktisi(
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
            return freakSonucunuOlustur(
                testsslFreakCiktisiniAyristir(hamSonuc.standartCikti), hedef, port
            )

        try:
            return aracSonucunuStandartlastir(KONTROL_KIMLIGI, hedef, komutSonucu, basariliSonuc)
        except CiktiAyristirmaHatasi as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
