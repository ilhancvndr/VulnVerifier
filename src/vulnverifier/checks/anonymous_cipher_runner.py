# Anonymous TLS cipher kontrolunu calistirip ham ve normalize kanitlarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.anonymous_cipher_support import (
    KONTROL_KIMLIGI,
    anonymousCipherSonucunuOlustur,
)
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
from vulnverifier.testssl_cipher_parser import testsslAnonymousCipherCiktisiniAyristir
from vulnverifier.tool_management import (
    TESTSSL_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI,
)


@dataclass(frozen=True, slots=True)
class AnonymousCipherCalismaCiktisi:
    # Standart sonucu ve ayni calismada uretilen evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class TestsslAnonymousCipherCalistirmaServisi:
    # testssl, ayristirma, siniflandirma ve evidence akislarini birlestirir.
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

    def calistir(
        self,
        hedef: str,
        portlar: PortGirdisi = None,
    ) -> AnonymousCipherCalismaCiktisi:
        # Tek taramayi standart sonuca ve evidence dosyalarina donusturur.
        standartPortlar = portlariDogrula(portlar)
        if len(standartPortlar) > 1:
            raise PortValidationError(
                "Anonymous cipher kontrolü tek seferde yalnızca bir port kabul eder."
            )
        secilenPort = standartPortlar[0] if standartPortlar else VARSAYILAN_SSL_PORTU
        uretilenDosyalar: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def anonymousCipherKontrolunuCalistir(
            standartHedef: str,
            _standartPortlar: tuple[int, ...],
        ) -> KontrolSonucu:
            kanitKlasoru = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._testsslAdaptoru.anonymousCipherlariTara(
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
                    KONTROL_KIMLIGI,
                    standartHedef,
                    hata,
                )
            except KomutIptalHatasi as hata:
                kontrolSonucu = iptalHatasiniStandartlastir(
                    KONTROL_KIMLIGI,
                    standartHedef,
                    hata,
                )

            normalizeKanitYolu = normalizeEdilmisKanitiKaydet(
                kanitKlasoru,
                kontrolSonucu,
            )
            uretilenDosyalar.append((kanitKlasoru, hamDosyalar, normalizeKanitYolu))
            return kontrolSonucu

        ortakServis = KontrolCalistirmaServisi(varsayilanKataloguOlustur())
        ortakServis.calistiriciEkle(KONTROL_KIMLIGI, anonymousCipherKontrolunuCalistir)
        kontrolSonucu = ortakServis.kontroluCalistir(
            KONTROL_KIMLIGI,
            hedef,
            (secilenPort,),
        )
        kanitKlasoru, hamCiktiDosyalari, normalizeKanitYolu = uretilenDosyalar[0]
        kanitDosyaYollari = [normalizeKanitYolu]
        if hamCiktiDosyalari is not None:
            kanitDosyaYollari[0:0] = [
                hamCiktiDosyalari.standartCiktiYolu,
                hamCiktiDosyalari.standartHataYolu,
            ]

        return AnonymousCipherCalismaCiktisi(
            kontrolSonucu=kontrolSonucu,
            kanitKlasoru=kanitKlasoru,
            hamCiktiDosyalari=hamCiktiDosyalari,
            normalizeKanitYolu=normalizeKanitYolu,
            kanitDosyasiOzetleri=tuple(
                kanitDosyasiOzetiniHesapla(dosyaYolu) for dosyaYolu in kanitDosyaYollari
            ),
        )

    def _komutSonucunuDonustur(
        self,
        hedef: str,
        port: int,
        komutSonucu: KomutSonucu,
    ) -> KontrolSonucu:
        # Basarili ciktiyi degerlendirir, arac ve ayristirma hatalarini standartlastirir.
        def basariliSonucuDonustur(hamSonuc: KomutSonucu) -> KontrolSonucu:
            taramaSonucu = testsslAnonymousCipherCiktisiniAyristir(hamSonuc.standartCikti)
            return anonymousCipherSonucunuOlustur(taramaSonucu, hedef, port)

        try:
            return aracSonucunuStandartlastir(
                KONTROL_KIMLIGI,
                hedef,
                komutSonucu,
                basariliSonucuDonustur,
            )
        except CiktiAyristirmaHatasi as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
