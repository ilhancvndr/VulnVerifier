# MS17-010 Metasploit dogrulamasini calistirip evidence dosyalarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.ms17010_metasploit import (
    KONTROL_KIMLIGI,
    ms17010MetasploitSonucunuOlustur,
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
from vulnverifier.metasploit_adapter import VARSAYILAN_MS17010_PORTU, MetasploitAdaptoru
from vulnverifier.metasploit_ms17010_parser import metasploitMs17010CiktisiniAyristir
from vulnverifier.models import KontrolSonucu
from vulnverifier.port_validation import PortGirdisi, PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKataloguOlustur
from vulnverifier.tool_management import (
    METASPLOIT_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI,
)


@dataclass(frozen=True, slots=True)
class Ms17010MetasploitCalismaCiktisi:
    # Standart sonucu ve uretilen evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class MetasploitMs17010CalistirmaServisi:
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

    def calistir(self, hedef: str, portlar: PortGirdisi = None) -> Ms17010MetasploitCalismaCiktisi:
        # Tek taramayi standart sonuca ve evidence dosyalarina donusturur.
        standartPortlar = portlariDogrula(portlar)
        if len(standartPortlar) > 1:
            raise PortValidationError("MS17-010 doğrulaması yalnızca bir port kabul eder.")
        secilenPort = standartPortlar[0] if standartPortlar else VARSAYILAN_MS17010_PORTU
        uretilenDosyalar: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def dogrulamayiCalistir(
            standartHedef: str, _standartPortlar: tuple[int, ...]
        ) -> KontrolSonucu:
            kanitKlasoru = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._metasploitAdaptoru.ms17010TaramasiCalistir(
                    standartHedef, secilenPort, zamanAsimi=self._zamanAsimi
                )
                hamDosyalar = hamAracCiktisiniKaydet(kanitKlasoru, komutSonucu)
                kontrolSonucu = self._komutSonucunuDonustur(standartHedef, secilenPort, komutSonucu)
            except KomutZamanAsimiHatasi as hata:
                kontrolSonucu = zamanAsimiHatasiniStandartlastir(
                    KONTROL_KIMLIGI, standartHedef, hata
                )
            except KomutIptalHatasi as hata:
                kontrolSonucu = iptalHatasiniStandartlastir(KONTROL_KIMLIGI, standartHedef, hata)
            normalizeYolu = normalizeEdilmisKanitiKaydet(kanitKlasoru, kontrolSonucu)
            uretilenDosyalar.append((kanitKlasoru, hamDosyalar, normalizeYolu))
            return kontrolSonucu

        ortakServis = KontrolCalistirmaServisi(varsayilanKataloguOlustur())
        ortakServis.calistiriciEkle(KONTROL_KIMLIGI, dogrulamayiCalistir)
        kontrolSonucu = ortakServis.kontroluCalistir(KONTROL_KIMLIGI, hedef, (secilenPort,))
        kanitKlasoru, hamDosyalar, normalizeYolu = uretilenDosyalar[0]
        dosyalar = [normalizeYolu]
        if hamDosyalar is not None:
            dosyalar[0:0] = [hamDosyalar.standartCiktiYolu, hamDosyalar.standartHataYolu]
        return Ms17010MetasploitCalismaCiktisi(
            kontrolSonucu,
            kanitKlasoru,
            hamDosyalar,
            normalizeYolu,
            tuple(kanitDosyasiOzetiniHesapla(yol) for yol in dosyalar),
        )

    def _komutSonucunuDonustur(
        self, hedef: str, port: int, komutSonucu: KomutSonucu
    ) -> KontrolSonucu:
        # Arac ciktisini standart sonuca cevirir.
        def basariliSonucuDonustur(hamSonuc: KomutSonucu) -> KontrolSonucu:
            return ms17010MetasploitSonucunuOlustur(
                metasploitMs17010CiktisiniAyristir(hamSonuc.standartCikti), hedef, port
            )

        try:
            return aracSonucunuStandartlastir(
                KONTROL_KIMLIGI, hedef, komutSonucu, basariliSonucuDonustur
            )
        except CiktiAyristirmaHatasi as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
