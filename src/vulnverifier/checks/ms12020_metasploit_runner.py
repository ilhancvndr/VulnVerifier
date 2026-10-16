# Metasploit MS12-020 kontrolunu calistirip ham ve normalize kanitlarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.ms12020_metasploit import (
    KONTROL_KIMLIGI,
    ms12020MetasploitSonucunuOlustur,
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
from vulnverifier.metasploit_adapter import (
    VARSAYILAN_MS12020_PORTU,
    MetasploitAdaptoru,
)
from vulnverifier.metasploit_ms12020_parser import metasploitMs12020CiktisiniAyristir
from vulnverifier.models import KontrolSonucu
from vulnverifier.port_validation import PortGirdisi, PortValidationError, portlariDogrula
from vulnverifier.registry import varsayilanKataloguOlustur
from vulnverifier.tool_management import (
    METASPLOIT_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI,
)


@dataclass(frozen=True, slots=True)
class Ms12020MetasploitCalismaCiktisi:
    # Standart sonucu ve ayni calismada uretilen evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class MetasploitMs12020CalistirmaServisi:
    # Metasploit, ayristirma, siniflandirma ve evidence akislarini birlestirir.
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

    def calistir(
        self,
        hedef: str,
        portlar: PortGirdisi = None,
    ) -> Ms12020MetasploitCalismaCiktisi:
        # Tek taramayi standart sonuca ve evidence dosyalarina donusturur.
        standartPortlar = portlariDogrula(portlar)
        if len(standartPortlar) > 1:
            raise PortValidationError(
                "MS12-020 Metasploit kontrolü tek seferde yalnızca bir port kabul eder."
            )
        secilenPort = standartPortlar[0] if standartPortlar else VARSAYILAN_MS12020_PORTU
        uretilenDosyalar: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def ms12020KontrolunuCalistir(
            standartHedef: str,
            _standartPortlar: tuple[int, ...],
        ) -> KontrolSonucu:
            kanitKlasoru = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._metasploitAdaptoru.ms12020TaramasiCalistir(
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
        ortakServis.calistiriciEkle(KONTROL_KIMLIGI, ms12020KontrolunuCalistir)
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

        return Ms12020MetasploitCalismaCiktisi(
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
            taramaSonucu = metasploitMs12020CiktisiniAyristir(hamSonuc.standartCikti)
            return ms12020MetasploitSonucunuOlustur(taramaSonucu, hedef, port)

        try:
            return aracSonucunuStandartlastir(
                KONTROL_KIMLIGI,
                hedef,
                komutSonucu,
                basariliSonucuDonustur,
            )
        except CiktiAyristirmaHatasi as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
