# Port ve servis kesfini CLI bagimliligi olmadan calistirip kanitlarini kaydeder.

from dataclasses import dataclass
from pathlib import Path

from vulnverifier.checks.port_service_discovery import (
    KONTROL_KIMLIGI,
    portServisTaramaSonucunuOlustur,
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
    KontrolCalistirici,
    KontrolCalistirmaServisi,
    aracSonucunuStandartlastir,
    ayristirmaHatasiniStandartlastir,
    iptalHatasiniStandartlastir,
    zamanAsimiHatasiniStandartlastir,
)
from vulnverifier.models import KontrolSonucu
from vulnverifier.nmap_adapter import NmapAdaptoru
from vulnverifier.nmap_parser import NmapXmlAyristirmaHatasi, nmapXmliniAyristir
from vulnverifier.port_validation import PortGirdisi
from vulnverifier.registry import varsayilanKataloguOlustur
from vulnverifier.tool_management import NMAP_VARSAYILAN_ZAMAN_ASIMI as VARSAYILAN_ZAMAN_ASIMI


@dataclass(frozen=True, slots=True)
class PortServisCalismaCiktisi:
    # Standart sonucu ve ayni calismada uretilen evidence yollarini tasir.
    kontrolSonucu: KontrolSonucu
    kanitKlasoru: Path
    hamCiktiDosyalari: HamCiktiDosyalari | None
    normalizeKanitYolu: Path
    kanitDosyasiOzetleri: tuple[KanitDosyasiOzeti, ...]


class PortServisCalistirmaServisi:
    # Kontrole ozel calistiriciyi ortak servis ve katalog uzerinden yonetir.
    def __init__(self, calistirici: KontrolCalistirici) -> None:
        ortakServis = KontrolCalistirmaServisi(varsayilanKataloguOlustur())
        ortakServis.calistiriciEkle(KONTROL_KIMLIGI, calistirici)
        self._ortakServis = ortakServis

    def calistir(
        self,
        hedef: str,
        portlar: PortGirdisi = None,
    ) -> KontrolSonucu:
        # Hedef ve portu ortak servis uzerinden dogrulayarak kontrolu calistirir.
        return self._ortakServis.kontroluCalistir(
            KONTROL_KIMLIGI,
            hedef,
            portlar,
        )


class NmapPortServisCalistirmaServisi:
    # Nmap calistirma, ayristirma, degerlendirme ve evidence akislarini birlestirir.
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
    ) -> PortServisCalismaCiktisi:
        # Tek calismada Nmap sonucunu standartlastirir ve evidence dosyalarini yazar.
        uretilenDosyalar: list[tuple[Path, HamCiktiDosyalari | None, Path]] = []

        def nmapKontrolunuCalistir(
            standartHedef: str,
            standartPortlar: tuple[int, ...],
        ) -> KontrolSonucu:
            kanitKlasoru = kanitKlasoruOlustur(self._kanitAnaDizini)
            hamDosyalar = None
            try:
                komutSonucu = self._nmapAdaptoru.portServisTaramasiCalistir(
                    standartHedef,
                    standartPortlar,
                    zamanAsimi=self._zamanAsimi,
                )
                hamDosyalar = hamAracCiktisiniKaydet(kanitKlasoru, komutSonucu)
                kontrolSonucu = self._komutSonucunuDonustur(
                    standartHedef,
                    standartPortlar,
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

        kontrolSonucu = PortServisCalistirmaServisi(nmapKontrolunuCalistir).calistir(
            hedef,
            portlar,
        )
        kanitKlasoru, hamCiktiDosyalari, normalizeKanitYolu = uretilenDosyalar[0]
        kanitDosyaYollari = [normalizeKanitYolu]
        if hamCiktiDosyalari is not None:
            kanitDosyaYollari[0:0] = [
                hamCiktiDosyalari.standartCiktiYolu,
                hamCiktiDosyalari.standartHataYolu,
            ]
        kanitDosyasiOzetleri = tuple(
            kanitDosyasiOzetiniHesapla(dosyaYolu) for dosyaYolu in kanitDosyaYollari
        )
        return PortServisCalismaCiktisi(
            kontrolSonucu=kontrolSonucu,
            kanitKlasoru=kanitKlasoru,
            hamCiktiDosyalari=hamCiktiDosyalari,
            normalizeKanitYolu=normalizeKanitYolu,
            kanitDosyasiOzetleri=kanitDosyasiOzetleri,
        )

    def _komutSonucunuDonustur(
        self,
        hedef: str,
        portlar: tuple[int, ...],
        komutSonucu: KomutSonucu,
    ) -> KontrolSonucu:
        # Basarili XML'i degerlendirir, cikis ve ayristirma hatalarini standartlastirir.
        def basariliSonucuDonustur(hamSonuc: KomutSonucu) -> KontrolSonucu:
            nmapSonucu = nmapXmliniAyristir(hamSonuc.standartCikti)
            return portServisTaramaSonucunuOlustur(nmapSonucu, hedef, portlar)

        try:
            return aracSonucunuStandartlastir(
                KONTROL_KIMLIGI,
                hedef,
                komutSonucu,
                basariliSonucuDonustur,
            )
        except NmapXmlAyristirmaHatasi as hata:
            return ayristirmaHatasiniStandartlastir(KONTROL_KIMLIGI, hedef, hata)
