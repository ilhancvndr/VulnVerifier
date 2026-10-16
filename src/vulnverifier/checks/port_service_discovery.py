# Nmap port ve servis sonucunu standart VulnVerifier sonucuna donusturur.

from vulnverifier.models import KanitBilgisi, KontrolSonucu, ResultStatus
from vulnverifier.nmap_parser import NmapHostSonucu, NmapPortSonucu, NmapTaramaSonucu
from vulnverifier.port_validation import portuDogrula
from vulnverifier.target_validation import hedefiDogrula

KONTROL_KIMLIGI = "port-service-discovery"


class PortServisDegerlendirmeHatasi(ValueError):
    # Degerlendirme islevine gecersiz Nmap sonucu verildiginde olusan hatadir.
    pass


def portServisSonucunuOlustur(
    nmapSonucu: NmapTaramaSonucu,
    hedef: str,
    port: str | int,
) -> KontrolSonucu:
    # Nmap host ve port durumunu standart kontrol durumu ve kanitlara cevirir.
    if not isinstance(nmapSonucu, NmapTaramaSonucu):
        raise PortServisDegerlendirmeHatasi("Geçerli bir NmapTaramaSonucu gereklidir.")

    standartHedef = hedefiDogrula(hedef)
    standartPort = portuDogrula(port)

    if not nmapSonucu.hostlar:
        return _belirsizSonucOlustur(
            standartHedef,
            "Nmap çıktısında hedef host bulunamadı.",
            (KanitBilgisi(anahtar="port", deger=str(standartPort)),),
        )

    if len(nmapSonucu.hostlar) != 1:
        return _belirsizSonucOlustur(
            standartHedef,
            "Nmap çıktısında tek hedef yerine birden fazla host bulundu.",
            (
                KanitBilgisi(anahtar="port", deger=str(standartPort)),
                KanitBilgisi(anahtar="hostSayisi", deger=str(len(nmapSonucu.hostlar))),
            ),
        )

    hostSonucu = nmapSonucu.hostlar[0]
    temelKanitlar = _hostKanitlariniOlustur(hostSonucu, standartPort)
    if hostSonucu.durum != "up":
        return _belirsizSonucOlustur(
            standartHedef,
            f"Hedef host durumu '{hostSonucu.durum}' olduğu için port doğrulanamadı.",
            temelKanitlar,
        )

    eslesenPortlar = tuple(
        portSonucu
        for portSonucu in hostSonucu.portlar
        if portSonucu.port == standartPort and portSonucu.protokol == "tcp"
    )
    if len(eslesenPortlar) != 1:
        return _belirsizSonucOlustur(
            standartHedef,
            f"Nmap çıktısında {standartPort}/tcp için tek bir port kaydı bulunamadı.",
            temelKanitlar,
        )

    return _portDurumunuDegerlendir(
        standartHedef,
        eslesenPortlar[0],
        temelKanitlar,
    )


def portServisTaramaSonucunuOlustur(
    nmapSonucu: NmapTaramaSonucu,
    hedef: str,
    portlar: tuple[int, ...],
) -> KontrolSonucu:
    # Coklu veya varsayilan Nmap taramasini tek standart kontrol sonucuna cevirir.
    if not isinstance(nmapSonucu, NmapTaramaSonucu):
        raise PortServisDegerlendirmeHatasi("Geçerli bir NmapTaramaSonucu gereklidir.")

    standartHedef = hedefiDogrula(hedef)
    if len(portlar) == 1:
        return portServisSonucunuOlustur(nmapSonucu, standartHedef, portlar[0])
    if not nmapSonucu.hostlar:
        return _belirsizSonucOlustur(
            standartHedef,
            "Nmap çıktısında hedef host bulunamadı.",
            (),
        )
    if len(nmapSonucu.hostlar) != 1:
        return _belirsizSonucOlustur(
            standartHedef,
            "Nmap çıktısında tek hedef yerine birden fazla host bulundu.",
            (KanitBilgisi(anahtar="hostSayisi", deger=str(len(nmapSonucu.hostlar))),),
        )

    hostSonucu = nmapSonucu.hostlar[0]
    if hostSonucu.durum != "up":
        return _belirsizSonucOlustur(
            standartHedef,
            f"Hedef host durumu '{hostSonucu.durum}' olduğu için portlar doğrulanamadı.",
            (KanitBilgisi(anahtar="hostDurumu", deger=hostSonucu.durum),),
        )

    tcpPortlari = tuple(port for port in hostSonucu.portlar if port.protokol == "tcp")
    degerlendirilecekPortlar = (
        tuple(port for port in tcpPortlari if port.port in portlar) if portlar else tcpPortlari
    )
    acikPortlar = tuple(port for port in degerlendirilecekPortlar if port.durum == "open")
    kanitlar = _taramaKanitlariniOlustur(hostSonucu, degerlendirilecekPortlar, portlar)

    if acikPortlar:
        portMetni = ", ".join(str(port.port) for port in acikPortlar)
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=standartHedef,
            durum=ResultStatus.VULNERABLE,
            ozet=f"Açık TCP portları tespit edildi: {portMetni}.",
            kanitlar=kanitlar,
        )

    bulunanPortlar = {port.port for port in degerlendirilecekPortlar}
    eksikPortlar = tuple(port for port in portlar if port not in bulunanPortlar)
    yalnizcaKapaliMi = bool(degerlendirilecekPortlar) and all(
        port.durum == "closed" for port in degerlendirilecekPortlar
    )
    if portlar and not eksikPortlar and yalnizcaKapaliMi:
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=standartHedef,
            durum=ResultStatus.NOT_VULNERABLE,
            ozet="Seçilen TCP portlarının tamamı kapalı.",
            kanitlar=kanitlar,
        )

    return _belirsizSonucOlustur(
        standartHedef,
        "Tarama açık port göstermedi ancak kesin kapalı sonucu üretilemedi.",
        kanitlar,
    )


def _portDurumunuDegerlendir(
    hedef: str,
    portSonucu: NmapPortSonucu,
    temelKanitlar: tuple[KanitBilgisi, ...],
) -> KontrolSonucu:
    # Port durumuna gore sonuc sinifini, ozeti ve servis kanitlarini olusturur.
    kanitlar = temelKanitlar + _servisKanitlariniOlustur(portSonucu)
    portTanimi = f"{portSonucu.port}/{portSonucu.protokol}"

    if portSonucu.durum == "open":
        servisMetni = (
            f"; {portSonucu.servisAdi} servisi tespit edildi"
            if portSonucu.servisAdi is not None
            else ""
        )
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=hedef,
            durum=ResultStatus.VULNERABLE,
            ozet=f"{portTanimi} portu açık{servisMetni}.",
            kanitlar=kanitlar,
        )

    if portSonucu.durum == "closed":
        return KontrolSonucu(
            kontrolKimligi=KONTROL_KIMLIGI,
            hedef=hedef,
            durum=ResultStatus.NOT_VULNERABLE,
            ozet=f"{portTanimi} portu kapalı.",
            kanitlar=kanitlar,
        )

    return _belirsizSonucOlustur(
        hedef,
        f"{portTanimi} port durumu '{portSonucu.durum}' olduğu için sonuç belirsiz.",
        kanitlar,
    )


def _hostKanitlariniOlustur(
    hostSonucu: NmapHostSonucu,
    port: int,
) -> tuple[KanitBilgisi, ...]:
    # Host durumu, adresler ve istenen port icin temel kanitlari olusturur.
    kanitlar = [
        KanitBilgisi(anahtar="hostDurumu", deger=hostSonucu.durum),
        KanitBilgisi(anahtar="port", deger=str(port)),
    ]
    if hostSonucu.adresler:
        kanitlar.append(KanitBilgisi(anahtar="adresler", deger=",".join(hostSonucu.adresler)))
    return tuple(kanitlar)


def _servisKanitlariniOlustur(portSonucu: NmapPortSonucu) -> tuple[KanitBilgisi, ...]:
    # Port kaydindaki zorunlu ve istege bagli servis alanlarini kanita cevirir.
    kanitlar = [
        KanitBilgisi(anahtar="protokol", deger=portSonucu.protokol),
        KanitBilgisi(anahtar="portDurumu", deger=portSonucu.durum),
    ]
    istegeBagliAlanlar = (
        ("servis", portSonucu.servisAdi),
        ("urun", portSonucu.urun),
        ("surum", portSonucu.surum),
    )
    kanitlar.extend(
        KanitBilgisi(anahtar=anahtar, deger=deger)
        for anahtar, deger in istegeBagliAlanlar
        if deger is not None
    )
    return tuple(kanitlar)


def _taramaKanitlariniOlustur(
    hostSonucu: NmapHostSonucu,
    portSonuclari: tuple[NmapPortSonucu, ...],
    istenenPortlar: tuple[int, ...],
) -> tuple[KanitBilgisi, ...]:
    # Host ve birden fazla port sonucunu tekrar edebilen kanit alanlarina cevirir.
    kanitlar = [KanitBilgisi(anahtar="hostDurumu", deger=hostSonucu.durum)]
    if hostSonucu.adresler:
        kanitlar.append(KanitBilgisi(anahtar="adresler", deger=",".join(hostSonucu.adresler)))
    if istenenPortlar:
        kanitlar.append(
            KanitBilgisi(
                anahtar="istenenPortlar",
                deger=",".join(map(str, istenenPortlar)),
            )
        )
    for portSonucu in portSonuclari:
        servisParcalari = [str(portSonucu.port), portSonucu.durum]
        if portSonucu.servisAdi is not None:
            servisParcalari.append(portSonucu.servisAdi)
        if portSonucu.urun is not None:
            servisParcalari.append(portSonucu.urun)
        if portSonucu.surum is not None:
            servisParcalari.append(portSonucu.surum)
        kanitlar.append(KanitBilgisi(anahtar="tcpPort", deger="|".join(servisParcalari)))
    return tuple(kanitlar)


def _belirsizSonucOlustur(
    hedef: str,
    ozet: str,
    kanitlar: tuple[KanitBilgisi, ...],
) -> KontrolSonucu:
    # Belirsiz Nmap durumlari icin ortak kontrol sonucunu olusturur.
    return KontrolSonucu(
        kontrolKimligi=KONTROL_KIMLIGI,
        hedef=hedef,
        durum=ResultStatus.INCONCLUSIVE,
        ozet=ozet,
        kanitlar=kanitlar,
    )
