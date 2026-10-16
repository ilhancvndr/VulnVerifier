# IPv4, IPv6 ve hostname hedeflerinin bicimsel dogrulamasini saglar.

import ipaddress
import re

HOSTNAME_ETIKET_DESENI = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


class TargetValidationError(ValueError):
    # Gecersiz hedef girdisi verildiginde olusan hatadir.
    pass


def hedefiDogrula(hedef: str) -> str:
    # Hedefi ag baglantisi kurmadan dogrular ve standartlastirilmis degeri dondurur.
    if not hedef:
        raise TargetValidationError("Hedef boş olamaz.")

    if hedef != hedef.strip() or any(karakter.isspace() for karakter in hedef):
        raise TargetValidationError("Hedef boşluk karakteri içeremez.")

    if "://" in hedef:
        raise TargetValidationError("Hedef URL değil, IP adresi veya hostname olmalıdır.")

    if "/" in hedef:
        raise TargetValidationError("Tek hedef bekleniyor; CIDR veya URL yolu kullanılamaz.")

    if "%" in hedef:
        raise TargetValidationError("IPv6 zone kimliği bu sürümde desteklenmiyor.")

    try:
        return ipaddress.ip_address(hedef).compressed
    except ValueError:
        pass

    if all(karakter in "0123456789." for karakter in hedef):
        raise TargetValidationError("Geçersiz IP adresi.")

    standartHedef = hedef[:-1] if hedef.endswith(".") else hedef
    if not standartHedef:
        raise TargetValidationError("Hostname boş olamaz.")

    try:
        standartHedef.encode("ascii")
    except UnicodeEncodeError as hata:
        raise TargetValidationError("Hostname yalnızca ASCII karakterler içerebilir.") from hata

    if len(standartHedef) > 253:
        raise TargetValidationError("Hostname 253 karakterden uzun olamaz.")

    hostnameEtiketleri = standartHedef.split(".")
    if not all(HOSTNAME_ETIKET_DESENI.fullmatch(etiket) for etiket in hostnameEtiketleri):
        raise TargetValidationError("Geçersiz hostname biçimi.")

    return standartHedef.lower()
