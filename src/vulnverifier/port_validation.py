# Tek veya birden fazla TCP ya da UDP port girdisini dogrular.

import re
from collections.abc import Sequence

PORT_DESENI = re.compile(r"^[0-9]+$")

type PortGirdisi = Sequence[str | int] | str | int | None


class PortValidationError(ValueError):
    # Gecersiz port girdisi verildiginde olusan hatadir.
    pass


def portuDogrula(port: str | int) -> int:
    # Portu yalnizca ondalik rakamlardan kabul eder ve sayisal degeri dondurur.
    if isinstance(port, bool):
        raise PortValidationError("Port sayısal bir değer olmalıdır.")

    if isinstance(port, int):
        portDegeri = port
    elif isinstance(port, str):
        if not port:
            raise PortValidationError("Port boş olamaz.")

        if port != port.strip():
            raise PortValidationError("Port boşluk karakteri içeremez.")

        if not PORT_DESENI.fullmatch(port):
            raise PortValidationError("Port yalnızca rakamlardan oluşmalıdır.")

        portDegeri = int(port)
    else:
        raise PortValidationError("Port metin veya tam sayı olmalıdır.")

    if not 1 <= portDegeri <= 65535:
        raise PortValidationError("Port 1 ile 65535 arasında olmalıdır.")

    return portDegeri


def portlariDogrula(portlar: PortGirdisi) -> tuple[int, ...]:
    # Tek veya birden fazla portu dogrular, tekrar etmeden sirali dondurur.
    if portlar is None:
        return ()
    if isinstance(portlar, (str, int)):
        hamPortlar = (portlar,)
    elif isinstance(portlar, Sequence) and not isinstance(portlar, bytes):
        hamPortlar = tuple(portlar)
    else:
        raise PortValidationError("Portlar bir liste, metin veya tam sayı olmalıdır.")

    dogrulanmisPortlar: list[int] = []
    gorulenPortlar: set[int] = set()
    for port in hamPortlar:
        dogrulanmisPort = portuDogrula(port)
        if dogrulanmisPort not in gorulenPortlar:
            dogrulanmisPortlar.append(dogrulanmisPort)
            gorulenPortlar.add(dogrulanmisPort)

    return tuple(dogrulanmisPortlar)
