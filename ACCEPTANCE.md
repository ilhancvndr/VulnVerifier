# MVP Kabul Kaydi

Bu belge, VulnVerifier 0.1.0 icin manuel kabul kontrollerini ve teslim kapilarini kaydeder.

## Manuel kabul

Tarih: 2026-10-17

- Yetkili yerel hedef `127.0.0.1`, kapali `65534/tcp` portu ile tarandi.
- Hedef `--allow-target 127.0.0.1` ile acikca kapsam icine alindi.
- Sonuc `NOT_VULNERABLE`, surec cikis kodu `0` oldu.
- `stdout.txt`, `stderr.txt`, `evidence.json` ve `manifest.json` olusturuldu.
- Manifesto dosya boyutlarini, SHA-256 degerlerini, arac surumunu ve zaman bilgisini icerdi.
- Dort evidence kaydi SQLite `evidence_dosyalari` tablosunda dogrulandi.
- Allowlist verilmeden yapilan ayni istek, harici arac calistirilmadan cikis kodu `2` ile reddedildi.

TLS kabul testinde `testssl.net:443` icin SSLv2 ve SSLv3 sunulmadigi dogrulandi. Birden fazla
IP adresinin sonuclari ayri yapilandirilmis kanitlar olarak saklandi ve sonuc `NOT_VULNERABLE`
oldu.

## Otomatik teslim kapilari

Teslimden once asagidaki komutlarin tamami basarili olmalidir:

```bash
pytest
ruff check .
ruff format --check .
python -m build
```

Paket kurulum smoke testi, olusan wheel dosyasinin temiz bir sanal ortama kurulmasi ve su
komutlarin calistirilmasiyla tamamlanir:

```bash
vulnverifier --version
vulnverifier list
vulnverifier doctor
```
