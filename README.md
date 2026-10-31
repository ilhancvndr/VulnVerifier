# VulnVerifier

VulnVerifier, yalnızca yetkili güvenlik testlerinde kullanılmak üzere geliştirilen, kanıt odaklı bir zafiyet doğrulama aracıdır.

MVP `0.1.0` sürümündeki ilk 15 doğrulama yöntemine ek olarak SMB güvenlik keşfi de standart sonuç modeli ve evidence altyapısıyla birlikte `verify` komutuna bağlanmıştır.

## Gereksinimler

- Python 3.12 veya üzeri
- Standart PNG kanıt görüntüleri için Pillow
- Port ve servis keşfi için Nmap
- Nmap tabanlı kontroller için kurulumla gelen ilgili NSE betikleri
- TLS kontrolleri için `testssl.sh`
- Metasploit tabanlı kontroller için PATH içinde erişilebilir `msfconsole`

macOS üzerinde `testssl.sh` kurulumu:

```bash
brew install testssl
```

VulnVerifier hem `testssl` hem de Homebrew tarafından sağlanan `testssl.sh` komut adını tanır. Eksik araç yalnızca ilgili kontrolü `SKIPPED` durumuyla atlatır; diğer komutları engellemez.

## Kurulum

Proje kök dizininde sanal ortam oluşturup paketi geliştirme bağımlılıklarıyla kurun:

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
```

`python3 --version` çıktısı en az 3.12 olmalıdır. Bu geliştirme ortamında varsayılan `python3` komutu 3.11'e işaret ettiği için sanal ortam oluştururken `python3.14 -m venv .venv` kullanılmalıdır.

Kurulumdan sonra komutun erişilebilir olduğunu doğrulayın:

```bash
vulnverifier --version
vulnverifier --help
```

## Mevcut CLI komutları

Kayıtlı doğrulama kontrollerini listelemek için:

```bash
vulnverifier list
```

Python ile harici araçların durumunu, sürümünü, yolunu ve varsayılan timeout değerini görmek için:

```bash
vulnverifier doctor
```

Varsayılan tarama timeout değerleri Nmap için 180 saniye, `testssl.sh` ve Metasploit için 300 saniyedir. Sürüm denetimi sırasında eksik araçlar ve çalıştırma hataları ortak durum kodlarıyla gösterilir; diğer araçların kontrolü devam eder.

Varsayılan `vulnverifier.db` dosyasını oluşturup SQLite bağlantısını kontrol etmek için:

```bash
vulnverifier database-check
```

Farklı bir veritabanı yolu kullanmak için:

```bash
vulnverifier database-check --database ./data/vulnverifier.db
```

Bu komut bağlantıyı açar, güncel şemayı uygular; SQLite sürümünü, şema sürümünü ve foreign key denetimini gösterir.

Doğrulamalar varsayılan olarak `default` projesine ve `vulnverifier.db` dosyasına kaydedilir. Proje ve veritabanı yolu değiştirilebilir:

```bash
vulnverifier verify port-service-discovery \
  --target 192.0.2.10 \
  --port 443 \
  --project musteri-a \
  --database ./data/vulnverifier.db
```

Kaydedilmiş doğrulama geçmişini ve ortak bulgu anahtarına göre birleştirilen bulguları görüntülemek için:

```bash
vulnverifier history --project musteri-a
vulnverifier findings --project musteri-a
```

Yetkili bir hedefte belirli bir portu doğrulamak için:

```bash
vulnverifier verify port-service-discovery \
  --target 192.0.2.10 \
  --port 443
```

`--allow-target` verilmezse yalnızca `--target` ile belirtilen kesin hedef örtük olarak yetkili kabul edilir. Daha geniş veya açık bir kapsam denetimi gerektiğinde tek IP, hostname ya da CIDR ile `--allow-target` kullanılabilir ve seçenek birden fazla kez tekrarlanabilir. Seçenek verilmişse hedef bu listenin dışında kaldığında araç çalıştırılmaz. `intrusive` kontroller ayrıca `--confirm-intrusive` olmadan başlatılmaz.

Port ve servis keşfi bir zafiyet doğrulaması değildir. Açık port bulunduğunda sonuç
`DISCOVERED`, istenen port kesin olarak kapalıysa `NOT_FOUND` olur. Bu iki durum da `0`
çıkış kodu üretir ve `findings` listesine zafiyet olarak eklenmez; çalışma geçmişi ve
evidence kayıtları yine korunur.

Birden fazla port virgülle ayrılarak tek `--port` seçeneğinde verilir. `--port` verilmezse
Nmap varsayılan en yaygın 1000 TCP portunu tarar. Sonuç, yapılandırılmış kanıtlar ve
evidence dosyalarının SHA-256 değerleri terminalde gösterilir. Dosyalar varsayılan olarak
proje dizinindeki `evidence/` klasörüne yazılır. Farklı bir ana dizin kullanmak için
`--evidence-dir` verilebilir.

```bash
vulnverifier verify port-service-discovery \
  --target 192.0.2.10 \
  --port 80,443,445 \
  --allow-target 192.0.2.0/24 \
  --evidence-dir ./guvenli-evidence
```

Herhangi bir doğrulamanın sonucunu rapora eklenebilir standart bir PNG kanıt görüntüsüne
dönüştürmek için `--screenshot` kullanılır:

```bash
vulnverifier verify port-service-discovery \
  --target 127.0.0.1 \
  --port 443 \
  --screenshot
```

Kullanıcıya sunulan PNG varsayılan olarak proje kökündeki `screenshots/` klasörüne
yazılır. Denetim bütünlüğü için aynı açıklayıcı adla evidence klasöründe de tutulur;
SHA-256 değeri `*-manifest.json` ve SQLite kaydına eklenir. Tek hedef görüntüsü kontrol
türüne göre yalnızca raporda gerekli hedef, port, servis, protokol, sürüm veya doğrulama
alanlarını gösterir. Hassas değerler mevcut evidence politikasıyla maskelenir.

Varsayılan klasör yerine farklı bir konum kullanmak için `--screenshot-dir` verilebilir.
Bu seçenek tek başına kullanıldığında da ekran görüntüsü üretimini etkinleştirir:

```bash
vulnverifier verify smb-security-discovery \
  --target "10.0.100.2, 10.0.100.3" \
  --port 445 \
  --screenshot-dir ./screenshots
```

Tek hedefte kullanıcıya sunulan dosya adı `hedef-kontrol-durum-YYYYAAGG-SSDD.png`
biçimindedir. Çoklu hedeflerde her CIDR bloğu için ayrı, CIDR dışındaki seçili hedefler
için tek toplu özet oluşturulur. Port/servis ve sürüm keşifleri tablo; SSLv2/SSLv3 ve SMB
kontrolleri bulgu türlerine ayrılmış hedef listeleri; diğer kontroller doğrulanmış hedef
listesi kullanır. Çok sayıda sonuç otomatik olarak `sayfa-1`, `sayfa-2` biçiminde bölünür.
Dosya adında saniye bulunmaz. Aynı ad mevcutsa dosyanın üzerine yazmak yerine kısa çalışma
kimliği eklenir. Görsel sayısı azaltılsa da bütün hedeflerin evidence ve SQLite kayıtları
korunur.

`--all-screenshots` geriye dönük uyumluluk için PNG üretimini etkinleştirir. Toplu
özetler zaten kapsamdaki bütün kesin sonuçları içerir:

```bash
vulnverifier verify port-service-discovery \
  --target "10.20.10.0/24, 10.30.10.0/24" \
  --all-screenshots
```

Çoklu `smb-security-discovery` görüntüsü yalnızca `SMBv1 açık olan hedefler` ve `SMB
imzalaması zorunlu olmayan hedefler` listelerini içerir. Her bölümde 25 hedefden sonra
yeni PNG sayfası açılır.

Ham çıktı, hata çıktısı, normalize sonuç ve manifesto da aynı ad temelini kullanır;
dosya türü sırasıyla `-stdout.txt`, `-stderr.txt`, `-evidence.json` ve
`-manifest.json` son ekiyle belirtilir. Böylece dışarı alınan dosyalar klasörden ayrı
paylaşılsa bile hedef ve doğrulama bilgisi dosya adından anlaşılır.

Bir TLS servisinde SSLv2 ve SSLv3 desteğini doğrulamak için:

```bash
vulnverifier verify sslv2-sslv3-support \
  --target example.com \
  --port 443
```

Bu kontrolde port verilmezse `443` kullanılır. Kontrol tek çalışmada bir port kabul eder. Bir hostname birden fazla IP adresine çözülürse her IP sonucu ayrı tutulur. Herhangi bir IP SSLv2 veya SSLv3 sunuyorsa sonuç `VULNERABLE`, yalnızca bütün IP'lerde ikisi de kapalı ve modern bir TLS protokolü açıksa `NOT_VULNERABLE`, sonuçlardan biri eksikse `INCONCLUSIVE` olur.

Yetkili bir HPE iLO hedefinde ürün ve firmware sürümünü tespit etmek için:

```bash
vulnverifier verify hpe-ilo-version-detection \
  --target 192.168.1.50 \
  --port 443
```

Bu kontrolde port verilmezse `443` kullanılır ve tek çalışmada yalnızca bir port kabul edilir. iLO türü ile firmware sürümü birlikte tespit edilirse sonuç `POTENTIALLY_VULNERABLE` olur; bu durum tek başına kesin bir zafiyet anlamına gelmez. Port filtreliyse veya iLO bilgisi alınamazsa sonuç `INCONCLUSIVE` olur.

Bir TLS servisinde anonymous cipher desteğini doğrulamak için:

```bash
vulnverifier verify anonymous-cipher-support \
  --target testssl.net \
  --port 443
```

Bu kontrolde port verilmezse `443` kullanılır ve tek çalışmada yalnızca bir port kabul edilir. Herhangi bir IP anonymous cipher sunuyorsa sonuç `VULNERABLE`, bütün IP sonuçları kesin olarak kapalıysa `NOT_VULNERABLE`, eksik veya anlaşılamayan bir sonuç varsa `INCONCLUSIVE` olur.

Yetkili bir RDP hedefinde MS12-020 zafiyetini Metasploit ile doğrulamak için:

```bash
vulnverifier verify ms12-020-metasploit \
  --target 192.0.2.10 \
  --port 3389
```

Bu kontrolde port verilmezse `3389` kullanılır ve tek çalışmada yalnızca bir port kabul edilir. Metasploit zafiyeti doğrularsa sonuç `VULNERABLE`, hedefin etkilenmediğini bildirirse `NOT_VULNERABLE`, RDP servisine ulaşılamaz veya durum kesinleştirilemezse `INCONCLUSIVE` olur. Kullanılan `auxiliary/scanner/rdp/ms12_020_check` modülü zafiyeti kontrol eder; DoS modülü çalıştırılmaz.

Yetkili bir hedefte varsayılan SNMP `public` community değerini doğrulamak için:

```bash
sudo .venv/bin/vulnverifier verify snmp-public-community \
  --target 192.168.1.50 \
  --port 161
```

Bu kontrolde port verilmezse `161/udp` kullanılır ve tek çalışmada yalnızca bir port kabul edilir. `snmp-sysdescr` yanıtı alınırsa `public` community doğrulanır ve sonuç `VULNERABLE` olur. UDP yanıtı alınamazsa güvenli olduğu varsayılmaz; sonuç `INCONCLUSIVE` olur. Nmap UDP taraması macOS üzerinde yönetici yetkisi gerektirdiği için komut `sudo` ile çalıştırılır. Evidence klasörü bu kullanımda `root` sahibi olabilir.

Yetkili bir VMware ESX veya ESXi hedefinde sürüm bilgisini tespit etmek için:

```bash
vulnverifier verify vmware-esxi-version-detection \
  --target 192.168.1.60 \
  --port 443
```

Bu doğrulamada port verilmezse `443/tcp` kullanılır. Ürün ve sürüm bilgisi tespit edilirse sonuç `POTENTIALLY_VULNERABLE` olur; bu sonuç kesin zafiyet anlamına gelmez ve sürümün ayrıca güvenlik duyurularıyla karşılaştırılması gerekir. Port kapalı, filtreli veya VMware SOAP bilgisi alınamazsa sonuç `INCONCLUSIVE` olur.

Yetkili bir SMB hedefinde MS17-010 durumunu Metasploit ile doğrulamak için:

```bash
vulnverifier verify ms17-010-metasploit \
  --target 192.168.1.70 \
  --port 445
```

Port verilmezse `445/tcp` kullanılır. Sonuç `VULNERABLE`, `NOT_VULNERABLE` veya `INCONCLUSIVE` olabilir. Yalnızca `auxiliary/scanner/smb/smb_ms17_010` tarayıcısı kullanılır; exploit çalıştırılmaz. DoublePulsar, mimari ve named-pipe ek sorguları açıkça kapatılır.

Yetkili bir DNS sunucusunda cache snooping doğrulaması yapmak için:

```bash
sudo .venv/bin/vulnverifier verify dns-cache-snooping \
  --target 192.168.1.53 \
  --port 53 \
  --confirm-intrusive
```

Bu doğrulama `intrusive` olarak işaretlidir ve Nmap `dns-cache-snoop` betiğini yalnızca `nonrecursive` modda çalıştırır. `timed` mod kullanılmaz ve DNS önbelleğine kayıt eklenmez. Gereksiz UDP servis sürümü taraması yapılmaz ve NSE betiği 45 saniyeyle sınırlandırılır. Önbellekte alan adı doğrulanırsa `VULNERABLE`; alan adı bulunamaz veya cevap alınamazsa `INCONCLUSIVE` üretilir. UDP taraması macOS üzerinde `sudo` gerektirir.

Yetkili bir SMB hedefinde MS17-010 durumunu Nmap ile doğrulamak için:

```bash
vulnverifier verify ms17-010-nmap \
  --target 192.168.1.70 \
  --port 445
```

Port verilmezse `445/tcp` kullanılır. Güvenli `smb-vuln-ms17-010` NSE betiği çalıştırılır; exploit uygulanmaz. `vulns.showall=1` argümanı sayesinde yamalı sistem sonucu da açıkça alınır. Sonuç `VULNERABLE`, `NOT_VULNERABLE` veya kesin NSE sonucu üretilemediğinde `INCONCLUSIVE` olabilir. Bu yöntem ve Metasploit yöntemi aynı `ms17-010-smb-vulnerability` bulgu anahtarına bağlıdır.

Yetkili bir RDP hedefinde MS12-020 durumunu Nmap ile doğrulamak için:

```bash
vulnverifier verify ms12-020-nmap \
  --target 192.168.1.50 \
  --port 3389 \
  --confirm-intrusive
```

Port verilmezse `3389/tcp` kullanılır. Nmap `rdp-vuln-ms12-020` NSE betiği `intrusive` kategorisindedir; yalnızca açıkça yetkilendirilmiş hedeflerde çalıştırılmalıdır. Betik exploit çalıştırmaz ancak birden fazla özel RDP isteği gönderir. NSE sonucu açıkça zafiyet gösterirse `VULNERABLE`, iki MS12-020 CVE kaydı da açıkça güvenli ise `NOT_VULNERABLE` üretilir. Beklenmeyen sunucu cevabı, eksik betik çıktısı veya filtreli port `INCONCLUSIVE` olarak değerlendirilir. Bu yöntem ve Metasploit yöntemi aynı `ms12-020-rdp-vulnerability` bulgu anahtarına bağlıdır.

Yetkili bir IPMI 2.0 hedefinde RAKP parola hash disclosure durumunu doğrulamak için:

```bash
vulnverifier verify ipmi-v2-hash-disclosure \
  --target 192.168.1.80 \
  --port 623 \
  --confirm-intrusive
```

Port verilmezse `623/udp` kullanılır. Metasploit `auxiliary/scanner/ipmi/ipmi_dumphashes` modülü tek iş parçacığıyla çalıştırılır ve otomatik parola kırma davranışı `CRACK_COMMON false` ile kapatılır. Hash alınırsa `VULNERABLE`; cevap alınamazsa veya hash bulunamazsa `INCONCLUSIVE` üretilir. Kullanıcı tercihi gereği tam RAKP hash değeri ham ve normalize evidence içinde saklanır. Bu dosyalar hassastır; VulnVerifier evidence dizinlerini `0700`, dosyaları `0600` izinleriyle oluşturur ve yalnızca yetkili kişilerle paylaşılmalıdır.

Yetkili bir TLS servisinde FREAK ve EXPORT RSA desteğini doğrulamak için:

```bash
vulnverifier verify freak-export-rsa \
  --target testssl.net \
  --port 443
```

Port verilmezse `443/tcp` kullanılır ve tek çalışmada yalnızca bir port kabul edilir. `testssl.sh --freak` çıktısı her IP için ayrı değerlendirilir. En az bir tarama noktası EXPORT RSA cipher sunduğunda `VULNERABLE`, bütün tarama noktaları açıkça etkilenmediğini bildirdiğinde `NOT_VULNERABLE`, test yapılamadığında veya sonuç eksik kaldığında `INCONCLUSIVE` üretilir.

Yetkili bir TLS servisinde OpenSSL CCS Injection durumunu doğrulamak için:

```bash
vulnverifier verify openssl-ccs-injection \
  --target testssl.net \
  --port 443 \
  --confirm-intrusive
```

Port verilmezse `443/tcp` kullanılır ve tek çalışmada yalnızca bir port kabul edilir. Bu aktif TLS kontrolü `intrusive` olarak işaretlidir ve yalnızca yetkili hedeflerde kullanılmalıdır. `testssl.sh --ccs` çıktısı her IP için ayrı değerlendirilir. Kesin bulgu `VULNERABLE`, şüpheli TLS uyarısı `POTENTIALLY_VULNERABLE`, bütün sonuçlar açıkça güvenliyse `NOT_VULNERABLE`, test başarısız veya belirsizse `INCONCLUSIVE` üretir.

Yetkili bir NTP servisinde Mode 6 READVAR cevaplarını doğrulamak için:

```bash
sudo .venv/bin/vulnverifier verify ntp-mode-6 \
  --target 192.168.1.123 \
  --port 123
```

Port verilmezse `123/udp` kullanılır. Nmap `ntp-info` betiği bir normal zaman isteği ve tek bir Mode 6 READVAR isteği gönderir; betik çalışması 20 saniyeyle sınırlandırılır. READVAR değişkenleri alınırsa `VULNERABLE`, yalnızca normal zaman cevabı alınıp Mode 6 cevabı alınmazsa `NOT_VULNERABLE`, UDP portu cevap vermediğinde `INCONCLUSIVE` üretilir. UDP taraması macOS üzerinde `sudo` gerektirir.

Yetkili SMB hedeflerinin kimlik ve güvenlik yapılandırmasını keşfetmek için:

```bash
vulnverifier verify smb-security-discovery \
  --target 192.168.1.50 \
  --port 445
```

Birden fazla hedef virgülle ayrılarak verilebilir:

```bash
vulnverifier verify smb-security-discovery \
  --target "10.0.100.2, 10.0.100.3, 10.0.100.20" \
  --port 445
```

CIDR blokları kullanılabilir ve birden fazla blok aynı komutta birleştirilebilir:

```bash
vulnverifier verify smb-security-discovery \
  --target "10.20.10.0/24, 10.30.10.0/24" \
  --port 445 \
  --screenshot
```

IPv4 CIDR bloklarında network ve broadcast adresleri tarama dışında tutulur. Tekil
hedefler ve CIDR blokları birleştirilip tekrarlar kaldırıldıktan sonra en fazla 4096 hedef
kullanılabilir.

Hedefler isteğe bağlı bir UTF-8 metin dosyasından da okunabilir. Boş satırlar ile `#` karakteriyle başlayan açıklamalar yok sayılır. `--target` ve `--target-file` birlikte kullanıldığında girdiler birleştirilir ve tekrarlar kaldırılır.

```bash
vulnverifier verify smb-security-discovery \
  --target "10.0.100.2, 10.0.100.3" \
  --target-file ./targets.txt
```

Hedefler varsayılan olarak en fazla dört kontrollü iş parçacığıyla taranır. Bu değer
`--workers 1` ile sıralı çalışmaya indirilebilir veya `--workers 16` değerine kadar
artırılabilir. Terminal ve SQLite sırası hedef giriş sırasını korur. Çoklu hedeflerde
varsayılan terminal tablosu ve toplu PNG üretimi kesin `VULNERABLE`, bilgi amaçlı
`DISCOVERED` ve sürüm incelemesi gerektiren `POTENTIALLY_VULNERABLE` sonuçlarını kapsar.
`-v` veya `--verbose` verilirse temiz, bulunamayan, belirsiz, atlanan ve hatalı sonuçlar
terminal tablosunda da gösterilir. Toplu PNG'ler verbose durumundan bağımsız olarak yalnızca
kesin bulguları ve doğrulanmış keşifleri listeler.
Filtre ne olursa olsun her hedefin sonucu ayrı evidence klasörü ve SQLite kaydıyla
saklanır. Virgüllü hedef, CIDR ve `--target-file` desteği bütün mevcut ve daha sonra
kaydedilecek kontrollerin ortak çalışma akışında kullanılabilir.

Port verilmezse `445/tcp` kullanılır. Nmap `smb-os-discovery`, `smb-protocols` ve `smb2-security-mode` betiklerini birlikte çalıştırır. Bilgisayar adı, işletim sistemi, domain, SMB sürümleri, SMBv1 ve imzalama zorunluluğu yapılandırılmış kanıta dönüştürülür. SMBv1 etkinse veya SMB imzalama zorunlu değilse `VULNERABLE`; SMBv1 kapalı ve imzalama zorunluysa `NOT_VULNERABLE`; bilgiler eksik ya da port filtreliyse `INCONCLUSIVE` üretilir. Kontrol kimlik bilgisi kullanmaz.

`verify` sonuç çıkış kodları:

- `0`: Zafiyet doğrulanmadı veya keşif tamamlandı (`NOT_VULNERABLE`, `DISCOVERED`, `NOT_FOUND`)
- `10`: Zafiyet veya potansiyel zafiyet tespit edildi
- `20`: Sonuç kesinleştirilemedi (`INCONCLUSIVE`)
- `30`: Kontrol atlandı (`SKIPPED`)
- `40`: Kontrol hatayla tamamlandı (`ERROR`)
- `130`: Tarama kullanıcı tarafından `Ctrl+C` ile iptal edildi
- `2`: Girdi geçersiz veya hedef/risk güvenlik politikası tarafından reddedildi

Geçersiz hedef/port girdileri, kapsam dışı hedefler ve onaysız `intrusive` kontroller `2` çıkış koduyla reddedilir:

```bash
vulnverifier verify port-service-discovery \
  --target '192.0.2.10;whoami' \
  --port 443
```

## Paket oluşturma ve teslim kontrolü

Dağıtım paketlerini oluşturmak için geliştirme bağımlılıklarının kurulu olduğu ortamda:

```bash
ruff check .
ruff format --check .
python -m build
```

Komut sonunda `dist/` altında kaynak dağıtımı ve wheel paketi oluşur. Wheel paketini temiz bir
sanal ortamda doğrulamak için:

```bash
python -m venv /tmp/vulnverifier-smoke
source /tmp/vulnverifier-smoke/bin/activate
python -m pip install dist/vulnverifier-0.1.0-py3-none-any.whl
vulnverifier --version
vulnverifier list
vulnverifier doctor
deactivate
```

Proje için henüz bir lisans seçilmemiştir; paket metadata'sında varsayımsal bir lisans
beyanı bulunmaz. Public kullanım ve yeniden dağıtım koşulları yayın sahibi tarafından
lisans dosyası eklenerek ayrıca belirlenmelidir.

## Hazır olan teknik parçalar

- Shell kullanmayan merkezi komut çalıştırıcı
- Timeout, Ctrl+C ve program içi iptalde tüm harici süreç grubunu sonlandırma
- IPv4, IPv6, hostname ve çoklu port doğrulama
- İsteğe bağlı hedef/hostname/CIDR allowlist denetimi
- Intrusive kontroller için ayrı açık onay
- Salt-okunur olmayan, DoS veya exploit etkili kontrol engeli
- Çoklu hedeflerde 1-16 arası ayarlanabilir kontrollü paralellik
- Terminal ve evidence çıktılarında hassas veri maskeleme
- Harici araç bulunabilirlik kontrolü
- Güvenli Nmap argüman üretimi
- Nmap XML ayrıştırma
- Port keşfini zafiyetten ayıran `DISCOVERED` ve `NOT_FOUND` durumları
- Güvenli testssl argüman üretimi
- SSLv2, SSLv3 ve modern TLS protokol çıktısı ayrıştırma
- testssl çoklu IP sonuçlarını ayrı değerlendirip korumacı biçimde birleştirme
- Eski SSL protokol desteğini standart sonuca dönüştürme
- Ham stdout ve stderr kaydı
- Açıklayıcı adlı normalize `*-evidence.json` kaydı
- Evidence dosyası SHA-256 hesaplama
- 5 MiB ham çıktı sınırı ve hassas değer maskeleme
- Atomik evidence yazımı ve kısmi yazım temizliği
- Çalışma kimliği, araç sürümü, çıkış kodu, zaman ve dosya hash'lerini içeren `*-manifest.json`
- Rich tabanlı doğrulama sonucu ve evidence gösterimi
- Pillow tabanlı, tüm kontrollerde kullanılabilen standart PNG kanıt görüntüsü
- Yalnızca sabit `auxiliary/scanner` modüllerine izin veren Metasploit güvenlik listesi
- Güvenli Metasploit MS12-020 argüman üretimi ve çıktı ayrıştırma
- Güvenli Nmap SNMP public community argüman üretimi ve XML çıktı ayrıştırma
- Güvenli Nmap VMware sürüm argüman üretimi ve XML çıktı ayrıştırma
- Güvenli Metasploit MS17-010 argüman üretimi ve çıktı ayrıştırma
- Nonrecursive Nmap DNS cache snooping argüman üretimi ve XML çıktı ayrıştırma
- Güvenli Nmap MS17-010 NSE argüman üretimi ve XML çıktı ayrıştırma
- Aynı bulguya ait Metasploit ve Nmap doğrulama yöntemlerini ilişkilendirme
- Nmap MS12-020 NSE argüman üretimi, XML çıktı ayrıştırma ve korumacı hata değerlendirmesi
- Parola kırma kapalı Metasploit IPMI RAKP hash doğrulaması ve izinleri kısıtlı hassas evidence yönetimi
- testssl FREAK/EXPORT RSA argüman üretimi, çoklu IP ayrıştırması ve korumacı sonuç birleştirmesi
- testssl OpenSSL CCS Injection argüman üretimi, kesinlik ayrımı ve çoklu IP değerlendirmesi
- Nmap NTP Mode 6 READVAR sorgusu, XML ayrıştırması ve zaman cevabından ayrı değerlendirme

## Güncel sınırlamalar

- MS12-020 ve MS17-010 yöntemlerinin pozitif kabulü için etkilenmiş ve yetkili Windows hedefleri gerekir.
- HPE iLO ve VMware sürüm keşiflerinin pozitif kabulü için erişilebilir gerçek yönetim hedefleri gerekir.
- IPMI hash disclosure pozitif kabulü için yetkili ve etkilenmiş bir IPMI 2.0 hedefi gerekir.
- İlk 15 doğrulama yönteminin tamamı kod ve yazılım testleri bakımından hazırdır.
- SQLite şeması, kalıcı doğrulama kayıtları ve CLI geçmiş komutları hazırdır.
- Yerel arayüz, manuel bulgu ekleme/düzenleme ve rapor oluşturma MVP sonrası kapsama taşındı.

## Güvenli kullanım

VulnVerifier yalnızca açıkça yetkilendirilmiş sistemlerde kullanılmalıdır. DoS oluşturan, hedef sistemde değişiklik yapan veya otomatik exploit çalıştıran yöntemler MVP kapsamı dışındadır.

Public depo yalnızca çalıştırma için gereken kaynak kodu, paket ayarlarını ve bu kullanım
belgesini içerir. İç geliştirme notları ve test varlıkları dağıtım paketine dahil edilmez.

