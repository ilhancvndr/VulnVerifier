# VulnVerifier Feature Listesi

Bu dosya, VulnVerifier MVP ve MVP sonrasi kapsamindaki tamamlanan ve eksik ozellikleri takip eder.

Durumlar:

- `[x]` Tamamlandi ve test edildi.
- `[ ]` Henuz tamamlanmadi.
- `[!]` Kod tamamlandi, yalnizca manuel kabul dogrulamasi bekliyor.

## 1. Proje temeli

- [x] Python paket yapisi
- [x] `pyproject.toml` yapilandirmasi
- [x] Python 3.12 ve uzeri surum destegi
- [x] Typer tabanli CLI iskeleti
- [x] Rich terminal ciktisi
- [x] `list` komutu
- [x] `doctor` komutu
- [x] `verify` komut iskeleti
- [x] Uygulama surumu komutu
- [x] pytest test altyapisi
- [x] Ruff kod kalitesi ve format kontrolu
- [x] Yerel Python sanal ortami
- [x] Gelistirme ve kodlama kurallarinin `RULES.md` icinde tutulmasi
- [x] README kullanim bilgilerinin mevcut davranislarla guncellenmesi
- [x] Temiz ortamda kurulum ve CLI smoke testi

## 2. Dogrulama cekirdegi

- [x] Standart sonuc durumlari
- [x] `SAFE` ve `INTRUSIVE` risk seviyeleri
- [x] Kontrol metadata modeli
- [x] Kontrol katalogu
- [x] Hedef dogrulama
- [x] Port dogrulama
- [x] `verify` komutunda tekrarlanabilir `--port` secenegi
- [x] `shell=False` kullanan guvenli komut calistirici
- [x] Komut timeout yonetimi
- [x] Calisan sureci iptal etme
- [x] stdout, stderr ve cikis kodu modeli
- [x] Harici arac bulunabilirlik kontrolu
- [x] Standart kontrol sonucu modeli
- [x] Yapilandirilmis kanit modeli
- [x] Kontroller icin ortak calistirma servisi
- [x] Basarili arac sonucunu standart kontrol sonucuna aktarma
- [x] Sifir olmayan arac cikis kodunu `ERROR` sonucuna aktarma
- [x] Timeout durumunu standart sonuca aktarma
- [x] Kullanici iptalini `SKIPPED` sonucuna aktarma
- [x] Ayristirma hatasini `ERROR` sonucuna aktarma
- [x] Eksik araci `SKIPPED` sonucuna aktarma
- [x] Kontrol calisma suresi ve zaman bilgilerinin kaydi

## 3. Ilk kontrol: belirli port ve servis kesfi

- [x] `port-service-discovery` katalog kaydi
- [x] Nmap bulunabilirlik kontrolu
- [x] Nmap komut argumanlarini guvenli olusturma
- [x] IPv4, IPv6 ve hostname destegi
- [x] Secilen portlari tek Nmap taramasinda sinirlama
- [x] Nmap XML ciktisi isteme
- [x] Nmap XML ayristiricisi
- [x] Host durumu ayristirma
- [x] Port durumu ayristirma
- [x] Servis, urun ve surum bilgisi ayristirma
- [x] Acik portu `VULNERABLE` olarak siniflandirma
- [x] Kapali portu `NOT_VULNERABLE` olarak siniflandirma
- [x] Filtrelenmis veya belirsiz portu `INCONCLUSIVE` olarak siniflandirma
- [x] Eksik host veya port kaydini `INCONCLUSIVE` olarak siniflandirma
- [x] Port verilmezse Nmap varsayilan en yaygin 1000 TCP portunu tarama karari
- [x] Birden fazla portu tek taramada destekleme
- [x] Ilk kontrol icin CLI'dan bagimsiz calistirma servisi
- [x] Nmap adaptoru ile XML ayristiricisini birlestirme
- [x] Ayristirilmis sonucu standart sonuca baglama
- [x] Ham ve normalize evidence islemlerini ayni akis icinde calistirma
- [x] Evidence hash'lerini kontrol sonucuyla iliskilendirme
- [x] `verify port-service-discovery` komutunu gercek motora baglama
- [x] Sonucu Rich ile terminalde gosterme
- [x] Basarili, zafiyetli, belirsiz, atlanan ve hatali sonuclar icin CLI cikis kodlari
- [x] Eksik Nmap senaryosu icin uctan uca test
- [x] Nmap hata cikisi icin uctan uca test
- [x] Timeout senaryosu icin uctan uca test
- [x] Acik port senaryosu icin uctan uca test
- [x] Kapali port senaryosu icin uctan uca test
- [x] Yerel `127.0.0.1` hedefinde gercek manuel tarama

> Ilk port ve servis kesfi yontemi gercek motor, evidence ve uctan uca testleriyle tamamlanmistir.

## 4. Ilk 15 dogrulama yontemi

- [x] 1. Nmap belirli port ve servis kesfi
- [x] 2. SSLv2 ve SSLv3 destegi
- [x] 3. HPE iLO surum tespiti
- [x] 4. Anonymous TLS cipher destegi
- [x] 5. MS12-020 - Metasploit yontemi
- [x] 6. SNMP `public` community kontrolu
- [x] 7. VMware ESXi surum tespiti
- [x] 8. MS17-010 - Metasploit yontemi
- [x] 9. DNS cache snooping
- [x] 10. MS17-010 - Nmap yontemi
- [x] 11. MS12-020 - Nmap yontemi
- [x] 12. IPMI 2.0 hash disclosure
- [x] 13. FREAK kontrolu
- [x] 14. OpenSSL CCS Injection kontrolu
- [x] 15. NTP Mode 6 kontrolu
- [x] Her yontem icin kontrol katalog kaydi
- [x] Her yontem icin temizlenmis gercek arac ciktisi fixture'i
- [x] Her yontem icin sonuc siniflandirma testleri
- [x] Ayni bulguya ait farkli yontemleri tek bulgu anahtariyla iliskilendirme
- [x] MS17-010 Metasploit ve Nmap yontemlerini ortak bulgu anahtariyla iliskilendirme
- [x] Yalnizca surum tespit eden kontrolleri kesin zafiyet olarak isaretlememe

### 3. HPE iLO surum tespiti

- [x] `hpe-ilo-version-detection` katalog kaydi
- [x] Nmap `http-hp-ilo-info` komut argumanlarini guvenli olusturma
- [x] Nmap XML ciktisindan iLO urun ve firmware surumunu ayristirma
- [x] Surum bilgisini `POTENTIALLY_VULNERABLE` veya `INCONCLUSIVE` olarak siniflandirma
- [x] Kontrol calistirma servisi
- [x] CLI baglantisi
- [x] Ham ve yapilandirilmis evidence olusturma
- [x] Birim ve entegrasyon testleri
- [x] CLI testleri
- [x] Yetkili hedefte CLI manuel kabul testi
- [!] Gercek HPE iLO cihazinda pozitif manuel kabul testi icin uygun hedef gerekiyor

### 4. Anonymous TLS cipher destegi

- [x] `anonymous-cipher-support` katalog kaydi
- [x] `testssl.sh -s` komut argumanlarini guvenli olusturma
- [x] Anonymous cipher ciktisini tek ve coklu IP icin ayristirma
- [x] Sonucu `VULNERABLE`, `NOT_VULNERABLE` veya `INCONCLUSIVE` olarak siniflandirma
- [x] Kontrol calistirma servisi
- [x] CLI baglantisi
- [x] Ham ve yapilandirilmis evidence olusturma
- [x] Birim, entegrasyon ve CLI testleri
- [x] Yetkili hedefte CLI manuel kabul testi

### 5. MS12-020 - Metasploit yontemi

- [x] `ms12-020-metasploit` katalog kaydi
- [x] Guvenli `msfconsole` komut argumanlarini olusturma
- [x] Gercek arac ciktisindan ve guncel modul mesajlarindan temizlenmis test fixture'lari
- [x] Metasploit ciktisini ayristirma
- [x] Sonucu standart durumlarla siniflandirma
- [x] Kontrol calistirma servisi
- [x] CLI baglantisi
- [x] Ham ve yapilandirilmis evidence olusturma
- [x] Birim, entegrasyon ve CLI testleri
- [x] Yetkili hedefte CLI manuel kabul testi

> Yerel ve filtreli RDP hedeflerinde `INCONCLUSIVE` sonucu, cikis kodu ve evidence akisi manuel olarak dogrulanmistir.

### 6. SNMP `public` community kontrolu

- [x] `snmp-public-community` katalog kaydi
- [x] Guvenli Nmap UDP komut argumanlarini olusturma
- [x] Temizlenmis gercek arac ciktisi fixture'lari
- [x] Nmap XML ciktisini ayristirma
- [x] Sonucu standart durumlarla siniflandirma
- [x] Kontrol calistirma servisi
- [x] CLI baglantisi
- [x] Ham ve yapilandirilmis evidence olusturma
- [x] Birim, entegrasyon ve CLI testleri
- [x] Yetkili hedefte CLI manuel kabul testi

> Yetkili hedefte CLI sonucu, cikis kodu ve evidence akisi kullanici tarafindan kabul edilmistir.

### 7. VMware ESXi surum tespiti

- [x] `vmware-esxi-version-detection` katalog kaydi
- [x] Guvenli Nmap `vmware-version` komut argumanlarini olusturma
- [x] Temizlenmis gercek arac ciktisi fixture'lari
- [x] Nmap XML ciktisindan VMware urun, surum ve build bilgisini ayristirma
- [x] Surum bilgisini `POTENTIALLY_VULNERABLE` veya `INCONCLUSIVE` olarak siniflandirma
- [x] Kontrol calistirma servisi
- [x] CLI baglantisi
- [x] Ham ve yapilandirilmis evidence olusturma
- [x] Birim, entegrasyon ve CLI testleri
- [x] Yetkili hedefte CLI manuel kabul testi

> Yetkili hedefte CLI sonucu, cikis kodu ve evidence akisi kullanici tarafindan kabul edilmistir.

### 8. MS17-010 - Metasploit yontemi

- [x] `ms17-010-metasploit` katalog kaydi
- [x] Guvenli `auxiliary/scanner/smb/smb_ms17_010` komut argumanlarini olusturma
- [x] Temizlenmis gercek arac ciktisi fixture'lari
- [x] Metasploit ciktisini ayristirma
- [x] Sonucu standart durumlarla siniflandirma
- [x] Dogrulama calistirma servisi
- [x] CLI baglantisi
- [x] Ham ve yapilandirilmis evidence olusturma
- [x] Cekirdek birim, entegrasyon ve CLI testleri
- [x] Yetkili hedefte CLI manuel kabul testi

> Filtreli SMB hedefinde `INCONCLUSIVE` sonucu, cikis kodu ve evidence akisi kullanici tarafindan kabul edilmistir.

### 9. DNS cache snooping

- [x] `dns-cache-snooping` katalog kaydi
- [x] `nonrecursive` Nmap komut argumanlarini olusturma
- [x] Gereksiz UDP surum taramasini kaldirma ve NSE betigini 45 saniyeyle sinirlama
- [x] Temizlenmis XML fixture ve parser
- [x] Korumaci sonuc siniflandirmasi
- [x] Dogrulama calistirma ve evidence servisi
- [x] CLI baglantisi
- [x] Cekirdek testler
- [x] Yetkili hedefte CLI manuel kabul testi

> Cevap vermeyen UDP hedefinde NSE zaman siniri, `INCONCLUSIVE` sonucu ve evidence akisi kullanici tarafindan kabul edilmistir.

### 10. MS17-010 - Nmap yontemi

- [x] `ms17-010-nmap` katalog kaydi
- [x] Metasploit yontemiyle ortak bulgu anahtari
- [x] Guvenli `smb-vuln-ms17-010` Nmap komut argumanlarini olusturma
- [x] Temizlenmis XML fixture ve parser
- [x] Sonucu standart durumlarla siniflandirma
- [x] Dogrulama calistirma ve evidence servisi
- [x] CLI baglantisi
- [x] Cekirdek testler
- [x] Yetkili hedefte CLI manuel kabul testi

### 11. MS12-020 - Nmap yontemi

- [x] `ms12-020-nmap` katalog kaydi
- [x] Metasploit yontemiyle ortak bulgu anahtari
- [x] Guvenli `rdp-vuln-ms12-020` Nmap komut argumanlarini olusturma
- [x] Temizlenmis XML fixture ve parser
- [x] Beklenmeyen sunucu cevabini korumaci bicimde siniflandirma
- [x] Dogrulama calistirma ve evidence servisi
- [x] CLI baglantisi
- [x] Cekirdek testler
- [x] Yetkili hedefte CLI manuel kabul testi

### 12. IPMI 2.0 hash disclosure

- [x] `ipmi-v2-hash-disclosure` katalog kaydi
- [x] Guvenli `auxiliary/scanner/ipmi/ipmi_dumphashes` komut argumanlarini olusturma
- [x] Otomatik parola kirma davranisini kapatma
- [x] Temizlenmis Metasploit cikti fixture ve parser
- [x] Hash bulunan ve sonuc alinamayan durumlari korumaci bicimde siniflandirma
- [x] Hassas hash degerini ham evidence dosyasina yazmadan once maskeleme
- [x] Dogrulama calistirma ve evidence servisi
- [x] CLI baglantisi
- [x] Cekirdek testler
- [x] Yetkili hedefte CLI manuel kabul testi

### 13. FREAK kontrolu

- [x] `freak-export-rsa` katalog kaydi
- [x] Guvenli `testssl.sh --freak` komut argumanlarini olusturma
- [x] Temizlenmis tek ve coklu hedef cikti fixture'lari
- [x] FREAK sonucunu hedef bazinda ayristirma
- [x] Sonucu korumaci bicimde siniflandirma
- [x] Dogrulama calistirma ve evidence servisi
- [x] CLI baglantisi
- [x] Cekirdek testler
- [x] Yetkili hedefte CLI manuel kabul testi

### 14. OpenSSL CCS Injection kontrolu

- [x] `openssl-ccs-injection` katalog kaydi
- [x] Guvenli `testssl.sh --ccs` komut argumanlarini olusturma
- [x] Temizlenmis kesin, olasi, guvenli ve belirsiz cikti fixture'lari
- [x] CCS Injection sonucunu hedef bazinda ayristirma
- [x] Kesin ve olasi zafiyet sonuclarini ayri siniflandirma
- [x] Coklu IP sonucunu korumaci bicimde birlestirme
- [x] Dogrulama calistirma ve evidence servisi
- [x] CLI baglantisi
- [x] Cekirdek testler
- [x] Yetkili hedefte CLI manuel kabul testi

> Coklu IP hedefinde `NOT_VULNERABLE` sonucu, cikis kodu ve evidence akisi kullanici tarafindan kabul edilmistir.

### 15. NTP Mode 6 kontrolu

- [x] `ntp-mode-6` katalog kaydi
- [x] Guvenli ve zaman sinirli `ntp-info` Nmap komut argumanlarini olusturma
- [x] Temizlenmis zafiyetli, guvenli ve belirsiz XML fixture'lari
- [x] Normal NTP zaman cevabi ile Mode 6 READVAR cevabini ayirma
- [x] Sonucu korumaci bicimde siniflandirma
- [x] Dogrulama calistirma ve evidence servisi
- [x] CLI baglantisi
- [x] Cekirdek testler
- [x] Yetkili hedefte CLI manuel kabul testi

> Cevapsiz UDP hedefinde `INCONCLUSIVE` sonucu, cikis kodu ve evidence akisi kullanici tarafindan kabul edilmistir.

## 5. Harici arac adaptorleri

- [x] Nmap adaptoru
- [x] Nmap XML ayristiricisi
- [x] Nmap surumu tespiti
- [x] `testssl.sh` adaptoru
- [x] `testssl.sh` ciktisi ayristiricisi
- [x] `testssl.sh` surumu tespiti
- [x] Metasploit adaptoru
- [x] Metasploit ciktisi ayristiricisi
- [x] Metasploit surumu tespiti
- [x] Araclara ozel varsayilan timeout degerleri
- [x] Arac hata mesajlarini ortak hata modeline donusturme
- [x] Eksik arac durumunda uygulamayi cokertmeden devam etme

> Gelistirme ortaminda Nmap, `testssl.sh` ve kaynak kurulumla saglanan `msfconsole` kuruludur.

## 6. Evidence ve dosya yonetimi

- [x] Benzersiz evidence klasoru olusturma
- [x] Evidence klasoru icin `0700` izni
- [x] Ham stdout ve stderr dosyalarini saklama
- [x] Ham cikti dosyalari icin `0600` izni
- [x] Mevcut evidence dosyalarinin uzerine yazmama
- [x] Normalize edilmis `evidence.json` dosyasi
- [x] Evidence sema surumu
- [x] Evidence dosyasi SHA-256 hesaplama
- [x] Hash isleminde sembolik baglari reddetme
- [x] Uygulamanin varsayilan `evidence/` ana dizini
- [x] Evidence ana dizini icin yapilandirma secenegi
- [x] Calisma kimligi ile evidence klasoru baglantisi
- [x] Arac adi, arac surumu, komut cikis kodu ve zaman bilgisini metadata olarak saklama
- [x] stdout ve stderr icin azami boyut siniri
- [x] Hassas bilgileri dosyaya yazmadan once maskeleme
- [x] Birden fazla evidence dosyasi icin manifest olusturma
- [x] Dosya yollari ve SHA-256 degerlerini kalici kayitla iliskilendirme
- [x] Kismi dosya yazimi hatalarinda temizlik veya atomik yazim

## 7. Guvenlik ve kapsam kontrolleri

- [x] Komutlari shell kullanmadan calistirma
- [x] Hedef ve port girdilerini dogrulama
- [x] Nmap XML boyut siniri
- [x] Nmap XML icinde `DOCTYPE` ve `ENTITY` reddi
- [x] Evidence dosyalarinda sinirli erisim izinleri
- [x] Yetkili kullanim uyarisi
- [x] Hedef kapsam listesi veya allowlist
- [x] Kapsam disi hedefi reddetme
- [x] Intrusive kontrolleri varsayilan olarak kapali tutma
- [x] Intrusive kontroller icin acik kullanici onayi
- [x] Paralel kontrol sayisi siniri
- [x] Hassas veri maskeleme
- [x] Terminal ciktisinda hassas veri maskeleme
- [x] DoS yapan kontrolleri engelleme
- [x] Hedef sistemde degisiklik yapan kontrolleri engelleme
- [x] Metasploit modullerini salt okunur veya guvenli modlarla sinirlama
- [x] Kontrol bazinda risk ve yetki denetimi

## 8. SQLite ve kalici kayitlar

- [x] SQLite baglanti yonetimi
- [x] Sema surumu ve migration yapisi
- [x] Proje tablosu ve proje kaydi
- [x] Hedef tablosu ve hedef kaydi
- [x] Tarama calismasi tablosu
- [x] Kontrol sonucu tablosu
- [x] Bulgu tablosu
- [x] Evidence dosya tablosu
- [x] Evidence yolu ve SHA-256 kaydi
- [x] Tarama gecmisini listeleme
- [x] Ayni bulguya birden fazla dogrulama sonucu baglama
- [x] Veritabani foreign key ve indeksleri
- [x] Veritabani hata ve transaction yonetimi

## 9. MVP sonrasi - Yerel arayuz

- [ ] Yerel arayuz teknolojisi karari ve yeni bagimlilik onayi
- [ ] Yerel arayuz iskeleti
- [ ] Proje olusturma ve secme
- [ ] Hedef ekleme ve secme
- [ ] Kontrol secme
- [ ] Tarama baslatma
- [ ] Tarama ilerleme ve durum bilgisi
- [ ] Bulgulari listeleme
- [ ] Bulgu detayini goruntuleme
- [ ] Evidence goruntuleme
- [ ] Hata ve eksik arac mesajlarini gosterme

> Ilk plan Streamlit kullanmaktir ancak bagimlilik eklenmeden once kullanici onayi alinacaktir.

## 10. MVP sonrasi - Manuel bulgu yonetimi ve raporlama

- [ ] Manuel bulgu kaydi icin veri modeli
- [ ] Manuel bulgu ekleme
- [ ] Bulguyu duzenleme
- [ ] False positive durumu ve isaretleme
- [ ] Bulguyu rapora dahil etme veya cikarma
- [ ] Kullanici rapor kalibini alma ve inceleme
- [ ] Nihai rapor formati ve belge teknolojisi karari
- [ ] Rapor proje bilgileri
- [ ] Hedef ve kapsam bilgileri
- [ ] Secilen bulgulari rapora aktarma
- [ ] Bulgu basligi ve risk bilgisi
- [ ] Teknik aciklama ve etki
- [ ] Cozum onerisi
- [ ] Evidence ve ekran goruntusu ekleme
- [ ] Manuel bulgulari raporlama
- [ ] False positive bulgulari haric tutma
- [ ] Hassas verileri maskeleme
- [ ] Rapor onizleme
- [ ] Nihai raporu disari aktarma

## 11. Test, kalite ve teslim

- [x] Birim test altyapisi
- [x] Ruff lint ve format kontrolu
- [x] Hedef, port, komut, arac, Nmap XML ve evidence birim testleri
- [x] Ilk kontrol icin entegrasyon testleri
- [x] Ilk kontrol icin CLI uctan uca testleri
- [x] Her yeni kontrol icin basarili sonuc testi
- [x] Her yeni kontrol icin hata ve belirsiz sonuc testi
- [x] Eksik harici arac testleri
- [x] Timeout ve iptal entegrasyon testleri
- [x] SQLite entegrasyon testleri
- [x] Yetkili test hedefinde manuel kabul testi
- [x] Kurulum ve kullanim dokumani
- [x] MVP surumleme ve paketleme kontrolu

## MVP disinda tutulanlar

- Yerel grafik arayuz ve Streamlit entegrasyonu
- Arayuz temel akis testleri
- Manuel bulgu ekleme ve duzenleme
- False positive ve rapora dahil etme durumlarinin yonetimi
- Rapor kalibi entegrasyonu, rapor onizleme ve rapor olusturma
- Manuel bulgu ve raporlama testleri
- DoS veya servis kesintisi olusturan aktif saldirilar
- Hedef sistemde veri ya da yapilandirma degisikligi yapan kontroller
- Otomatik exploit calistirma
- Yetkilendirme olmadan hedef tarama

## Aktif siradaki ozellik

Henuz secilmedi. Sonraki MVP ozelligine kullanici onayiyla baslanacak.
