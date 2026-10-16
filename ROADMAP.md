# VulnVerifier Roadmap

VulnVerifier, yetkili ortamlarda güvenlik bulgularını doğrulayan, doğrulama kanıtlarını saklayan ve sonraki aşamada bu bulguları bir rapor kalıbına aktarabilen Python tabanlı bir uygulama olacaktır.

İlk hedef, gereksiz karmaşıklık oluşturmadan çalışan CLI tabanlı bir MVP çıkarmaktır. CLI, doğrulama motoru ve veritabanı ayrı aşamalarda geliştirilecektir. Yerel arayüz, manuel bulgu yönetimi ve raporlama MVP sonrasında ele alınacaktır.

## Teknik yaklaşım

- Uygulama Python 3.12 veya üzeriyle geliştirilecek.
- Proje ve bağımlılık bilgileri `pyproject.toml` içinde tutulacak.
- CLI için Typer, terminal çıktıları için Rich kullanılması planlanıyor.
- Kontroller, ortak bir sözleşmeyi uygulayan bağımsız Python modülleri olacak.
- Harici araçlar shell komut metniyle değil, güvenli argüman listeleriyle çalıştırılacak.
- Nmap sonuçlarında mümkün olduğunda XML gibi yapılandırılmış çıktı kullanılacak.
- Ham araç çıktıları dosya sisteminde, özet sonuçlar SQLite içinde saklanacak.
- Bir kontrol sonucu standart durumlardan biriyle ifade edilecek: `VULNERABLE`, `NOT_VULNERABLE`, `POTENTIALLY_VULNERABLE`, `INCONCLUSIVE`, `SKIPPED` veya `ERROR`.

## Aşama 1 — Proje temeli

- `src/vulnverifier` ve `tests` dizinlerini içeren Python proje yapısını kurmak.
- `list`, `doctor` ve `verify` komutlarını destekleyecek temel CLI giriş noktasını oluşturmak.
- Ruff ve pytest yapılandırmasını eklemek.
- Sonraki geliştirmelerde kullanılacak temel veri tiplerini hazırlamak.
- Kullanıcıyla birlikte seçilecek tek bir örnek doğrulama kontrolünü uçtan uca çalıştırmak.

**Tamamlanma ölçütü:** Uygulama kurulabilmeli, CLI açılabilmeli ve örnek kontrolün testleri başarılı olmalıdır.

## Aşama 2 — Doğrulama çekirdeği

- `shell=False` kullanan merkezi bir komut çalıştırıcı oluşturmak.
- Timeout, exit code, stdout, stderr ve süreç iptalini yönetmek.
- IP adresi, hostname ve port girdilerini doğrulamak.
- Kontrol kayıt tablosu ve ortak kontrol sözleşmesini oluşturmak.
- Ham çıktı ve normalize edilmiş kanıt dosyalarını ayrı saklamak.
- Eksik araç, kapalı port ve belirsiz çıktı gibi durumları uygulamayı çökertmeden raporlamak.

**Tamamlanma ölçütü:** Kontroller aynı çalışma motorunu kullanmalı; başarılı, başarısız, zaman aşımı ve eksik araç senaryoları test edilmelidir.

## Aşama 3 — İlk 15 kontrol

- FastVulnVerify referansındaki ilk 15 yöntemi kontrollü biçimde eklemek.
- Aynı bulguya ait yinelenen yöntemleri tek bulgu altında toplamak.
- Nmap, testssl.sh ve opsiyonel Metasploit adaptörlerini oluşturmak.
- Intrusive kontrolleri varsayılan olarak kapalı tutmak.
- Sadece sürüm tespiti yapan kontrolleri kesin zafiyet olarak değil, `POTENTIALLY_VULNERABLE` veya `INCONCLUSIVE` olarak değerlendirmek.
- Her çıktı ayrıştırıcısı için gerçek araç çıktılarından temizlenmiş test fixture'ları hazırlamak.

İlk 15 yöntem; port/servis keşfi, SSLv2/SSLv3, iLO sürümü, anonymous cipher, MS12-020, SNMP public community, ESXi sürümü, MS17-010, DNS cache snooping, IPMI hash disclosure, FREAK, OpenSSL CCS ve NTP Mode 6 kontrollerini kapsayacaktır.

**Tamamlanma ölçütü:** Desteklenen 15 yöntem listelenebilmeli, seçilerek çalıştırılabilmeli ve her yöntem standart sonuç ile evidence üretebilmelidir.

## Aşama 4 — SQLite kayıtları

- Proje, hedef, tarama, bulgu ve kanıt kayıtlarını saklamak.
- Otomatik doğrulama sonuçları için veri modeli oluşturmak.
- Geçmiş tarama sonuçlarını listelemek.
- Büyük ham çıktılar yerine evidence dosya yollarını ve bütünlük hash'lerini kaydetmek.
- Aynı zafiyete ait birden fazla doğrulama yöntemini tek bulgu altında ilişkilendirmek.

**Tamamlanma ölçütü:** Bir tarama kapatılıp uygulama yeniden açıldığında sonuçlar, bulgular ve evidence bağlantıları tekrar görüntülenebilmelidir.

**Durum:** Tamamlandı. CLI doğrulamaları proje, hedef, sonuç, ortak bulgu ve evidence bağlantılarıyla SQLite içinde saklanmaktadır.

## MVP sonrası — Yerel arayüz

- Proje ve hedef yönetimi eklemek.
- Kontrol seçme ve tarama başlatma ekranı hazırlamak.
- Bulguları ve evidence kayıtlarını görüntülemek.
- İlk sürümde basit ve yerel çalışan bir Streamlit arayüzü kullanmak.

**Tamamlanma ölçütü:** Kullanıcı kod veya SQL yazmadan proje oluşturabilmeli, tarama başlatabilmeli ve sonuçları görüntüleyebilmelidir.

## MVP sonrası — Manuel bulgu yönetimi ve raporlama

- Bulguları arayüzden manuel olarak eklemek ve düzenlemek.
- Bulguları rapora dahil etmek, hariç bırakmak veya yanlış pozitif olarak işaretlemek.
- Kullanıcının sağlayacağı rapor kalıbını incelemek.
- Seçilen bulguları kalıba aktarmak.
- Kanıtları, açıklamaları ve çözüm önerilerini rapora eklemek.
- Manuel eklenen bulgularla otomatik bulunan bulguları aynı raporda desteklemek.
- Rapor üretmeden önce düzenlenebilir bir önizleme ve bulgu seçimi sunmak.

Rapor formatı ve kullanılacak belge teknolojisi, rapor kalıbı incelendikten sonra belirlenecektir.

Yerel arayüz, manuel bulgu yönetimi ve raporlama çalışmaları MVP kabulü tamamlandıktan sonra ayrı özellikler halinde planlanacaktır.

## Güvenlik sınırları

- Araç yalnızca açıkça yetkilendirilmiş hedeflerde kullanılmak üzere tasarlanacak.
- Salt okunur kontroller varsayılan olarak çalışabilecek.
- Hash elde etme gibi intrusive kontroller açık kullanıcı onayı gerektirecek.
- DoS veya hedef sistemde değişiklik yapan kontroller MVP kapsamına alınmayacak.
- Parola, hash ve benzeri hassas bilgiler terminalde veya raporda kontrolsüz biçimde gösterilmeyecek.
