# SSHMap - Modern SSH Exposure Management Platform Geliştirme Planı

## 0. Dokümanın Amacı

Bu doküman, **SSHMap** projesinin basit bir SSH tarayıcısından çıkarılıp modern, kapsamlı, güvenilir ve ürünleşebilir bir **SSH Exposure Management Platformu** haline getirilmesi için hazırlanmış ana geliştirme planıdır.

SSHMap'in hedefi sadece "hangi IP'de SSH açık?" sorusuna cevap vermek değildir. Ürünün asıl değeri şudur:

```text
Kim, hangi public key ile, hangi kullanıcı olarak, hangi sunucuya erişebiliyor?
Bu erişim hangi sudo yetkileriyle birleşiyor?
Aynı key kaç sistemde ve kaç farklı kullanıcıda kullanılıyor?
Root erişimi nerelerde mümkün?
Password authentication nerelerde açık?
SSH client config, known_hosts ve ProxyJump ilişkileri lateral movement için ne söylüyor?
Bir kullanıcı, key veya servis hesabı kompromize olursa blast radius ne olur?
```

Bu plan, Codex veya başka bir geliştirici ajan tarafından doğrudan uygulanabilir teknik ayrıntıya sahip olacak şekilde tasarlanmıştır.

---

## 1. Mevcut Plan Analizi

Mevcut plan güçlü bir ürün fikri ortaya koymaktadır:

```text
- SSH exposure kavramı doğru konumlandırılmış.
- Agentless yaklaşım doğru seçilmiş.
- Rust + SQLite tercihleri taşınabilirlik için uygundur.
- Discovery, remote scan, local scan ve import modları doğru ayrılmıştır.
- authorized_keys, sshd_config, sudoers, known_hosts ve ssh_config parserları ürünün çekirdeği olarak doğru belirlenmiştir.
- Key reuse, root login, password auth ve sudo NOPASSWD riskleri doğru önceliklendirilmiştir.
- Graph yaklaşımı ürünü klasik scanner araçlarından ayıracak en kritik farklılaştırıcıdır.
```

Geliştirilmesi gereken alanlar:

```text
- Ürün vizyonu, persona, kullanım yolculukları ve başarı metrikleri daha açık tanımlanmalıdır.
- Kodlama dili, isimlendirme standardı ve repo disiplini zorunlu kural olarak yazılmalıdır.
- Veri modeli scan_run, source, confidence, evidence, exception, baseline ve diff kavramlarıyla güçlendirilmelidir.
- Risk engine sadece statik kurallar değil, context-aware ve graph-aware çalışan bir yapı olmalıdır.
- Parserlar için test fixture, golden file, fuzzing ve tolerans stratejisi netleşmelidir.
- Web UI, API, raporlama, entegrasyon ve enterprise dağıtım hedefleri ayrıntılandırılmalıdır.
- Güvenlik sınırları, veri minimizasyonu, redaction ve audit trail ayrı bir threat model ile desteklenmelidir.
- Geliştirme fazları MVP'den v1.0'a kadar daha ölçülebilir kabul kriterleriyle bölünmelidir.
```

---

## 2. Ürün Vizyonu

SSHMap, kurumların SSH erişimlerini görünür hale getiren, risklendiren, graph üzerinde analiz eden ve iyileştirme aksiyonlarını önceliklendiren modern bir güvenlik ürünüdür.

### 2.1 Konumlandırma

SSHMap şu şekilde konumlandırılmalıdır:

```text
SSHMap is not just an SSH scanner.
SSHMap is an SSH Exposure Management and Access Graph platform.
```

Türkçe ürün cümlesi:

```text
SSHMap, kurum içindeki SSH erişim ilişkilerini haritalayan, key reuse ve yetki zincirlerini analiz eden agentless güvenlik görünürlüğü platformudur.
```

### 2.2 Temel Farklılaştırıcılar

```text
- Agentless çalışır.
- Tek binary ve SQLite ile taşınabilir olur.
- Private key veya password toplamaz.
- Erişim ilişkilerini graph olarak gösterir.
- Public key reuse riskini kullanıcı, host ve sudo bağlamında analiz eder.
- Root login, password auth, sudo, known_hosts, ssh_config ve ProxyJump ilişkilerini birlikte değerlendirir.
- Pentest raporuna doğrudan eklenebilecek HTML/JSON/CSV çıktıları üretir.
- Kurumsal operasyon ekipleri için remediation önceliği ve trend takibi sunar.
- Offline import ile canlı SSH erişimi olmadan da değer üretir.
```

### 2.3 Slogan

```text
Map who can SSH where - and how far they can go.
```

Türkçe:

```text
Kim nereye SSH yapabiliyor ve oradan ne kadar ilerleyebiliyor?
```

---

## 3. Zorunlu Kodlama ve Dil Standardı

Bu bölüm projenin en kritik mühendislik kurallarından biridir.

### 3.1 Kodlama Dili Kesinlikle İngilizce Olmalıdır

SSHMap kod tabanında **tüm kodlama İngilizce yapılmalıdır**.

Bu kural zorunludur ve istisna kabul etmez:

```text
- Değişken adları İngilizce olmalıdır.
- Fonksiyon adları İngilizce olmalıdır.
- Struct, enum, trait, modül ve crate adları İngilizce olmalıdır.
- Dosya ve dizin adları İngilizce olmalıdır.
- Veritabanı tablo ve kolon adları İngilizce olmalıdır.
- JSON/YAML field isimleri İngilizce olmalıdır.
- CLI komutları ve flag isimleri İngilizce olmalıdır.
- Log mesajları İngilizce olmalıdır.
- Error mesajları İngilizce olmalıdır.
- Test isimleri İngilizce olmalıdır.
- Kod yorumları İngilizce olmalıdır.
- Commit mesajları İngilizce olmalıdır.
- Branch isimleri İngilizce olmalıdır.
- API endpoint isimleri İngilizce olmalıdır.
```

Dokümantasyon Türkçe olabilir. Ancak kaynak kod, testler, migration dosyaları, config şemaları ve geliştiriciye dönük teknik metinler İngilizce tutulmalıdır.

### 3.2 Doğru ve Yanlış Örnekler

Yanlış:

```rust
struct Kullanici {
    kullanici_adi: String,
    anahtar_sayisi: u32,
}

fn risk_hesapla() {}
```

Doğru:

```rust
struct UserAccount {
    username: String,
    key_count: u32,
}

fn calculate_risk_score() {}
```

Yanlış:

```sql
CREATE TABLE kullanicilar (
    kimlik INTEGER PRIMARY KEY,
    kullanici_adi TEXT NOT NULL
);
```

Doğru:

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL
);
```

Yanlış:

```text
sshmap kullanici listele
sshmap riskleri-goster
```

Doğru:

```text
sshmap user list
sshmap risks list
```

### 3.3 User-Facing Dil Stratejisi

İlk sürümde CLI ve rapor dili İngilizce olmalıdır.

İleride Türkçe veya başka diller desteklenecekse bu destek i18n katmanı ile eklenmelidir:

```text
- Kod İngilizce kalır.
- Çeviri dosyaları ayrı tutulur.
- CLI varsayılan dili İngilizce olur.
- HTML rapor için --language tr gibi opsiyon eklenebilir.
```

---

## 4. Hedef Kullanıcılar

### 4.1 Security Engineering Ekibi

İhtiyaçları:

```text
- SSH attack surface görünürlüğü
- Key reuse riskleri
- Eski çalışan keylerinin bulunması
- Root login ve password auth risklerinin takibi
- Risklerin remediation önceliği
- Zaman içinde trend ve diff analizi
```

### 4.2 Linux / Platform Operations Ekibi

İhtiyaçları:

```text
- Hangi sunucuda hangi kullanıcı var?
- Hangi servis hesapları hangi keyleri kullanıyor?
- Sudo yetkileri nerelerde geniş?
- Ansible inventory ve CMDB ile gerçek ortam uyumlu mu?
- SSH hardening standardına uyumsuz hostlar hangileri?
```

### 4.3 Pentest ve Red Team Ekibi

İhtiyaçları:

```text
- Yetkili iç ağ değerlendirmesinde SSH exposure raporu
- Lateral movement sinyalleri
- Key reuse üzerinden blast radius analizi
- Evidence tabanlı teknik bulgular
- HTML/JSON rapor çıktısı
```

### 4.4 GRC / Audit Ekibi

İhtiyaçları:

```text
- Kanıtlanabilir erişim envanteri
- Kullanıcı ve key yaşam döngüsü kontrolü
- Policy uyum raporu
- İstisna ve risk kabul takibi
- Periyodik denetim çıktısı
```

### 4.5 MSP / MSSP Ekibi

İhtiyaçları:

```text
- Müşteri bazlı ayrı SQLite çıktıları
- Tek binary ile hızlı çalışma
- Tekrarlanabilir audit workflow
- Rapor şablonları
- Offline çalışma kabiliyeti
```

---

## 5. Ürün İlkeleri

SSHMap aşağıdaki ürün ilkelerine göre geliştirilmelidir.

### 5.1 Agentless

Hedef sistemlere kalıcı agent kurulmaz.

```text
- SSH üzerinden read-only komutlar çalıştırılır.
- Local scan sadece çalıştığı hostu inceler.
- Import modları offline veri ile çalışır.
```

### 5.2 Evidence-First

Her risk kanıta dayanmalıdır.

```text
- Riskin hangi hosttan üretildiği bilinmelidir.
- Hangi dosya ve satırdan geldiği mümkünse tutulmalıdır.
- Raw evidence redaction sonrasında saklanmalıdır.
- Evidence yoksa risk üretilmemeli, sadece low-confidence signal üretilebilir.
```

### 5.3 Privacy-Preserving

SSHMap hassas sırları toplamamalıdır.

```text
- Private key içeriği asla okunmaz.
- Password asla saklanmaz.
- Token, secret, password patternleri maskelenir.
- Raporlarda hassas path ve kullanıcı adları opsiyonel anonimleştirilebilir.
```

### 5.4 Explainable Risk

Her risk açıklanabilir olmalıdır.

```text
- Risk code
- Severity
- Score
- Confidence
- Evidence
- Impact
- Recommendation
- References veya internal policy mapping
```

### 5.5 Graph-Native

SSHMap veriyi sadece tablo olarak değil graph olarak da modellemelidir.

```text
- Host
- User
- Public key
- Host key
- Sudo rule
- Known host
- SSH config route
- Risk
```

### 5.6 Offline-Friendly

Ürün internet bağlantısı gerektirmeden çalışabilmelidir.

```text
- Tek binary
- SQLite veritabanı
- Local report generation
- Offline import
- Offline web UI read-only mode
```

### 5.7 Safe by Default

Varsayılan ayarlar üretim ortamları için güvenli olmalıdır.

```text
- Düşük concurrency
- Scope doğrulama
- Read-only komut manifesti
- Sudo sadece --sudo ile
- No brute force
- No exploit
- No unauthorized login attempts
```

---

## 6. Temel Kullanım Senaryoları

### 6.1 Kurumsal SSH Envanteri

Komut:

```bash
sshmap scan \
  --targets servers.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --sudo \
  --db sshmap.db
```

Beklenen özet:

```text
Hosts scanned: 512
SSH open: 428
Users discovered: 1260
Public keys discovered: 384
Critical risks: 18
High risks: 73

Top findings:
- Reused public key grants access to 78 hosts
- Root login is enabled on 14 hosts
- Password authentication is enabled on 42 hosts
- backup user has passwordless sudo on 9 hosts
```

### 6.2 Ayrılan Personel Key Denetimi

Komut:

```bash
sshmap user show mehmet --db sshmap.db
```

Beklenen çıktı:

```text
User: mehmet

Keys:
- SHA256:AbC123...
- SHA256:Def456...

Still authorized on:
- mehmet@web01
- mehmet@web02
- mehmet@app01
- mehmet@db01
- root@backup01

Risk:
HIGH - Former employee key is still active on 5 systems.
```

### 6.3 Key Reuse ve Blast Radius Analizi

Komut:

```bash
sshmap keys reuse --db sshmap.db
sshmap blast-radius --key SHA256:qwe123 --db sshmap.db
```

Örnek çıktı:

```text
Fingerprint: SHA256:qwe123...
Used on:
- deploy@web01
- deploy@web02
- deploy@web03
- app@app01
- root@backup01

Reachable privileged contexts:
- root@backup01
- deploy@web02 -> sudo NOPASSWD:ALL

Risk: CRITICAL
```

### 6.4 Root Login ve Password Auth Hardening

Komut:

```bash
sshmap risks list --code SSH_ROOT_LOGIN_ENABLED --db sshmap.db
sshmap risks list --code SSH_PASSWORD_AUTH_ENABLED --db sshmap.db
```

### 6.5 Pentest İç Ağ Değerlendirmesi

Komut:

```bash
sshmap scan \
  --targets 10.10.0.0/16 \
  --scope scope.yaml \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --sudo \
  --concurrency 25 \
  --rate-limit 5 \
  --db customer.db

sshmap report create \
  --format html \
  --output sshmap-report.html \
  --db customer.db
```

### 6.6 Sürekli Denetim ve Diff

Komut:

```bash
sshmap baseline create --name 2026-q2 --db sshmap.db
sshmap scan --config sshmap.yaml
sshmap diff --from 2026-q2 --to latest --db sshmap.db
```

Değer:

```text
- Yeni açılan SSH servisleri
- Yeni eklenen authorized keyler
- Yeni root login enable olan hostlar
- Yeni NOPASSWD sudo kuralları
- Kapanan veya remediated riskler
```

---

## 7. Çalışma Modları

### 7.1 Discover Mode

Login gerektirmez.

Toplanacak bilgiler:

```text
- TCP open/closed state
- SSH banner
- SSH protocol version
- Host key fingerprint
- Host key reuse
- Supported algorithms, mümkün olduğunda
- DNS reverse lookup, opsiyonel
```

Komut:

```bash
sshmap discover --targets 10.10.0.0/24 --db sshmap.db
```

### 7.2 Authenticated Scan Mode

Yetkili SSH hesabı ile çalışır.

Toplanacak bilgiler:

```text
- Hostname, OS, kernel, uptime metadata
- /etc/passwd
- /etc/group
- /etc/ssh/sshd_config
- /etc/ssh/sshd_config.d/*.conf
- authorized_keys dosyaları
- known_hosts dosyaları
- ssh client config dosyaları
- sudoers dosyaları
- file permission metadata
```

### 7.3 Local Scan Mode

Tek host üzerinde lokal audit yapar.

Komut:

```bash
sshmap local-scan --db local.db
```

Sınırlar:

```text
- Private key içeriği okunmaz.
- Sadece public key, permission, owner ve path metadata incelenir.
- Eğer public counterpart yoksa private key fingerprint çıkarılmaya çalışılmaz.
```

### 7.4 Offline Import Mode

Desteklenecek kaynaklar:

```text
- Ansible inventory
- Nmap XML
- CMDB CSV
- Zabbix veya monitoring export CSV
- known_hosts
- sshd_config dosya kopyaları
- authorized_keys dosya kopyaları
- sudoers dosya kopyaları
- GitHub/GitLab deploy key export dosyaları
- Cloud instance inventory CSV/JSON çıktıları
```

### 7.5 Analyze-Only Mode

Mevcut DB üstünden yeniden analiz yapar.

```bash
sshmap analyze --db sshmap.db
```

### 7.6 Serve Mode

SQLite DB'yi read-only web UI olarak sunar.

```bash
sshmap serve --db sshmap.db --listen 127.0.0.1:8080 --read-only
```

---

## 8. Güvenlik, Etik ve Yetki Sınırları

SSHMap sadece sahip olunan veya açıkça yetki verilen sistemlerde kullanılmalıdır.

### 8.1 Yasak Davranışlar

```text
- Brute force yoktur.
- Exploit çalıştırılmaz.
- Password spraying yapılmaz.
- Yetkisiz login denenmez.
- Private key içeriği toplanmaz.
- Password saklanmaz.
- Shell history veya kişisel dosyalar toplanmaz.
- Komut manifesti dışında keyfi komut çalıştırılmaz.
```

### 8.2 Safe Scan Kontrolleri

```text
- --scope ile izinli hedef aralıkları tanımlanır.
- --exclude ile hassas hedefler hariç tutulur.
- --rate-limit ve --concurrency varsayılanları muhafazakar olur.
- Her scan_run audit_events tablosuna kaydedilir.
- Remote komutlar allowlist üzerinden üretilir.
- Sudo komutları sudo -n ile non-interactive çalışır.
```

### 8.3 İlk Çalıştırma Uyarısı

CLI ilk kritik komutta şu uyarıyı göstermelidir:

```text
SSHMap must only be used against systems you own or are explicitly authorized to assess.
```

---

## 9. Genel Mimari

### 9.1 Yüksek Seviye Bileşenler

```text
sshmap
├── CLI Layer
├── Configuration Layer
├── Scope Validator
├── Discovery Engine
├── SSH Transport Layer
├── Remote Collector
├── Local Collector
├── Importer Framework
├── Parser Framework
├── Normalization Layer
├── SQLite Storage
├── Risk Engine
├── Graph Engine
├── Query Layer
├── Report Engine
├── Web/API Server
└── Integration Layer
```

### 9.2 Veri Akışı

```text
Targets
  -> Scope validation
  -> Discovery
  -> Collection / Import
  -> Raw evidence redaction
  -> Parser normalization
  -> SQLite persistence
  -> Risk engine
  -> Graph engine
  -> Query / Report / UI
```

### 9.3 Tasarım İlkeleri

```text
- Parserlar collector bağımsız olmalıdır.
- Risk engine raw command output yerine normalize edilmiş veriden çalışmalıdır.
- Graph engine risk engine ile çift yönlü veri paylaşabilmelidir.
- Her veri scan_run_id ve source ile ilişkilendirilmelidir.
- Her bulgu confidence ve evidence ile desteklenmelidir.
```

---

## 10. Rust Teknoloji Stack

### 10.1 Ana Teknolojiler

```text
Language: Rust
Database: SQLite
Async runtime: Tokio
CLI: clap
Serialization: serde
Logging: tracing
Reports: tera or askama
HTTP server: axum
Frontend: React + TypeScript, v1 sonrası
Graph UI: Cytoscape.js
```

### 10.2 Bağımlılık Seçim Stratejisi

Kesin sürümler geliştirme anında `cargo add` ile güncel stabil major sürümlerden seçilmelidir. Plan içinde major aileler belirtilir:

```toml
[dependencies]
tokio = { version = "1", features = ["full"] }
clap = { version = "4", features = ["derive"] }
rusqlite = { version = "0", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
serde_yaml = "0"
anyhow = "1"
thiserror = "1"
tracing = "0"
tracing-subscriber = "0"
chrono = { version = "0", features = ["serde"] }
uuid = { version = "1", features = ["v4", "serde"] }
regex = "1"
ipnet = "2"
sha2 = "0"
base64 = "0"
csv = "1"
quick-xml = "0"
walkdir = "2"
shell-words = "1"
tera = "1"
```

### 10.3 SSH Transport Stratejisi

MVP:

```text
OpenSSH binary kullanılır.
```

Neden:

```text
- ProxyJump, IdentityFile, ControlMaster ve config edge-case'leri daha uyumludur.
- İşletim sistemindeki OpenSSH davranışıyla tutarlıdır.
- MVP daha hızlı çıkar.
```

v2:

```text
Native Rust SSH transport opsiyonel olarak eklenir.
```

Kural:

```text
Transport abstraction baştan tasarlanmalıdır.
Collector doğrudan ssh binary komutu üretmemelidir.
```

Örnek trait:

```rust
pub trait SshTransport {
    async fn run_command(&self, target: &SshTarget, command: &RemoteCommand) -> Result<CommandOutput>;
    async fn read_file(&self, target: &SshTarget, path: &RemotePath) -> Result<FileEvidence>;
}
```

---

## 11. Repository ve Workspace Yapısı

### 11.1 MVP Yapısı

```text
sshmap/
├── Cargo.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── SECURITY.md
├── CONTRIBUTING.md
├── migrations/
│   └── 001_init.sql
├── templates/
│   ├── report.html.tera
│   └── report.css
├── examples/
│   ├── hosts.txt
│   ├── inventory.ini
│   ├── scope.yaml
│   └── sshmap.yaml
├── fixtures/
│   ├── authorized_keys/
│   ├── sshd_config/
│   ├── sudoers/
│   ├── known_hosts/
│   └── ssh_config/
└── src/
    ├── main.rs
    ├── cli.rs
    ├── config.rs
    ├── db.rs
    ├── error.rs
    ├── models.rs
    ├── scope.rs
    ├── discovery.rs
    ├── transport/
    ├── collector/
    ├── importer/
    ├── parser/
    ├── risk/
    ├── graph/
    ├── report/
    └── query/
```

### 11.2 İleri Seviye Workspace Yapısı

```text
sshmap/
├── Cargo.toml
├── crates/
│   ├── sshmap-cli/
│   ├── sshmap-core/
│   ├── sshmap-db/
│   ├── sshmap-discovery/
│   ├── sshmap-transport/
│   ├── sshmap-collector/
│   ├── sshmap-importer/
│   ├── sshmap-parser/
│   ├── sshmap-risk/
│   ├── sshmap-graph/
│   ├── sshmap-report/
│   ├── sshmap-server/
│   └── sshmap-integrations/
├── migrations/
├── templates/
├── fixtures/
├── examples/
└── xtask/
```

Workspace yapısına geçiş v0.5 civarında yapılmalıdır. Erken aşamada gereksiz crate ayrımı geliştirmeyi yavaşlatabilir.

---

## 12. CLI Tasarımı

### 12.1 Global Parametreler

```bash
--db sshmap.db
--config sshmap.yaml
--scope scope.yaml
--verbose
--quiet
--json
--no-color
--log-format text|json
--unsafe-allow-out-of-scope
```

### 12.2 Komut Ağacı

```text
sshmap init
sshmap doctor
sshmap db stats
sshmap db migrate
sshmap discover
sshmap scan
sshmap local-scan
sshmap import
sshmap analyze
sshmap risks list
sshmap risks show
sshmap host list
sshmap host show
sshmap user list
sshmap user show
sshmap keys list
sshmap keys reuse
sshmap graph export
sshmap path
sshmap blast-radius
sshmap report create
sshmap baseline create
sshmap diff
sshmap serve
sshmap completion
```

### 12.3 init

```bash
sshmap init --db sshmap.db
```

Görev:

```text
- SQLite dosyasını oluşturur.
- Migration çalıştırır.
- Varsayılan config örneği oluşturabilir.
- DB PRAGMA ayarlarını uygular.
```

### 12.4 doctor

```bash
sshmap doctor
```

Kontroller:

```text
- ssh binary mevcut mu?
- ssh-keygen mevcut mu?
- SQLite açılabiliyor mu?
- Config dosyası geçerli mi?
- Scope dosyası geçerli mi?
- Template dosyaları erişilebilir mi?
```

### 12.5 discover

```bash
sshmap discover \
  --targets 10.10.0.0/24 \
  --ports 22,2222 \
  --concurrency 100 \
  --timeout 3 \
  --db sshmap.db
```

### 12.6 scan

```bash
sshmap scan \
  --targets hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --sudo \
  --concurrency 20 \
  --timeout 10 \
  --db sshmap.db
```

### 12.7 analyze

```bash
sshmap analyze --db sshmap.db
sshmap analyze --only risks --db sshmap.db
sshmap analyze --only graph --db sshmap.db
```

### 12.8 report

```bash
sshmap report create --format html --output report.html --db sshmap.db
sshmap report create --format json --output report.json --db sshmap.db
sshmap report create --format csv --output out/ --db sshmap.db
```

### 12.9 path ve blast-radius

```bash
sshmap path \
  --from key:SHA256:abc123 \
  --to host:db01 \
  --db sshmap.db

sshmap blast-radius \
  --user deploy \
  --db sshmap.db
```

---

## 13. Konfigürasyon Tasarımı

### 13.1 sshmap.yaml

```yaml
database: sshmap.db

runtime:
  concurrency: 25
  timeout_seconds: 10
  rate_limit_per_second: 5
  retry_count: 1
  log_format: text

scan:
  user: audituser
  key: /home/operator/.ssh/audit_ed25519
  sudo: true
  ports: [22]
  collect_sudoers: true
  collect_known_hosts: true
  collect_ssh_config: true
  collect_root_authorized_keys: true
  collect_file_permissions: true

scope:
  include:
    - 10.10.0.0/16
    - 10.20.0.0/16
  exclude:
    - 10.10.99.0/24

redaction:
  mask_home_paths: false
  mask_usernames: false
  store_raw_evidence: true

report:
  default_format: html
  include_raw_evidence: false
  include_remediation_plan: true
```

### 13.2 risk-policy.yaml

```yaml
severity_thresholds:
  critical: 90
  high: 70
  medium: 40
  low: 10

rules:
  SSH_KEY_REUSED_MANY_HOSTS:
    enabled: true
    high_threshold: 5
    critical_threshold: 20

  SSH_PASSWORD_AUTH_ENABLED:
    enabled: true
    severity: HIGH

  SSH_FORWARD_AGENT_WILDCARD:
    enabled: true
    severity: HIGH
```

---

## 14. SQLite Veri Modeli

SQLite tek dosyalık, taşınabilir ve audit çıktısı olarak paylaşılabilir bir veri formatı sağlar.

### 14.1 Tasarım Kuralları

```text
- Her tablo İngilizce isimlendirilir.
- Her kayıtta mümkünse scan_run_id tutulur.
- Kaynağı belirsiz veri saklanmaz.
- Riskler evidence_id ile ilişkilendirilir.
- Tablolarda created_at ve updated_at alanları tercih edilir.
- Büyük metinler raw_evidence veya normalized_evidence tablolarında tutulur.
- Repeated scan desteklemek için first_seen ve last_seen alanları kullanılır.
```

### 14.2 Temel Tablolar

#### schema_migrations

```sql
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);
```

#### scan_runs

```sql
CREATE TABLE scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_uuid TEXT NOT NULL UNIQUE,
    mode TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL,
    targets_json TEXT,
    config_hash TEXT,
    operator TEXT,
    summary_json TEXT,
    error_message TEXT
);
```

#### hosts

```sql
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT,
    fqdn TEXT,
    ip_address TEXT NOT NULL,
    port INTEGER NOT NULL DEFAULT 22,
    os_family TEXT,
    os_version TEXT,
    environment TEXT,
    criticality TEXT,
    ssh_open INTEGER NOT NULL DEFAULT 0,
    ssh_banner TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    source TEXT NOT NULL,
    UNIQUE(ip_address, port)
);
```

#### host_aliases

```sql
CREATE TABLE host_aliases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    alias TEXT NOT NULL,
    alias_type TEXT NOT NULL,
    source TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, alias, alias_type)
);
```

#### host_keys

```sql
CREATE TABLE host_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    key_type TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL,
    fingerprint_md5 TEXT,
    key_bits INTEGER,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, key_type, fingerprint_sha256)
);
```

#### users

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    uid INTEGER,
    gid INTEGER,
    home_dir TEXT,
    shell TEXT,
    is_root INTEGER NOT NULL DEFAULT 0,
    is_system_account INTEGER NOT NULL DEFAULT 0,
    is_service_account INTEGER NOT NULL DEFAULT 0,
    account_state TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, username)
);
```

#### groups

```sql
CREATE TABLE groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    group_name TEXT NOT NULL,
    gid INTEGER,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, group_name)
);
```

#### user_groups

```sql
CREATE TABLE user_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    group_id INTEGER NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(group_id) REFERENCES groups(id),
    UNIQUE(host_id, user_id, group_id)
);
```

#### public_keys

```sql
CREATE TABLE public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    fingerprint_sha256 TEXT NOT NULL UNIQUE,
    fingerprint_md5 TEXT,
    key_bits INTEGER,
    key_comment TEXT,
    normalized_public_key TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
```

#### authorized_keys

```sql
CREATE TABLE authorized_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    host_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    public_key_id INTEGER NOT NULL,
    source_file TEXT,
    line_number INTEGER,
    options TEXT,
    has_from_restriction INTEGER NOT NULL DEFAULT 0,
    has_command_restriction INTEGER NOT NULL DEFAULT 0,
    permits_pty INTEGER NOT NULL DEFAULT 1,
    permits_port_forwarding INTEGER NOT NULL DEFAULT 1,
    permits_agent_forwarding INTEGER NOT NULL DEFAULT 1,
    permits_x11_forwarding INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(public_key_id) REFERENCES public_keys(id),
    UNIQUE(host_id, user_id, public_key_id, source_file, line_number)
);
```

#### sshd_config_entries

```sql
CREATE TABLE sshd_config_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    host_id INTEGER NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    source_file TEXT,
    line_number INTEGER,
    match_context TEXT,
    effective INTEGER NOT NULL DEFAULT 1,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);
```

#### ssh_algorithms

```sql
CREATE TABLE ssh_algorithms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    risk_level TEXT,
    source TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    UNIQUE(host_id, category, algorithm)
);
```

#### sudo_rules

```sql
CREATE TABLE sudo_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    host_id INTEGER NOT NULL,
    subject TEXT NOT NULL,
    subject_type TEXT NOT NULL,
    run_as TEXT,
    command TEXT,
    tags TEXT,
    nopasswd INTEGER NOT NULL DEFAULT 0,
    source_file TEXT,
    line_number INTEGER,
    risk_level TEXT,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);
```

#### known_hosts_entries

```sql
CREATE TABLE known_hosts_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    source_host_id INTEGER,
    source_user_id INTEGER,
    known_host TEXT,
    known_ip TEXT,
    host_key_type TEXT,
    host_key_fingerprint TEXT,
    hashed INTEGER NOT NULL DEFAULT 0,
    source_file TEXT,
    line_number INTEGER,
    confidence TEXT NOT NULL DEFAULT 'LOW',
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(source_host_id) REFERENCES hosts(id),
    FOREIGN KEY(source_user_id) REFERENCES users(id)
);
```

#### ssh_client_config_entries

```sql
CREATE TABLE ssh_client_config_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    host_id INTEGER,
    user_id INTEGER,
    host_pattern TEXT,
    hostname TEXT,
    ssh_user TEXT,
    port INTEGER,
    identity_file TEXT,
    proxy_jump TEXT,
    proxy_command TEXT,
    forward_agent TEXT,
    local_forward TEXT,
    remote_forward TEXT,
    dynamic_forward TEXT,
    strict_host_key_checking TEXT,
    source_file TEXT,
    line_number INTEGER,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
);
```

#### raw_evidence

```sql
CREATE TABLE raw_evidence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER NOT NULL,
    host_id INTEGER,
    evidence_type TEXT NOT NULL,
    source TEXT NOT NULL,
    command TEXT,
    content TEXT,
    stderr TEXT,
    exit_code INTEGER,
    content_hash TEXT,
    redacted INTEGER NOT NULL DEFAULT 0,
    collected_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id)
);
```

#### risks

```sql
CREATE TABLE risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    host_id INTEGER,
    user_id INTEGER,
    public_key_id INTEGER,
    risk_code TEXT NOT NULL,
    severity TEXT NOT NULL,
    score INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    impact TEXT,
    evidence TEXT,
    recommendation TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id),
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(public_key_id) REFERENCES public_keys(id)
);
```

#### graph_edges

```sql
CREATE TABLE graph_edges (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_type TEXT NOT NULL,
    from_id INTEGER NOT NULL,
    to_type TEXT NOT NULL,
    to_id INTEGER NOT NULL,
    edge_type TEXT NOT NULL,
    weight INTEGER NOT NULL DEFAULT 1,
    confidence TEXT NOT NULL DEFAULT 'MEDIUM',
    evidence TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE(from_type, from_id, to_type, to_id, edge_type)
);
```

#### baselines

```sql
CREATE TABLE baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    scan_run_id INTEGER,
    summary_json TEXT,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);
```

#### exceptions

```sql
CREATE TABLE exceptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_code TEXT NOT NULL,
    host_id INTEGER,
    user_id INTEGER,
    public_key_id INTEGER,
    reason TEXT NOT NULL,
    owner TEXT,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(host_id) REFERENCES hosts(id),
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(public_key_id) REFERENCES public_keys(id)
);
```

#### audit_events

```sql
CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_run_id INTEGER,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata_json TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id)
);
```

### 14.3 Indexler

```sql
CREATE INDEX idx_hosts_ip ON hosts(ip_address);
CREATE INDEX idx_hosts_hostname ON hosts(hostname);
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_public_keys_fp ON public_keys(fingerprint_sha256);
CREATE INDEX idx_authorized_keys_public_key ON authorized_keys(public_key_id);
CREATE INDEX idx_risks_code ON risks(risk_code);
CREATE INDEX idx_risks_severity ON risks(severity);
CREATE INDEX idx_graph_edges_from ON graph_edges(from_type, from_id);
CREATE INDEX idx_graph_edges_to ON graph_edges(to_type, to_id);
CREATE INDEX idx_raw_evidence_scan_run ON raw_evidence(scan_run_id);
```

### 14.4 PRAGMA Ayarları

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;
```

---

## 15. Collector Tasarımı

### 15.1 Remote Collector İlkeleri

Remote collector sadece izinli, read-only komutlar çalıştırır.

```text
- Komutlar manifest dosyasından üretilir.
- Shell injection riskine karşı argümanlar güvenli şekilde quote edilir.
- Timeout her komut için ayrı uygulanır.
- Büyük dosyalar için max size limiti vardır.
- stderr ve exit_code raw_evidence içine kaydedilir.
- Host bazında partial success desteklenir.
```

### 15.2 İlk Komut Manifesti

```yaml
commands:
  hostname:
    command: "hostname -f || hostname"
    sudo: false
    evidence_type: "hostname"

  passwd:
    command: "getent passwd"
    sudo: false
    evidence_type: "passwd"

  group:
    command: "getent group"
    sudo: false
    evidence_type: "group"

  sshd_config:
    command: "cat /etc/ssh/sshd_config 2>/dev/null"
    sudo: true
    evidence_type: "sshd_config"

  sshd_config_d_list:
    command: "find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name '*.conf' -print 2>/dev/null"
    sudo: true
    evidence_type: "sshd_config_list"

  authorized_keys_list:
    command: "find /home -maxdepth 3 -path '*/.ssh/authorized_keys' -type f -print 2>/dev/null"
    sudo: true
    evidence_type: "authorized_keys_list"

  root_authorized_keys:
    command: "cat /root/.ssh/authorized_keys 2>/dev/null"
    sudo: true
    evidence_type: "authorized_keys"

  sudoers:
    command: "cat /etc/sudoers 2>/dev/null"
    sudo: true
    evidence_type: "sudoers"
```

### 15.3 Kısıtlı Sudoers Örneği

Dağıtıma göre path farkı olabileceği için ürün içinde distro bazlı örnekler sunulmalıdır.

```sudoers
audituser ALL=(root) NOPASSWD: /bin/cat /etc/ssh/sshd_config
audituser ALL=(root) NOPASSWD: /usr/bin/find /etc/ssh/sshd_config.d -maxdepth 1 -type f -name *.conf -print
audituser ALL=(root) NOPASSWD: /bin/cat /etc/ssh/sshd_config.d/*.conf
audituser ALL=(root) NOPASSWD: /usr/bin/find /home -maxdepth 3 -path */.ssh/authorized_keys -type f -print
audituser ALL=(root) NOPASSWD: /bin/cat /home/*/.ssh/authorized_keys
audituser ALL=(root) NOPASSWD: /bin/cat /root/.ssh/authorized_keys
audituser ALL=(root) NOPASSWD: /bin/cat /etc/sudoers
audituser ALL=(root) NOPASSWD: /bin/cat /etc/sudoers.d/*
```

### 15.4 Local Collector

İncelenecek kaynaklar:

```text
/etc/ssh/
/home/*/.ssh/
/root/.ssh/
/etc/sudoers
/etc/sudoers.d/
```

Özel kural:

```text
Private key dosyalarının içeriği okunmaz.
Sadece dosya adı, owner, group, mode, mtime ve public counterpart metadata incelenir.
```

---

## 16. Parser Motorları

Parserlar SSHMap'in kalite merkezidir. Her parser şu kurallara uymalıdır:

```text
- Tolerant parsing
- Line number preservation
- Source file preservation
- Structured error reporting
- Golden fixture tests
- No panic on malformed input
```

### 16.1 passwd Parser

Çıktı alanları:

```text
username
uid
gid
gecos
home_dir
shell
is_root
is_system_account
is_service_account
```

Service account heuristics:

```text
- uid < 1000
- shell contains nologin or false
- username: backup, deploy, app, git, jenkins, zabbix, ansible, oracle, postgres, mysql, nginx, apache
```

### 16.2 sshd_config Parser

Desteklenecek direktifler:

```text
PermitRootLogin
PasswordAuthentication
PubkeyAuthentication
ChallengeResponseAuthentication
KbdInteractiveAuthentication
PermitEmptyPasswords
AllowUsers
AllowGroups
DenyUsers
DenyGroups
AuthorizedKeysFile
AuthenticationMethods
MaxAuthTries
LoginGraceTime
ClientAliveInterval
X11Forwarding
AllowTcpForwarding
PermitTunnel
GatewayPorts
PermitUserEnvironment
Include
Match
```

Geliştirme sırası:

```text
MVP: global directives
v0.4: Include support
v0.6: Match block parsing
v0.8: effective config evaluation
```

### 16.3 authorized_keys Parser

Desteklenecek örnekler:

```text
ssh-ed25519 AAAAC3Nza... user@host
from="10.0.0.0/8" ssh-rsa AAAAB3Nza... backup
command="/usr/local/bin/backup",no-pty ssh-ed25519 AAAA...
no-agent-forwarding,no-port-forwarding ssh-ed25519 AAAA...
```

Parse edilecek alanlar:

```text
options
key_type
key_blob
comment
line_number
has_from_restriction
has_command_restriction
permits_pty
permits_port_forwarding
permits_agent_forwarding
permits_x11_forwarding
```

### 16.4 sudoers Parser

MVP hedefi:

```text
- NOPASSWD tespiti
- ALL command tespiti
- Group subject tespiti
- Dangerous binary tespiti
```

Riskli binary listesi:

```text
bash
sh
zsh
vim
vi
nano
less
more
find
tar
rsync
python
python3
perl
ruby
awk
sed
scp
ssh
systemctl
docker
kubectl
mysql
psql
```

### 16.5 known_hosts Parser

Amaç:

```text
Kullanıcı veya hostun geçmişte hangi SSH hedeflerini tanıdığını lateral movement sinyali olarak modellemek.
```

Hashed known_hosts:

```text
Hostname çözülemeyebilir.
Host key fingerprint yine çıkarılabilir.
Confidence LOW olur.
```

### 16.6 ssh_config Parser

Desteklenecek alanlar:

```text
Host
HostName
User
Port
IdentityFile
ProxyJump
ProxyCommand
ForwardAgent
LocalForward
RemoteForward
DynamicForward
StrictHostKeyChecking
```

Riskler:

```text
ForwardAgent yes under Host * => HIGH
ProxyCommand present => INFO/MEDIUM
RemoteForward present => MEDIUM
DynamicForward present => MEDIUM
StrictHostKeyChecking no => MEDIUM
```

---

## 17. Public Key Fingerprint Engine

Amaç, aynı public keyin tüm ortam boyunca tekil kimlikle izlenmesidir.

### 17.1 Desteklenecek Key Tipleri

```text
ssh-ed25519
ssh-rsa
ecdsa-sha2-nistp256
ecdsa-sha2-nistp384
ecdsa-sha2-nistp521
ssh-dss
sk-ssh-ed25519@openssh.com
sk-ecdsa-sha2-nistp256@openssh.com
```

### 17.2 Üretilecek Fingerprintler

```text
SHA256 fingerprint
MD5 legacy fingerprint, opsiyonel
Normalized public key hash
Key type
Key size, mümkün olduğunda
```

### 17.3 Kabul Kriteri

```text
Aynı public key 100 farklı hostta görülse bile public_keys tablosunda tek kayıt olmalıdır.
authorized_keys tablosu bu public_key_id ile ilişkilendirilmelidir.
```

---

## 18. Risk Engine

### 18.1 Severity Model

```text
CRITICAL = 90-100
HIGH     = 70-89
MEDIUM   = 40-69
LOW      = 10-39
INFO     = 0-9
```

### 18.2 Confidence Model

```text
HIGH   = Direct evidence from config, authorized_keys, sudoers
MEDIUM = Inferred from ssh_config, ProxyJump, known_hosts with hostname
LOW    = Weak signal, hashed known_hosts, incomplete import
```

### 18.3 Risk Kategorileri

```text
SSH Configuration
Authentication
Public Key Hygiene
Privilege Escalation
Lateral Movement
Cryptographic Weakness
Inventory Drift
Operational Hygiene
```

### 18.4 İlk Risk Kataloğu

```text
SSH_ROOT_LOGIN_ENABLED
SSH_ROOT_LOGIN_WITH_KEYS
SSH_PASSWORD_AUTH_ENABLED
SSH_EMPTY_PASSWORD_ALLOWED
SSH_WEAK_KEX_ENABLED
SSH_WEAK_CIPHER_ENABLED
SSH_WEAK_MAC_ENABLED
SSH_DSA_KEY_DETECTED
SSH_RSA_LESS_THAN_2048
SSH_HOST_KEY_REUSED
SSH_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS
SSH_ROOT_AUTHORIZED_KEY_WITHOUT_RESTRICTIONS
SSH_KEY_REUSED_MANY_HOSTS
SSH_KEY_REUSED_ROOT
SSH_KEY_USED_BY_MULTIPLE_USERS
SSH_KEY_REUSE_WITH_SUDO
SSH_STALE_USER_KEY
SSH_FORWARD_AGENT_ENABLED
SSH_FORWARD_AGENT_WILDCARD
SSH_PROXYJUMP_CHAIN_DETECTED
SSH_STRICT_HOST_KEY_CHECKING_DISABLED
SSH_GATEWAY_PORTS_ENABLED
SSH_TCP_FORWARDING_ENABLED
SUDO_NOPASSWD_ALL
SUDO_DANGEROUS_BINARY_NOPASSWD
SUDO_GROUP_WIDE_ADMIN
USER_SERVICE_ACCOUNT_INTERACTIVE_SHELL
USER_ORPHANED_HOME_AUTHORIZED_KEYS
INVENTORY_UNKNOWN_SSH_HOST
```

### 18.5 Kombine Risk Örnekleri

```text
Same key reused on 20 hosts
+
One target user has NOPASSWD:ALL
=
CRITICAL SSH_KEY_REUSE_WITH_SUDO
```

```text
Root login enabled
+
Root authorized_keys contains unrestricted key
+
Same key appears on another host
=
CRITICAL SSH_ROOT_KEY_REUSE_LATERAL_MOVEMENT
```

### 18.6 Risk Kuralı Örneği

```yaml
- code: SSH_ROOT_LOGIN_ENABLED
  category: SSH Configuration
  severity: CRITICAL
  score: 95
  confidence: HIGH
  title: Root login is enabled
  condition:
    config_key: PermitRootLogin
    equals: "yes"
  recommendation: Set PermitRootLogin to no and use least-privileged named accounts.
```

---

## 19. Graph Engine

### 19.1 Node Türleri

```text
HOST
USER
GROUP
PUBLIC_KEY
HOST_KEY
AUTHORIZED_KEY
SUDO_RULE
KNOWN_HOST
SSH_CLIENT_CONFIG
RISK
TAG
```

### 19.2 Edge Türleri

```text
HOST_HAS_USER
USER_MEMBER_OF_GROUP
USER_HAS_AUTHORIZED_KEY
PUBLIC_KEY_CAN_LOGIN_TO_USER
USER_HAS_SUDO_RULE
USER_HAS_PASSWORDLESS_SUDO
HOST_HAS_RISK
USER_HAS_RISK
PUBLIC_KEY_HAS_RISK
USER_KNOWS_HOST
USER_USES_PROXYJUMP
USER_ENABLES_AGENT_FORWARDING
PUBLIC_KEY_REUSED_ON_HOST
HOST_REUSES_HOST_KEY
RISK_DEPENDS_ON_RISK
```

### 19.3 Path Analizi

Komut:

```bash
sshmap path --from key:SHA256:abc123 --to host:db01 --db sshmap.db
```

Örnek çıktı:

```text
Path found:

1. PUBLIC_KEY SHA256:abc123
2. CAN_LOGIN_TO deploy@web01
3. deploy@web01 HAS_PASSWORDLESS_SUDO root@web01
4. root@web01 KNOWS_HOST db01

Risk: CRITICAL
Confidence: MEDIUM
```

### 19.4 Blast Radius

Blast radius şu sorulara cevap vermelidir:

```text
- Bu key ele geçirilirse kaç host etkilenir?
- Kaç root veya sudo context'e ulaşılabilir?
- Hangi production veya critical hostlara giden yol vardır?
- Hangi yollar direct evidence, hangileri inference?
```

---

## 20. Raporlama

### 20.1 Formatlar

```text
HTML
JSON
CSV
DOT
Cytoscape JSON
SARIF, v1 sonrası
PDF, opsiyonel
```

### 20.2 HTML Rapor Bölümleri

```text
1. Executive Summary
2. Scope
3. Methodology
4. Key Metrics
5. Critical Findings
6. SSH Configuration Risks
7. Public Key Inventory
8. Key Reuse Matrix
9. Root Login Findings
10. Password Authentication Findings
11. Sudo Findings
12. Lateral Movement Indicators
13. Attack Path Examples
14. Remediation Roadmap
15. Exceptions
16. Appendix
```

### 20.3 Executive Summary Örneği

```text
SSHMap identified 428 SSH-enabled systems in the assessed environment.
The assessment found 18 critical and 73 high severity SSH exposure risks.

The most significant issue is public key reuse. One deploy key grants access
to 78 systems, including 4 systems where the target user has passwordless sudo.
Root login is enabled on 14 systems and password authentication is enabled on
42 systems.
```

### 20.4 JSON Rapor Şeması

```json
{
  "summary": {
    "hosts_scanned": 512,
    "ssh_open": 428,
    "users_found": 1260,
    "public_keys_found": 384,
    "critical_risks": 18,
    "high_risks": 73
  },
  "top_risks": [
    {
      "code": "SSH_KEY_REUSE_WITH_SUDO",
      "severity": "CRITICAL",
      "score": 100,
      "confidence": "HIGH",
      "title": "Reused SSH key reaches passwordless sudo",
      "evidence": "SHA256:abc123 used on 23 hosts; sudo NOPASSWD found on 4 hosts"
    }
  ]
}
```

### 20.5 CSV Çıktıları

```text
hosts.csv
users.csv
groups.csv
public_keys.csv
authorized_keys.csv
sshd_config.csv
sudo_rules.csv
known_hosts.csv
ssh_client_config.csv
risks.csv
key_reuse.csv
graph_edges.csv
```

---

## 21. Web UI ve API

Web UI MVP sonrası geliştirilmelidir. İlk hedef read-only analiz deneyimi olmalıdır.

### 21.1 Teknoloji

```text
Backend: axum
Frontend: React + TypeScript
Graph: Cytoscape.js
Database: SQLite read-only connection
Auth: localhost-only by default, token auth for remote use
```

### 21.2 Sayfalar

```text
Dashboard
Hosts
Users
Keys
Risks
Graph
Paths
Reports
Baselines
Settings
```

### 21.3 Modern Ürün Deneyimi

UI sadece tablo göstermemelidir. Kullanıcının karar vermesini kolaylaştırmalıdır:

```text
- Top critical paths
- Most reused keys
- Users with highest blast radius
- Hosts with highest SSH exposure
- Remediation priority queue
- Risk trend over time
- Filterable graph
- Evidence drawer
- Export actions
```

### 21.4 API Örnekleri

```text
GET /api/summary
GET /api/hosts
GET /api/hosts/{id}
GET /api/users
GET /api/keys/reuse
GET /api/risks
GET /api/graph
GET /api/path?from=key:SHA256:abc&to=host:db01
POST /api/reports
```

---

## 22. Importer Framework

### 22.1 Importer İlkeleri

```text
- Her importer source metadata üretmelidir.
- Input validation yapılmalıdır.
- Aynı verinin tekrar import edilmesi idempotent olmalıdır.
- CSV mapping konfigüre edilebilir olmalıdır.
```

### 22.2 İlk Importerlar

```text
Ansible inventory
Nmap XML
CSV host inventory
known_hosts
sshd_config file
authorized_keys file
sudoers file
SSHMap JSON export
```

### 22.3 Komut Örnekleri

```bash
sshmap import ansible --file inventory.ini --db sshmap.db
sshmap import nmap --file nmap.xml --db sshmap.db
sshmap import csv --file hosts.csv --mapping hosts.mapping.yaml --db sshmap.db
sshmap import known-hosts --file ~/.ssh/known_hosts --db sshmap.db
```

---

## 23. Redaction ve Veri Güvenliği

### 23.1 Private Key Koruması

Aşağıdaki patternlerden biri görülürse içerik DB'ye yazılmamalıdır:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN DSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
```

### 23.2 Maskelenecek Patternler

```text
password=
passwd=
secret=
token=
api_key=
access_key=
private_key=
```

### 23.3 Rapor Redaction Seçenekleri

```text
--mask-usernames
--mask-hostnames
--mask-home-paths
--exclude-raw-evidence
```

### 23.4 Data Classification

SSHMap DB dosyası hassas kabul edilmelidir.

```text
Classification: Confidential
Contains: user inventory, host inventory, access relationships, security findings
Does not contain: private keys, passwords, secrets
```

---

## 24. Test Stratejisi

### 24.1 Unit Testler

```text
target parser
scope validator
CIDR expansion
SSH banner parser
authorized_keys parser
sshd_config parser
sudoers parser
known_hosts parser
ssh_config parser
public key fingerprinting
risk rules
graph BFS
redaction
```

### 24.2 Golden Fixture Testleri

Her parser için fixture dosyaları oluşturulmalıdır:

```text
fixtures/authorized_keys/basic.input
fixtures/authorized_keys/basic.expected.json
fixtures/sshd_config/include.input
fixtures/sshd_config/include.expected.json
fixtures/sudoers/nopasswd.input
fixtures/sudoers/nopasswd.expected.json
```

### 24.3 Integration Test

Docker Compose ortamı:

```text
ubuntu-ssh-default
ubuntu-ssh-root-login
ubuntu-ssh-password-auth
ubuntu-key-reuse-1
ubuntu-key-reuse-2
ubuntu-sudo-nopasswd
```

Test beklentileri:

```text
- Root login açık host tespit edilir.
- Password auth açık host tespit edilir.
- Aynı key iki hostta tespit edilir.
- Sudo NOPASSWD tespit edilir.
- HTML report üretilir.
```

### 24.4 Fuzz ve Robustness

Parserlar bozuk inputta panic etmemelidir.

```text
cargo fuzz, v0.6 sonrası
proptest, parser edge-case testleri için
```

### 24.5 Performans Testleri

```text
1,000 host discovery
10,000 host import
100,000 authorized_keys relation
1,000,000 graph edges query simulation
```

---

## 25. Performans ve Ölçeklenebilirlik

### 25.1 MVP Hedefleri

```text
- 1,000 host discovery makul sürede tamamlanmalı.
- 100 eşzamanlı TCP connect desteklenmeli.
- 25 eşzamanlı SSH collection desteklenmeli.
- SQLite transaction ile batch insert yapılmalı.
- Rapor üretimi 100,000 risk kaydında kullanılabilir kalmalı.
```

### 25.2 Büyük Ortam Hedefleri

```text
- 10,000 host inventory
- 100,000 user account
- 250,000 authorized key relation
- 1,000,000 graph edge
```

### 25.3 Optimizasyonlar

```text
- Prepared statements
- Batch insert
- WAL mode
- Index tuning
- Incremental analysis
- Baseline diff
- Lazy graph export
```

---

## 26. Geliştirme Fazları

### Faz 0 - Repository Hazırlığı

Amaç:

```text
Proje temelini oluşturmak.
```

Görevler:

```text
- Rust binary project oluştur.
- README.md, LICENSE, SECURITY.md, CONTRIBUTING.md ekle.
- .gitignore ekle.
- rustfmt ve clippy ayarlarını ekle.
- GitHub Actions veya eşdeğer CI ekle.
- Kodlama dilinin İngilizce olduğunu CONTRIBUTING.md içinde zorunlu kural yap.
```

Kabul kriteri:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

### Faz 1 - CLI ve SQLite Init

Görevler:

```text
- clap ile CLI kur.
- init, doctor, db stats komutlarını ekle.
- migration runner yaz.
- scan_runs, hosts, risks temel tablolarını oluştur.
- PRAGMA ayarlarını uygula.
```

Kabul kriteri:

```bash
sshmap init --db test.db
sshmap db stats --db test.db
```

### Faz 2 - Scope ve Target Parser

Görevler:

```text
- CIDR parser
- host file parser
- port parser
- scope include/exclude
- out-of-scope protection
```

### Faz 3 - Host Discovery

Görevler:

```text
- TCP connect scanner
- timeout
- concurrency
- SSH banner capture
- hosts tablosuna kayıt
```

### Faz 4 - Host Key ve Algorithm Audit

Görevler:

```text
- Host key fingerprint
- Supported algorithm discovery
- Weak algorithm riskleri
```

### Faz 5 - Remote Collector

Görevler:

```text
- OpenSSH binary transport
- command manifest
- sudo -n desteği
- raw_evidence kaydı
- partial success handling
```

### Faz 6 - Parser Framework

Görevler:

```text
- passwd parser
- group parser
- sshd_config parser
- authorized_keys parser
- sudoers parser
- known_hosts parser
- ssh_config parser
- golden fixture tests
```

### Faz 7 - Public Key Engine

Görevler:

```text
- OpenSSH public key parse
- SHA256 fingerprint
- key type normalization
- authorized_keys relation
```

### Faz 8 - Risk Engine MVP

Görevler:

```text
- Root login riskleri
- Password auth riskleri
- Empty password riskleri
- Key reuse riskleri
- Sudo NOPASSWD riskleri
```

### Faz 9 - Graph Engine MVP

Görevler:

```text
- graph_edges üretimi
- path command
- basic blast-radius
- DOT ve Cytoscape export
```

### Faz 10 - Reporting MVP

Görevler:

```text
- JSON report
- CSV exports
- single-file HTML report
- remediation section
```

### Faz 11 - Importers

Görevler:

```text
- Ansible inventory
- Nmap XML
- CSV
- known_hosts
- file-based config import
```

### Faz 12 - Baseline ve Diff

Görevler:

```text
- baseline create
- diff scan runs
- new/resolved risk detection
- trend summary
```

### Faz 13 - Web UI Read-Only

Görevler:

```text
- axum server
- React dashboard
- hosts/users/keys/risks pages
- graph viewer
- evidence drawer
```

### Faz 14 - Enterprise Hazırlık

Görevler:

```text
- API token auth
- report templates
- exceptions
- integration hooks
- packaging
- SBOM
- signed releases
```

### Faz 15 - v1.0 Stabilizasyon

Görevler:

```text
- CLI backward compatibility
- migration stability
- performance hardening
- security review
- documentation completion
- public release notes
```

---

## 27. MVP Kapsamı

MVP'de kesin olacaklar:

```text
- Rust CLI
- İngilizce kod tabanı
- SQLite DB
- init
- doctor
- db stats
- discover
- scan
- local-scan
- analyze
- report json/html
- TCP SSH discovery
- SSH banner toplama
- remote sshd_config toplama
- authorized_keys toplama
- public key fingerprint
- key reuse detection
- root login detection
- password auth detection
- sudo NOPASSWD detection
- temel graph_edges
```

MVP dışı bırakılabilecekler:

```text
- Web UI
- Native Rust SSH transport
- gelişmiş Match block effective config
- GitHub/GitLab API entegrasyonu
- LDAP/FreeIPA entegrasyonu
- gelişmiş graph confidence scoring
- PDF export
```

---

## 28. Kalite Kapıları

Her PR veya geliştirme adımı için:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Ek kontroller:

```text
- Kodda Türkçe identifier olmamalıdır.
- Test fixture eklenmeden parser değişikliği yapılmamalıdır.
- Migration geri uyumluluğu kontrol edilmelidir.
- Rapor snapshot testleri güncellenmelidir.
- Security-sensitive değişikliklerde threat model notu eklenmelidir.
```

---

## 29. Dokümantasyon Planı

### 29.1 README

İçerik:

```text
- SSHMap nedir?
- Hızlı başlangıç
- Güvenlik ve yetki uyarısı
- Örnek komutlar
- Rapor örneği
- MVP kapsamı
```

### 29.2 Kullanıcı Dokümantasyonu

```text
docs/getting-started.md
docs/scope.md
docs/discovery.md
docs/authenticated-scan.md
docs/local-scan.md
docs/importers.md
docs/reports.md
docs/remediation.md
```

### 29.3 Geliştirici Dokümantasyonu

```text
docs/development/coding-standards.md
docs/development/architecture.md
docs/development/database.md
docs/development/parsers.md
docs/development/risk-engine.md
docs/development/graph-engine.md
```

`coding-standards.md` içinde İngilizce kod zorunluluğu tekrar yazılmalıdır.

---

## 30. Packaging ve Dağıtım

### 30.1 Dağıtım Formatları

```text
Linux x86_64 binary
Linux aarch64 binary
macOS arm64 binary
macOS x86_64 binary
Debian package
RPM package
Container image, opsiyonel
Homebrew tap, v1 sonrası
```

### 30.2 Release Güvenliği

```text
- Checksums
- Signed artifacts
- SBOM
- Changelog
- Reproducible build hedefi
```

---

## 31. Başarı Metrikleri

### 31.1 Ürün Başarı Metrikleri

```text
- İlk scan süresi
- Bulunan unknown SSH host sayısı
- Key reuse bulgusu sayısı
- Critical risk remediation oranı
- Rapor üretme süresi
- False positive oranı
- Parser error oranı
```

### 31.2 Teknik Başarı Metrikleri

```text
- Test coverage, özellikle parser ve risk engine
- Panic-free parser runs
- 1,000 host discovery stabilitesi
- DB migration güvenilirliği
- CLI backward compatibility
```

---

## 32. İlk Büyük Codex Prompt

Kod üretimine başlanırken kullanılabilecek prompt:

```text
Build a Rust CLI project named "sshmap".

Important coding standard:
All source code, identifiers, comments, database names, CLI commands, tests,
error messages and log messages must be written in English. Do not use Turkish
identifiers or Turkish code comments.

Goal:
SSHMap is an agentless SSH Exposure Management tool. It discovers SSH services,
stores results in SQLite, and prepares the foundation for analyzing SSH users,
public keys, root login, password authentication, sudo risks and key reuse.

Implement the first milestone:
1. clap-based CLI:
   - sshmap init --db sshmap.db
   - sshmap doctor
   - sshmap db stats --db sshmap.db
   - sshmap discover --targets 10.10.0.0/24 --db sshmap.db
   - sshmap discover --file hosts.txt --db sshmap.db

2. SQLite:
   - Use rusqlite.
   - Create migrations/001_init.sql.
   - Create schema_migrations, scan_runs, hosts, risks and audit_events tables.
   - Enable foreign_keys and WAL mode.

3. Discovery:
   - Support CIDR input.
   - Support host file input.
   - Use TCP connect to check SSH ports.
   - Add timeout and concurrency options.
   - Capture SSH banner when available.
   - Store results in hosts.

4. Code structure:
   src/main.rs
   src/cli.rs
   src/config.rs
   src/db.rs
   src/discovery.rs
   src/scope.rs
   src/models.rs
   src/error.rs

5. Quality:
   - Use anyhow and thiserror.
   - Use tracing for logs.
   - Add unit tests for target parsing and CIDR expansion.
   - Add README usage examples.

Security:
- Do not brute force.
- Do not attempt password login.
- Do not run exploits.
- Only perform TCP connect and SSH banner reading in discover mode.
```

---

## 33. Remote Collector Codex Prompt

```text
Add authenticated remote scan support to SSHMap.

Coding standard:
All code, identifiers, comments, logs, errors and tests must be in English.

New command:
sshmap scan \
  --targets hosts.txt \
  --user audituser \
  --key ~/.ssh/audit_ed25519 \
  --sudo \
  --db sshmap.db

Requirements:
- Use the system OpenSSH binary through a transport abstraction.
- Add a RemoteCommand manifest.
- Collect hostname, getent passwd, getent group, /etc/ssh/sshd_config,
  authorized_keys and sudoers data when allowed.
- Use sudo -n only when --sudo is provided.
- Store stdout, stderr, exit_code, command, evidence_type and timestamps in raw_evidence.
- Do not crash on failed hosts.
- Support timeout and concurrency.
- Never read private key contents from remote hosts.
```

---

## 34. Parser ve Risk Engine Codex Prompt

```text
Add parser and risk engine modules to SSHMap.

Coding standard:
All code, identifiers, comments, logs, errors and tests must be in English.

Parsers:
- passwd parser
- group parser
- sshd_config parser
- authorized_keys parser
- sudoers parser

Risk rules:
- PermitRootLogin yes => CRITICAL
- PasswordAuthentication yes => HIGH
- PermitEmptyPasswords yes => CRITICAL
- Same public key on 5+ hosts => HIGH
- Same public key on root and other hosts => CRITICAL
- NOPASSWD:ALL => CRITICAL

Database tables:
- users
- groups
- user_groups
- public_keys
- authorized_keys
- sshd_config_entries
- sudo_rules
- risks

Command:
sshmap analyze --db sshmap.db

Quality:
- Add unit tests with fixtures for each parser.
- Do not panic on malformed input.
- Preserve source_file and line_number when possible.
```

---

## 35. v1.0 Public Release Kriterleri

SSHMap v1.0 için kabul kriterleri:

```text
- Tek binary olarak çalışır.
- Kod tabanı tamamen İngilizcedir.
- SQLite dışında zorunlu runtime bağımlılığı minimumdur.
- Discovery, scan, local-scan, import, analyze ve report komutları stabildir.
- En az 100 hostluk test ortamında stabil çalışır.
- Root login, password auth, key reuse ve sudo NOPASSWD bulgularını doğru üretir.
- Private key veya password toplamaz.
- HTML rapor profesyonel pentest raporuna eklenebilir kalitededir.
- JSON ve CSV çıktıları otomasyon için kullanılabilir yapıdadır.
- Parserlar bozuk inputta panic etmez.
- DB migrationları güvenilirdir.
- README ve kullanıcı dokümantasyonu tamamdır.
```

---

## 36. Önerilen Versiyonlama

```text
v0.1.0 - init, DB, doctor, basic discovery
v0.2.0 - scope validation, SSH banner, host key collection
v0.3.0 - remote collector, raw evidence
v0.4.0 - parsers, normalized tables
v0.5.0 - public key fingerprinting, key reuse
v0.6.0 - risk engine MVP
v0.7.0 - sudo analyzer and ssh_config/known_hosts parser
v0.8.0 - graph engine, path, blast-radius
v0.9.0 - reports, importers, baseline diff
v1.0.0 - stable CLI release
v1.1.0 - web UI read-only
v1.2.0 - API and integrations
v2.0.0 - native Rust SSH transport option
```

---

## 37. Son Ürün Hedefi

SSHMap doğru geliştirilirse klasik port scanner veya basit SSH audit scriptlerinden farklı bir ürün kategorisine oturur.

Ürünün nihai değeri:

```text
SSH erişimleri büyür, paylaşılır, unutulur ve zamanla görünmez hale gelir.
SSHMap bu görünmez erişimleri kanıt, risk ve graph bağlamında görünür hale getirir.
```

En önemli mühendislik hatırlatması:

```text
SSHMap'in dokümantasyonu Türkçe yazılabilir, ancak kodlama kesinlikle İngilizce yapılmalıdır.
Kaynak kodda Türkçe identifier, yorum, hata mesajı, log mesajı, test adı veya veritabanı alanı kullanılmamalıdır.
```
