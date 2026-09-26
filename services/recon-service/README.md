# Cloudflare Analyzer (Rust)

Bu proje, bir domainin Cloudflare arkasında olup olmadığını tespit eden, HTTP başlıklarını analiz eden ve subdomain keşfi yaparak gerçek IP adreslerini bulmaya çalışan yüksek performanslı bir Rust aracıdır.

## Özellikler

- **DNS Analizi**: Domainin A kayıtlarını kontrol eder ve Cloudflare IP aralıklarıyla karşılaştırır.
- **HTTP Analizi**: HTTP başlıklarında Cloudflare izlerini arar.
- **Subdomain Keşfi**: SecLists veya özel wordlist kullanarak subdomainleri tarar ve IP'lerini kontrol eder.
- **Yüksek Performans**: Rust'ın `tokio` kütüphanesi ile asenkron ve çok kanallı (multi-threaded) tarama yapar.
- **Türkçe Loglama**: Tüm çıktılar Türkçe ve renklidir.

## Kurulum

Bu projeyi çalıştırmak için sisteminizde Rust ve Cargo yüklü olmalıdır.

1.  **Rust Yükleme (Eğer yüklü değilse):**
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    source $HOME/.cargo/env
    ```

2.  **Projeyi Derleme:**
    ```bash
    cd services/cf-analyzer
    cargo build --release
    ```

## Docker ile Çalıştırma

Bu servis Docker ile tam uyumludur ve `docker-compose` sistemine entegre edilmiştir.

1.  **Tekil Build ve Çalıştırma:**
    ```bash
    docker build -t cf-analyzer .
    docker run -v $(pwd)/../../files:/app/files cf-analyzer example.com
    ```

2.  **Docker Compose ile:**
    Ana dizindeki `docker-compose.yml` üzerinden tüm sistemle birlikte kalkar.
    ```bash
    docker-compose up -d --build cf-analyzer
    ```

## Kullanım

Derlenen binary dosyasını aşağıdaki gibi çalıştırabilirsiniz:

```bash
./target/release/cf_analyzer <hedef_domain> [wordlist_yolu]
```

**Örnek:**

```bash
./target/release/cf_analyzer example.com
```

veya özel bir wordlist ile:

```bash
./target/release/cf_analyzer example.com ../../files/SecLists-master/Discovery/DNS/subdomains-top1million-5000.txt
```

## Frontend Entegrasyonu

Bu servis şu anda CLI (Komut Satırı Arayüzü) olarak çalışmaktadır. Frontend tarafında (`/cf-analyzer` rotası) bu aracın simülasyonu ve arayüzü hazırlanmıştır. Gerçek entegrasyon için bu Rust servisinin bir HTTP API (örn. Actix-web veya Axum ile) olarak sarmalanması ve frontend'in bu API'ye istek atması gerekmektedir.

## Dosya Yapısı

- `src/main.rs`: Ana giriş noktası.
- `src/dns.rs`: DNS ve IP analiz modülü.
- `src/http.rs`: HTTP başlık analiz modülü.
- `src/subdomain.rs`: Subdomain tarama modülü.
- `src/logger.rs`: Loglama yardımcısı.
