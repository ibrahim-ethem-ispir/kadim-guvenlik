
## Nodejs Paket Kurulumu

```bash
# Yeni paket eklerken
pnpm add package-name

# Dev dependency
pnpm add -D package-name

# Paket kaldırma
pnpm remove package-name
```
## backend
# Backend Geliştirme Kuralları - Kadim Güvenlik Platformu

## 🏗️ Mimari Farkındalık
- Bu proje **Docker Compose** ile orkestre edilen mikroservis mimarisinde çalışır
- Servisler arası iletişim Docker network (`kadim-net`) üzerinden gerçekleşir
- Gateway (nginx) → Frontend (React) ve Orchestrator (FastAPI) arasında reverse proxy görevi görür
- Orchestrator → Redis (message broker) ve mikroservisler (nmap, nikto) ile haberleşir
- **Her değişiklik Docker container ortamını göz önünde bulundurmalı**

## 🔗 Frontend-Backend Bağlantı Analizi
- Frontend API çağrıları `/api/*` prefix'i ile yapılır (nginx.conf'ta rewrite edilir)
- Orchestrator endpoint'leri:
  - `POST /scan` → Tarama başlatır (scan_id döner)
  - `GET /scan/{scan_id}` → Tarama sonuçlarını getirir
- **Backend endpoint'lerinde değişiklik yapılırsa frontend route'ları kontrol et**
- **Response şeması değişirse frontend TypeScript interface'lerini güncelle**
- **Yeni endpoint eklenirse nginx.conf proxy ayarlarını kontrol et**

- ** kesinlikle her sayfa tasarımında olabildiğince bilgi tooltip veya bilgi kutusu olması lazım ve her sayfada detaylı örnek kullanım senaryoları olması lazım.

## 📝 Kod Yorumlama Standartları
- **Her fonksiyon başına Türkçe açıklama ekle** (ne yaptığını, neden var olduğunu)
- **Kritik güvenlik kontrolleri için satır içi yorum ekle** (örn: input validation)
- **Karmaşık iş mantığı için adım adım Türkçe açıklama yap**
- **Docker/network spesifik kodlar için ortam bilgisi ekle** (örn: "Redis container'ına bağlanıyor")
- **API endpoint'lerinde request/response formatını yorum olarak belirt**

Örnek:
```python
# Hedef IP/domain validasyonu - Command injection saldırılarını önlemek için kritik
@validator('target')
def validate_target(cls, v):
    # IPv4 veya domain formatı kontrolü
    if not (re.match(ipv4_pattern, v) or re.match(domain_pattern, v)):
        raise ValueError('Geçersiz hedef formatı')
    return v
```

## 🔒 Güvenlik Öncelikleri
- **Input validation her zaman ilk adım** (command injection, SQL injection önleme)
- **Shell komutlarına kullanıcı girdisi geçerken ekstra sanitizasyon yap**
- **Hassas bilgiler (API keys, credentials) environment variable'da sakla**
- **Rate limiting ve timeout değerleri her endpoint için tanımla**
- **Error mesajlarında sistem detayı verme** (stack trace, path bilgisi)

## 🐳 Docker Container Özellikleri
- **Port mapping'leri docker-compose.yml'de tanımlı** (değiştirme)
- **Servis URL'leri environment variable'dan gelir** (hardcode etme)
- **Health check'ler eklenirse docker-compose.yml'e ekle**
- **Volume mount'lar için güvenlik izinlerini kontrol et**
- **Container içi log'lar stdout/stderr'e yazılmalı** (Docker logs için)

## 🔄 Mikroservis İletişim Kuralları
- **Orchestrator her zaman merkezi kontrol noktası** (direkt mikroservis çağrısı yapma)
- **Async/background task'ler için Redis kullan** (uzun süren işlemler için)
- **Timeout değerleri gerçekçi belirle** (nmap: 600s, nikto: 1200s)
- **Servis arası hata yönetimi implement et** (retry logic, fallback)
- **Response formatı JSON standardında olmalı** (tutarlılık için)

## 📊 Veri Yönetimi
- **Redis key naming convention'ı koru**: `scan:{scan_id}:{service_name}`
- **Scan sonuçları JSON serialize edilerek saklanır**
- **TTL (Time To Live) değerleri büyük veriler için ayarla**
- **Scan ID'ler UUID v4 formatında üretilir** (değiştirme)

## 🧪 Test ve Debugging
- **Her endpoint için logging ekle** (başlangıç, bitiş, hata durumları)
- **Log level'ları doğru kullan**: INFO (normal akış), ERROR (hatalar), DEBUG (detaylı)
- **Docker logs ile takip edilebilir log formatı kullan**
- **Test için mock servisler oluşturulabilir** (docker-compose.test.yml)

## 🚀 Performans ve Ölçeklenebilirlik
- **Background task'ler için FastAPI BackgroundTasks kullan**
- **Uzun süren işlemler asenkron çalışmalı** (async/await)
- **Redis connection pool'u optimize et** (max connections)
- **HTTP client timeout'ları belirle** (httpx.AsyncClient)
- **Container resource limit'leri docker-compose.yml'de tanımla**

## 📦 Dependency Yönetimi
- **Python servisleri için requirements.txt güncel tut**
- **Node.js servisleri için package.json güncel tut**
- **Güvenlik açığı olan paketleri düzenli kontrol et**
- **Docker image'leri alpine versiyonları tercih et** (küçük boyut)

## 🔧 Yeni Servis Ekleme Checklist
1. ✅ `services/` altında yeni klasör oluştur
2. ✅ Dockerfile, main dosyası, requirements/package.json ekle
3. ✅ docker-compose.yml'e servis tanımı ekle
4. ✅ Orchestrator'a dispatch fonksiyonu ekle
5. ✅ Environment variable'ları tanımla
6. ✅ Redis key pattern'i belirle
7. ✅ Frontend'e yeni scan_type ekle (gerekirse)
8. ✅ Logging ve error handling implement et

## 🌐 API Endpoint Değişiklik Prosedürü
1. **Backend'de endpoint değiştir/ekle**
2. **Orchestrator main.py'da route'u güncelle**
3. **Frontend'de API çağrısını güncelle** (fetch URL'leri)
4. **TypeScript type'ları güncelle** (request/response)
5. **nginx.conf proxy ayarlarını kontrol et** (gerekirse)
6. **Dokümantasyon güncelle** (API spec)

## ⚠️ Yapılmaması Gerekenler
- ❌ Hardcoded IP/port kullanma (environment variable kullan)
- ❌ Senkron blocking işlemler yapma (async kullan)
- ❌ Frontend'den direkt mikroservislere istek atma (orchestrator üzerinden git)
- ❌ Hassas bilgileri log'lama (IP, credentials)
- ❌ Docker container içinde root user olarak çalıştırma (mümkünse)
- ❌ Error handling olmadan external servis çağrısı yapma
- ❌ Input validation bypass etme (her katmanda kontrol et)

## 🎯 Kod Kalitesi Standartları
- **Fonksiyon isimleri açıklayıcı olmalı** (ne yaptığını belli etmeli)
- **Magic number kullanma** (constant tanımla)
- **DRY prensibi uygula** (tekrar eden kodu fonksiyona çıkar)
- **Single Responsibility** (her fonksiyon tek iş yapmalı)
- **Type hints kullan** (Python) / TypeScript kullan (Node.js)
- **Pydantic model'ları validation için kullan** (FastAPI)

---

**Not**: Bu kurallar projenin mevcut mimarisini koruyarak, güvenli ve ölçeklenebilir geliştirme sağlamak için tasarlanmıştır. Her değişiklik öncesi bu kuralları gözden geçirin.


## frontend
# Frontend Geliştirme Kuralları - Kadim Güvenlik Platformu

## 🎨 Teknoloji Stack
- **Framework**: React Router v7 (SSR destekli)
- **Styling**: Tailwind CSS v4
- **Build Tool**: Vite
- **TypeScript**: Tip güvenliği için zorunlu
- **Icons**: Lucide React
- **Deployment**: Docker container (nginx ile serve)

## 🔗 Backend Entegrasyonu
- **API Base URL**: `/api` (nginx reverse proxy üzerinden)
- **Backend Endpoints**:
  - `POST /api/scan` → Tarama başlat
  - `GET /api/scan/{scan_id}` → Sonuçları getir
- **Her API çağrısında error handling zorunlu**
- **Loading state'leri kullanıcıya göster**
- **Backend response şeması değişirse TypeScript interface'leri güncelle**

## 📝 Kod Yorumlama Standartları
- **Component başına Türkçe açıklama ekle** (ne işe yaradığını)
- **Karmaşık state logic için yorum ekle**
- **API çağrıları için endpoint ve response formatını belirt**
- **Tailwind class'ları karmaşıksa gruplandırma mantığını açıkla**

Örnek:
```tsx
// Tarama sonuçlarını backend'den çeken ve real-time güncelleyen component
function ScanResults({ scanId }: Props) {
  // Her 3 saniyede bir sonuçları kontrol et (polling)
  useEffect(() => {
    const interval = setInterval(fetchResults, 3000);
    return () => clearInterval(interval);
  }, [scanId]);
}
```

## 🏗️ Component Yapısı
- **Layouts**: `app/layouts/` altında (main.tsx gibi)
- **Routes**: `app/routes/` altında (home.tsx, scan.tsx, results.tsx)
- **Shared Components**: `app/components/` altında oluştur (Button, Card, vb.)
- **Hooks**: `app/hooks/` altında custom hook'lar
- **Types**: `app/types/` altında TypeScript interface'leri
- **Utils**: `app/utils/` altında yardımcı fonksiyonlar

## 🎯 State Yönetimi
- **Local state için useState kullan** (component-specific)
- **Form state için controlled components**
- **API data için loading/error/data pattern kullan**
- **Global state gerekirse Context API kullan** (Redux ekleme)

Örnek pattern:
```tsx
const [data, setData] = useState(null);
const [loading, setLoading] = useState(false);
const [error, setError] = useState(null);
```

## 🌐 API Çağrıları
- **Fetch API veya axios kullan** (tutarlı ol)
- **Error handling her çağrıda olmalı**
- **Timeout değerleri belirle** (uzun süren taramalar için)
- **Loading indicator göster**
- **Network hatalarını kullanıcıya bildir**

Örnek:
```tsx
// Backend'e tarama isteği gönder
async function startScan(target: string, scanTypes: string[]) {
  try {
    const response = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, scan_types: scanTypes })
    });
    
    if (!response.ok) throw new Error('Tarama başlatılamadı');
    return await response.json();
  } catch (error) {
    console.error('API Hatası:', error);
    throw error;
  }
}
```

## 🎨 Styling Kuralları
- **Tailwind utility classes kullan** (custom CSS minimize et)
- **Responsive design zorunlu** (mobile-first approach)
- **Dark mode desteği eklenebilir** (Tailwind dark: prefix)
- **Consistent spacing kullan** (4, 8, 16, 24, 32px gibi)
- **Color palette tutarlı olmalı** (Tailwind default veya custom theme)

## ♿ Accessibility (Erişilebilirlik)
- **Semantic HTML kullan** (button, nav, main, article)
- **Alt text ekle** (img tag'leri için)
- **Keyboard navigation destekle** (tab, enter, escape)
- **ARIA labels ekle** (screen reader için)
- **Contrast ratio kontrol et** (text ve background)

## 🔒 Güvenlik
- **XSS önleme**: React otomatik escape eder ama dangerouslySetInnerHTML kullanma
- **Input validation**: Backend'e göndermeden önce client-side validation
- **Sensitive data gösterme**: API keys, tokens frontend'de olmamalı
- **HTTPS kullan**: Production'da SSL zorunlu

## 📱 Responsive Design Breakpoints
```
sm: 640px   // Mobil landscape
md: 768px   // Tablet
lg: 1024px  // Laptop
xl: 1280px  // Desktop
2xl: 1536px // Large desktop
```

## 🧪 Component Geliştirme Checklist
1. ✅ TypeScript interface/type tanımla
2. ✅ Props validation yap
3. ✅ Loading state ekle
4. ✅ Error handling implement et
5. ✅ Responsive design kontrol et
6. ✅ Accessibility kontrol et
7. ✅ Türkçe yorum ekle
8. ✅ Console.log'ları temizle (production öncesi)

## 🔄 Backend Değişiklik Senkronizasyonu
**Backend endpoint değişirse:**
1. API çağrısı yapan fonksiyonu güncelle
2. Request/Response TypeScript type'larını güncelle
3. Error handling'i kontrol et
4. Loading state'leri test et

**Backend response şeması değişirse:**
1. TypeScript interface'i güncelle
2. Data mapping fonksiyonlarını güncelle
3. UI render logic'i kontrol et

## 🚀 Performance Optimizasyonu
- **Lazy loading kullan**: React.lazy() ile route-based code splitting
- **Memoization**: useMemo, useCallback gereksiz re-render'ları önle
- **Image optimization**: WebP format, lazy loading
- **Bundle size kontrol et**: Gereksiz dependency ekleme
- **Debounce/Throttle**: Search input, scroll event'leri için

## 📦 Dependency Yönetimi
- **pnpm kullan** (proje standardı)
- **Güvenlik açığı kontrol et**: `pnpm audit`
- **Gereksiz paket ekleme**: Bundle size'ı şişirme
- **Version lock**: package.json'da version'ları sabitle

## 🐳 Docker Deployment
- **Build**: `pnpm build` → `build/` klasörü oluşur
- **Serve**: nginx ile static file serve edilir
- **Environment variables**: `VITE_API_URL` gibi build-time variable'lar
- **nginx.conf**: Frontend routing için fallback ayarları

## 🎯 Kod Kalitesi Standartları
- **Component isimleri PascalCase** (UserProfile, ScanResults)
- **Fonksiyon isimleri camelCase** (fetchData, handleClick)
- **Constant'lar UPPER_SNAKE_CASE** (API_BASE_URL)
- **Dosya isimleri kebab-case veya PascalCase** (scan-results.tsx)
- **Props destructure et**: `function Button({ label, onClick })` 
- **Early return kullan**: Nested if'leri azalt

## ⚠️ Yapılmaması Gerekenler
- ❌ Inline style kullanma (Tailwind kullan)
- ❌ Any type kullanma (TypeScript strict mode)
- ❌ Console.log production'da bırakma
- ❌ Hardcoded API URL (environment variable kullan)
- ❌ Gereksiz re-render (React DevTools ile kontrol et)
- ❌ Key prop eksik bırakma (list rendering'de)
- ❌ useEffect dependency array eksik bırakma

## 🎨 UI/UX Prensipleri
- **Feedback ver**: Her aksiyonda kullanıcıya geri bildirim (loading, success, error)
- **Consistent ol**: Button, input, card gibi component'ler tutarlı görünmeli
- **Hata mesajları açıklayıcı**: "Bir hata oluştu" yerine "Hedef IP adresi geçersiz"
- **Loading state'leri anlamlı**: Skeleton loader veya spinner
- **Empty state'ler**: Veri yoksa kullanıcıya ne yapması gerektiğini söyle

## 📋 Route Yapısı
```
/ → home.tsx (Ana sayfa, platform tanıtımı)
/scan → scan.tsx (Tarama başlatma formu)
/results → results.tsx (Tarama sonuçları)
```

**Yeni route eklerken:**
1. `app/routes/` altında dosya oluştur
2. `app/routes.ts` dosyasına route ekle
3. Layout'a navigation link ekle (gerekirse)

## 🔧 Development Workflow
1. **Local development**: `pnpm dev` (hot reload)
2. **Type check**: `tsc --noEmit`
3. **Build test**: `pnpm build`
4. **Docker test**: `docker-compose up --build`

---

**Not**: Frontend değişiklikleri backend API contract'ını etkilememelidir. API değişikliği gerekiyorsa önce backend ekibi ile koordine edin.
