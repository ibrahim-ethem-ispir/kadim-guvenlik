// Türkçe: Otomatik route tanımlamaları - dosya adı = route path
import { type RouteConfig, route, layout, index } from '@react-router/dev/routes';

export default [
  layout('routes/_layout.tsx', [
    index('routes/_index.tsx'),
    route('scan', 'routes/scan.tsx'),
    route('auto-scan', 'routes/auto-scan.tsx'),
    route('results', 'routes/results.tsx'),
    route('scan-history', 'routes/scan-history.tsx'),
    route('vulnerabilities', 'routes/vulnerabilities.tsx'),
    route('nmap-advanced', 'routes/nmap-advanced.tsx'),
    route('active-scans', 'routes/active-scans.tsx'),
    route('cf-analyzer', 'routes/cf-analyzer.tsx'),
    route('hash-cracker', 'routes/hash-cracker.tsx'),
    route('recon-intelligence', 'routes/recon-intelligence.tsx'),
    // Türkçe: AI Security Reports - Nessus'tan 10x daha güçlü rapor sistemi
    route('ai-reports', 'routes/ai-reports.tsx'),
    // Türkçe: Admin kullanıcı yönetimi sayfası
    route('admin/users', 'routes/admin/users.tsx'),
    // Türkçe: AI Yapılandırma sayfası (Ollama/Claude/Gemini)
    route('admin/ai-settings', 'routes/admin/ai-settings.tsx'),
    route('stress-test', 'routes/stress-test.tsx'),
    // Türkçe: Zamanlanmış Tarama Kayıtları — kullanıcının domain/IP'lerini kaydettiği,
    // tablodan "Çalıştır" ikonu ile auto-scan'e yönlendiren modül.
    route('scheduled-scans', 'routes/scheduled-scans.tsx'),

    // ai-brain
    route('ai-brain', 'routes/ai-brain.tsx'),

    layout('routes/osint/layout.tsx', [
      route('osint', 'routes/osint/_index.tsx'),
      route('osint/investigate', 'routes/osint/investigate.tsx'),
      route('osint/entities', 'routes/osint/entities.tsx'),
      route('osint/domains', 'routes/osint/domains.tsx'),
      route('osint/history', 'routes/osint/history.tsx'),
      route('osint/reports', 'routes/osint/reports.tsx'),
      route('osint/threat-intel', 'routes/osint/threat-intel.tsx'),
    ]),
  ]),
  route('login', 'routes/login.tsx'),
  route('register', 'routes/register.tsx'),
] satisfies RouteConfig;

