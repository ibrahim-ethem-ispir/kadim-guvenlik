/**
 * Feroxbuster Fuzz Service Types
 * Rust backend API ile uyumlu TypeScript type tanımları
 */

// ============================================================================
// SCAN PRESETS
// ============================================================================

export type ScanPreset = 'quick' | 'normal' | 'thorough' | 'stealth';

export const PRESET_INFO: Record<ScanPreset, { name: string; description: string; icon: string }> = {
  quick: {
    name: 'Hızlı',
    description: '20 thread, derinlik 1 - Hızlı keşif taraması',
    icon: '⚡'
  },
  normal: {
    name: 'Normal',
    description: '50 thread, derinlik 2, auto-tune - Dengeli tarama',
    icon: '⚖️'
  },
  thorough: {
    name: 'Kapsamlı',
    description: '100 thread, derinlik 4, thorough mode - Detaylı tarama',
    icon: '🔍'
  },
  stealth: {
    name: 'Gizli',
    description: '5 thread, rate-limit 10/s - Düşük profilli tarama',
    icon: '🥷'
  }
};

// ============================================================================
// SCAN CONFIGURATION
// ============================================================================

export interface ScanConfig {
  /** Thread sayısı (varsayılan: 50) */
  threads?: number;
  /** Recursion derinliği (varsayılan: 4, 0 = sınırsız) */
  depth?: number;
  /** Dosya uzantıları (.php, .txt, vb.) */
  extensions?: string[];
  /** HTTP metodları (GET, POST, vb.) */
  methods?: string[];
  /** Dahil edilecek status kodları */
  status_codes?: number[];
  /** Filtrelenecek status kodları */
  filter_status?: number[];
  /** Filtrelenecek response boyutları */
  filter_size?: number[];
  /** Filtrelenecek kelime sayıları */
  filter_words?: number[];
  /** Rate limit (istek/saniye) */
  rate_limit?: number;
  /** Hata durumunda otomatik yavaşlatma */
  auto_tune?: boolean;
  /** Çok fazla hata durumunda otomatik durdurma */
  auto_bail?: boolean;
  /** Yönlendirmeleri takip et */
  redirects?: boolean;
  /** TLS sertifika doğrulamasını atla */
  insecure?: boolean;
  /** İstek timeout'u (saniye) */
  timeout?: number;
  /** Özel HTTP başlıkları */
  headers?: string[];
  /** Recursive taramayı devre dışı bırak */
  no_recursion?: boolean;
}

// ============================================================================
// REQUEST TYPES
// ============================================================================

export interface FeroxRequest {
  /** Hedef URL */
  target: string;
  /** Benzersiz tarama ID'si */
  scan_id: string;
  /** Wordlist dosya adı */
  wordlist?: string;
  /** Preset seçimi */
  preset?: ScanPreset;
  /** Detaylı yapılandırma */
  config?: ScanConfig;
  /** OSINT zenginleştirme */
  smart_seeding?: boolean;
}

// ============================================================================
// RESPONSE TYPES
// ============================================================================

export interface StartScanResponse {
  status: string;
  scan_id: string;
  message: string;
}

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ScanResult {
  _id?: string;
  scan_id: string;
  url: string;
  original_url: string;
  status: number;
  method: string;
  content_length: number;
  word_count: number;
  line_count: number;
  content_type?: string;
  timestamp: string;
}

export interface ActiveScan {
  _id?: string;
  scan_id: string;
  target: string;
  status: ScanStatus;
  started_at: string;
  completed_at?: string;
  error?: string;
  findings_count: number;
}

// ============================================================================
// SSE EVENT TYPES
// ============================================================================

export type ScanEvent =
  | { type: 'finding'; data: ScanResult }
  | { type: 'progress'; scan_id: string; status: ScanStatus; findings_count: number }
  | { type: 'complete'; scan_id: string; status: ScanStatus; findings_count: number }
  | { type: 'error'; message: string }
  | { type: 'heartbeat' };

// ============================================================================
// WORDLIST TYPES
// ============================================================================

export interface WordlistInfo {
  filename: string;
  path: string;
  name: string;
  description: string;
  category: string;
  size_label: 'small' | 'medium' | 'large';
  size_bytes: number;
  line_count: number;
  recommended: boolean;
  tooltip?: string;
}

export interface WordlistsResponse {
  wordlists: WordlistInfo[];
  total: number;
}

// ============================================================================
// HEALTH CHECK
// ============================================================================

export interface FuzzHealthResponse {
  status: string;
  service: string;
  engine: string;
  version: string;
  mongodb: string;
}
