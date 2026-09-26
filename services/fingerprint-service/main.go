// Kadim Güvenlik — Parmak İzi (Fingerprint) Servisi
// ==================================================================
// Türkçe: ProjectDiscovery wappalyzergo motorunu (binlerce GÜNCEL Wappalyzer imzası) ince
// bir HTTP servisi olarak sarmalar. Amaç: elle bakımı çürüyen 142-imzalık Rust tespitini
// KİMLİK omurgasında bir "kiralık motor+veri" ile değiştirmek — bakım = `go get -u`.
//
// Tasarım:
//   - DEGRADE-SAFE: hata/erişilemezlik durumunda motoru DÜŞÜRMEZ; boş sonuç döner
//     (orchestrator tarafında mevcut Rust/header sezgisi kural-fallback olarak kalır).
//   - SPA SİNERJİSİ: `html` alanı verilirse (crawler-service'in Playwright ile render ettiği
//     DOM) doğrudan onun üstünde parmak izi çıkarır; verilmezse URL'i kendisi çeker.
//   - Tek sorumluluk: yüzeyi TANIMLAR (isim/sürüm/kategori/CPE), bulgu ÜRETMEZ.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// İstek: url VEYA html'den en az biri. html verilirse çekme atlanır (SPA render sinerjisi).
type fpRequest struct {
	URL     string              `json:"url"`
	HTML    string              `json:"html"`
	Headers map[string][]string `json:"headers"`
}

type techItem struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Categories []string `json:"categories,omitempty"`
	CPE        string   `json:"cpe,omitempty"`
	Website    string   `json:"website,omitempty"`
}

type fpResponse struct {
	Technologies []techItem `json:"technologies"`
	Count        int        `json:"count"`
	Title        string     `json:"title,omitempty"`
	Source       string     `json:"source"` // "html" | "fetch"
	FinalURL     string     `json:"final_url,omitempty"`
	Engine       string     `json:"engine"`
}

var wc *wappalyzer.Wappalyze

func main() {
	var err error
	wc, err = wappalyzer.New()
	if err != nil {
		log.Fatalf("wappalyzer init hatası: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]string{"status": "ok", "engine": "wappalyzergo"})
	})
	mux.HandleFunc("/fingerprint", handleFingerprint)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8013"
	}
	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      mux,
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 25 * time.Second,
	}
	log.Printf("fingerprint-service (wappalyzergo) dinliyor :%s", port)
	log.Fatal(srv.ListenAndServe())
}

func handleFingerprint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST gerekli", http.StatusMethodNotAllowed)
		return
	}
	var req fpRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024*1024)).Decode(&req); err != nil {
		http.Error(w, "geçersiz JSON", http.StatusBadRequest)
		return
	}

	var (
		headers  map[string][]string
		body     []byte
		source   string
		finalURL string
	)

	if strings.TrimSpace(req.HTML) != "" {
		// crawler'ın render ettiği DOM verildi → doğrudan kullan (SPA isabeti; çekme yok).
		headers = req.Headers
		if headers == nil {
			headers = map[string][]string{}
		}
		body = []byte(req.HTML)
		source = "html"
	} else {
		h, b, u, err := fetch(req.URL)
		if err != nil {
			// DEGRADE-SAFE: hedefe ulaşılamadı → boş sonuç (motor düşmez).
			log.Printf("fetch hatası (%s): %v", req.URL, err)
			writeJSON(w, fpResponse{Technologies: []techItem{}, Count: 0, Source: "fetch", Engine: "wappalyzergo"})
			return
		}
		headers, body, finalURL, source = h, b, u, "fetch"
	}

	infos := wc.FingerprintWithInfo(headers, body)
	_, title := wc.FingerprintWithTitle(headers, body)

	items := make([]techItem, 0, len(infos))
	for name, info := range infos {
		nm, ver := splitVersion(name)
		items = append(items, techItem{
			Name:       nm,
			Version:    ver,
			Categories: info.Categories,
			CPE:        info.CPE,
			Website:    info.Website,
		})
	}

	writeJSON(w, fpResponse{
		Technologies: items,
		Count:        len(items),
		Title:        strings.TrimSpace(title),
		Source:       source,
		FinalURL:     finalURL,
		Engine:       "wappalyzergo",
	})
}

// splitVersion: wappalyzergo bazı teknolojilerde sürümü anahtara "Ad:sürüm" olarak gömer.
// Sürüm rakamla başlıyorsa ayır; değilse tüm anahtar isimdir (ör. "Google Font API").
func splitVersion(key string) (string, string) {
	i := strings.LastIndex(key, ":")
	if i > 0 && i < len(key)-1 {
		suf := key[i+1:]
		if suf[0] >= '0' && suf[0] <= '9' {
			return key[:i], suf
		}
	}
	return key, ""
}

// fetch: https:// öncelikli, olmazsa http://. TLS doğrulaması kapalı (kurumsal/self-signed
// hedefler), 12sn timeout, gövde 4MB ile sınırlı (bellek koruması).
func fetch(raw string) (map[string][]string, []byte, string, error) {
	raw = strings.TrimSpace(raw)
	var candidates []string
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		candidates = []string{raw}
	} else {
		candidates = []string{"https://" + raw, "http://" + raw}
	}

	client := &http.Client{
		Timeout: 12 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	var lastErr error
	for _, u := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		// GERÇEKÇİ TARAYICI UA: aksi halde Cloudflare/WAF sunucu-taraflı isteği bot sayıp
		// "Attention Required" challenge sayfası döner → gerçek site yerine ENGEL sayfası
		// parmaklanır (yalnız Cloudflare/HTTP-3 çıkar). Gerçek Chrome UA + Accept başlıkları
		// pasif CF kontrolünü geçer. (Not: JS-render gereken SPA tespiti için ayrıca crawler
		// render-DOM'u `html` alanıyla beslenmeli — bu UA yalnız engeli aşar.)
		req.Header.Set("User-Agent",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "+
				"(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		req.Header.Set("Accept",
			"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
		req.Header.Set("Accept-Language", "tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7")
		resp, err := client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			continue
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
		resp.Body.Close()
		cancel()
		return resp.Header, data, resp.Request.URL.String(), nil
	}
	return nil, nil, "", lastErr
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
