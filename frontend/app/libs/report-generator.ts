import jsPDF from 'jspdf';
import autoTable from 'jspdf-autotable';

// Define types for scan results
interface ScanResult {
    scan_id: string;
    target: string;
    timestamp?: string;
    results: {
        nmap?: {
            output?: string;
        };
        nuclei?: {
            output?: string; // This might be JSON string or raw text depending on implementation
            findings?: any[];
        };
        subfinder?: {
            subdomains?: string[];
            subdomains_count?: number;
            source_counts?: Record<string, number>;
        };
        rustscan?: {
            output?: string;
        }
    };
}

export const generateScanReport = (scanData: ScanResult) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;

    // Header
    doc.setFillColor(16, 185, 129); // Emerald 500
    doc.rect(0, 0, pageWidth, 20, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.text('Kadim Güvenlik Platformu - Güvenlik Tarama Raporu', 10, 12);

    // Meta Info
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);
    doc.text(`Hedef: ${scanData.target} `, 10, 30);
    doc.text(`Tarama ID: ${scanData.scan_id} `, 10, 36);
    doc.text(`Tarih: ${new Date().toLocaleString('tr-TR')} `, 10, 42);

    let currentY = 50;

    // 1. Nmap Results
    if (scanData.results.nmap && scanData.results.nmap.output) {
        doc.setFontSize(14);
        doc.setTextColor(16, 185, 129);
        doc.text('1. Port Tarama Sonuçları (Nmap)', 10, currentY);
        currentY += 8;

        doc.setFontSize(8);
        doc.setTextColor(0, 0, 0);
        const splitText = doc.splitTextToSize(scanData.results.nmap.output, pageWidth - 20);
        doc.text(splitText, 10, currentY);
        currentY += splitText.length * 4 + 10;
    }

    // 2. RustScan Results (if Nmap didn't catch something or as summary)
    if (scanData.results.rustscan && scanData.results.rustscan.output) {
        if (currentY + 20 > doc.internal.pageSize.height) { doc.addPage(); currentY = 20; }

        doc.setFontSize(14);
        doc.setTextColor(249, 115, 22); // Orange
        doc.text('2. Hızlı Port Tarama (RustScan)', 10, currentY);
        currentY += 8;

        doc.setFontSize(8);
        doc.setTextColor(0, 0, 0);
        const splitText = doc.splitTextToSize(scanData.results.rustscan.output, pageWidth - 20);
        doc.text(splitText, 10, currentY);
        currentY += splitText.length * 4 + 10;
    }

    // 3. Nuclei Vulnerabilities
    if (scanData.results.nuclei) {
        if (currentY + 20 > doc.internal.pageSize.height) { doc.addPage(); currentY = 20; }

        doc.setFontSize(14);
        doc.setTextColor(168, 85, 247); // Purple
        doc.text('3. Zafiyet Taraması (Nuclei)', 10, currentY);
        currentY += 10;

        // Parse Nuclei output if possible, otherwise dump text
        // Assuming we might have structured findings or just raw log
        // For now, let's try to make a table if we can parse it, or just text

        // Example: detailed findings table if available
        // For this generic impl, we'll put a placeholder table or text

        // Using autoTable for better formatting
        autoTable(doc, {
            startY: currentY,
            head: [['Bulgu', 'Önem Düzeyi', 'Detay']],
            body: [
                ['Örnek Bulgu', 'Yüksek', 'Detaylar loglarda mevcuttur.'],
            ],
            theme: 'grid',
            headStyles: { fillColor: [168, 85, 247] }
        });

        // Get final Y from table
        // @ts-ignore
        currentY = doc.lastAutoTable.finalY + 10;
    }

    // 4. Subfinder Results
    if (scanData.results.subfinder && scanData.results.subfinder.subdomains && scanData.results.subfinder.subdomains.length > 0) {
        if (currentY + 20 > doc.internal.pageSize.height) { doc.addPage(); currentY = 20; }

        doc.setFontSize(14);
        doc.setTextColor(6, 182, 212); // Cyan
        doc.text('4. Subdomain Keşfi (Subfinder)', 10, currentY);
        currentY += 8;

        doc.setFontSize(10);
        doc.setTextColor(0, 0, 0);
        doc.text(`Toplam ${scanData.results.subfinder.subdomains_count || scanData.results.subfinder.subdomains.length} subdomain bulundu:`, 10, currentY);
        currentY += 6;

        doc.setFontSize(8);
        // List subdomains (limit to prevent overflow)
        const subdomains = scanData.results.subfinder.subdomains.slice(0, 50);
        const subdomainText = subdomains.join('\n');
        const splitText = doc.splitTextToSize(subdomainText, pageWidth - 20);
        doc.text(splitText, 10, currentY);
        currentY += splitText.length * 4 + 10;

        if (scanData.results.subfinder.subdomains.length > 50) {
            doc.text(`... ve ${scanData.results.subfinder.subdomains.length - 50} subdomain daha`, 10, currentY);
            currentY += 8;
        }
    }

    // Footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFontSize(8);
        doc.setTextColor(150);
        doc.text('Kadim Güvenlik Platformu - Gizli Belge', 10, doc.internal.pageSize.height - 10);
        doc.text(`Sayfa ${i} / ${pageCount}`, pageWidth - 30, doc.internal.pageSize.height - 10);
    }

    doc.save(`tarama-raporu-${scanData.target.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.pdf`);
};

export const generateOSINTReport = (osintData: any) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;

    // Header
    doc.setFillColor(59, 130, 246); // Blue 500
    doc.rect(0, 0, pageWidth, 20, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.text('Kadim Güvenlik Platformu - OSINT İstihbarat Raporu', 10, 12);

    let currentY = 40;
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);

    // Basic Info using autoTable for kv pairs
    autoTable(doc, {
        startY: currentY,
        head: [['Alan', 'Değer']],
        body: [
            ['Hedef Domain', osintData?.domain || '-'],
            ['IP Adresi', osintData?.ip || '-'],
            ['Organizasyon', osintData?.organization || '-'],
            ['Lokasyon', `${osintData?.city || '-'}, ${osintData?.country || '-'}`],
        ],
        theme: 'striped',
        headStyles: { fillColor: [59, 130, 246] }
    });

    // @ts-ignore
    currentY = doc.lastAutoTable.finalY + 15;

    // DNS Records
    if (osintData?.dns_records) {
        doc.setFontSize(12);
        doc.text('DNS Kayıtları', 10, currentY);
        currentY += 5;

        const dnsBody = osintData.dns_records.map((r: any) => [r.type, r.value]);
        autoTable(doc, {
            startY: currentY,
            head: [['Kayıt Tipi', 'Değer']],
            body: dnsBody,
            theme: 'grid',
            // @ts-ignore
            headStyles: { fillColor: [100, 100, 100] }
        });
        // @ts-ignore
        currentY = doc.lastAutoTable.finalY + 15;
    }

    // Save
    doc.save(`osint-raporu-${osintData?.domain || 'hedef'}.pdf`);
};

export const generateHashCrackerReport = (jobData: any) => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;

    // Header
    doc.setFillColor(147, 51, 234); // Purple 600
    doc.rect(0, 0, pageWidth, 20, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(16);
    doc.text('Kadim Güvenlik Platformu - Hash Kırma Raporu', 10, 12);

    let currentY = 40;
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(10);

    // Job Info
    autoTable(doc, {
        startY: currentY,
        head: [['Parametre', 'Değer']],
        body: [
            ['Job ID', jobData.job_id || '-'],
            ['Tarih', new Date().toLocaleString('tr-TR')],
            ['Hash Türü', jobData.hash_type || 'Bilinmiyor'],
            ['Saldırı Modu', jobData.attack_mode || '-'],
            ['Hedef Hash', jobData.hash || '-']
        ],
        theme: 'striped',
        headStyles: { fillColor: [147, 51, 234] }
    });

    // @ts-ignore
    currentY = doc.lastAutoTable.finalY + 15;

    // Result
    doc.setFontSize(14);
    if (jobData.result?.found) {
        doc.setTextColor(16, 185, 129); // Green
        doc.text('SONUÇ: ŞİFRE ÇÖZÜLDÜ', 10, currentY);
        currentY += 10;

        doc.setTextColor(0, 0, 0);
        doc.setFontSize(12);
        doc.text(`Kırılan Şifre: ${jobData.result.password}`, 10, currentY);
    } else {
        doc.setTextColor(239, 68, 68); // Red
        doc.text('SONUÇ: ŞİFRE BULUNAMADI', 10, currentY);
    }

    currentY += 15;

    // Stats
    autoTable(doc, {
        startY: currentY,
        head: [['İstatistik', 'Değer']],
        body: [
            ['Deneme Sayısı', jobData.result?.attempts?.toLocaleString() || '0'],
            ['Geçen Süre', `${(jobData.result?.elapsed_ms / 1000).toFixed(2)} saniye`],
            ['Hız', `${jobData.result?.rate?.toFixed(0)} H/s`]
        ],
        theme: 'grid',
        headStyles: { fillColor: [100, 100, 100] }
    });

    // Save
    doc.save(`hash-report-${jobData.job_id.slice(0, 8)}.pdf`);
};

import type { AIAnalysisResponse } from '../types/ai';

const loadFont = async (url: string): Promise<string> => {
    const response = await fetch(url);
    const blob = await response.blob();
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result as string);
        reader.readAsDataURL(blob);
    });
};

export const generateAIAnalysisReport = async (analysis: AIAnalysisResponse, metadata: { target?: string, scanId?: string, date?: string }) => {
    const doc = new jsPDF();

    // Load Turkish capable font (Roboto)
    try {
        // Load fonts from local public directory
        // Using Roboto-Medium as 'normal' since Regular was missing, and Roboto-Bold for bold.
        const fontBaseUrl = window.location.origin + '/fonts/roboto';

        const [fontMedium, fontBold] = await Promise.all([
            loadFont(`${fontBaseUrl}/Roboto-Medium.ttf`),
            loadFont(`${fontBaseUrl}/Roboto-Bold.ttf`)
        ]);

        const mediumData = fontMedium.split(',')[1];
        const boldData = fontBold.split(',')[1];

        // Add fonts to VFS
        doc.addFileToVFS('Roboto-Medium.ttf', mediumData);
        doc.addFileToVFS('Roboto-Bold.ttf', boldData);

        // Register fonts
        // We map Medium -> Roboto normal
        doc.addFont('Roboto-Medium.ttf', 'Roboto', 'normal');
        // We map Bold -> Roboto bold
        doc.addFont('Roboto-Bold.ttf', 'Roboto', 'bold');

        doc.setFont('Roboto', 'normal');
    } catch (e) {
        console.error('Local font loading failed:', e);
    }

    const pageWidth = doc.internal.pageSize.width;
    const pageHeight = doc.internal.pageSize.height;

    // --- Header & Branding (Premium Look) ---
    // Background for header
    doc.setFillColor(30, 27, 75); // Indigo 950 (Dark theme background)
    doc.rect(0, 0, pageWidth, 40, 'F');

    // Accent line
    doc.setDrawColor(139, 92, 246); // Violet 500
    doc.setLineWidth(1);
    doc.line(0, 39, pageWidth, 39);

    // Title
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(22);
    // Note: bold font might not work if we only loaded Regular. 
    // We'll stick to 'Roboto' normal for everything to ensure char support, or load Bold too.
    // For simplicity and speed, let's use Regular with heavier weight if supported or just Regular.
    // jsPDF can fake bold but it looks bad. Let's just use the loaded font.
    doc.setFont('Roboto', 'bold');
    doc.text('GÜVENLİK ANALİZ RAPORU', 15, 20);

    doc.setFontSize(10);
    doc.setTextColor(167, 139, 250); // Violet 300
    doc.text('Yapay Zeka Destekli Değerlendirme', 15, 28);

    // Logo/Badge Placeholder (Right side)
    doc.setFillColor(139, 92, 246); // Violet 500
    doc.circle(pageWidth - 25, 20, 10, 'F');
    doc.setTextColor(255, 255, 255);
    doc.setFontSize(10);
    doc.text('AI', pageWidth - 29, 22);

    // --- Metadata Section ---
    let currentY = 55;

    // Info Cards Style using autoTable for layout
    const infoData = [
        ['HEDEF', metadata.target || 'Belirtilmedi'],
        ['TARAMA ID', metadata.scanId || '-'],
        ['TARİH', metadata.date || new Date().toLocaleString('tr-TR')],
        ['MODEL', analysis.model]
    ];

    autoTable(doc, {
        startY: currentY,
        head: [],
        body: [
            [infoData[0][0], infoData[0][1], infoData[2][0], infoData[2][1]],
            [infoData[1][0], infoData[1][1], infoData[3][0], infoData[3][1]]
        ],
        theme: 'plain',
        styles: {
            font: 'Roboto', // Important for autoTable to use the custom font
            fontSize: 9,
            cellPadding: 3,
            textColor: [50, 50, 50]
        },
        columnStyles: {
            0: { fontStyle: 'bold', textColor: [88, 28, 135] }, // Violet 900
            2: { fontStyle: 'bold', textColor: [88, 28, 135] }
        },
        didDrawCell: (data) => {
            // Add light border bottom to separate rows visually
            if (data.row.index === 0 && data.column.index === 3) {
                doc.setDrawColor(230, 230, 230);
                doc.line(15, data.cell.y + data.cell.height, pageWidth - 15, data.cell.y + data.cell.height);
            }
        }
    });

    // @ts-ignore
    currentY = doc.lastAutoTable.finalY + 15;

    // --- Executive Summary (Risk Score) ---
    // Draw Risk Circle/Badge
    const riskScore = analysis.risk_score || 0;
    let riskColor: [number, number, number] = [16, 185, 129]; // Green
    let riskText = 'DÜŞÜK RİSK';

    if (riskScore >= 80) { riskColor = [239, 68, 68]; riskText = 'KRİTİK RİSK'; }
    else if (riskScore >= 60) { riskColor = [249, 115, 22]; riskText = 'YÜKSEK RİSK'; }
    else if (riskScore >= 40) { riskColor = [234, 179, 8]; riskText = 'ORTA RİSK'; }
    else if (riskScore >= 20) { riskColor = [59, 130, 246]; riskText = 'DÜŞÜK RİSK'; }

    // Risk Box
    doc.setFillColor(...riskColor);
    doc.roundedRect(14, currentY, 40, 40, 3, 3, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFont('Roboto', 'bold'); // Ensure using supported font
    doc.setFontSize(20);
    doc.text(riskScore.toString(), 34, currentY + 18, { align: 'center' });

    doc.setFontSize(8);
    doc.text('/ 100', 34, currentY + 28, { align: 'center' });

    doc.setFontSize(9);
    doc.text(riskText, 34, currentY + 35, { align: 'center' });

    // Summary Text next to Risk Box
    doc.setFont('Roboto', 'normal');
    doc.setTextColor(30, 41, 59); // Slate 800
    doc.setFontSize(10);

    // Multi-line text handling
    const summaryWidth = pageWidth - 70;
    // Strip markdown bold markers roughly
    const cleanAnalysis = analysis.analysis.replace(/\*\*/g, '');
    // Take first paragraph or chunks for summary
    const summaryLines = doc.splitTextToSize(cleanAnalysis, summaryWidth);

    // Limit summary on first page to some lines
    const maxSummaryLines = 15;
    const firstPageSummary = summaryLines.slice(0, maxSummaryLines);

    doc.text(firstPageSummary, 60, currentY + 5);

    currentY += 50;

    // Remaining Summary if any
    if (summaryLines.length > maxSummaryLines) {
        const remainingSummary = summaryLines.slice(maxSummaryLines);
        doc.text(remainingSummary, 14, currentY);
        currentY += (remainingSummary.length * 4) + 10;
    }

    // --- Sections Helper ---
    const addSection = (title: string, items: string[], colorRGB: [number, number, number]) => {
        if (!items || items.length === 0) return;

        // Check page break
        if (currentY + 30 > pageHeight) {
            doc.addPage();
            currentY = 20;
        }

        doc.setFillColor(...colorRGB);
        doc.rect(14, currentY, 3, 6, 'F'); // Little indicator bar

        doc.setFont('Roboto', 'normal');
        doc.setFontSize(12);
        doc.setTextColor(30, 41, 59);
        doc.text(title.toUpperCase(), 20, currentY + 5);
        currentY += 10;

        items.forEach((item, index) => {
            // Check page break
            if (currentY + 10 > pageHeight) {
                doc.addPage();
                currentY = 20;
            }

            doc.setFont('Roboto', 'normal');
            doc.setFontSize(10);
            doc.setTextColor(51, 65, 85); // Slate 700

            // Bullets
            doc.setTextColor(...colorRGB);
            doc.text('•', 18, currentY);

            doc.setTextColor(51, 65, 85);
            // Wrap text
            const itemText = doc.splitTextToSize(item.replace(/\*\*/g, ''), pageWidth - 30);
            doc.text(itemText, 25, currentY);

            currentY += (itemText.length * 5) + 3;
        });

        currentY += 10; // Spacing after section
    };

    // --- Critical Findings ---
    addSection('Kritik Bulgular', analysis.critical_findings, [239, 68, 68]); // Red

    // --- Recommendations ---
    addSection('Çözüm Önerileri', analysis.recommendations, [16, 185, 129]); // Green

    // --- Next Steps ---
    addSection('Sonraki Adımlar', analysis.next_steps, [59, 130, 246]); // Blue

    // --- AI Uyum & Güvence (OWASP LLM Top-10 2025 / MITRE ATLAS / EU AI Act) ---
    // Yalnız otonom taramada AI/LLM yüzeyi bulunduysa alan dolu olur (degrade-safe).
    const _att: any = (analysis as any).compliance_attestation;
    if (_att && _att.classes) {
        const _eu: any = _att.eu_ai_act || {};
        const postureTr: Record<string, string> = {
            fail: 'UYGUNSUZLUK SİNYALİ', attention: 'DİKKAT',
            inconclusive: 'SONUÇSUZ (kapsam boşluğu)', pass: 'GEÇTİ', not_applicable: 'AI YÜZEYİ YOK',
        };
        const statusTr: Record<string, string> = {
            confirmed: 'kanıtlı', probable: 'olası', tested_clean: 'temiz',
            not_tested: 'test edilmedi', not_reachable: 'white-box', not_applicable: 'n/a',
        };
        const _rows: string[] = Object.entries(_att.classes).map(([k, c]) => {
            const cc: any = c || {};
            return `${k} ${cc.title || ''}: ${statusTr[cc.status] || cc.status || '-'}`;
        });
        addSection(`AI Uyum & Güvence — EU AI Act Art.15: ${postureTr[_eu.posture] || _eu.posture || '-'}`,
                   _rows, [139, 92, 246]); // Violet
        if (Array.isArray(_eu.gaps_not_tested) && _eu.gaps_not_tested.length) {
            addSection('Test Edilmeyen Sınıflar (Kapsam Boşluğu)',
                       _eu.gaps_not_tested.map((g: string) => `${g} — test edilmedi`), [245, 158, 11]); // Amber
        }
        if (_att.llm_confirmed === false) {
            addSection('Uyarı', ['AI/agent yolu bulundu ancak LLM doğrulanamadı — AI sınıfları test EDİLEMEDİ.'],
                       [245, 158, 11]);
        }
        const _smp: any = _att.sampling;
        if (_smp) {
            addSection('Aday Aileleri (generate-and-verify · kazanma oranı)',
                       Object.entries(_smp).map(([f, s]) => {
                           const ss: any = s || {};
                           return `${f}: %${Math.round((ss.win_rate || 0) * 100)} (${ss.wins || 0}/${ss.tried || 0})`;
                       }), [139, 92, 246]);
        }
    }

    // --- Footer ---
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
        doc.setPage(i);
        doc.setFont('Roboto', 'normal');
        doc.setFontSize(8);
        doc.setTextColor(150);
        doc.text('Kadim Güvenlik Platformu - Gizli Belge', 14, pageHeight - 10);
        doc.text(`${i} / ${pageCount}`, pageWidth - 20, pageHeight - 10);

        // Watermark style text if needed
        doc.setTextColor(240, 240, 240);
        doc.setFontSize(40);
        doc.text('GİZLİ', pageWidth / 2, pageHeight / 2, { align: 'center', angle: 45 });
    }

    const filename = `ai-analiz-${(metadata.scanId || 'report').replace(/[^a-z0-9]/gi, '_')}.pdf`;
    doc.save(filename);
};
