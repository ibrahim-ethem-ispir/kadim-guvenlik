import { X, Book, Shield, AlertTriangle, Zap, Target, FileText, CheckCircle, Info } from "lucide-react";

interface NucleiGuideModalProps {
    isOpen: boolean;
    onClose: () => void;
}

export default function NucleiGuideModal({ isOpen, onClose }: NucleiGuideModalProps) {
    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/90 backdrop-blur-sm p-4 animate-in fade-in duration-200">
            <div className="bg-slate-950 border border-slate-800 rounded-2xl w-full max-w-4xl h-[85vh] flex flex-col shadow-2xl shadow-purple-900/20 overflow-hidden">

                {/* Header */}
                <div className="flex items-center justify-between p-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md">
                    <div className="flex items-center gap-4">
                        <div className="p-3 bg-purple-500/10 rounded-xl border border-purple-500/20">
                            <Book className="w-6 h-6 text-purple-500" />
                        </div>
                        <div>
                            <h2 className="text-xl font-bold text-white tracking-tight">Nuclei Kullanım Kılavuzu</h2>
                            <p className="text-sm text-slate-400">Etkili zafiyet taraması için ipuçları ve stratejiler</p>
                        </div>
                    </div>
                    <button onClick={onClose} className="p-2 hover:bg-slate-800 rounded-lg text-slate-400 hover:text-white transition-colors">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                {/* Content */}
                <div className="flex-1 overflow-y-auto p-8 space-y-10 custom-scrollbar">

                    {/* Section 1: Introduction */}
                    <section className="space-y-4">
                        <div className="flex items-center gap-3 mb-2">
                            <Shield className="w-6 h-6 text-purple-400" />
                            <h3 className="text-lg font-bold text-white">Nuclei Nedir ve Neden Kullanılır?</h3>
                        </div>
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl p-6 text-slate-300 leading-relaxed">
                            <p className="mb-4">
                                Nuclei, şablon tabanlı (template-based) çalışan, son derece hızlı ve özelleştirilebilir bir zafiyet tarayıcısıdır.
                                Geleneksel tarayıcıların aksine, Nuclei topluluk tarafından sürekli güncellenen binlerce YAML şablonunu kullanarak
                                en yeni zafiyetleri (CVE'ler), yanlış yapılandırmaları ve hassas dosyaları tespit eder.
                            </p>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                                <div className="flex items-start gap-3 p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                                    <Zap className="w-5 h-5 text-yellow-400 mt-0.5" />
                                    <div>
                                        <h4 className="font-semibold text-white text-sm">Hız ve Performans</h4>
                                        <p className="text-xs text-slate-400 mt-1">Binlerce isteği saniyeler içinde göndererek geniş kapsamlı taramalar yapabilir.</p>
                                    </div>
                                </div>
                                <div className="flex items-start gap-3 p-3 bg-slate-950/50 rounded-lg border border-slate-800/50">
                                    <FileText className="w-5 h-5 text-blue-400 mt-0.5" />
                                    <div>
                                        <h4 className="font-semibold text-white text-sm">Güncel Şablonlar</h4>
                                        <p className="text-xs text-slate-400 mt-1">Sürekli güncellenen veritabanı sayesinde 0-day zafiyetlerini bile tespit edebilir.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                    {/* Section 2: Configuration Strategies */}
                    <section className="space-y-4">
                        <div className="flex items-center gap-3 mb-2">
                            <Target className="w-6 h-6 text-emerald-400" />
                            <h3 className="text-lg font-bold text-white">Doğru Yapılandırma Stratejileri</h3>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                            {/* Severity */}
                            <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
                                <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                                    <AlertTriangle className="w-4 h-4 text-orange-400" />
                                    Severity (Önem Derecesi) Seçimi
                                </h4>
                                <ul className="space-y-3 text-sm text-slate-300">
                                    <li className="flex items-start gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-red-500 mt-2 flex-shrink-0"></span>
                                        <span><strong>Critical & High:</strong> Acil düzeltilmesi gereken, RCE veya SQLi gibi kritik açıkları tarar. İlk taramalarda mutlaka seçilmelidir.</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-yellow-500 mt-2 flex-shrink-0"></span>
                                        <span><strong>Medium & Low:</strong> Bilgi ifşası veya düşük riskli yapılandırma hatalarını bulur. Kapsamlı analiz için ekleyin.</span>
                                    </li>
                                    <li className="flex items-start gap-2">
                                        <span className="w-1.5 h-1.5 rounded-full bg-blue-500 mt-2 flex-shrink-0"></span>
                                        <span><strong>Info:</strong> Teknoloji tespiti ve versiyon bilgisi toplar. Keşif (recon) aşamasında faydalıdır.</span>
                                    </li>
                                </ul>
                            </div>

                            {/* Rate Limiting */}
                            <div className="bg-slate-900/30 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-colors">
                                <h4 className="font-semibold text-white mb-3 flex items-center gap-2">
                                    <Zap className="w-4 h-4 text-purple-400" />
                                    Rate Limit ve Timeout Ayarları
                                </h4>
                                <div className="space-y-4 text-sm text-slate-300">
                                    <div>
                                        <p className="font-medium text-white mb-1">Rate Limit (İstek Hızı)</p>
                                        <p>Varsayılan <strong>150 req/s</strong> güvenli bir başlangıçtır. WAF (Güvenlik Duvarı) olan sistemlerde bu değeri <strong>50-100</strong> arasına düşürün. WAF yoksa ve hızlı sonuç istiyorsanız <strong>500+</strong> yapabilirsiniz.</p>
                                    </div>
                                    <div>
                                        <p className="font-medium text-white mb-1">Timeout (Zaman Aşımı)</p>
                                        <p>Yavaş yanıt veren sunucular için varsayılan <strong>5 saniye</strong> yetersiz kalabilir. Yanıt alamadığınız durumlarda <strong>10-15 saniyeye</strong> çıkarın.</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </section>

                    {/* Section 3: Template Selection */}
                    <section className="space-y-4">
                        <div className="flex items-center gap-3 mb-2">
                            <FileText className="w-6 h-6 text-blue-400" />
                            <h3 className="text-lg font-bold text-white">Template ve Kategori Kullanımı</h3>
                        </div>
                        <div className="bg-slate-900/50 border border-slate-800 rounded-xl overflow-hidden">
                            <div className="p-6 border-b border-slate-800">
                                <p className="text-slate-300 text-sm leading-relaxed">
                                    Nuclei'nin en güçlü yanı, neyi tarayacağınızı tam olarak seçebilmenizdir.
                                    Tüm şablonları çalıştırmak yerine, hedefinize uygun kategorileri seçmek hem zaman kazandırır hem de daha isabetli sonuçlar verir.
                                </p>
                            </div>
                            <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-slate-800">
                                <div className="p-5">
                                    <h5 className="font-semibold text-white mb-2 text-sm">CVE Taramaları</h5>
                                    <p className="text-xs text-slate-400">Bilinen güvenlik açıklarını (CVE) tarar. Sisteminizde patchlenmemiş yazılım olup olmadığını kontrol etmek için idealdir.</p>
                                </div>
                                <div className="p-5">
                                    <h5 className="font-semibold text-white mb-2 text-sm">Misconfiguration</h5>
                                    <p className="text-xs text-slate-400">Yanlış yapılandırılmış sunucu ayarlarını, varsayılan şifreleri ve açık bırakılmış panelleri tespit eder.</p>
                                </div>
                                <div className="p-5">
                                    <h5 className="font-semibold text-white mb-2 text-sm">Exposures (İfşalar)</h5>
                                    <p className="text-xs text-slate-400">API anahtarları, tokenlar, log dosyaları ve yedek dosyaları gibi hassas verilerin ifşasını arar.</p>
                                </div>
                            </div>
                        </div>
                    </section>

                    {/* Section 4: Pro Tips */}
                    <section className="space-y-4">
                        <div className="flex items-center gap-3 mb-2">
                            <CheckCircle className="w-6 h-6 text-green-400" />
                            <h3 className="text-lg font-bold text-white">Uzman İpuçları</h3>
                        </div>
                        <div className="bg-gradient-to-br from-purple-900/20 to-slate-900/50 border border-purple-500/20 rounded-xl p-6">
                            <ul className="space-y-4">
                                <li className="flex gap-3">
                                    <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center flex-shrink-0 text-purple-400 font-bold text-xs">1</div>
                                    <div>
                                        <h5 className="text-white font-medium text-sm">Hedef Odaklı Tarama Yapın</h5>
                                        <p className="text-slate-400 text-xs mt-1">Eğer hedefiniz bir WordPress sitesi ise, sadece WordPress ile ilgili tag'leri veya şablonları seçerek gereksiz trafiği önleyin ve süreci hızlandırın.</p>
                                    </div>
                                </li>
                                <li className="flex gap-3">
                                    <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center flex-shrink-0 text-purple-400 font-bold text-xs">2</div>
                                    <div>
                                        <h5 className="text-white font-medium text-sm">False Positive (Hatalı Pozitif) Kontrolü</h5>
                                        <p className="text-slate-400 text-xs mt-1">Nuclei genellikle çok isabetlidir ancak bazen hatalı sonuç verebilir. Kritik bulguları manuel olarak doğrulamadan raporlamayın.</p>
                                    </div>
                                </li>
                                <li className="flex gap-3">
                                    <div className="w-6 h-6 rounded-full bg-purple-500/20 flex items-center justify-center flex-shrink-0 text-purple-400 font-bold text-xs">3</div>
                                    <div>
                                        <h5 className="text-white font-medium text-sm">WAF Bypass</h5>
                                        <p className="text-slate-400 text-xs mt-1">Sürekli engelleniyorsanız, Rate Limit'i düşürün ve taramayı parçalara bölün. Tek seferde tüm kategorileri taramak yerine kategori bazlı ilerleyin.</p>
                                    </div>
                                </li>
                            </ul>
                        </div>
                    </section>

                </div>

                {/* Footer */}
                <div className="p-6 border-t border-slate-800 bg-slate-900/50 backdrop-blur-md flex justify-end">
                    <button
                        onClick={onClose}
                        className="px-6 py-2.5 bg-slate-800 hover:bg-slate-700 text-white font-medium rounded-xl transition-colors"
                    >
                        Anlaşıldı, Kapat
                    </button>
                </div>
            </div>
        </div>
    );
}
