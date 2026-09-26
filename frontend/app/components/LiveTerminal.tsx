import { useEffect, useRef, useState } from 'react';
import { Terminal, Download, Loader2, AlertCircle } from 'lucide-react';

interface LiveTerminalProps {
  scanId: string;
  title?: string;
  onComplete?: () => void;
}

export default function LiveTerminal({ scanId, title = "Canlı Tarama Logları", onComplete }: LiveTerminalProps) {
  const [output, setOutput] = useState<string[]>([]);
  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting');
  const bottomRef = useRef<HTMLDivElement>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    // Yeni birleşik ham log endpoint'i: nmap + nuclei çıktısını tek akışta verir.
    const wsUrl = `${protocol}//${window.location.host}/api/scan/raw/${scanId}`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      setStatus('connected');
      setOutput(prev => [...prev, `📡 Canlı ham log izleme başlatıldı (${new Date().toLocaleTimeString()})`]);
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        const source = data.source ? `[${data.source.toUpperCase()}] ` : '';

        // Birleşik raw log formatı: { type, source, data, timestamp }
        if (data.type === 'output' || data.type === 'log' || data.type === 'discovery' ||
            data.type === 'progress' || data.type === 'script' || data.type === 'info' ||
            data.type === 'status' || data.type === 'finding') {

          const payload = typeof data.data === 'string' ? data.data : JSON.stringify(data.data);
          if (payload) {
            const lines = payload.split('\n').filter((l: string) => l.trim());
            setOutput(prev => [...prev, ...lines.map((l: string) => `${source}${l}`)]);
          }

        } else if (data.type === 'complete') {
          setOutput(prev => [...prev, `\n✅ Tarama tamamlandı (${new Date().toLocaleTimeString()})`,
                                      `   Kaynak: ${data.source || 'N/A'}`,
                                      `   Exit Code: ${data.exit_code || 'N/A'}`,
                                      `   Toplam Satır: ${data.total_lines || 'N/A'}`]);
          setStatus('disconnected');
          if (onComplete) onComplete();

        } else if (data.type === 'error') {
          console.error("❌ Hata mesajı:", data.message);
          setOutput(prev => [...prev, `\n❌ Hata: ${data.message}`]);
          setStatus('error');
        }
      } catch (err) {
        console.error("❌ JSON parse hatası:", err, event.data);
      }
    };

    ws.onclose = () => {
      setStatus('disconnected');
      setOutput(prev => [...prev, `\n🔌 Bağlantı kapatıldı (${new Date().toLocaleTimeString()})`]);
      if (onComplete) onComplete();
    };

    ws.onerror = (error) => {
      console.error("❌ LiveTerminal WebSocket HATA:", error);
      setStatus('error');
      setOutput(prev => [...prev, `\n⚠️ WebSocket bağlantı hatası`]);
    };

    return () => {
      ws.close();
    };
  }, [scanId]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [output]);

  const downloadLog = () => {
    window.open(`/api/nmap/logs/${scanId}`, '_blank');
  };

  return (
    <div className="bg-slate-950 rounded-xl border border-slate-800 overflow-hidden flex flex-col h-[500px]">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-slate-900 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-500" />
          <span className="text-sm font-medium text-slate-300">{title}</span>
          {status === 'connected' && (
            <span className="flex h-2 w-2 relative">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button 
            onClick={downloadLog}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-800 rounded-lg transition-colors"
            title="Log İndir"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Terminal Content */}
      <div className="flex-1 overflow-y-auto p-4 font-mono text-xs sm:text-sm space-y-1">
        {output.map((line, i) => (
          <div key={i} className="text-slate-300 whitespace-pre-wrap break-all">
            {line}
          </div>
        ))}
        
        {status === 'connecting' && (
          <div className="flex items-center gap-2 text-slate-500 italic">
            <Loader2 className="w-3 h-3 animate-spin" />
            Bağlanıyor...
          </div>
        )}
        
        {status === 'error' && (
          <div className="flex items-center gap-2 text-red-400 italic">
            <AlertCircle className="w-3 h-3" />
            Bağlantı hatası
          </div>
        )}

        <div ref={bottomRef} />
      </div>
    </div>
  );
}
