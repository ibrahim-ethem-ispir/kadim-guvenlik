import { useState, useEffect, useCallback, useRef } from 'react';
import type { ScanEvent, ScanStatus, ScanResult } from '../types/feroxbuster';

interface UseScanStreamOptions {
  onFinding?: (result: ScanResult) => void;
  onProgress?: (count: number, status: ScanStatus) => void;
  onComplete?: (count: number, status: ScanStatus) => void;
  onError?: (message: string) => void;
}

interface UseScanStreamReturn {
  isConnected: boolean;
  isComplete: boolean;
  findingsCount: number;
  status: ScanStatus;
  error: string | null;
  connect: (scanId: string) => void;
  disconnect: () => void;
}

/**
 * SSE hook for real-time scan updates
 * Feroxbuster Rust backend'den SSE stream dinler
 */
export function useScanStream(options: UseScanStreamOptions = {}): UseScanStreamReturn {
  const [isConnected, setIsConnected] = useState(false);
  const [isComplete, setIsComplete] = useState(false);
  const [findingsCount, setFindingsCount] = useState(0);
  const [status, setStatus] = useState<ScanStatus>('pending');
  const [error, setError] = useState<string | null>(null);
  
  const eventSourceRef = useRef<EventSource | null>(null);
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const disconnect = useCallback(() => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    setIsConnected(false);
  }, []);

  const connect = useCallback((scanId: string) => {
    // Close existing connection
    disconnect();
    
    setError(null);
    setIsComplete(false);
    setFindingsCount(0);
    setStatus('running');

    // SSE endpoint (v2 API)
    const url = `/api/fuzz/stream/${scanId}`;
    const es = new EventSource(url);
    eventSourceRef.current = es;

    es.onopen = () => {
      setIsConnected(true);
    };

    es.onerror = (e) => {
      console.error('[SSE] Connection error:', e);
      setError('Bağlantı hatası. Yeniden bağlanılıyor...');
      
      // Auto-reconnect after 3 seconds
      setTimeout(() => {
        if (eventSourceRef.current === es) {
          connect(scanId);
        }
      }, 3000);
    };

    // Handle different event types
    es.addEventListener('finding', (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data);
        if (event.type === 'finding') {
          optionsRef.current.onFinding?.(event.data);
        }
      } catch (err) {
        console.error('[SSE] Parse error:', err);
      }
    });

    es.addEventListener('progress', (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data);
        if (event.type === 'progress') {
          setFindingsCount(event.findings_count);
          setStatus(event.status);
          optionsRef.current.onProgress?.(event.findings_count, event.status);
        }
      } catch (err) {
        console.error('[SSE] Parse error:', err);
      }
    });

    es.addEventListener('complete', (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data);
        if (event.type === 'complete') {
          setFindingsCount(event.findings_count);
          setStatus(event.status);
          setIsComplete(true);
          optionsRef.current.onComplete?.(event.findings_count, event.status);
          disconnect();
        }
      } catch (err) {
        console.error('[SSE] Parse error:', err);
      }
    });

    es.addEventListener('error', (e) => {
      try {
        const event: ScanEvent = JSON.parse(e.data);
        if (event.type === 'error') {
          setError(event.message);
          optionsRef.current.onError?.(event.message);
        }
      } catch (err) {
        console.error('[SSE] Parse error:', err);
      }
    });

    es.addEventListener('heartbeat', () => {
      // Keep-alive, no action needed
    });
  }, [disconnect]);

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      disconnect();
    };
  }, [disconnect]);

  return {
    isConnected,
    isComplete,
    findingsCount,
    status,
    error,
    connect,
    disconnect,
  };
}
