import { useEffect, useRef, useState, useCallback } from 'react';

export interface ScheduleStreamEvent {
    type: 'scan_event' | 'snapshot' | 'heartbeat';
    event_type?: string;
    scan_id?: string;
    target?: string;
    schedule_id?: string;
    data?: any;
    timestamp?: string;
    active_schedules?: Array<{ schedule_id: string; target: string; label: string }>;
    server_time?: string;
}

export interface UseSchedulesStreamOptions {
    onScanCompleted?: (e: ScheduleStreamEvent) => void;
    onCriticalFinding?: (e: ScheduleStreamEvent) => void;
    onScanFailed?: (e: ScheduleStreamEvent) => void;
    onSubdomainFound?: (e: ScheduleStreamEvent) => void;
    onSnapshot?: (e: ScheduleStreamEvent) => void;
}

export function useSchedulesStream(opts: UseSchedulesStreamOptions = {}) {
    const [connected, setConnected] = useState(false);
    const [lastEvent, setLastEvent] = useState<ScheduleStreamEvent | null>(null);
    const wsRef = useRef<WebSocket | null>(null);
    const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
    const optsRef = useRef(opts);
    optsRef.current = opts;

    const connect = useCallback(() => {
        if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) return;
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const host = window.location.host;
        const url = `${proto}//${host}/api/schedules/ws/events`;
        try {
            const ws = new WebSocket(url);
            wsRef.current = ws;
            ws.onopen = () => setConnected(true);
            ws.onclose = () => {
                setConnected(false);
                // 3sn'de reconnect
                if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
                reconnectTimerRef.current = setTimeout(connect, 3000);
            };
            ws.onerror = () => { /* onclose tetiklenir */ };
            ws.onmessage = (ev) => {
                try {
                    const data: ScheduleStreamEvent = JSON.parse(ev.data);
                    setLastEvent(data);
                    if (data.type === 'scan_event') {
                        if (data.event_type === 'scan_completed') optsRef.current.onScanCompleted?.(data);
                        else if (data.event_type === 'critical_finding') optsRef.current.onCriticalFinding?.(data);
                        else if (data.event_type === 'scan_failed') optsRef.current.onScanFailed?.(data);
                        else if (data.event_type === 'subdomain_found') optsRef.current.onSubdomainFound?.(data);
                    } else if (data.type === 'snapshot') {
                        optsRef.current.onSnapshot?.(data);
                    }
                } catch (e) {
                    // ignore parse errors
                }
            };
        } catch (e) {
            if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
            reconnectTimerRef.current = setTimeout(connect, 5000);
        }
    }, []);

    useEffect(() => {
        connect();
        return () => {
            if (reconnectTimerRef.current) clearTimeout(reconnectTimerRef.current);
            if (wsRef.current) {
                wsRef.current.onclose = null;
                wsRef.current.close();
            }
        };
    }, [connect]);

    return { connected, lastEvent };
}
