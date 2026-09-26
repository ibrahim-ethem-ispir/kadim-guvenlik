import React from 'react';
import { History, CheckCircle, XCircle, Clock } from 'lucide-react';

export default function OsintHistory() {
    const scans = [
        { id: "scan-123", target: "target1.com", status: "completed", date: "2 minutes ago", entities: 45 },
        { id: "scan-124", target: "192.168.1.105", status: "failed", date: "1 hour ago", entities: 2 },
        { id: "scan-125", target: "test.org", status: "completed", date: "Yesterday", entities: 120 },
    ];

    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold flex items-center gap-2">
                    <History className="w-6 h-6 text-purple-500" /> Investigation History
                </h2>
                <p className="text-slate-400">Past OSINT investigations and their results.</p>
            </div>

            <div className="space-y-4">
                {scans.map((scan) => (
                    <div key={scan.id} className="bg-slate-900 border border-slate-800 rounded-lg p-4 flex items-center justify-between hover:border-slate-700 transition-colors">
                        <div className="flex items-center gap-4">
                            <div className={`p-2 rounded-full ${scan.status === 'completed' ? 'bg-emerald-900/20' : 'bg-red-900/20'}`}>
                                {scan.status === 'completed' ?
                                    <CheckCircle className="w-5 h-5 text-emerald-500" /> :
                                    <XCircle className="w-5 h-5 text-red-500" />
                                }
                            </div>
                            <div>
                                <h3 className="font-semibold text-lg">{scan.target}</h3>
                                <div className="flex items-center gap-3 text-xs text-slate-500">
                                    <span className="flex items-center gap-1"><Clock className="w-3 h-3" /> {scan.date}</span>
                                    <span>•</span>
                                    <span>{scan.entities} Entities Found</span>
                                    <span>•</span>
                                    <span className="uppercase">{scan.id}</span>
                                </div>
                            </div>
                        </div>

                        <button className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm rounded font-medium transition-colors">
                            View Report
                        </button>
                    </div>
                ))}
            </div>
        </div>
    );
}
