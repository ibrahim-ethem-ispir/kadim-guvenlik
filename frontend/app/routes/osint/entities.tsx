import React, { useState } from 'react';
import { Database, Filter, ChevronLeft, ChevronRight } from 'lucide-react';
import { TipBox } from '../../components/osint/ui-components';

export default function OsintEntities() {
    const [filter, setFilter] = useState("");

    // Mock Data
    const entities = [
        { id: 1, type: "domain", value: "example.com", source: "user_input", firstSeen: "2024-05-20" },
        { id: 2, type: "ip", value: "93.184.216.34", source: "dns_scan", firstSeen: "2024-05-20" },
        { id: 3, type: "technology", value: "Nginx 1.18.0", source: "tech_detect", firstSeen: "2024-05-21" },
        { id: 4, type: "subdomain", value: "www.example.com", source: "bruteforce", firstSeen: "2024-05-21" },
        { id: 5, type: "mx_record", value: "mail.example.com", source: "dns_scan", firstSeen: "2024-05-21" },
    ];

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-end">
                <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                        <Database className="w-6 h-6 text-blue-500" /> Entity Browser
                    </h2>
                    <p className="text-slate-400">Database of all discovered OSINT entities.</p>
                </div>

                <div className="flex gap-2">
                    <input
                        type="text"
                        placeholder="Filter entities..."
                        className="bg-slate-900 border border-slate-700 rounded-md px-3 py-1.5 text-sm w-64 focus:ring-1 focus:ring-blue-500 outline-none"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                    />
                    <button className="p-1.5 bg-slate-800 rounded border border-slate-700 hover:bg-slate-700">
                        <Filter className="w-4 h-4 text-slate-400" />
                    </button>
                </div>
            </div>

            <TipBox title="Entity Database" variant="info">
                This table shows all unique entities discovered across all investigations.
                Entities are deduplicated automatically. You can start a new transformation from any entity here.
            </TipBox>

            <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
                <table className="w-full text-left text-sm">
                    <thead className="bg-slate-950 text-slate-400 uppercase text-xs font-semibold">
                        <tr>
                            <th className="px-6 py-4">Type</th>
                            <th className="px-6 py-4">Value</th>
                            <th className="px-6 py-4">Source</th>
                            <th className="px-6 py-4">First Seen</th>
                            <th className="px-6 py-4 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800">
                        {entities.map((ent) => (
                            <tr key={ent.id} className="hover:bg-slate-800/50 transition-colors">
                                <td className="px-6 py-4">
                                    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium border
                    ${ent.type === 'domain' ? 'bg-blue-900/20 text-blue-400 border-blue-900/50' :
                                            ent.type === 'ip' ? 'bg-emerald-900/20 text-emerald-400 border-emerald-900/50' :
                                                ent.type === 'vulnerability' ? 'bg-red-900/20 text-red-400 border-red-900/50' :
                                                    'bg-slate-800 text-slate-400 border-slate-700'
                                        }`}>
                                        {ent.type}
                                    </span>
                                </td>
                                <td className="px-6 py-4 font-mono text-slate-200">{ent.value}</td>
                                <td className="px-6 py-4 text-slate-500">{ent.source}</td>
                                <td className="px-6 py-4 text-slate-500">{ent.firstSeen}</td>
                                <td className="px-6 py-4 text-right">
                                    <button className="text-blue-400 hover:text-blue-300 font-medium text-xs">Analyze</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>

                {/* Pagination Placeholder */}
                <div className="p-4 border-t border-slate-800 flex justify-between items-center text-xs text-slate-500">
                    <span>Showing 1-5 of 1450</span>
                    <div className="flex gap-1">
                        <button className="p-1 hover:bg-slate-800 rounded disabled:opacity-50"><ChevronLeft className="w-4 h-4" /></button>
                        <button className="p-1 hover:bg-slate-800 rounded disabled:opacity-50"><ChevronRight className="w-4 h-4" /></button>
                    </div>
                </div>
            </div>
        </div>
    );
}
