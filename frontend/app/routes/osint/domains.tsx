import React from 'react';
import { Shield, Plus } from 'lucide-react';
import { TipBox } from '../../components/osint/ui-components';

export default function OsintDomains() {
    return (
        <div className="space-y-6">
            <div className="flex justify-between items-start">
                <div>
                    <h2 className="text-2xl font-bold flex items-center gap-2">
                        <Shield className="w-6 h-6 text-emerald-500" /> Managed Domains
                    </h2>
                    <p className="text-slate-400">Tracked organizations and their attack surface.</p>
                </div>
                <button className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg flex items-center gap-2 font-medium">
                    <Plus className="w-4 h-4" /> Add Domain
                </button>
            </div>

            <TipBox title="Continuous Monitoring" variant="tip">
                Domains added here are automatically scanned according to the schedule.
                You will be alerted if new subdomains, open ports, or vulnerabilities are detected.
            </TipBox>

            <div className="text-center py-12 bg-slate-900 border border-slate-800 rounded-lg border-dashed">
                <p className="text-slate-500">No domains currently tracked.</p>
                <button className="mt-4 text-emerald-400 hover:underline">Add your first organization</button>
            </div>
        </div>
    );
}
