import React from 'react';
import { FileText } from 'lucide-react';

export default function OsintReports() {
    return (
        <div className="space-y-6">
            <div>
                <h2 className="text-2xl font-bold flex items-center gap-2 text-slate-900 dark:text-white">
                    <FileText className="w-6 h-6 text-slate-600 dark:text-slate-400" /> Generated Reports
                </h2>
                <p className="text-slate-600 dark:text-slate-400">PDF and JSON reports from past investigations.</p>
            </div>

            <div className="text-center py-12 bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-800 rounded-lg border-dashed">
                <p className="text-slate-500 dark:text-slate-500">No reports generated yet.</p>
            </div>
        </div>
    );
}
