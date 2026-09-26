import React from 'react';
import { Info, HelpCircle, AlertTriangle, Lightbulb } from 'lucide-react';

export function TipBox({ title, children, variant = 'info' }: { title?: string, children: React.ReactNode, variant?: 'info' | 'tip' | 'warning' }) {
    const styles = {
        info: {
            bg: "bg-blue-100 dark:bg-blue-950/30",
            border: "border-blue-300 dark:border-blue-800/50",
            text: "text-blue-800 dark:text-blue-200",
            icon: <Info className="w-5 h-5 text-blue-400" />
        },
        tip: {
            bg: "bg-emerald-100 dark:bg-emerald-950/30",
            border: "border-emerald-300 dark:border-emerald-800/50",
            text: "text-emerald-800 dark:text-emerald-200",
            icon: <Lightbulb className="w-5 h-5 text-emerald-400" />
        },
        warning: {
            bg: "bg-amber-100 dark:bg-amber-950/30",
            border: "border-amber-300 dark:border-amber-800/50",
            text: "text-amber-800 dark:text-amber-200",
            icon: <AlertTriangle className="w-5 h-5 text-amber-400" />
        }
    };

    const style = styles[variant];

    return (
        <div className={`p-4 rounded-lg border ${style.bg} ${style.border} ${style.text} mb-4`}>
            <div className="flex items-start gap-3">
                <div className="mt-0.5 shrink-0">{style.icon}</div>
                <div>
                    {title && <h4 className="font-semibold mb-1">{title}</h4>}
                    <div className="text-sm opacity-90 leading-relaxed">
                        {children}
                    </div>
                </div>
            </div>
        </div>
    );
}

export function InfoCard({ label, value, icon: Icon, subtext }: { label: string, value: string | number | null, icon?: React.ElementType, subtext?: string }) {
    return (
        <div className="bg-white dark:bg-slate-900/50 border border-slate-200 dark:border-slate-800 p-4 rounded-lg hover:border-slate-300 dark:hover:border-slate-700 transition-colors group">
            <div className="flex items-center justify-between mb-2">
                <span className="text-slate-400 text-xs font-medium uppercase tracking-wider">{label}</span>
                {Icon && <Icon className="w-4 h-4 text-slate-500 group-hover:text-blue-400 transition-colors" />}
            </div>
            <div className="font-mono text-lg text-slate-900 dark:text-white truncate" title={String(value)}>
                {value || <span className="text-slate-400 dark:text-slate-600">-</span>}
            </div>
            {subtext && <div className="text-xs text-slate-500 mt-1">{subtext}</div>}
        </div>
    );
}
