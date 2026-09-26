import React from 'react';
import { NavLink, Outlet } from 'react-router';
import {
    Globe,
    Search,
    Database,
    History,
    FileText,
    Shield,
    Skull
} from 'lucide-react';

export default function OsintLayout() {
    const navItems = [
        { to: "/osint", icon: Globe, label: "Dashboard", end: true },
        { to: "/osint/investigate", icon: Search, label: "Investigate" },
        { to: "/osint/threat-intel", icon: Skull, label: "Threat Intel" },
        { to: "/osint/entities", icon: Database, label: "Entities" },
        { to: "/osint/domains", icon: Shield, label: "Domains" },
        { to: "/osint/history", icon: History, label: "History" },
        { to: "/osint/reports", icon: FileText, label: "Reports" },
    ];


    return (
        <div className="flex flex-col h-full bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100">
            <header className="border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 px-6 py-4">
                <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-3">
                        <div className="bg-blue-600 p-2 rounded-lg">
                            <Globe className="w-6 h-6 text-white" />
                        </div>
                        <div>
                            <h1 className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-blue-600 to-cyan-500 dark:from-blue-400 dark:to-cyan-300">
                                Kadim OSINT Intelligence
                            </h1>
                            <p className="text-xs text-slate-500 dark:text-slate-400">Open Source Intelligence Platform</p>
                        </div>
                    </div>

                    <nav className="flex space-x-1">
                        {navItems.map((item) => (
                            <NavLink
                                key={item.to}
                                to={item.to}
                                end={item.end}
                                className={({ isActive }) =>
                                    `flex items-center space-x-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${isActive
                                        ? "bg-blue-600 text-white shadow-lg shadow-blue-900/20"
                                        : "text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800"
                                    }`
                                }
                            >
                                <item.icon className="w-4 h-4" />
                                <span>{item.label}</span>
                            </NavLink>
                        ))}
                    </nav>
                </div>
            </header>

            <main className="flex-1 overflow-auto p-6 bg-slate-100 dark:bg-slate-950 bg-[url('/grid-pattern.svg')] bg-fixed">
                <div className="max-w-7xl mx-auto">
                    <Outlet />
                </div>
            </main>

            {/* Footer / Status Bar could go here */}
        </div>
    );
}
