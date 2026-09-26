import { useState, useEffect } from 'react';
import { Zap, Gauge, Search, EyeOff } from 'lucide-react';
import type { ScanPreset } from '../types/feroxbuster';
import { PRESET_INFO } from '../types/feroxbuster';

interface ScanPresetsProps {
  value: ScanPreset;
  onChange: (preset: ScanPreset) => void;
}

const PRESET_ICONS = {
  quick: Zap,
  normal: Gauge,
  thorough: Search,
  stealth: EyeOff,
};

const PRESET_COLORS = {
  quick: 'from-yellow-500 to-orange-500',
  normal: 'from-blue-500 to-indigo-500',
  thorough: 'from-green-500 to-emerald-500',
  stealth: 'from-purple-500 to-violet-500',
};

export default function ScanPresets({ value, onChange }: ScanPresetsProps) {
  const presets: ScanPreset[] = ['quick', 'normal', 'thorough', 'stealth'];

  return (
    <div className="space-y-3">
      <label className="block text-sm font-medium text-txt-main">
        Tarama Profili
      </label>
      <div className="grid grid-cols-2 gap-3">
        {presets.map((preset) => {
          const Icon = PRESET_ICONS[preset];
          const info = PRESET_INFO[preset];
          const isSelected = value === preset;
          const gradientClass = PRESET_COLORS[preset];

          return (
            <button
              key={preset}
              type="button"
              onClick={() => onChange(preset)}
              className={`group relative p-4 rounded-xl border-2 transition-all duration-300 text-left ${
                isSelected
                  ? `bg-gradient-to-br ${gradientClass} border-transparent text-white shadow-lg shadow-${preset === 'quick' ? 'orange' : preset === 'normal' ? 'indigo' : preset === 'thorough' ? 'emerald' : 'violet'}-500/20 scale-[1.02]`
                  : 'bg-element border-brd-main hover:border-brd-strong hover:bg-hover'
              }`}
            >
              <div className="flex items-start gap-3">
                <div className={`p-2 rounded-lg ${
                  isSelected 
                    ? 'bg-white/20' 
                    : 'bg-hover group-hover:bg-element'
                }`}>
                  <Icon className={`w-5 h-5 ${
                    isSelected ? 'text-white' : 'text-txt-muted'
                  }`} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{info.icon}</span>
                    <span className={`font-semibold ${
                      isSelected ? 'text-white' : 'text-txt-main'
                    }`}>
                      {info.name}
                    </span>
                  </div>
                  <p className={`text-xs mt-1 line-clamp-2 ${
                    isSelected ? 'text-white/80' : 'text-txt-muted'
                  }`}>
                    {info.description}
                  </p>
                </div>
              </div>
              
              {/* Selection indicator */}
              {isSelected && (
                <div className="absolute top-2 right-2">
                  <div className="w-5 h-5 rounded-full bg-white/30 flex items-center justify-center">
                    <svg className="w-3 h-3 text-white" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                    </svg>
                  </div>
                </div>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}
