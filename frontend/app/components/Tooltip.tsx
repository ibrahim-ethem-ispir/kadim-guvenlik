import { useState, useRef, useEffect } from 'react';

interface TooltipProps {
    content: string | React.ReactNode;
    children?: React.ReactNode;
    position?: 'top' | 'bottom' | 'left' | 'right';
    className?: string;
}

export default function Tooltip({ content, children, position = 'top', className = '' }: TooltipProps) {
    const [isVisible, setIsVisible] = useState(false);
    const [tooltipPosition, setTooltipPosition] = useState({ top: 0, left: 0 });
    const triggerRef = useRef<HTMLDivElement>(null);
    const tooltipRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (isVisible && triggerRef.current && tooltipRef.current) {
            const triggerRect = triggerRef.current.getBoundingClientRect();
            const tooltipRect = tooltipRef.current.getBoundingClientRect();

            let top = 0;
            let left = 0;

            switch (position) {
                case 'top':
                    top = -tooltipRect.height - 8;
                    left = (triggerRect.width - tooltipRect.width) / 2;
                    break;
                case 'bottom':
                    top = triggerRect.height + 8;
                    left = (triggerRect.width - tooltipRect.width) / 2;
                    break;
                case 'left':
                    top = (triggerRect.height - tooltipRect.height) / 2;
                    left = -tooltipRect.width - 8;
                    break;
                case 'right':
                    top = (triggerRect.height - tooltipRect.height) / 2;
                    left = triggerRect.width + 8;
                    break;
            }

            setTooltipPosition({ top, left });
        }
    }, [isVisible, position]);

    return (
        <div
            ref={triggerRef}
            className={`relative inline-flex items-center ${className}`}
            onMouseEnter={() => setIsVisible(true)}
            onMouseLeave={() => setIsVisible(false)}
        >
            {children || (
                <div className="w-4 h-4 rounded-full bg-slate-700 hover:bg-slate-600 flex items-center justify-center cursor-help transition-colors border border-slate-600">
                    <span className="text-[10px] text-slate-300 font-bold">?</span>
                </div>
            )}

            {isVisible && (
                <div
                    ref={tooltipRef}
                    className="absolute z-50 pointer-events-none"
                    style={{
                        top: `${tooltipPosition.top}px`,
                        left: `${tooltipPosition.left}px`,
                    }}
                >
                    <div className="bg-slate-200 border border-slate-300 rounded-lg px-3 py-2 shadow-xl max-w-xs animate-in fade-in zoom-in-95 duration-200">
                        <div className="text-xs text-slate-900 font-medium leading-relaxed whitespace-normal">
                            {content}
                        </div>
                        {/* Arrow */}
                        <div
                            className={`absolute w-2 h-2 bg-slate-200 border-slate-300 transform rotate-45 ${position === 'top' ? 'bottom-[-5px] left-1/2 -translate-x-1/2 border-r border-b' :
                                position === 'bottom' ? 'top-[-5px] left-1/2 -translate-x-1/2 border-l border-t' :
                                    position === 'left' ? 'right-[-5px] top-1/2 -translate-y-1/2 border-t border-r' :
                                        'left-[-5px] top-1/2 -translate-y-1/2 border-b border-l'
                                }`}
                        />
                    </div>
                </div>
            )}
        </div>
    );
}
