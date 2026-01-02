import React from 'react';
import { Tab } from '../types';
import { Map, Crosshair, Wallet, Trophy, Megaphone, ShieldCheck, Users } from 'lucide-react';
import { clsx } from 'clsx';

interface NavigationProps {
    currentTab: Tab;
    onTabChange: (tab: Tab) => void;
    isAdmin?: boolean;
}

export const Navigation: React.FC<NavigationProps> = ({ currentTab, onTabChange, isAdmin }) => {
    const navItems = [
        { id: Tab.MAP, icon: Map, label: 'Home' },
        { id: Tab.HUNT, icon: Crosshair, label: 'Drop' },
        { id: Tab.LEADERBOARD, icon: Trophy, label: 'Store' },
        { id: Tab.ADS, icon: Megaphone, label: 'Wishlist' },
        { id: Tab.FRENS, icon: Users, label: 'Cart' },
        { id: Tab.WALLET, icon: Wallet, label: 'Wallet' },
        { id: Tab.ADMIN, icon: ShieldCheck, label: 'Admin' },
    ];

    const visibleItems = navItems.filter(item => item.id !== Tab.ADMIN || isAdmin);

    const handleTabClick = (id: Tab) => {
        if (id !== currentTab) {
            if (window.Telegram?.WebApp?.HapticFeedback) {
                window.Telegram.WebApp.HapticFeedback.impactOccurred('light');
            }
            onTabChange(id);
        }
    };

    return (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 w-full max-w-md px-4">
            <div className="bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 p-1 rounded-full shadow-2xl">
                <div className="bg-slate-900/90 backdrop-blur-xl rounded-full px-6 py-4 flex items-center justify-between">
                    {visibleItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = currentTab === item.id;

                        return (
                            <button
                                key={item.id}
                                onClick={() => handleTabClick(item.id)}
                                className={clsx(
                                    "flex flex-col items-center gap-1.5 px-5 py-3 rounded-full transition-all duration-300 relative",
                                    isActive && "bg-gradient-to-b from-blue-600 to-indigo-700 shadow-lg shadow-blue-500/50"
                                )}
                            >
                                {isActive && (
                                    <div className="absolute inset-0 rounded-full bg-cyan-500/20 blur-xl" />
                                )}
                                <Icon 
                                    size={22} 
                                    strokeWidth={isActive ? 2.8 : 2}
                                    className={clsx("relative z-10", isActive ? "text-white" : "text-gray-400")}
                                />
                                <span className={clsx(
                                    "text-xs font-semibold relative z-10",
                                    isActive ? "text-white" : "text-gray-500"
                                )}>
                                    {item.label}
                                </span>
                            </button>
                        );
                    })}
                </div>
            </div>
        </div>
    );
};