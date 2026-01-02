import React from 'react';
import { Tab } from '../types';
import { Map, Crosshair, Wallet, Trophy, Megaphone, ShieldCheck, Users, ShoppingCart } from 'lucide-react';
import { clsx } from 'clsx';

interface NavigationProps {
    currentTab: Tab;
    onTabChange: (tab: Tab) => void;
    userWalletAddress?: string;
    isAdmin?: boolean;
}

export const Navigation: React.FC<NavigationProps> = ({ currentTab, onTabChange, userWalletAddress, isAdmin }) => {
    const navItems = [
        { id: Tab.MAP, icon: Map, label: 'Home' },
        { id: Tab.HUNT, icon: Crosshair, label: 'Drop' },
        { id: Tab.LEADERBOARD, icon: Trophy, label: 'Store' },
        { id: Tab.ADS, icon: Megaphone, label: 'Wishlist' },
        { id: Tab.FRENS, icon: Users, label: 'Cart' },
        { id: Tab.WALLET, icon: Wallet, label: 'Wallet' }, // dacă ai Wallet separat
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
        <div className="fixed bottom-4 left-1/2 -translate-x-1/2 z-50">
            <div className="bg-gradient-to-r from-purple-600 to-blue-600 p-1 rounded-full shadow-2xl">
                <div className="bg-black/80 rounded-full px-4 py-3 flex items-center justify-between gap-2">
                    {visibleItems.map((item) => {
                        const Icon = item.icon;
                        const isActive = currentTab === item.id;

                        return (
                            <button
                                key={item.id}
                                onClick={() => handleTabClick(item.id)}
                                className={clsx(
                                    "flex flex-col items-center justify-center gap-1 px-4 py-2 rounded-full transition-all duration-300 min-w-16",
                                    isActive && "bg-gradient-to-r from-blue-500 to-purple-500 text-white shadow-lg"
                                )}
                            >
                                <Icon 
                                    size={20} 
                                    strokeWidth={isActive ? 2.5 : 2}
                                    className={clsx(isActive ? "text-white" : "text-gray-400")}
                                />
                                <span className={clsx(
                                    "text-xs font-medium",
                                    isActive ? "text-white" : "text-gray-400"
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