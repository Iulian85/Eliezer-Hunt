import React from 'react';
import { Tab } from '../types';
import { Home, Droplet, Store, Heart, ShoppingCart, Wallet, ShieldCheck } from 'lucide-react';
import { clsx } from 'clsx';

interface NavigationProps {
  currentTab: Tab;
  onTabChange: (tab: Tab) => void;
  isAdmin?: boolean;
  hasSale?: boolean;
  cartCount?: number;
}

export const Navigation: React.FC<NavigationProps> = ({ 
  currentTab, 
  onTabChange, 
  isAdmin = false,
  hasSale = true,
  cartCount = 1 
}) => {
  const navItems = [
    { id: Tab.MAP, icon: Home, label: 'Home' },
    { id: Tab.HUNT, icon: Droplet, label: 'Drop' },
    { id: Tab.LEADERBOARD, icon: Store, label: 'Store', hasSale },
    { id: Tab.ADS, icon: Heart, label: 'Wishlist' },
    { id: Tab.FRENS, icon: ShoppingCart, label: 'Cart', badge: cartCount },
    { id: Tab.WALLET, icon: Wallet, label: 'Wallet' },
    { id: Tab.ADMIN, icon: ShieldCheck, label: 'Admin' },
  ];

  const visibleItems = navItems.filter(item => item.id !== Tab.ADMIN || isAdmin);

  const handleTabClick = (id: Tab) => {
    if (id !== currentTab) {
      if (window.Telegram?.WebApp?.HapticFeedback) {
        window.Telegram.WebApp.HapticFeedback.impactOccurred('medium');
      }
      onTabChange(id);
    }
  };

  return (
    <div className="fixed inset-x-0 bottom-4 z-50 pointer-events-none px-4">
      <div className="pointer-events-auto mx-auto max-w-md">
        {/* Fundal gradient violet-albastru blurat */}
        <div className="absolute inset-0 bg-gradient-to-r from-purple-600 via-blue-600 to-indigo-600 rounded-full blur-3xl opacity-70 scale-110" />
        
        {/* Capsulă albă principală */}
        <nav className="relative bg-white/95 backdrop-blur-2xl rounded-full shadow-2xl py-4 px-6 flex items-center justify-between">
          {visibleItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => handleTabClick(item.id)}
                className="relative flex flex-col items-center gap-2 w-20 h-20"
              >
                {/* Bubble "strop de apă" active */}
                {isActive && (
                  <>
                    {/* Glow principal */}
                    <div className="absolute inset-0 bg-gradient-to-b from-cyan-400/80 to-blue-600/80 rounded-full shadow-2xl shadow-cyan-400/60 animate-pulse" />
                    {/* Glow extra blur */}
                    <div className="absolute -inset-4 bg-cyan-400/40 rounded-full blur-2xl animate-ping" />
                    {/* Ripple efect */}
                    <div className="absolute -inset-2 bg-cyan-300/30 rounded-full blur-xl animate-ping animation-delay-300" />
                  </>
                )}

                <div className="relative z-10 flex flex-col items-center gap-1">
                  <div className="relative">
                    <Icon 
                      size={26} 
                      strokeWidth={isActive ? 3 : 2}
                      className={clsx(
                        "drop-shadow-lg",
                        isActive ? "text-white" : "text-gray-700"
                      )}
                    />
                    
                    {/* Badge sale */}
                    {item.hasSale && (
                      <span className="absolute -top-1 -right-4 bg-red-500 text-white text-[9px] font-bold px-2 py-0.5 rounded-full uppercase shadow-md">
                        sale
                      </span>
                    )}
                    
                    {/* Badge cart */}
                    {item.badge && item.badge > 0 && (
                      <span className="absolute -top-1 -right-3 bg-orange-500 text-white text-[10px] font-bold w-5 h-5 rounded-full flex items-center justify-center shadow-md">
                        {item.badge}
                      </span>
                    )}
                  </div>
                  
                  <span className={clsx(
                    "text-xs font-bold drop-shadow",
                    isActive ? "text-white" : "text-gray-700"
                  )}>
                    {item.label}
                  </span>
                </div>
              </button>
            );
          })}
        </nav>
      </div>
    </div>
  );
};