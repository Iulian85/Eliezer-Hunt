import React from 'react';
import { Tab } from '../types';
import { Home, Droplet, Store, Heart, ShoppingCart, Wallet, ShieldCheck } from 'lucide-react';
import { clsx } from 'clsx';

interface NavigationProps {
  currentTab: Tab;
  onTabChange: (tab: Tab) => void;
  isAdmin?: boolean;
  hasSale?: boolean; // pentru badge "sale" pe Store
  cartCount?: number; // pentru badge număr pe Cart
}

export const Navigation: React.FC<NavigationProps> = ({ 
  currentTab, 
  onTabChange, 
  isAdmin = false,
  hasSale = true,
  cartCount = 1 
}) => {
  const navItems = [
    { id: Tab.MAP as Tab, icon: Home, label: 'Home' },
    { id: Tab.HUNT as Tab, icon: Droplet, label: 'Drop' },
    { id: Tab.LEADERBOARD as Tab, icon: Store, label: 'Store', hasSale },
    { id: Tab.ADS as Tab, icon: Heart, label: 'Wishlist' },
    { id: Tab.FRENS as Tab, icon: ShoppingCart, label: 'Cart', badge: cartCount },
    { id: Tab.WALLET as Tab, icon: Wallet, label: 'Wallet' },
    { id: Tab.ADMIN as Tab, icon: ShieldCheck, label: 'Admin' },
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
    <div className="fixed inset-x-0 bottom-6 z-50 pointer-events-none">
      <div className="pointer-events-auto mx-auto max-w-md">
        <div className="relative">
          {/* Fundal gradient violet-albastru */}
          <div className="absolute inset-0 bg-gradient-to-r from-purple-600 via-indigo-600 to-blue-600 rounded-full blur-xl opacity-80" />
          
          {/* Bară capsulă albă */}
          <nav className="relative bg-white/95 backdrop-blur-xl rounded-full shadow-2xl px-6 py-4 flex items-center justify-between">
            {visibleItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => handleTabClick(item.id)}
                  className={clsx(
                    "relative flex flex-col items-center gap-1 px-4 py-2 rounded-full transition-all duration-300",
                    isActive && "text-white"
                  )}
                >
                  {/* Bubble activ (pseudo-element simulat cu div) */}
                  {isActive && (
                    <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-indigo-700 rounded-full shadow-lg" />
                  )}
                  
                  <div className="relative z-10 flex flex-col items-center gap-1">
                    <div className="relative">
                      <Icon 
                        size={24} 
                        strokeWidth={isActive ? 2.5 : 2}
                        className={clsx(isActive ? "text-white" : "text-gray-600")}
                      />
                      
                      {/* Badge "sale" pe Store */}
                      {item.hasSale && (
                        <span className="absolute -top-1 -right-1 bg-red-500 text-white text-[9px] font-bold px-1.5 py-0.5 rounded-full">
                          sale
                        </span>
                      )}
                      
                      {/* Badge număr pe Cart */}
                      {item.badge && item.badge > 0 && (
                        <span className="absolute -top-1 -right-1 bg-orange-500 text-white text-[9px] font-bold w-4 h-4 rounded-full flex items-center justify-center">
                          {item.badge}
                        </span>
                      )}
                    </div>
                    
                    <span className={clsx(
                      "text-xs font-medium",
                      isActive ? "text-white" : "text-gray-600"
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
    </div>
  );
};