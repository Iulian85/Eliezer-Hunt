import React, { useState, useEffect, useRef } from 'react';
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
  const [activePosition, setActivePosition] = useState({ x: 0, width: 0 });
  const navRef = useRef<HTMLDivElement>(null);
  const itemRefs = useRef<Record<string, HTMLButtonElement>>({});

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

  // Efect pentru calcularea poziției și dimensiunii indicatorului
  useEffect(() => {
    const updateIndicatorPosition = () => {
      const activeItem = itemRefs.current[currentTab];
      if (activeItem && navRef.current) {
        const navRect = navRef.current.getBoundingClientRect();
        const itemRect = activeItem.getBoundingClientRect();
        
        // Calculăm poziția relativă în interiorul containerului
        const x = itemRect.left - navRect.left;
        const width = itemRect.width;
        
        setActivePosition({ x, width });
      }
    };

    updateIndicatorPosition();
    
    // Recalculăm la redimensionarea ferestrei
    window.addEventListener('resize', updateIndicatorPosition);
    return () => window.removeEventListener('resize', updateIndicatorPosition);
  }, [currentTab, visibleItems]);

  const handleTabClick = (id: Tab) => {
    if (id !== currentTab) {
      if (window.Telegram?.WebApp?.HapticFeedback) {
        window.Telegram.WebApp.HapticFeedback.impactOccurred('light');
      }
      onTabChange(id);
    }
  };

  return (
    <div className="fixed inset-x-0 bottom-6 z-50 pointer-events-none px-4">
      <div className="pointer-events-auto mx-auto max-w-md">
        {/* Fundal blurat */}
        <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-600 rounded-full blur-3xl opacity-60" />
        
        {/* Container principal cu efect lichid */}
        <div className="relative bg-gradient-to-r from-purple-50 to-blue-50 rounded-full shadow-2xl py-2 px-6">
          {/* Indicator lichid - se mișcă între tab-uri */}
          <div
            className="absolute top-1/2 -translate-y-1/2 h-[85%] bg-gradient-to-r from-purple-600 via-blue-500 to-indigo-600 rounded-full transition-all duration-500 ease-out"
            style={{
              left: `${activePosition.x}px`,
              width: `${activePosition.width}px`,
              filter: 'drop-shadow(0 4px 6px rgba(99, 102, 241, 0.3))',
            }}
          />
          
          {/* Efect de reflectare pe indicator */}
          <div
            className="absolute top-1/2 -translate-y-1/2 h-[60%] w-[70%] bg-gradient-to-t from-white/30 to-transparent rounded-full transition-all duration-500 ease-out pointer-events-none"
            style={{
              left: `${activePosition.x + activePosition.width * 0.15}px`,
              width: `${activePosition.width * 0.7}px`,
            }}
          />
          
          {/* Container pentru item-uri */}
          <nav 
            ref={navRef}
            className="relative flex items-center justify-between gap-2 py-1"
          >
            {visibleItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;

              return (
                <button
                  key={item.id}
                  ref={(el) => {
                    if (el) {
                      itemRefs.current[item.id] = el;
                    }
                  }}
                  onClick={() => handleTabClick(item.id)}
                  className="relative flex-1 min-w-0 flex flex-col items-center gap-1.5 py-2 px-1 rounded-full transition-all duration-300 z-10"
                >
                  <div className="relative z-20 flex flex-col items-center gap-1">
                    <div className="relative">
                      <Icon 
                        size={22} 
                        strokeWidth={isActive ? 2.5 : 2}
                        className={clsx(
                          "transition-all duration-300",
                          isActive 
                            ? "text-white drop-shadow-md" 
                            : "text-gray-600 hover:text-gray-900"
                        )}
                      />
                      
                      {/* Badge sale */}
                      {item.hasSale && (
                        <span className={clsx(
                          "absolute -top-1.5 -right-2.5 text-white text-[7px] font-bold px-1.5 py-0.5 rounded-full uppercase shadow-md transition-all duration-300",
                          isActive 
                            ? "bg-red-400" 
                            : "bg-red-500"
                        )}>
                          sale
                        </span>
                      )}
                      
                      {/* Badge cart */}
                      {item.badge && item.badge > 0 && (
                        <span className={clsx(
                          "absolute -top-1.5 -right-2.5 text-white text-[8px] font-bold w-4 h-4 rounded-full flex items-center justify-center shadow-md transition-all duration-300",
                          isActive 
                            ? "bg-orange-400" 
                            : "bg-orange-500"
                        )}>
                          {item.badge}
                        </span>
                      )}
                    </div>
                    
                    <span className={clsx(
                      "text-xs font-medium transition-all duration-300",
                      isActive 
                        ? "text-white drop-shadow-md" 
                        : "text-gray-600 hover:text-gray-900"
                    )}>
                      {item.label}
                    </span>
                  </div>
                  
                  {/* Efect de hover - mic glow */}
                  <div className={clsx(
                    "absolute inset-0 rounded-full opacity-0 transition-opacity duration-300",
                    isActive 
                      ? "opacity-100 bg-gradient-to-r from-purple-500/10 to-blue-500/10" 
                      : "hover:opacity-100 hover:bg-gray-200/30"
                  )} />
                </button>
              );
            })}
          </nav>
        </div>
        
        {/* Umbra subtilă dedesubt */}
        <div className="absolute -bottom-2 inset-x-6 h-4 bg-gradient-to-t from-purple-200/50 to-transparent blur-md rounded-full" />
      </div>
    </div>
  );
};