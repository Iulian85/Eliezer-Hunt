import React, { useState, useEffect } from 'react';
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
  const [activePosition, setActivePosition] = useState({ 
    left: '0%', 
    bubbleLeft: '-5%',
    bubbleRight: '15%',
    bottomLeft: '-10%'
  });

  const navItems = [
    { id: Tab.MAP, icon: Home, label: 'Home', accentColor: '#FF5342' },
    { id: Tab.HUNT, icon: Droplet, label: 'Drop', accentColor: '#FF7779' },
    { id: Tab.LEADERBOARD, icon: Store, label: 'Store', accentColor: '#BABC53', hasSale },
    { id: Tab.ADS, icon: Heart, label: 'Wishlist', accentColor: '#EBDD4D' },
    { id: Tab.FRENS, icon: ShoppingCart, label: 'Cart', accentColor: '#BB6DE0', badge: cartCount },
    { id: Tab.WALLET, icon: Wallet, label: 'Wallet', accentColor: '#5352ED' },
    { id: Tab.ADMIN, icon: ShieldCheck, label: 'Admin', accentColor: '#6C5CE7' },
  ];

  const visibleItems = navItems.filter(item => item.id !== Tab.ADMIN || isAdmin);
  const itemCount = visibleItems.length;
  const activeIndex = visibleItems.findIndex(item => item.id === currentTab);
  const activeItem = visibleItems[activeIndex];

  useEffect(() => {
    const percentagePerItem = 100 / itemCount;
    const left = percentagePerItem * activeIndex;
    
    setActivePosition({
      left: `${left}%`,
      bubbleLeft: `${left - 5}%`,
      bubbleRight: `${left + percentagePerItem - 5}%`,
      bottomLeft: `${left - 10}%`
    });
  }, [currentTab, visibleItems, itemCount, activeIndex]);

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
        {/* Fundal blurat - păstrat din codul tău original */}
        <div className="absolute inset-0 bg-gradient-to-r from-purple-600 to-blue-600 rounded-full blur-3xl opacity-60" />
        
        {/* Container principal cu efect lichid EXACT ca în HTML/CSS */}
        <div className="relative bg-gradient-to-br from-cyan-50 to-blue-50 rounded-[40px] shadow-2xl shadow-blue-900/20 p-2 overflow-hidden">
          
          {/* EFECT LICHID - implementat din HTML/CSS */}
          <div className="absolute inset-0 overflow-hidden">
            {/* Forma lichidă principală */}
            <div 
              className="absolute h-full transition-all duration-300 ease-out z-0"
              style={{
                left: activePosition.left,
                width: `${100 / itemCount}%`,
                backgroundColor: activeItem?.accentColor || '#5352ED',
                borderRadius: '30px 30px 0 0',
              }}
            />
            
            {/* Partea rotunjită stânga */}
            <div 
              className="absolute h-full w-[30px] bg-[#77f7ff] transition-all duration-300 ease-out z-10"
              style={{
                left: activePosition.bubbleLeft,
                top: '1px',
                borderBottomRightRadius: '30px',
              }}
            />
            
            {/* Partea rotunjită dreapta */}
            <div 
              className="absolute h-full w-[30px] bg-[#77f7ff] transition-all duration-300 ease-out z-10"
              style={{
                left: activePosition.bubbleRight,
                top: '1px',
                borderBottomLeftRadius: '30px',
              }}
            />
            
            {/* Partea inferioară lichidă */}
            <div 
              className="absolute w-[100px] h-[40px] bottom-0 transition-all duration-300 ease-out z-0"
              style={{
                left: activePosition.bottomLeft,
                backgroundColor: activeItem?.accentColor || '#5352ED',
                borderRadius: '0 0 10px 10px',
              }}
            />
          </div>

          {/* Butoanele - păstrate din structura ta */}
          <nav className="relative flex items-center justify-between gap-1 py-1 z-20">
            {visibleItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;

              return (
                <button
                  key={item.id}
                  onClick={() => handleTabClick(item.id)}
                  className={clsx(
                    "relative flex-1 min-w-0 flex flex-col-reverse items-center justify-center",
                    "w-16 h-16 p-2 transition-all duration-300 ease-out",
                    "hover:text-[#5352ed] focus:outline-none",
                    isActive ? "text-[#77f7ff]" : "text-[#253542]"
                  )}
                  style={{
                    zIndex: isActive ? 2 : 1,
                  }}
                >
                  {/* Text label */}
                  <span className="text-[10px] leading-[3] font-medium">
                    {item.label}
                  </span>
                  
                  {/* Icon */}
                  <Icon 
                    size={20} 
                    strokeWidth={isActive ? 2.5 : 2}
                    className={clsx(
                      isActive ? "drop-shadow-md" : ""
                    )}
                  />
                  
                  {/* Badge sale - păstrat din original */}
                  {item.hasSale && (
                    <span className={clsx(
                      "absolute top-1 right-1 max-w-[25px] h-[15px] px-1.5",
                      "flex items-center justify-center text-[9px] font-bold",
                      "rounded-[3px] transition-all duration-300 z-20",
                      isActive 
                        ? "text-[#77f7ff] bg-[#ff6b91]" 
                        : "text-[#ff6b91] bg-[#ff6b91]/20"
                    )}>
                      sale
                    </span>
                  )}
                  
                  {/* Badge cart - păstrat din original */}
                  {item.badge && item.badge > 0 && (
                    <span className={clsx(
                      "absolute top-1 right-2 w-4 h-4",
                      "flex items-center justify-center text-[9px] font-bold",
                      "rounded-full transition-all duration-300 z-20",
                      isActive 
                        ? "text-[#77f7ff] bg-orange-500" 
                        : "text-white bg-orange-500"
                    )}>
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>
        
        {/* Umbra din codul original */}
        <div className="absolute -bottom-2 inset-x-6 h-4 bg-gradient-to-t from-purple-200/50 to-transparent blur-md rounded-full" />
      </div>
    </div>
  );
};