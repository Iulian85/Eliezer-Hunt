import React, { useState, useEffect, useRef } from 'react';
import { Tab } from '../types';
import React, { useState } from 'react';
import { Home, Droplet, Store, Heart, ShoppingCart } from 'lucide-react';
import { clsx } from 'clsx';

type Tab = 'home' | 'drop' | 'store' | 'wishlist' | 'cart';

interface NavigationProps {
  currentTab: Tab;
  onTabChange: (tab: Tab) => void;
  hasSale?: boolean;
  cartCount?: number;
}

export const LiquidNavigation: React.FC<NavigationProps> = ({
  currentTab,
  onTabChange,
  hasSale = true,
  cartCount = 1,
}) => {
  const navItems = [
    { 
      id: 'home' as Tab, 
      icon: Home, 
      label: 'Home', 
      accentColor: '#FF5342' 
    },
    { 
      id: 'drop' as Tab, 
      icon: Droplet, 
      label: 'Drop', 
      accentColor: '#FF7779' 
    },
    { 
      id: 'store' as Tab, 
      icon: Store, 
      label: 'Store', 
      accentColor: '#BABC53',
      hasSale 
    },
    { 
      id: 'wishlist' as Tab, 
      icon: Heart, 
      label: 'Wishlist', 
      accentColor: '#EBDD4D' 
    },
    { 
      id: 'cart' as Tab, 
      icon: ShoppingCart, 
      label: 'Cart', 
      accentColor: '#BB6DE0',
      badge: cartCount 
    },
  ];

  const handleClick = (id: Tab) => {
    if (id !== currentTab) {
      onTabChange(id);
    }
  };

  const activeIndex = navItems.findIndex(item => item.id === currentTab);
  const activeItem = navItems[activeIndex];

  return (
    <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50">
      {/* Container principal - fundal blurat */}
      <nav className="relative bg-gradient-to-br from-cyan-50 to-blue-50 w-[456px] mx-auto p-2 rounded-[40px] shadow-2xl shadow-blue-900/20 overflow-hidden">
        
        {/* Efectul lichid - implementat cu pseudo-elemente Tailwind */}
        <div className="absolute inset-0 overflow-hidden">
          {/* Forma lichidă principală */}
          <div 
            className="absolute transition-all duration-300 ease-out"
            style={{
              left: `${activeIndex * 20}%`,
              width: '20%',
              height: '100%',
              backgroundColor: activeItem.accentColor,
              borderRadius: '30px 30px 0 0',
              transform: 'translateY(0)',
              zIndex: 0,
            }}
          />
          
          {/* Partea rotunjită stânga */}
          <div 
            className="absolute transition-all duration-300 ease-out"
            style={{
              left: `${activeIndex * 20 - 5}%`,
              width: '30px',
              height: '100%',
              backgroundColor: '#77f7ff',
              borderBottomRightRadius: '30px',
              top: '1px',
              zIndex: 1,
            }}
          />
          
          {/* Partea rotunjită dreapta */}
          <div 
            className="absolute transition-all duration-300 ease-out"
            style={{
              left: `${activeIndex * 20 + 20 - 5}%`,
              width: '30px',
              height: '100%',
              backgroundColor: '#77f7ff',
              borderBottomLeftRadius: '30px',
              top: '1px',
              zIndex: 1,
            }}
          />
          
          {/* Partea inferioară a efectului lichid */}
          <div 
            className="absolute transition-all duration-300 ease-out"
            style={{
              left: `${activeIndex * 20 - 10}%`,
              width: '100px',
              height: '40px',
              backgroundColor: activeItem.accentColor,
              bottom: 0,
              borderRadius: '0 0 10px 10px',
              transform: 'translateY(0)',
              zIndex: 0,
            }}
          />
        </div>

        {/* Lista de butoane */}
        <ul className="relative flex items-center z-10">
          {navItems.map((item, index) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;
            
            return (
              <li key={item.id} className="relative flex-1">
                <button
                  onClick={() => handleClick(item.id)}
                  className={clsx(
                    "relative flex flex-col-reverse items-center justify-center",
                    "w-20 h-20 p-4 transition-all duration-300 ease-out",
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
                  <Icon size={24} strokeWidth={isActive ? 2.5 : 2} />
                  
                  {/* Badge sale */}
                  {item.hasSale && (
                    <span className={clsx(
                      "absolute top-2 right-2 max-w-[25px] h-[15px] px-1.5",
                      "flex items-center justify-center text-[10px] font-bold",
                      "rounded-[3px] transition-all duration-300 z-20",
                      isActive 
                        ? "text-[#77f7ff] bg-[#ff6b91]" 
                        : "text-[#ff6b91] bg-[#ff6b91]/20"
                    )}>
                      sale
                    </span>
                  )}
                  
                  {/* Badge cart */}
                  {item.badge && item.badge > 0 && (
                    <span className={clsx(
                      "absolute top-2 right-3 max-w-[25px] h-[15px] px-1.5",
                      "flex items-center justify-center text-[10px] font-bold",
                      "rounded-[3px] transition-all duration-300 z-20",
                      isActive 
                        ? "text-[#77f7ff] bg-[#ffa502]" 
                        : "text-[#ffa502] bg-[#ffa502]/20"
                    )}>
                      {item.badge}
                    </span>
                  )}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Stiluri CSS pentru animații specifice */}
      <style jsx>{`
        @keyframes liquidRise {
          0% {
            transform: translateY(15px);
            border-radius: 10px 10px 0 0;
          }
          100% {
            transform: translateY(0);
            border-radius: 30px 30px 0 0;
          }
        }
        
        .liquid-enter {
          animation: liquidRise 0.3s ease-out forwards;
        }
        
        /* Stiluri pentru elementele pseudo - Tailwind nu suportă pseudo-elemente dinamice */
        nav::before {
          content: '';
          position: absolute;
          height: 100%;
          width: 30px;
          top: 25px;
          transition: top 0.3s;
        }
      `}</style>
    </div>
  );
};