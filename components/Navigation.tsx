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
  const [indicatorStyle, setIndicatorStyle] = useState({ left: '0%', width: '14.285%' });
  const [isAnimating, setIsAnimating] = useState(false);
  const navRef = useRef<HTMLDivElement>(null);
  const blobRef = useRef<HTMLDivElement>(null);

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
  const itemCount = visibleItems.length;

  // Efect pentru calcularea poziției indicatorului lichid
  useEffect(() => {
    const updateIndicatorPosition = () => {
      const index = visibleItems.findIndex(item => item.id === currentTab);
      if (index !== -1 && navRef.current) {
        const percentagePerItem = 100 / itemCount;
        const left = percentagePerItem * index;
        
        setIsAnimating(true);
        setIndicatorStyle({
          left: `${left}%`,
          width: `${percentagePerItem}%`
        });

        // Animație blob liquid
        if (blobRef.current) {
          blobRef.current.style.transition = 'all 0.6s cubic-bezier(0.34, 1.56, 0.64, 1)';
        }

        // Reset animație
        setTimeout(() => setIsAnimating(false), 600);
      }
    };

    updateIndicatorPosition();
    window.addEventListener('resize', updateIndicatorPosition);
    return () => window.removeEventListener('resize', updateIndicatorPosition);
  }, [currentTab, visibleItems, itemCount]);

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
        {/* Container principal cu efect glassmorphism */}
        <div className="relative bg-white/80 backdrop-blur-xl rounded-3xl shadow-2xl shadow-purple-900/20 border border-white/40">
          {/* Efectul lichid blurat principal - BLOB ORGANIC */}
          <div
            ref={blobRef}
            className="absolute top-1/2 -translate-y-1/2 h-[110%] rounded-[30px] transition-all duration-600 ease-out-back"
            style={{
              left: indicatorStyle.left,
              width: indicatorStyle.width,
              // Gradient lichid din poza
              background: 'linear-gradient(90deg, rgba(147, 51, 234, 0.7) 0%, rgba(59, 130, 246, 0.7) 100%)',
              // Blur intens ca în poză
              filter: 'blur(12px)',
              // Margini organice
              borderRadius: '30px',
              // Umbra interioară pentru efect 3D
              boxShadow: `
                inset 0 4px 20px rgba(255, 255, 255, 0.4),
                inset 0 -2px 10px rgba(0, 0, 0, 0.1),
                0 8px 32px rgba(147, 51, 234, 0.3)
              `,
              // Efect de undă/animație
              transform: isAnimating ? 'scale(1.05, 1.1)' : 'scale(1, 1)',
            }}
          >
            {/* Efect de lumină/reflectare pe blob */}
            <div
              className="absolute inset-0 rounded-[30px] opacity-50"
              style={{
                background: 'linear-gradient(180deg, rgba(255,255,255,0.4) 0%, rgba(255,255,255,0) 60%)',
                mixBlendMode: 'overlay',
              }}
            />
          </div>

          {/* Container pentru butoane */}
          <nav 
            ref={navRef}
            className="relative flex items-center justify-between gap-1 py-3 px-2 z-10"
          >
            {visibleItems.map((item) => {
              const Icon = item.icon;
              const isActive = currentTab === item.id;
              const index = visibleItems.findIndex(i => i.id === item.id);
              const isLeftOfActive = index < visibleItems.findIndex(i => i.id === currentTab);
              const isRightOfActive = index > visibleItems.findIndex(i => i.id === currentTab);

              return (
                <button
                  key={item.id}
                  onClick={() => handleTabClick(item.id)}
                  className={clsx(
                    "relative flex-1 min-w-0 flex flex-col items-center gap-1 py-2 px-1 rounded-2xl",
                    "transition-all duration-300 z-20",
                    isActive 
                      ? "transform scale-105" 
                      : "hover:scale-95 hover:bg-white/30 active:scale-90"
                  )}
                >
                  {/* Iconiță */}
                  <div className="relative">
                    <Icon 
                      size={22} 
                      strokeWidth={isActive ? 2.5 : 2}
                      className={clsx(
                        "transition-all duration-300 relative z-10",
                        isActive 
                          ? "text-white drop-shadow-lg" 
                          : "text-gray-600"
                      )}
                      style={{
                        filter: isActive ? 'drop-shadow(0 2px 4px rgba(0,0,0,0.2))' : 'none',
                      }}
                    />
                    
                    {/* Efect de lumină pe iconiță când e activă */}
                    {isActive && (
                      <div className="absolute inset-0 flex items-center justify-center">
                        <Icon 
                          size={22}
                          strokeWidth={2.5}
                          className="text-white/30 blur-[2px] absolute"
                        />
                      </div>
                    )}
                    
                    {/* Badge sale */}
                    {item.hasSale && (
                      <span className={clsx(
                        "absolute -top-2 -right-2 text-white text-[8px] font-bold px-1.5 py-0.5 rounded-full uppercase",
                        "shadow-lg transition-all duration-300 z-20",
                        isActive 
                          ? "bg-red-400 scale-110" 
                          : "bg-red-500 hover:scale-110"
                      )}>
                        sale
                      </span>
                    )}
                    
                    {/* Badge cart */}
                    {item.badge && item.badge > 0 && (
                      <span className={clsx(
                        "absolute -top-2 -right-2 text-white text-[9px] font-bold w-5 h-5 rounded-full",
                        "flex items-center justify-center shadow-lg transition-all duration-300 z-20",
                        isActive 
                          ? "bg-orange-400 scale-110" 
                          : "bg-orange-500 hover:scale-110"
                      )}>
                        {item.badge}
                      </span>
                    )}
                  </div>
                  
                  {/* Text */}
                  <span className={clsx(
                    "text-xs font-semibold transition-all duration-300 relative z-10",
                    isActive 
                      ? "text-white drop-shadow-md" 
                      : "text-gray-600"
                  )}>
                    {item.label}
                  </span>

                  {/* Efect de undă la click */}
                  {isActive && (
                    <div className="absolute inset-0 rounded-2xl overflow-hidden">
                      <div 
                        className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent"
                        style={{
                          animation: 'wave 2s linear infinite',
                        }}
                      />
                    </div>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Efect de umbră dinamică sub blob */}
          <div 
            className="absolute -bottom-3 left-0 right-0 h-4 blur-md transition-all duration-600"
            style={{
              left: indicatorStyle.left,
              width: indicatorStyle.width,
              background: 'radial-gradient(ellipse at center, rgba(147, 51, 234, 0.4) 0%, transparent 70%)',
              transform: 'translateY(50%)',
            }}
          />
        </div>
      </div>

      {/* Stiluri CSS pentru animația de undă */}
      <style jsx>{`
        @keyframes wave {
          0% {
            transform: translateX(-100%);
          }
          100% {
            transform: translateX(100%);
          }
        }
        
        .ease-out-back {
          animation-timing-function: cubic-bezier(0.34, 1.56, 0.64, 1);
        }
      `}</style>
    </div>
  );
};