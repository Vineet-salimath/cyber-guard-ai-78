import { cn } from "@/lib/utils";

interface LogoProps {
  className?: string;
  variant?: "default" | "icon" | "full";
  animated?: boolean;
}

export const MalwareSnipperLogo = ({ 
  className, 
  variant = "default",
  animated = false 
}: LogoProps) => {
  if (variant === "icon") {
    return (
      <svg
        viewBox="0 0 48 48"
        className={cn("w-8 h-8", animated && "animate-pulse", className)}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="premium-shield" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="50%" stopColor="#1e40af" />
            <stop offset="100%" stopColor="#0c4a6e" />
          </linearGradient>
          <linearGradient id="glow-effect" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#60a5fa" />
            <stop offset="100%" stopColor="#3b82f6" />
          </linearGradient>
          <filter id="shadow-glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
        
        {/* Outer Shield Layer - Glowing */}
        <path
          d="M24 2L6 9V18C6 30 14 40 24 45C34 40 42 30 42 18V9L24 2Z"
          fill="url(#premium-shield)"
          opacity="0.2"
          filter="url(#shadow-glow)"
        />
        
        {/* Outer Shield Border */}
        <path
          d="M24 2L6 9V18C6 30 14 40 24 45C34 40 42 30 42 18V9L24 2Z"
          stroke="url(#glow-effect)"
          strokeWidth="1.5"
          fill="none"
        />
        
        {/* Middle Shield Layer */}
        <path
          d="M24 5L10 11V18C10 27 16 36 24 41.5C32 36 38 27 38 18V11L24 5Z"
          stroke="url(#premium-shield)"
          strokeWidth="1"
          fill="none"
          opacity="0.7"
        />
        
        {/* Lock Container - Rounded */}
        <rect
          x="16"
          y="18"
          width="16"
          height="14"
          rx="2"
          fill="none"
          stroke="url(#glow-effect)"
          strokeWidth="1.2"
        />
        
        {/* Lock Top Arc */}
        <path
          d="M18 18V14C18 11.8 20.2 10 24 10C27.8 10 30 11.8 30 14V18"
          stroke="url(#glow-effect)"
          strokeWidth="1.2"
          fill="none"
          strokeLinecap="round"
        />
        
        {/* Lock Keyhole */}
        <circle cx="24" cy="24" r="1.2" fill="url(#glow-effect)" />
        
        {/* Tech Circuit Elements - Corner Accent */}
        <line x1="5" y1="13" x2="7" y2="13" stroke="url(#glow-effect)" strokeWidth="0.6" opacity="0.6" />
        <line x1="5" y1="13" x2="5" y2="15" stroke="url(#glow-effect)" strokeWidth="0.6" opacity="0.6" />
        
        <line x1="43" y1="13" x2="41" y2="13" stroke="url(#glow-effect)" strokeWidth="0.6" opacity="0.6" />
        <line x1="43" y1="13" x2="43" y2="15" stroke="url(#glow-effect)" strokeWidth="0.6" opacity="0.6" />
      </svg>
    );
  }

  if (variant === "full") {
    return (
      <div className={cn("flex items-center gap-4", className)}>
        <svg
          viewBox="0 0 48 48"
          className={cn("w-12 h-12", animated && "animate-pulse")}
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="premium-shield-full" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#3b82f6" />
              <stop offset="50%" stopColor="#1e40af" />
              <stop offset="100%" stopColor="#0c4a6e" />
            </linearGradient>
            <linearGradient id="glow-effect-full" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#60a5fa" />
              <stop offset="100%" stopColor="#3b82f6" />
            </linearGradient>
          </defs>
          
          <path
            d="M24 2L6 9V18C6 30 14 40 24 45C34 40 42 30 42 18V9L24 2Z"
            fill="url(#premium-shield-full)"
            opacity="0.2"
          />
          
          <path
            d="M24 2L6 9V18C6 30 14 40 24 45C34 40 42 30 42 18V9L24 2Z"
            stroke="url(#glow-effect-full)"
            strokeWidth="1.5"
            fill="none"
          />
          
          <path
            d="M24 5L10 11V18C10 27 16 36 24 41.5C32 36 38 27 38 18V11L24 5Z"
            stroke="url(#premium-shield-full)"
            strokeWidth="1"
            fill="none"
            opacity="0.7"
          />
          
          <rect
            x="16"
            y="18"
            width="16"
            height="14"
            rx="2"
            fill="none"
            stroke="url(#glow-effect-full)"
            strokeWidth="1.2"
          />
          
          <path
            d="M18 18V14C18 11.8 20.2 10 24 10C27.8 10 30 11.8 30 14V18"
            stroke="url(#glow-effect-full)"
            strokeWidth="1.2"
            fill="none"
            strokeLinecap="round"
          />
          
          <circle cx="24" cy="24" r="1.2" fill="url(#glow-effect-full)" />
          
          <line x1="5" y1="13" x2="7" y2="13" stroke="url(#glow-effect-full)" strokeWidth="0.6" opacity="0.6" />
          <line x1="5" y1="13" x2="5" y2="15" stroke="url(#glow-effect-full)" strokeWidth="0.6" opacity="0.6" />
          
          <line x1="43" y1="13" x2="41" y2="13" stroke="url(#glow-effect-full)" strokeWidth="0.6" opacity="0.6" />
          <line x1="43" y1="13" x2="43" y2="15" stroke="url(#glow-effect-full)" strokeWidth="0.6" opacity="0.6" />
        </svg>
        
        <div className="flex flex-col">
          <span className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-blue-600 bg-clip-text text-transparent">
            MalwareSnipper
          </span>
          <span className="text-xs text-blue-600 font-semibold">AI Security</span>
        </div>
      </div>
    );
  }

  // Default variant
  return (
    <div className={cn("flex items-center gap-3", className)}>
      <svg
        viewBox="0 0 48 48"
        className={cn("w-9 h-9", animated && "animate-pulse")}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="premium-shield-default" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="50%" stopColor="#1e40af" />
            <stop offset="100%" stopColor="#0c4a6e" />
          </linearGradient>
          <linearGradient id="glow-effect-default" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#60a5fa" />
            <stop offset="100%" stopColor="#3b82f6" />
          </linearGradient>
        </defs>
        
        <path
          d="M24 2L6 9V18C6 30 14 40 24 45C34 40 42 30 42 18V9L24 2Z"
          fill="url(#premium-shield-default)"
          opacity="0.2"
        />
        
        <path
          d="M24 2L6 9V18C6 30 14 40 24 45C34 40 42 30 42 18V9L24 2Z"
          stroke="url(#glow-effect-default)"
          strokeWidth="1.5"
          fill="none"
        />
        
        <path
          d="M24 5L10 11V18C10 27 16 36 24 41.5C32 36 38 27 38 18V11L24 5Z"
          stroke="url(#premium-shield-default)"
          strokeWidth="1"
          fill="none"
          opacity="0.7"
        />
        
        <rect
          x="16"
          y="18"
          width="16"
          height="14"
          rx="2"
          fill="none"
          stroke="url(#glow-effect-default)"
          strokeWidth="1.2"
        />
        
        <path
          d="M18 18V14C18 11.8 20.2 10 24 10C27.8 10 30 11.8 30 14V18"
          stroke="url(#glow-effect-default)"
          strokeWidth="1.2"
          fill="none"
          strokeLinecap="round"
        />
        
        <circle cx="24" cy="24" r="1.2" fill="url(#glow-effect-default)" />
        
        <line x1="5" y1="13" x2="7" y2="13" stroke="url(#glow-effect-default)" strokeWidth="0.6" opacity="0.6" />
        <line x1="5" y1="13" x2="5" y2="15" stroke="url(#glow-effect-default)" strokeWidth="0.6" opacity="0.6" />
        
        <line x1="43" y1="13" x2="41" y2="13" stroke="url(#glow-effect-default)" strokeWidth="0.6" opacity="0.6" />
        <line x1="43" y1="13" x2="43" y2="15" stroke="url(#glow-effect-default)" strokeWidth="0.6" opacity="0.6" />
      </svg>
      
      <span className="text-base font-bold bg-gradient-to-r from-blue-400 to-blue-600 bg-clip-text text-transparent">
        MalwareSnipper
      </span>
    </div>
  );
};
