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
          <linearGradient id="shield-gradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#8b5cf6" />
          </linearGradient>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
            <feMerge>
              <feMergeNode in="coloredBlur"/>
              <feMergeNode in="SourceGraphic"/>
            </feMerge>
          </filter>
        </defs>
        
        {/* Shield Background */}
        <path
          d="M24 4L8 10V20C8 30 15 38 24 44C33 38 40 30 40 20V10L24 4Z"
          fill="url(#shield-gradient)"
          opacity="0.2"
        />
        
        {/* Shield Border */}
        <path
          d="M24 4L8 10V20C8 30 15 38 24 44C33 38 40 30 40 20V10L24 4Z"
          stroke="url(#shield-gradient)"
          strokeWidth="2"
          fill="none"
          filter="url(#glow)"
        />
        
        {/* Lock Symbol */}
        <rect
          x="18"
          y="22"
          width="12"
          height="10"
          rx="1"
          fill="currentColor"
          className="text-blue-600"
        />
        <path
          d="M20 22V18C20 15.8 21.8 14 24 14C26.2 14 28 15.8 28 18V22"
          stroke="currentColor"
          strokeWidth="2"
          fill="none"
          className="text-blue-600"
        />
        <circle cx="24" cy="27" r="1.5" fill="white" />
      </svg>
    );
  }

  if (variant === "full") {
    return (
      <div className={cn("flex items-center gap-3", className)}>
        <svg
          viewBox="0 0 48 48"
          className={cn("w-10 h-10", animated && "animate-pulse")}
          fill="none"
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <linearGradient id="shield-gradient-full" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="#3b82f6" />
              <stop offset="100%" stopColor="#8b5cf6" />
            </linearGradient>
          </defs>
          
          <path
            d="M24 4L8 10V20C8 30 15 38 24 44C33 38 40 30 40 20V10L24 4Z"
            fill="url(#shield-gradient-full)"
            opacity="0.2"
          />
          
          <path
            d="M24 4L8 10V20C8 30 15 38 24 44C33 38 40 30 40 20V10L24 4Z"
            stroke="url(#shield-gradient-full)"
            strokeWidth="2"
            fill="none"
          />
          
          <rect x="18" y="22" width="12" height="10" rx="1" fill="currentColor" className="text-blue-600" />
          <path
            d="M20 22V18C20 15.8 21.8 14 24 14C26.2 14 28 15.8 28 18V22"
            stroke="currentColor"
            strokeWidth="2"
            fill="none"
            className="text-blue-600"
          />
          <circle cx="24" cy="27" r="1.5" fill="white" />
        </svg>
        
        <div className="flex flex-col">
          <span className="text-xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
            MalwareSnipper
          </span>
          <span className="text-xs text-muted-foreground">AI-Powered Protection</span>
        </div>
      </div>
    );
  }

  // Default variant
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <svg
        viewBox="0 0 48 48"
        className={cn("w-8 h-8", animated && "animate-pulse")}
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="shield-gradient-default" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor="#3b82f6" />
            <stop offset="100%" stopColor="#8b5cf6" />
          </linearGradient>
        </defs>
        
        <path
          d="M24 4L8 10V20C8 30 15 38 24 44C33 38 40 30 40 20V10L24 4Z"
          fill="url(#shield-gradient-default)"
          opacity="0.2"
        />
        
        <path
          d="M24 4L8 10V20C8 30 15 38 24 44C33 38 40 30 40 20V10L24 4Z"
          stroke="url(#shield-gradient-default)"
          strokeWidth="2"
          fill="none"
        />
        
        <rect x="18" y="22" width="12" height="10" rx="1" fill="currentColor" className="text-blue-600" />
        <path
          d="M20 22V18C20 15.8 21.8 14 24 14C26.2 14 28 15.8 28 18V22"
          stroke="currentColor"
          strokeWidth="2"
          fill="none"
          className="text-blue-600"
        />
        <circle cx="24" cy="27" r="1.5" fill="white" />
      </svg>
      
      <span className="text-lg font-semibold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
        MalwareSnipper
      </span>
    </div>
  );
};
