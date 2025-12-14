import { cn } from "@/lib/utils";
import { ReactNode } from "react";

// Animated gradient background
export const AnimatedGradientBackground = ({ 
  children, 
  className 
}: { 
  children: ReactNode; 
  className?: string 
}) => {
  return (
    <div className={cn("relative overflow-hidden", className)}>
      <div className="absolute inset-0 bg-gradient-to-br from-blue-500/10 via-purple-500/10 to-pink-500/10 animate-gradient-shift" />
      <div className="absolute inset-0 bg-gradient-to-tr from-transparent via-blue-500/5 to-transparent animate-pulse" />
      {children}
    </div>
  );
};

// Glowing border card
export const GlowCard = ({ 
  children, 
  className,
  glowColor = "blue" 
}: { 
  children: ReactNode; 
  className?: string;
  glowColor?: "blue" | "purple" | "green" | "red" | "yellow";
}) => {
  const glowColors = {
    blue: "shadow-blue-500/50",
    purple: "shadow-purple-500/50",
    green: "shadow-green-500/50",
    red: "shadow-red-500/50",
    yellow: "shadow-yellow-500/50",
  };

  return (
    <div 
      className={cn(
        "relative rounded-lg border bg-card p-6",
        "transition-all duration-300 hover:shadow-lg",
        `hover:${glowColors[glowColor]}`,
        className
      )}
    >
      <div className="absolute inset-0 rounded-lg bg-gradient-to-br from-transparent via-white/5 to-transparent opacity-0 hover:opacity-100 transition-opacity duration-300" />
      <div className="relative z-10">{children}</div>
    </div>
  );
};

// Shimmer effect
export const ShimmerText = ({ 
  children, 
  className 
}: { 
  children: ReactNode; 
  className?: string 
}) => {
  return (
    <div className={cn("relative inline-block", className)}>
      <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/20 to-transparent animate-shimmer" />
      <span className="relative z-10">{children}</span>
    </div>
  );
};

// Pulse dot indicator
export const PulseDot = ({ 
  color = "green",
  size = "sm" 
}: { 
  color?: "green" | "red" | "yellow" | "blue";
  size?: "sm" | "md" | "lg";
}) => {
  const colors = {
    green: "bg-green-500",
    red: "bg-red-500",
    yellow: "bg-yellow-500",
    blue: "bg-blue-500",
  };

  const sizes = {
    sm: "w-2 h-2",
    md: "w-3 h-3",
    lg: "w-4 h-4",
  };

  return (
    <div className="relative flex items-center justify-center">
      <div className={cn("rounded-full", colors[color], sizes[size])} />
      <div 
        className={cn(
          "absolute rounded-full animate-ping opacity-75",
          colors[color],
          sizes[size]
        )} 
      />
    </div>
  );
};

// Gradient text
export const GradientText = ({ 
  children, 
  className,
  from = "blue",
  to = "purple" 
}: { 
  children: ReactNode; 
  className?: string;
  from?: string;
  to?: string;
}) => {
  return (
    <span 
      className={cn(
        `bg-gradient-to-r from-${from}-600 to-${to}-600 bg-clip-text text-transparent font-semibold`,
        className
      )}
    >
      {children}
    </span>
  );
};

// Floating particles
export const FloatingParticles = ({ count = 20 }: { count?: number }) => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {Array.from({ length: count }).map((_, i) => (
        <div
          key={i}
          className="absolute w-1 h-1 bg-blue-500/30 rounded-full animate-float"
          style={{
            left: `${Math.random() * 100}%`,
            top: `${Math.random() * 100}%`,
            animationDelay: `${Math.random() * 5}s`,
            animationDuration: `${5 + Math.random() * 10}s`,
          }}
        />
      ))}
    </div>
  );
};

// Status badge with glow
export const GlowingBadge = ({ 
  children, 
  variant = "success",
  className 
}: { 
  children: ReactNode; 
  variant?: "success" | "warning" | "danger" | "info";
  className?: string;
}) => {
  const variants = {
    success: "bg-green-500/10 text-green-600 border-green-500/30 shadow-green-500/50",
    warning: "bg-yellow-500/10 text-yellow-600 border-yellow-500/30 shadow-yellow-500/50",
    danger: "bg-red-500/10 text-red-600 border-red-500/30 shadow-red-500/50",
    info: "bg-blue-500/10 text-blue-600 border-blue-500/30 shadow-blue-500/50",
  };

  return (
    <span 
      className={cn(
        "inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-xs font-medium",
        "transition-all duration-300 hover:shadow-lg",
        variants[variant],
        className
      )}
    >
      {children}
    </span>
  );
};

// Animated border
export const AnimatedBorder = ({ 
  children, 
  className 
}: { 
  children: ReactNode; 
  className?: string 
}) => {
  return (
    <div className={cn("relative p-[2px] rounded-lg overflow-hidden", className)}>
      <div className="absolute inset-0 bg-gradient-to-r from-blue-500 via-purple-500 to-pink-500 animate-gradient-x" />
      <div className="relative bg-background rounded-lg">
        {children}
      </div>
    </div>
  );
};

// Meteor effect
export const MeteorEffect = () => {
  return (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
      {[...Array(5)].map((_, i) => (
        <div
          key={i}
          className="absolute w-px h-20 bg-gradient-to-b from-transparent via-blue-500 to-transparent animate-meteor"
          style={{
            left: `${Math.random() * 100}%`,
            top: `-20px`,
            animationDelay: `${i * 2}s`,
            animationDuration: "3s",
          }}
        />
      ))}
    </div>
  );
};

// Grid pattern background
export const GridPattern = ({ className }: { className?: string }) => {
  return (
    <div 
      className={cn(
        "absolute inset-0 opacity-20",
        className
      )}
      style={{
        backgroundImage: `
          linear-gradient(to right, hsl(var(--border)) 1px, transparent 1px),
          linear-gradient(to bottom, hsl(var(--border)) 1px, transparent 1px)
        `,
        backgroundSize: '40px 40px',
      }}
    />
  );
};

// Spotlight effect
export const Spotlight = ({ className }: { className?: string }) => {
  return (
    <div 
      className={cn(
        "absolute inset-0 pointer-events-none",
        className
      )}
    >
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/20 rounded-full blur-3xl animate-pulse" />
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-pulse delay-1000" />
    </div>
  );
};
