import { LucideIcon } from "lucide-react";
import { motion } from "framer-motion";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  variant?: "default" | "success" | "warning" | "danger";
}

const StatCard = ({ title, value, icon: Icon, trend, variant = "default" }: StatCardProps) => {
  const variantStyles = {
    default: "border-primary/30 hover:border-primary/50 hover:shadow-[0_0_20px_hsl(180_100%_50%_/_0.2)]",
    success: "border-success/30 hover:border-success/50 hover:shadow-[0_0_20px_hsl(150_100%_45%_/_0.2)]",
    warning: "border-warning/30 hover:border-warning/50 hover:shadow-[0_0_20px_hsl(45_100%_60%_/_0.2)]",
    danger: "border-destructive/30 hover:border-destructive/50 hover:shadow-[0_0_20px_hsl(0_100%_60%_/_0.2)]",
  };

  const iconColors = {
    default: "text-primary",
    success: "text-success",
    warning: "text-warning",
    danger: "text-destructive",
  };

  return (
    <motion.div
      whileHover={{ scale: 1.02 }}
      className={`p-6 rounded-lg bg-card border transition-all duration-300 ${variantStyles[variant]}`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-sm text-muted-foreground">{title}</p>
          <p className="text-3xl font-orbitron font-bold">{value}</p>
          {trend && <p className="text-xs text-muted-foreground">{trend}</p>}
        </div>
        <Icon className={`w-10 h-10 ${iconColors[variant]}`} />
      </div>
    </motion.div>
  );
};

export default StatCard;
