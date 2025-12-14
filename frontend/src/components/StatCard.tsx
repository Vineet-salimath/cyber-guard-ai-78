import { LucideIcon } from "lucide-react";
import { motion } from "framer-motion";
import { GlowCard } from "@/components/ui/glowing-badge";

interface StatCardProps {
  title: string;
  value: string | number;
  icon: LucideIcon;
  trend?: string;
  variant?: "default" | "success" | "warning" | "danger";
}

const StatCard = ({ title, value, icon: Icon, trend, variant = "default" }: StatCardProps) => {
  const glowColors: Record<string, "blue" | "green" | "yellow" | "red"> = {
    default: "blue",
    success: "green",
    warning: "yellow",
    danger: "red",
  };

  const iconColors = {
    default: "text-blue-600 bg-blue-600/10",
    success: "text-green-600 bg-green-600/10",
    warning: "text-yellow-600 bg-yellow-600/10",
    danger: "text-red-600 bg-red-600/10",
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -4, scale: 1.02 }}
      transition={{ duration: 0.2 }}
    >
      <GlowCard glowColor={glowColors[variant]} className="h-full">
        <div className="flex items-start justify-between">
          <div className="space-y-2">
            <p className="text-sm font-medium text-muted-foreground">{title}</p>
            <p className="text-3xl font-bold tracking-tight bg-gradient-to-br from-foreground to-foreground/70 bg-clip-text">
              {value}
            </p>
            {trend && <p className="text-xs text-muted-foreground">{trend}</p>}
          </div>
          <motion.div 
            className={`p-2.5 rounded-lg ${iconColors[variant]}`}
            whileHover={{ rotate: 5, scale: 1.1 }}
            transition={{ type: "spring", stiffness: 300 }}
          >
            <Icon className="w-5 h-5" />
          </motion.div>
        </div>
      </GlowCard>
    </motion.div>
  );
};

export default StatCard;
