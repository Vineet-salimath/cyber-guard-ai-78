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
    default: "",
    success: "border-success/20",
    warning: "border-warning/20",
    danger: "border-destructive/20",
  };

  const iconColors = {
    default: "text-primary bg-primary/10",
    success: "text-success bg-success/10",
    warning: "text-warning bg-warning/10",
    danger: "text-destructive bg-destructive/10",
  };

  return (
    <motion.div
      whileHover={{ y: -2 }}
      className={`p-6 rounded-xl bg-card border transition-all duration-200 hover:shadow-md ${variantStyles[variant]}`}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-2">
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          <p className="text-3xl font-bold tracking-tight">{value}</p>
          {trend && <p className="text-xs text-muted-foreground">{trend}</p>}
        </div>
        <div className={`p-2.5 rounded-lg ${iconColors[variant]}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
    </motion.div>
  );
};

export default StatCard;
