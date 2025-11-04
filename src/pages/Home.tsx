import { motion } from "framer-motion";
import { Shield, Brain, Activity, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router-dom";
import heroImage from "@/assets/hero-cyber.jpg";

const Home = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: Shield,
      title: "Real-Time Protection",
      description: "Instant malware detection as you browse the web",
    },
    {
      icon: Brain,
      title: "AI-Powered Analysis",
      description: "Advanced machine learning algorithms for accurate threat detection",
    },
    {
      icon: Activity,
      title: "Live Monitoring",
      description: "Track all scans and threats in real-time dashboard",
    },
    {
      icon: Zap,
      title: "Lightning Fast",
      description: "Sub-second analysis with minimal performance impact",
    },
  ];

  return (
    <div className="min-h-screen">
      {/* Hero Section */}
      <section className="relative min-h-screen flex items-center justify-center overflow-hidden">
        {/* Background Image with Overlay */}
        <div 
          className="absolute inset-0 z-0"
          style={{
            backgroundImage: `url(${heroImage})`,
            backgroundSize: 'cover',
            backgroundPosition: 'center',
          }}
        >
          <div className="absolute inset-0 bg-gradient-to-b from-background/90 via-background/80 to-background" />
        </div>

        {/* Animated Grid Lines */}
        <div className="absolute inset-0 z-0">
          <div className="absolute inset-0" style={{
            backgroundImage: `
              linear-gradient(hsl(180 100% 50% / 0.05) 1px, transparent 1px),
              linear-gradient(90deg, hsl(180 100% 50% / 0.05) 1px, transparent 1px)
            `,
            backgroundSize: '50px 50px',
          }} />
        </div>

        {/* Content */}
        <div className="relative z-10 container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8 }}
            className="text-center space-y-8"
          >
            {/* Logo/Icon */}
            <motion.div
              initial={{ scale: 0 }}
              animate={{ scale: 1 }}
              transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
              className="flex justify-center"
            >
              <div className="relative">
                <Shield className="w-24 h-24 text-primary animate-pulse-glow" />
                <Brain className="w-10 h-10 text-success absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" />
              </div>
            </motion.div>

            {/* Title */}
            <div className="space-y-4">
              <h1 className="text-6xl md:text-7xl lg:text-8xl font-orbitron font-bold tracking-tight">
                <span className="text-gradient">MalwareSnipper</span>
              </h1>
              <p className="text-xl md:text-2xl text-muted-foreground max-w-2xl mx-auto">
                AI-Powered Threat Intelligence
              </p>
              <p className="text-lg md:text-xl text-foreground/80 max-w-3xl mx-auto">
                Detect, Analyze & Prevent Web-Based Malware in Real Time
              </p>
            </div>

            {/* CTA Buttons */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.4 }}
              className="flex flex-col sm:flex-row gap-4 justify-center items-center"
            >
              <Button 
                variant="hero" 
                size="lg"
                onClick={() => navigate("/dashboard")}
                className="text-lg px-8 py-6"
              >
                Launch Dashboard
              </Button>
              <Button 
                variant="outline" 
                size="lg"
                onClick={() => navigate("/extension")}
                className="text-lg px-8 py-6"
              >
                View Extension Demo
              </Button>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6 }}
              className="grid grid-cols-3 gap-8 max-w-2xl mx-auto pt-12"
            >
              <div className="text-center">
                <div className="text-3xl font-orbitron font-bold text-primary">99.8%</div>
                <div className="text-sm text-muted-foreground">Accuracy</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-orbitron font-bold text-success">{'<'}1s</div>
                <div className="text-sm text-muted-foreground">Scan Time</div>
              </div>
              <div className="text-center">
                <div className="text-3xl font-orbitron font-bold text-warning">24/7</div>
                <div className="text-sm text-muted-foreground">Protection</div>
              </div>
            </motion.div>
          </motion.div>
        </div>

        {/* Scroll Indicator */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1, repeat: Infinity, duration: 2 }}
          className="absolute bottom-8 left-1/2 -translate-x-1/2 z-10"
        >
          <div className="w-6 h-10 border-2 border-primary/50 rounded-full flex justify-center">
            <div className="w-1.5 h-3 bg-primary rounded-full mt-2 animate-pulse" />
          </div>
        </motion.div>
      </section>

      {/* Features Section */}
      <section className="py-20 relative">
        <div className="container mx-auto px-4">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            transition={{ duration: 0.8 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-4xl md:text-5xl font-orbitron font-bold mb-4">
              Why Choose <span className="text-gradient">MalwareSnipper</span>?
            </h2>
            <p className="text-xl text-muted-foreground max-w-2xl mx-auto">
              Advanced AI technology meets intuitive design for ultimate protection
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-8">
            {features.map((feature, index) => (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                viewport={{ once: true }}
                className="group"
              >
                <div className="h-full p-6 rounded-lg bg-card border border-primary/20 hover:border-primary/50 transition-all duration-300 hover:shadow-[0_0_30px_hsl(180_100%_50%_/_0.2)]">
                  <feature.icon className="w-12 h-12 text-primary mb-4 group-hover:scale-110 transition-transform" />
                  <h3 className="text-xl font-orbitron font-bold mb-2">{feature.title}</h3>
                  <p className="text-muted-foreground">{feature.description}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>
    </div>
  );
};

export default Home;
