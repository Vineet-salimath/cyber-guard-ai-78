import { motion } from "framer-motion";
import { Shield, Zap, Lock, TrendingUp, ArrowRight, Check, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useNavigate } from "react-router-dom";
import { MalwareSnipperLogo } from "@/components/ui/svg-logos";
import { 
  AnimatedGradientBackground, 
  GlowCard, 
  GradientText,
  PulseDot,
  GridPattern,
  Spotlight,
  FloatingParticles
} from "@/components/ui/glowing-badge";

const Home = () => {
  const navigate = useNavigate();

  const features = [
    {
      icon: Shield,
      title: "Real-Time Protection",
      description: "Instant malware detection powered by advanced AI algorithms",
    },
    {
      icon: Zap,
      title: "Lightning Fast",
      description: "Sub-second analysis with zero performance impact",
    },
    {
      icon: Lock,
      title: "Bank-Grade Security",
      description: "Enterprise-level threat detection for everyone",
    },
    {
      icon: TrendingUp,
      title: "Always Learning",
      description: "AI that adapts and improves with every threat detected",
    },
  ];

  const stats = [
    { value: "99.8%", label: "Detection Accuracy" },
    { value: "<1s", label: "Average Scan Time" },
    { value: "2.5K+", label: "Protected Users" },
    { value: "24/7", label: "Active Monitoring" },
  ];

  return (
    <div className="min-h-screen">
      {/* Navigation */}
      <nav className="fixed top-0 w-full z-50 bg-background/80 backdrop-blur-lg border-b">
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2 font-semibold text-xl">
            <Shield className="w-6 h-6 text-primary" />
            <span>MalwareSnipper</span>
          </div>
          <div className="flex items-center gap-4">
            <Button variant="ghost" onClick={() => navigate("/dashboard")}>
              Dashboard
            </Button>
            <Button onClick={() => navigate("/dashboard")}>Get Started</Button>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="pt-32 pb-20 px-4">
        <div className="container mx-auto max-w-6xl">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-center space-y-8"
          >
            {/* Badge */}
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.1 }}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium"
            >
              <Sparkles className="w-4 h-4" />
              AI-Powered Threat Intelligence
            </motion.div>

            {/* Headline */}
            <div className="space-y-4">
              <h1 className="text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight">
                Detect Malware
                <br />
                <span className="text-gradient">Before It Strikes</span>
              </h1>
              <p className="text-xl text-muted-foreground max-w-2xl mx-auto leading-relaxed">
                Real-time AI protection that learns and adapts. Browse safely with enterprise-grade security.
              </p>
            </div>

            {/* CTA Buttons */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.3 }}
              className="flex flex-col sm:flex-row gap-4 justify-center items-center pt-4"
            >
              <Button size="lg" className="text-base h-12 px-8" onClick={() => navigate("/dashboard")}>
                Launch Dashboard
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>
              <Button size="lg" variant="outline" className="text-base h-12 px-8">
                View Demo
              </Button>
            </motion.div>

            {/* Stats */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.5 }}
              className="grid grid-cols-2 md:grid-cols-4 gap-8 pt-12 max-w-4xl mx-auto"
            >
              {stats.map((stat, index) => (
                <div key={index} className="text-center">
                  <div className="text-3xl md:text-4xl font-bold mb-1">{stat.value}</div>
                  <div className="text-sm text-muted-foreground">{stat.label}</div>
                </div>
              ))}
            </motion.div>
          </motion.div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="py-20 px-4 bg-secondary/30">
        <div className="container mx-auto max-w-6xl">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Everything you need to stay protected
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Advanced security features that work seamlessly in the background
            </p>
          </motion.div>

          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
            {features.map((feature, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                viewport={{ once: true }}
              >
                <div className="h-full p-6 rounded-xl bg-card border hover:shadow-lg transition-shadow">
                  <feature.icon className="w-10 h-10 text-primary mb-4" />
                  <h3 className="text-lg font-semibold mb-2">{feature.title}</h3>
                  <p className="text-sm text-muted-foreground leading-relaxed">
                    {feature.description}
                  </p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20 px-4">
        <div className="container mx-auto max-w-4xl">
          <motion.div
            initial={{ opacity: 0 }}
            whileInView={{ opacity: 1 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="text-center mb-16"
          >
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Simple, powerful protection</h2>
            <p className="text-lg text-muted-foreground">Get started in three easy steps</p>
          </motion.div>

          <div className="space-y-8">
            {[
              {
                step: "01",
                title: "Install Extension",
                description: "Add MalwareSnipper to your browser in seconds",
              },
              {
                step: "02",
                title: "Browse Normally",
                description: "Our AI works silently in the background",
              },
              {
                step: "03",
                title: "Stay Protected",
                description: "Get instant alerts when threats are detected",
              },
            ].map((item, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                viewport={{ once: true }}
                className="flex items-start gap-6 p-6 rounded-xl bg-card border"
              >
                <div className="flex-shrink-0 w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center text-primary font-bold">
                  {item.step}
                </div>
                <div>
                  <h3 className="text-xl font-semibold mb-2">{item.title}</h3>
                  <p className="text-muted-foreground">{item.description}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-4">
        <div className="container mx-auto max-w-4xl">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            viewport={{ once: true }}
            className="p-12 rounded-2xl bg-gradient-to-br from-primary/10 via-primary/5 to-background border text-center space-y-6"
          >
            <h2 className="text-3xl md:text-4xl font-bold">Ready to secure your browsing?</h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Join thousands of users protecting themselves with AI-powered threat detection
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center pt-4">
              <Button size="lg" className="h-12 px-8" onClick={() => navigate("/dashboard")}>
                Get Started Free
                <ArrowRight className="w-4 h-4 ml-2" />
              </Button>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t py-12 px-4">
        <div className="container mx-auto max-w-6xl">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            <div className="flex items-center gap-2 font-semibold">
              <Shield className="w-5 h-5 text-primary" />
              <span>MalwareSnipper</span>
            </div>
            <p className="text-sm text-muted-foreground">
              © 2025 MalwareSnipper. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Home;
