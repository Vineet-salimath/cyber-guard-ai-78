import { useState } from "react";
import { MessageSquare, Send } from "lucide-react";
import DashboardLayout from "@/components/DashboardLayout";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";

const Feedback = () => {
  const [formData, setFormData] = useState({
    type: "",
    url: "",
    message: "",
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // Simulate form submission
    toast.success("Feedback submitted successfully!", {
      description: "Thank you for helping us improve MalwareSnipper.",
    });
    setFormData({ type: "", url: "", message: "" });
  };

  return (
    <DashboardLayout>
      <div className="p-6 max-w-4xl mx-auto space-y-8">
        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <MessageSquare className="w-10 h-10 text-primary" />
            <h1 className="text-4xl font-orbitron font-bold">Submit Feedback</h1>
          </div>
          <p className="text-muted-foreground">
            Help us improve by reporting false positives or suggesting improvements
          </p>
        </div>

        {/* Feedback Form */}
        <div className="p-8 rounded-lg bg-card border border-primary/20">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Feedback Type */}
            <div className="space-y-2">
              <Label htmlFor="type" className="text-base">
                Feedback Type
              </Label>
              <Select
                value={formData.type}
                onValueChange={(value) => setFormData({ ...formData, type: value })}
              >
                <SelectTrigger id="type" className="bg-background border-primary/30">
                  <SelectValue placeholder="Select feedback type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="false-positive">False Positive</SelectItem>
                  <SelectItem value="false-negative">False Negative</SelectItem>
                  <SelectItem value="feature-request">Feature Request</SelectItem>
                  <SelectItem value="bug-report">Bug Report</SelectItem>
                  <SelectItem value="other">Other</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Website URL */}
            <div className="space-y-2">
              <Label htmlFor="url" className="text-base">
                Website URL (if applicable)
              </Label>
              <Input
                id="url"
                type="url"
                placeholder="https://example.com"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                className="bg-background border-primary/30 font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Include the URL if your feedback is related to a specific scan
              </p>
            </div>

            {/* Message */}
            <div className="space-y-2">
              <Label htmlFor="message" className="text-base">
                Your Message
              </Label>
              <Textarea
                id="message"
                placeholder="Describe your feedback in detail..."
                value={formData.message}
                onChange={(e) => setFormData({ ...formData, message: e.target.value })}
                className="bg-background border-primary/30 min-h-[150px] resize-none"
                required
              />
            </div>

            {/* Submit Button */}
            <Button type="submit" variant="default" size="lg" className="w-full gap-2">
              <Send className="w-4 h-4" />
              Submit Feedback
            </Button>
          </form>
        </div>

        {/* Info Cards */}
        <div className="grid md:grid-cols-2 gap-6">
          <div className="p-6 rounded-lg bg-card border border-success/20">
            <h3 className="font-orbitron font-bold text-lg mb-3 text-success">False Positive</h3>
            <p className="text-sm text-muted-foreground">
              If a safe website was incorrectly flagged as malicious or suspicious, let us know so we can improve
              our detection accuracy.
            </p>
          </div>

          <div className="p-6 rounded-lg bg-card border border-destructive/20">
            <h3 className="font-orbitron font-bold text-lg mb-3 text-destructive">False Negative</h3>
            <p className="text-sm text-muted-foreground">
              Found a malicious website that wasn't detected? Report it to help protect other users and train our
              AI model.
            </p>
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
};

export default Feedback;
