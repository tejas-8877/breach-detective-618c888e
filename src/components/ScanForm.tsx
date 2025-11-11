import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, Search } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface ScanFormProps {
  onScanComplete: (scanId: string) => void;
}

export const ScanForm = ({ onScanComplete }: ScanFormProps) => {
  const [domain, setDomain] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const { toast } = useToast();

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!domain) {
      toast({
        title: "Domain Required",
        description: "Please enter a domain or URL to scan",
        variant: "destructive",
      });
      return;
    }

    setIsScanning(true);

    try {
      const { data: { session } } = await import("@/integrations/supabase/client").then(m => m.supabase.auth.getSession());
      const supabase = await import("@/integrations/supabase/client").then(m => m.supabase);
      
      const { data, error } = await supabase.functions.invoke('scan-vulnerabilities', {
        body: { domain }
      });

      if (error) throw error;

      toast({
        title: "Scan Complete",
        description: `Found ${data.vulnerabilities_found} vulnerabilities. Security Score: ${data.security_score}/100`,
      });

      onScanComplete(data.scan_id);
    } catch (error: any) {
      console.error('Scan error:', error);
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to scan domain. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <form onSubmit={handleScan} className="w-full max-w-2xl mx-auto">
      <div className="relative">
        <div className="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none">
          <Shield className="h-5 w-5 text-muted-foreground" />
        </div>
        <Input
          type="text"
          placeholder="Try: google.com, github.com, cloudflare.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          className="pl-12 pr-32 h-14 text-lg"
          disabled={isScanning}
        />
        <div className="absolute inset-y-0 right-0 pr-2 flex items-center">
          <Button
            type="submit"
            disabled={isScanning}
            size="lg"
            className="h-10"
          >
            {isScanning ? (
              <>
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                Scanning...
              </>
            ) : (
              <>
                <Search className="h-4 w-4 mr-2" />
                Scan Now
              </>
            )}
          </Button>
        </div>
      </div>
    </form>
  );
};