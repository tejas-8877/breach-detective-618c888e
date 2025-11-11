import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { formatDistanceToNow } from "date-fns";
import { History, ExternalLink } from "lucide-react";

interface Scan {
  id: string;
  domain: string;
  security_score: number;
  vulnerabilities_found: number;
  created_at: string;
}

interface ScanHistoryProps {
  onViewScan: (scanId: string) => void;
}

export const ScanHistory = ({ onViewScan }: ScanHistoryProps) => {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchScans = async () => {
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(10);

      if (error) {
        console.error('Error fetching scans:', error);
        return;
      }

      setScans(data || []);
      setLoading(false);
    };

    fetchScans();
  }, []);

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-success';
    if (score >= 60) return 'text-warning';
    return 'text-destructive';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
      </div>
    );
  }

  if (scans.length === 0) {
    return (
      <Card>
        <CardContent className="py-12 text-center">
          <History className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
          <h3 className="text-lg font-semibold mb-2">No Scan History</h3>
          <p className="text-sm text-muted-foreground">Your scan history will appear here.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center space-x-2 mb-4">
        <History className="h-5 w-5" />
        <h2 className="text-xl font-semibold">Recent Scans</h2>
      </div>
      {scans.map((scan) => (
        <Card key={scan.id} className="hover:border-primary transition-colors">
          <CardHeader>
            <div className="flex items-start justify-between">
              <div>
                <CardTitle className="text-lg">{scan.domain}</CardTitle>
                <CardDescription>
                  {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                </CardDescription>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onViewScan(scan.id)}
              >
                <ExternalLink className="h-4 w-4 mr-2" />
                View Report
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className={`text-2xl font-bold ${getScoreColor(scan.security_score)}`}>
                  {scan.security_score}/100
                </div>
                <div className="text-sm text-muted-foreground">Security Score</div>
              </div>
              <div>
                <div className="text-2xl font-bold text-destructive">
                  {scan.vulnerabilities_found}
                </div>
                <div className="text-sm text-muted-foreground">Issues Found</div>
              </div>
            </div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
};