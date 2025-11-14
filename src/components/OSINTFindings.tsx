import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Eye, Globe, Mail, Key, Database } from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface OSINTFinding {
  id: string;
  finding_type: string;
  description: string;
  severity: string;
  source: string;
  data?: any;
}

interface OSINTFindingsProps {
  scanId: string;
}

export const OSINTFindings = ({ scanId }: OSINTFindingsProps) => {
  const [findings, setFindings] = useState<OSINTFinding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFindings = async () => {
      try {
        const { supabase } = await import("@/integrations/supabase/client");
        const { data, error } = await supabase
          .from('osint_findings')
          .select('*')
          .eq('scan_id', scanId)
          .order('severity', { ascending: false });

        if (error) throw error;
        setFindings(data || []);
      } catch (error) {
        console.error('Error fetching OSINT findings:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchFindings();
  }, [scanId]);

  const getSeverityVariant = (severity: string): "default" | "secondary" | "destructive" | "outline" => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'outline';
    }
  };

  const getIcon = (findingType: string) => {
    switch (findingType) {
      case 'subdomain': return <Globe className="h-4 w-4" />;
      case 'email': return <Mail className="h-4 w-4" />;
      case 'exposed_api_keys': return <Key className="h-4 w-4" />;
      case 'data_breach': return <Database className="h-4 w-4" />;
      default: return <Eye className="h-4 w-4" />;
    }
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Eye className="h-5 w-5" />
            OSINT Exposure Check
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">Checking for exposed information...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Eye className="h-5 w-5" />
          OSINT Exposure Check
        </CardTitle>
        <p className="text-sm text-muted-foreground mt-2">
          Open Source Intelligence findings from public sources
        </p>
      </CardHeader>
      <CardContent>
        {findings.length === 0 ? (
          <Alert>
            <AlertDescription>
              No exposed information found in public sources. This is good!
            </AlertDescription>
          </Alert>
        ) : (
          <div className="space-y-4">
            {findings.map((finding) => (
              <div key={finding.id} className="border rounded-lg p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    {getIcon(finding.finding_type)}
                    <span className="font-medium capitalize">
                      {finding.finding_type.replace(/_/g, ' ')}
                    </span>
                  </div>
                  <Badge variant={getSeverityVariant(finding.severity)}>
                    {finding.severity}
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground">{finding.description}</p>
                <div className="text-xs text-muted-foreground">
                  Source: {finding.source}
                </div>
                {finding.data && (
                  <div className="mt-2 p-2 bg-muted rounded text-xs font-mono">
                    {JSON.stringify(finding.data, null, 2)}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};
