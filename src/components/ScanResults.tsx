import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, AlertTriangle, CheckCircle, XCircle, Info } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

interface Vulnerability {
  id: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  recommendation: string;
  found: boolean;
}

interface Scan {
  id: string;
  domain: string;
  security_score: number;
  vulnerabilities_found: number;
  created_at: string;
}

interface ScanResultsProps {
  scanId: string;
}

export const ScanResults = ({ scanId }: ScanResultsProps) => {
  const [scan, setScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchResults = async () => {
      setLoading(true);
      
      const { data: scanData, error: scanError } = await supabase
        .from('scans')
        .select('*')
        .eq('id', scanId)
        .single();

      if (scanError) {
        console.error('Error fetching scan:', scanError);
        return;
      }

      const { data: vulnData, error: vulnError } = await supabase
        .from('vulnerabilities')
        .select('*')
        .eq('scan_id', scanId)
        .order('severity', { ascending: false });

      if (vulnError) {
        console.error('Error fetching vulnerabilities:', vulnError);
        return;
      }

      setScan(scanData);
      setVulnerabilities(vulnData || []);
      setLoading(false);
    };

    fetchResults();
  }, [scanId]);

  if (loading) {
    return (
      <div className="flex items-center justify-center py-12">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary" />
      </div>
    );
  }

  if (!scan) {
    return <div>No scan data found</div>;
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'secondary';
      case 'low': return 'outline';
      case 'info': return 'outline';
      default: return 'secondary';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <XCircle className="h-5 w-5 text-destructive" />;
      case 'medium':
        return <AlertTriangle className="h-5 w-5 text-warning" />;
      case 'low':
      case 'info':
        return <Info className="h-5 w-5 text-muted-foreground" />;
      default:
        return <CheckCircle className="h-5 w-5 text-success" />;
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-success';
    if (score >= 60) return 'text-warning';
    return 'text-destructive';
  };

  const foundVulnerabilities = vulnerabilities.filter(v => v.found);
  const passedChecks = vulnerabilities.filter(v => !v.found);

  const groupedByCategory = vulnerabilities.reduce((acc, vuln) => {
    if (!acc[vuln.category]) {
      acc[vuln.category] = [];
    }
    acc[vuln.category].push(vuln);
    return acc;
  }, {} as Record<string, Vulnerability[]>);

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Security Score Card */}
      <Card className="border-2">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-2xl">Security Score</CardTitle>
              <CardDescription className="text-lg mt-1">{scan.domain}</CardDescription>
            </div>
            <div className={`text-6xl font-bold ${getScoreColor(scan.security_score)}`}>
              {scan.security_score}
              <span className="text-2xl text-muted-foreground">/100</span>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <Progress value={scan.security_score} className="h-3" />
          <div className="grid grid-cols-3 gap-4 mt-6">
            <div className="text-center">
              <div className="text-3xl font-bold">{vulnerabilities.length}</div>
              <div className="text-sm text-muted-foreground">Total Checks</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-destructive">{foundVulnerabilities.length}</div>
              <div className="text-sm text-muted-foreground">Issues Found</div>
            </div>
            <div className="text-center">
              <div className="text-3xl font-bold text-success">{passedChecks.length}</div>
              <div className="text-sm text-muted-foreground">Passed</div>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Vulnerabilities Tabs */}
      <Tabs defaultValue="all" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="all">All ({vulnerabilities.length})</TabsTrigger>
          <TabsTrigger value="issues">Issues ({foundVulnerabilities.length})</TabsTrigger>
          <TabsTrigger value="passed">Passed ({passedChecks.length})</TabsTrigger>
          <TabsTrigger value="categories">By Category</TabsTrigger>
        </TabsList>

        <TabsContent value="all" className="space-y-4">
          {vulnerabilities.map((vuln) => (
            <Card key={vuln.id} className={vuln.found ? 'border-destructive/50' : 'border-success/50'}>
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    {getSeverityIcon(vuln.severity)}
                    <div>
                      <CardTitle className="text-lg">{vuln.title}</CardTitle>
                      <CardDescription className="mt-1">{vuln.category}</CardDescription>
                    </div>
                  </div>
                  <Badge variant={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-sm">{vuln.description}</p>
                {vuln.found && (
                  <div className="bg-muted p-3 rounded-md">
                    <p className="text-sm font-medium mb-1">Recommendation:</p>
                    <p className="text-sm text-muted-foreground">{vuln.recommendation}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="issues" className="space-y-4">
          {foundVulnerabilities.length === 0 ? (
            <Card>
              <CardContent className="py-12 text-center">
                <Shield className="h-16 w-16 mx-auto text-success mb-4" />
                <h3 className="text-xl font-semibold mb-2">No Issues Found!</h3>
                <p className="text-muted-foreground">Your website passed all security checks.</p>
              </CardContent>
            </Card>
          ) : (
            foundVulnerabilities.map((vuln) => (
              <Card key={vuln.id} className="border-destructive/50">
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex items-start space-x-3">
                      {getSeverityIcon(vuln.severity)}
                      <div>
                        <CardTitle className="text-lg">{vuln.title}</CardTitle>
                        <CardDescription className="mt-1">{vuln.category}</CardDescription>
                      </div>
                    </div>
                    <Badge variant={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-sm">{vuln.description}</p>
                  <div className="bg-muted p-3 rounded-md">
                    <p className="text-sm font-medium mb-1">Recommendation:</p>
                    <p className="text-sm text-muted-foreground">{vuln.recommendation}</p>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="passed" className="space-y-4">
          {passedChecks.map((vuln) => (
            <Card key={vuln.id} className="border-success/50">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-3">
                    <CheckCircle className="h-5 w-5 text-success" />
                    <div>
                      <CardTitle className="text-lg">{vuln.title}</CardTitle>
                      <CardDescription className="mt-1">{vuln.category}</CardDescription>
                    </div>
                  </div>
                  <Badge variant="outline" className="border-success text-success">Passed</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <p className="text-sm">{vuln.description}</p>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="categories" className="space-y-4">
          {Object.entries(groupedByCategory).map(([category, vulns]) => (
            <Card key={category}>
              <CardHeader>
                <CardTitle>{category}</CardTitle>
                <CardDescription>
                  {vulns.filter(v => v.found).length} issues found out of {vulns.length} checks
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                {vulns.map((vuln) => (
                  <div key={vuln.id} className="flex items-center justify-between p-3 rounded-md bg-muted/50">
                    <div className="flex items-center space-x-3">
                      {getSeverityIcon(vuln.severity)}
                      <span className="text-sm font-medium">{vuln.title}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Badge variant={getSeverityColor(vuln.severity)}>{vuln.severity}</Badge>
                      {vuln.found ? (
                        <XCircle className="h-4 w-4 text-destructive" />
                      ) : (
                        <CheckCircle className="h-4 w-4 text-success" />
                      )}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          ))}
        </TabsContent>
      </Tabs>
    </div>
  );
};