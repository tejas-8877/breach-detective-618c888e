import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, AlertTriangle, CheckCircle, XCircle, Info, Download } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";

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

  const downloadReport = () => {
    const reportContent = generateTextReport();
    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `security-scan-${scan.domain}-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    toast.success('Report downloaded successfully');
  };

  const generateTextReport = () => {
    const date = new Date(scan.created_at).toLocaleString();
    let report = `
╔════════════════════════════════════════════════════════════════════════════╗
║                    SECURITY VULNERABILITY SCAN REPORT                      ║
╚════════════════════════════════════════════════════════════════════════════╝

Domain: ${scan.domain}
Scan Date: ${date}
Security Score: ${scan.security_score}/100
Total Checks: ${vulnerabilities.length}
Issues Found: ${foundVulnerabilities.length}
Passed Checks: ${passedChecks.length}

════════════════════════════════════════════════════════════════════════════

                            EXECUTIVE SUMMARY
────────────────────────────────────────────────────────────────────────────
`;

    const criticalCount = foundVulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = foundVulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = foundVulnerabilities.filter(v => v.severity === 'medium').length;
    const lowCount = foundVulnerabilities.filter(v => v.severity === 'low').length;

    report += `
Critical Vulnerabilities: ${criticalCount}
High Severity: ${highCount}
Medium Severity: ${mediumCount}
Low Severity: ${lowCount}

${scan.security_score >= 80 ? '✓ Good security posture' : scan.security_score >= 60 ? '⚠ Moderate security concerns' : '✗ Significant security issues detected'}

════════════════════════════════════════════════════════════════════════════

                        DETAILED FINDINGS
════════════════════════════════════════════════════════════════════════════
`;

    // Add found vulnerabilities
    if (foundVulnerabilities.length > 0) {
      report += '\n\n--- VULNERABILITIES DETECTED ---\n\n';
      foundVulnerabilities.forEach((vuln, index) => {
        report += `
${index + 1}. ${vuln.title}
${'─'.repeat(78)}
Category: ${vuln.category}
Severity: ${vuln.severity.toUpperCase()}
Status: VULNERABLE

Description:
${vuln.description}

Recommendation:
${vuln.recommendation}

${vuln.recommendation.includes('How to Fix:') ? '' : 'Please implement the recommended security controls to address this vulnerability.'}

`;
      });
    }

    // Add passed checks
    if (passedChecks.length > 0) {
      report += '\n\n--- PASSED SECURITY CHECKS ---\n\n';
      passedChecks.forEach((vuln, index) => {
        report += `${index + 1}. ${vuln.title} - ${vuln.category}\n`;
      });
    }

    report += `

════════════════════════════════════════════════════════════════════════════

                        REMEDIATION PRIORITY
────────────────────────────────────────────────────────────────────────────

`;

    if (criticalCount > 0) {
      report += `⚠ CRITICAL: Address ${criticalCount} critical issue(s) immediately\n`;
    }
    if (highCount > 0) {
      report += `⚠ HIGH: Fix ${highCount} high severity issue(s) within 7 days\n`;
    }
    if (mediumCount > 0) {
      report += `⚠ MEDIUM: Resolve ${mediumCount} medium severity issue(s) within 30 days\n`;
    }
    if (lowCount > 0) {
      report += `ℹ LOW: Plan to address ${lowCount} low severity issue(s) in next maintenance cycle\n`;
    }

    report += `
════════════════════════════════════════════════════════════════════════════

                    OWASP TOP 10 COVERAGE (2021)
────────────────────────────────────────────────────────────────────────────

This scan checked for vulnerabilities related to:
• A01:2021 - Broken Access Control
• A02:2021 - Cryptographic Failures
• A03:2021 - Injection
• A04:2021 - Insecure Design
• A05:2021 - Security Misconfiguration
• A07:2021 - Identification and Authentication Failures
• A08:2021 - Software and Data Integrity Failures

════════════════════════════════════════════════════════════════════════════

                            DISCLAIMER
────────────────────────────────────────────────────────────────────────────

This automated scan provides a preliminary security assessment. It does not
replace a comprehensive security audit performed by qualified professionals.
Manual testing and additional security measures may be required.

For critical applications, please consult with a security expert.

════════════════════════════════════════════════════════════════════════════

                        END OF REPORT
                        
`;

    return report;
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Security Score Card */}
      <Card className="border-2">
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <CardTitle className="text-2xl">Security Score</CardTitle>
              <CardDescription className="text-lg mt-1">{scan.domain}</CardDescription>
            </div>
            <div className="flex items-center gap-4">
              <Button onClick={downloadReport} variant="outline" size="lg" className="gap-2">
                <Download className="h-5 w-5" />
                Download Report (TXT)
              </Button>
              <div className={`text-6xl font-bold ${getScoreColor(scan.security_score)}`}>
                {scan.security_score}
                <span className="text-2xl text-muted-foreground">/100</span>
              </div>
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