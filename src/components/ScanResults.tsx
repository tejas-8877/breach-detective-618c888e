import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Shield, AlertTriangle, CheckCircle, XCircle, Info, Download } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import { AttackGraphVisualization } from "./AttackGraphVisualization";
import { OSINTFindings } from "./OSINTFindings";
import { EndpointsList } from "./EndpointsList";

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
    const criticalCount = foundVulnerabilities.filter(v => v.severity === 'critical').length;
    const highCount = foundVulnerabilities.filter(v => v.severity === 'high').length;
    const mediumCount = foundVulnerabilities.filter(v => v.severity === 'medium').length;
    const lowCount = foundVulnerabilities.filter(v => v.severity === 'low').length;
    const infoCount = foundVulnerabilities.filter(v => v.severity === 'info').length;

    // Group vulnerabilities by OWASP category
    const owaspGroups = foundVulnerabilities.reduce((acc, vuln) => {
      const category = vuln.category;
      if (!acc[category]) acc[category] = [];
      acc[category].push(vuln);
      return acc;
    }, {} as Record<string, Vulnerability[]>);

    let report = `
${'='.repeat(80)}
           COMPREHENSIVE SECURITY VULNERABILITY SCAN REPORT
${'='.repeat(80)}

Domain: ${scan.domain}
Scan Date: ${date}
Scan ID: ${scan.id}
Report Generated: ${new Date().toISOString()}

${'='.repeat(80)}
                          EXECUTIVE SUMMARY
${'='.repeat(80)}

Security Score: ${scan.security_score}/100

Risk Assessment: ${
  scan.security_score >= 80 ? 'LOW RISK - Good security posture' :
  scan.security_score >= 60 ? 'MODERATE RISK - Some vulnerabilities need attention' :
  scan.security_score >= 40 ? 'HIGH RISK - Multiple security issues detected' :
  'CRITICAL RISK - Immediate action required'
}

Total Checks Performed: ${vulnerabilities.length}
Vulnerabilities Found: ${foundVulnerabilities.length}
Passed Checks: ${passedChecks.length}

Severity Breakdown:
  🔴 Critical: ${criticalCount} (Immediate action required)
  🟠 High: ${highCount} (Address within 24-48 hours)
  🟡 Medium: ${mediumCount} (Plan for next update)
  🔵 Low: ${lowCount} (Address in routine maintenance)
  ⚪ Info: ${infoCount} (Informational findings)

${'='.repeat(80)}
                    DETAILED VULNERABILITY FINDINGS
${'='.repeat(80)}

${foundVulnerabilities.length > 0 ? foundVulnerabilities.map((vuln, index) => `
${'─'.repeat(80)}
[${index + 1}] ${vuln.title}
${'─'.repeat(80)}

⚠️  Severity: ${vuln.severity.toUpperCase()}
📁 Category: ${vuln.category}

📋 Description:
${vuln.description}

💡 Recommendation:
${vuln.recommendation.includes('How to Fix:') 
  ? vuln.recommendation.split('How to Fix:')[0].trim()
  : vuln.recommendation}

${vuln.recommendation.includes('How to Fix:') ? `
🔧 How to Fix:
${vuln.recommendation.split('How to Fix:')[1].trim()}
` : ''}
${'─'.repeat(80)}
`).join('\n') : 'No vulnerabilities detected!'}

${'='.repeat(80)}
                    VULNERABILITIES BY CATEGORY
${'='.repeat(80)}

${Object.entries(owaspGroups).map(([category, vulns]) => `
${category}:
${vulns.map((v, i) => `  ${i + 1}. [${v.severity.toUpperCase()}] ${v.title}`).join('\n')}
`).join('\n')}

${'='.repeat(80)}
                  PASSED SECURITY CHECKS (${passedChecks.length})
${'='.repeat(80)}

${passedChecks.map((vuln, index) => `✓ ${index + 1}. ${vuln.title} - ${vuln.category}`).join('\n')}

${'='.repeat(80)}
                        REMEDIATION ROADMAP
${'='.repeat(80)}

PHASE 1 - IMMEDIATE (Critical & High Severity):
${foundVulnerabilities.filter(v => v.severity === 'critical' || v.severity === 'high').map((v, i) => {
  const recommendation = v.recommendation.includes('How to Fix:') 
    ? v.recommendation.split('How to Fix:')[0].trim()
    : v.recommendation;
  return `  ${i + 1}. ${v.title}\n     Action: ${recommendation.split('.')[0]}.`;
}).join('\n') || '  ✓ No immediate action items'}

PHASE 2 - SHORT TERM (Medium Severity):
${foundVulnerabilities.filter(v => v.severity === 'medium').map((v, i) => {
  const recommendation = v.recommendation.includes('How to Fix:') 
    ? v.recommendation.split('How to Fix:')[0].trim()
    : v.recommendation;
  return `  ${i + 1}. ${v.title}\n     Action: ${recommendation.split('.')[0]}.`;
}).join('\n') || '  ✓ No short-term action items'}

PHASE 3 - LONG TERM (Low Severity):
${foundVulnerabilities.filter(v => v.severity === 'low').map((v, i) => {
  const recommendation = v.recommendation.includes('How to Fix:') 
    ? v.recommendation.split('How to Fix:')[0].trim()
    : v.recommendation;
  return `  ${i + 1}. ${v.title}\n     Action: ${recommendation.split('.')[0]}.`;
}).join('\n') || '  ✓ No long-term action items'}

${'='.repeat(80)}
                      OWASP TOP 10 2021 COVERAGE
${'='.repeat(80)}

This comprehensive scan covers the following OWASP Top 10 categories:

✓ A01:2021 - Broken Access Control
  - CORS Configuration
  - Directory Enumeration & Access Control
  
✓ A02:2021 - Cryptographic Failures
  - SSL/TLS Configuration
  - Mixed Content Detection
  
✓ A03:2021 - Injection
  - SQL Injection Testing
  - XSS Vulnerability Detection  
  - XXE (XML External Entity) Detection
  
✓ A04:2021 - Insecure Design
  - X-Frame-Options (Clickjacking Protection)
  
✓ A05:2021 - Security Misconfiguration
  - Security Headers Analysis
  - Server Information Disclosure
  
✓ A06:2021 - Vulnerable and Outdated Components
  - Framework and Library Detection
  
✓ A07:2021 - Identification and Authentication Failures
  - Cookie Security Analysis
  
✓ A08:2021 - Software and Data Integrity Failures
  - Subresource Integrity
  - Deserialization Vulnerability Checks
  
✓ A09:2021 - Security Logging and Monitoring Failures
  - Logging and Monitoring Assessment
  
✓ A10:2021 - Server-Side Request Forgery (SSRF)
  - SSRF Protection Assessment

${'='.repeat(80)}
                          COMPLIANCE NOTES
${'='.repeat(80)}

- Ensure findings are addressed according to your organization's security policy
- Document all remediation efforts for audit purposes
- Schedule regular security scans (recommended: monthly or after major updates)
- Consider professional penetration testing for critical applications
- Review and update security policies based on findings
- Maintain an inventory of all identified vulnerabilities
- Track remediation progress and validate fixes with re-scans

${'='.repeat(80)}
                            NEXT STEPS
${'='.repeat(80)}

1. Review all CRITICAL and HIGH severity findings immediately
2. Create tickets/tasks for each vulnerability in your tracking system
3. Assign remediation to appropriate team members
4. Set deadlines based on severity levels:
   - Critical: 24 hours
   - High: 48-72 hours
   - Medium: 1-2 weeks
   - Low: Next sprint/release cycle
5. Implement fixes following the "How to Fix" guidance
6. Re-scan after implementing fixes to verify remediation
7. Document lessons learned and update security practices
8. Schedule regular scans to maintain security posture

${'='.repeat(80)}
                     SECURITY BEST PRACTICES
${'='.repeat(80)}

General Recommendations:
- Implement a Security Development Lifecycle (SDL)
- Conduct regular security training for development teams
- Use automated security scanning in CI/CD pipelines
- Maintain up-to-date dependency management
- Implement Web Application Firewall (WAF)
- Enable DDoS protection services
- Use Content Delivery Network (CDN) with security features
- Implement rate limiting and request throttling
- Regular security audits and penetration testing
- Incident response plan and security monitoring

${'='.repeat(80)}
                            DISCLAIMER
${'='.repeat(80)}

This automated scan provides a baseline security assessment. It does NOT replace:

- Manual penetration testing by certified professionals
- Source code security reviews
- Architecture security analysis
- Business logic vulnerability assessment
- Social engineering and phishing assessments
- Physical security evaluation
- Third-party security audits

Limitations:
- Tests performed are from external perspective only
- Some vulnerabilities require authenticated access to detect
- Custom application logic vulnerabilities may not be detected
- Zero-day vulnerabilities are not included
- Results may contain false positives requiring manual verification

For comprehensive security assurance, engage qualified security professionals
for in-depth testing, code review, and assessment tailored to your application.

${'='.repeat(80)}
                          END OF REPORT
${'='.repeat(80)}

Generated by: Advanced Web Security Vulnerability Scanner
Report Version: 2.0
Scan Engine: OWASP Top 10 Compliance Scanner
Contact: For questions about this report, consult your security team
`;

    return report.trim();
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

      {/* Advanced Security Features */}
      <div className="space-y-6 mt-6">
        <AttackGraphVisualization scanId={scanId} />
        <OSINTFindings scanId={scanId} />
        <EndpointsList scanId={scanId} />
      </div>
    </div>
  );
};