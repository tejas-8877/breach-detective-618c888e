import { useState } from "react";
import { ScanForm } from "@/components/ScanForm";
import { ScanResults } from "@/components/ScanResults";
import { ScanHistory } from "@/components/ScanHistory";
import { Shield, Lock, Bug, FileCheck } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const Index = () => {
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-background to-secondary/20">
      {/* Header */}
      <header className="border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 py-6">
          <div className="flex items-center space-x-3">
            <Shield className="h-8 w-8 text-primary" />
            <div>
              <h1 className="text-2xl font-bold">Breach Detective</h1>
              <p className="text-sm text-muted-foreground">Advanced Web Vulnerability Scanner</p>
            </div>
          </div>
        </div>
      </header>

      <main className="container mx-auto px-4 py-12">
        {/* Hero Section */}
        {!currentScanId && (
          <section className="text-center mb-16">
            <div className="inline-flex items-center space-x-2 bg-primary/10 px-4 py-2 rounded-full mb-6">
              <Lock className="h-4 w-4 text-primary" />
              <span className="text-sm font-medium text-primary">25+ Security Checks</span>
            </div>
            <h2 className="text-4xl md:text-5xl font-bold mb-4">
              Scan Your Website for Vulnerabilities
            </h2>
            <p className="text-xl text-muted-foreground mb-4 max-w-2xl mx-auto">
              Get a comprehensive security analysis with actionable recommendations to protect your website
            </p>
            <p className="text-sm text-muted-foreground mb-8">
              💡 Tip: Some sites block scanners. Try well-known domains like google.com or github.com for best results
            </p>

            {/* Feature Cards */}
            <div className="grid md:grid-cols-3 gap-6 mb-12 max-w-4xl mx-auto">
              <div className="bg-card p-6 rounded-lg border">
                <Bug className="h-10 w-10 text-primary mx-auto mb-3" />
                <h3 className="font-semibold mb-2">25+ Checks</h3>
                <p className="text-sm text-muted-foreground">
                  Comprehensive scanning for SSL, headers, cookies, and more
                </p>
              </div>
              <div className="bg-card p-6 rounded-lg border">
                <FileCheck className="h-10 w-10 text-primary mx-auto mb-3" />
                <h3 className="font-semibold mb-2">Detailed Reports</h3>
                <p className="text-sm text-muted-foreground">
                  Get actionable recommendations for every vulnerability
                </p>
              </div>
              <div className="bg-card p-6 rounded-lg border">
                <Shield className="h-10 w-10 text-primary mx-auto mb-3" />
                <h3 className="font-semibold mb-2">Security Score</h3>
                <p className="text-sm text-muted-foreground">
                  Instant security rating from 0-100 based on findings
                </p>
              </div>
            </div>

            <ScanForm onScanComplete={setCurrentScanId} />
          </section>
        )}

        {/* Results and History */}
        <Tabs value={currentScanId ? "results" : "history"} className="w-full">
          {currentScanId && (
            <TabsList className="grid w-full max-w-md mx-auto grid-cols-2 mb-8">
              <TabsTrigger value="results" onClick={() => {}}>
                Scan Results
              </TabsTrigger>
              <TabsTrigger value="history" onClick={() => setCurrentScanId(null)}>
                History
              </TabsTrigger>
            </TabsList>
          )}

          <TabsContent value="results">
            {currentScanId && <ScanResults scanId={currentScanId} />}
          </TabsContent>

          <TabsContent value="history">
            <div className="max-w-4xl mx-auto">
              <ScanHistory onViewScan={setCurrentScanId} />
            </div>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t mt-20 py-8">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p>Breach Detective - Educational vulnerability scanner for college projects</p>
          <p className="mt-2">Always seek permission before scanning third-party websites</p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
