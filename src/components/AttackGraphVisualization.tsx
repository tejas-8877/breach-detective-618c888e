import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, ArrowRight, Target } from "lucide-react";

interface AttackStep {
  step: number;
  action: string;
  vulnerability: string;
  impact: string;
}

interface AttackPath {
  id: string;
  vulnerability_ids: string[];
  attack_steps: AttackStep[];
  impact_score: number;
  exploitability: string;
}

interface AttackGraphVisualizationProps {
  scanId: string;
}

export const AttackGraphVisualization = ({ scanId }: AttackGraphVisualizationProps) => {
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAttackPaths = async () => {
      try {
        const { supabase } = await import("@/integrations/supabase/client");
        const { data, error } = await supabase
          .from('attack_paths')
          .select('*')
          .eq('scan_id', scanId);

        if (error) throw error;
        setAttackPaths((data || []).map(item => ({
          ...item,
          attack_steps: item.attack_steps as unknown as AttackStep[]
        })));
      } catch (error) {
        console.error('Error fetching attack paths:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchAttackPaths();
  }, [scanId]);

  const getExploitabilityColor = (exploitability: string) => {
    switch (exploitability) {
      case 'critical': return 'destructive';
      case 'high': return 'destructive';
      case 'medium': return 'default';
      case 'low': return 'secondary';
      default: return 'secondary';
    }
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            Attack Graph Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">Loading attack paths...</p>
        </CardContent>
      </Card>
    );
  }

  if (attackPaths.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Target className="h-5 w-5" />
            Attack Graph Analysis
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">No attack paths identified.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Target className="h-5 w-5" />
          Attack Graph Analysis
        </CardTitle>
        <p className="text-sm text-muted-foreground mt-2">
          Visual representation of how attackers can chain vulnerabilities together
        </p>
      </CardHeader>
      <CardContent className="space-y-6">
        {attackPaths.map((path, pathIndex) => (
          <div key={path.id} className="border rounded-lg p-4 space-y-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-destructive" />
                <h3 className="font-semibold">Attack Chain #{pathIndex + 1}</h3>
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={getExploitabilityColor(path.exploitability)}>
                  {path.exploitability} exploitability
                </Badge>
                <Badge variant="outline">
                  Impact: {path.impact_score}/10
                </Badge>
              </div>
            </div>

            <div className="space-y-3">
              {path.attack_steps.map((step, stepIndex) => (
                <div key={stepIndex}>
                  <div className="flex items-start gap-3">
                    <div className="flex-shrink-0 w-8 h-8 rounded-full bg-primary/10 flex items-center justify-center text-sm font-medium">
                      {step.step}
                    </div>
                    <div className="flex-1 space-y-1">
                      <p className="font-medium">{step.action}</p>
                      <p className="text-sm text-muted-foreground">
                        Exploits: {step.vulnerability}
                      </p>
                      <p className="text-sm text-destructive">
                        Impact: {step.impact}
                      </p>
                    </div>
                  </div>
                  {stepIndex < path.attack_steps.length - 1 && (
                    <div className="ml-4 mt-2 mb-2 flex items-center gap-2 text-muted-foreground">
                      <ArrowRight className="h-4 w-4" />
                      <span className="text-xs">Then attacker can...</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
};
