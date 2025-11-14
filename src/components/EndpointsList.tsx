import { useEffect, useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Network, Clock, FileCode } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface Endpoint {
  id: string;
  path: string;
  method: string;
  status_code: number;
  discovered_by: string;
  response_time: number;
  content_type: string;
}

interface EndpointsListProps {
  scanId: string;
}

export const EndpointsList = ({ scanId }: EndpointsListProps) => {
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchEndpoints = async () => {
      try {
        const { supabase } = await import("@/integrations/supabase/client");
        const { data, error } = await supabase
          .from('endpoints')
          .select('*')
          .eq('scan_id', scanId)
          .order('status_code');

        if (error) throw error;
        setEndpoints(data || []);
      } catch (error) {
        console.error('Error fetching endpoints:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchEndpoints();
  }, [scanId]);

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'default';
    if (status >= 300 && status < 400) return 'secondary';
    if (status >= 400 && status < 500) return 'destructive';
    return 'outline';
  };

  const getDiscoveryBadge = (discoveredBy: string) => {
    switch (discoveredBy) {
      case 'wordlist': return <Badge variant="outline">Wordlist</Badge>;
      case 'ml': return <Badge variant="default">ML Detection</Badge>;
      case 'crawl': return <Badge variant="secondary">Crawl</Badge>;
      default: return <Badge variant="outline">{discoveredBy}</Badge>;
    }
  };

  if (loading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Network className="h-5 w-5" />
            Discovered Endpoints
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">Discovering endpoints...</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Network className="h-5 w-5" />
          Discovered Endpoints ({endpoints.length})
        </CardTitle>
        <p className="text-sm text-muted-foreground mt-2">
          Hidden endpoints detected using wordlists and ML-based pattern detection
        </p>
      </CardHeader>
      <CardContent>
        {endpoints.length === 0 ? (
          <p className="text-muted-foreground">No additional endpoints discovered.</p>
        ) : (
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Path</TableHead>
                  <TableHead>Method</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Discovery</TableHead>
                  <TableHead>Response Time</TableHead>
                  <TableHead>Content Type</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {endpoints.map((endpoint) => (
                  <TableRow key={endpoint.id}>
                    <TableCell className="font-mono text-sm">{endpoint.path}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{endpoint.method}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={getStatusColor(endpoint.status_code)}>
                        {endpoint.status_code}
                      </Badge>
                    </TableCell>
                    <TableCell>{getDiscoveryBadge(endpoint.discovered_by)}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        <span className="text-sm">{endpoint.response_time}ms</span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1">
                        <FileCode className="h-3 w-3" />
                        <span className="text-xs">{endpoint.content_type || 'N/A'}</span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        )}
      </CardContent>
    </Card>
  );
};
