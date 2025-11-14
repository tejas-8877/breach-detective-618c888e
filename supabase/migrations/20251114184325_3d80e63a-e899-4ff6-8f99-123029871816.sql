-- Create endpoints table to store discovered endpoints
CREATE TABLE IF NOT EXISTS public.endpoints (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  path TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'GET',
  status_code INTEGER,
  discovered_by TEXT NOT NULL, -- 'wordlist', 'ml', 'crawl'
  response_time INTEGER, -- in milliseconds
  content_type TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create attack_paths table to store attack graph data
CREATE TABLE IF NOT EXISTS public.attack_paths (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  vulnerability_ids UUID[] NOT NULL,
  attack_steps JSONB NOT NULL, -- [{step: 1, action: "...", vulnerability: "..."}]
  impact_score INTEGER NOT NULL DEFAULT 0,
  exploitability TEXT NOT NULL, -- 'low', 'medium', 'high', 'critical'
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create osint_findings table to store OSINT exposure data
CREATE TABLE IF NOT EXISTS public.osint_findings (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  finding_type TEXT NOT NULL, -- 'leaked_credentials', 'exposed_api_keys', 'data_breach', 'subdomain', 'email'
  description TEXT NOT NULL,
  severity TEXT NOT NULL, -- 'info', 'low', 'medium', 'high', 'critical'
  source TEXT NOT NULL, -- where the finding was discovered
  data JSONB, -- additional structured data
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable RLS on new tables
ALTER TABLE public.endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.attack_paths ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.osint_findings ENABLE ROW LEVEL SECURITY;

-- Create policies for endpoints
CREATE POLICY "Anyone can view endpoints"
  ON public.endpoints
  FOR SELECT
  USING (true);

CREATE POLICY "Anyone can create endpoints"
  ON public.endpoints
  FOR INSERT
  WITH CHECK (true);

-- Create policies for attack_paths
CREATE POLICY "Anyone can view attack_paths"
  ON public.attack_paths
  FOR SELECT
  USING (true);

CREATE POLICY "Anyone can create attack_paths"
  ON public.attack_paths
  FOR INSERT
  WITH CHECK (true);

-- Create policies for osint_findings
CREATE POLICY "Anyone can view osint_findings"
  ON public.osint_findings
  FOR SELECT
  USING (true);

CREATE POLICY "Anyone can create osint_findings"
  ON public.osint_findings
  FOR INSERT
  WITH CHECK (true);

-- Create indexes for better query performance
CREATE INDEX idx_endpoints_scan_id ON public.endpoints(scan_id);
CREATE INDEX idx_attack_paths_scan_id ON public.attack_paths(scan_id);
CREATE INDEX idx_osint_findings_scan_id ON public.osint_findings(scan_id);
CREATE INDEX idx_osint_findings_severity ON public.osint_findings(severity);