-- Create scans table to store scan history
CREATE TABLE public.scans (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  domain TEXT NOT NULL,
  security_score INTEGER NOT NULL,
  vulnerabilities_found INTEGER NOT NULL,
  scan_status TEXT NOT NULL DEFAULT 'completed',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Create vulnerabilities table to store detailed vulnerability findings
CREATE TABLE public.vulnerabilities (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  severity TEXT NOT NULL,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  found BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

-- Enable Row Level Security
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Create policies for public access (no auth required for this demo)
CREATE POLICY "Anyone can view scans" 
ON public.scans 
FOR SELECT 
USING (true);

CREATE POLICY "Anyone can create scans" 
ON public.scans 
FOR INSERT 
WITH CHECK (true);

CREATE POLICY "Anyone can view vulnerabilities" 
ON public.vulnerabilities 
FOR SELECT 
USING (true);

CREATE POLICY "Anyone can create vulnerabilities" 
ON public.vulnerabilities 
FOR INSERT 
WITH CHECK (true);

-- Create index for better performance
CREATE INDEX idx_vulnerabilities_scan_id ON public.vulnerabilities(scan_id);
CREATE INDEX idx_scans_created_at ON public.scans(created_at DESC);