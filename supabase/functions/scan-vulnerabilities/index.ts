import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.3';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface VulnerabilityCheck {
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  recommendation: string;
  found: boolean;
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { domain } = await req.json();
    
    if (!domain) {
      throw new Error('Domain is required');
    }

    console.log(`Starting scan for domain: ${domain}`);

    // Initialize Supabase client
    const supabaseUrl = Deno.env.get('SUPABASE_URL')!;
    const supabaseKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
    const supabase = createClient(supabaseUrl, supabaseKey);

    // Normalize domain
    const normalizedDomain = domain.replace(/^https?:\/\//, '').replace(/\/$/, '');
    const httpsUrl = `https://${normalizedDomain}`;
    const httpUrl = `http://${normalizedDomain}`;

    const vulnerabilities: VulnerabilityCheck[] = [];

    // Helper function to fetch with timeout
    const fetchWithTimeout = async (url: string, options: RequestInit = {}, timeoutMs = 10000) => {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      
      try {
        const response = await fetch(url, {
          ...options,
          signal: controller.signal,
        });
        clearTimeout(timeout);
        return response;
      } catch (error) {
        clearTimeout(timeout);
        throw error;
      }
    };

    // Perform vulnerability checks
    try {
      let response;
      try {
        response = await fetchWithTimeout(httpsUrl, {
          method: 'GET',
          redirect: 'manual',
        }, 10000);
      } catch (fetchError) {
        // If HTTPS fails, try HTTP
        console.log('HTTPS fetch failed, trying HTTP:', fetchError);
        try {
          response = await fetchWithTimeout(httpUrl, {
            method: 'GET',
            redirect: 'manual',
          }, 10000);
        } catch (httpError) {
          throw new Error('Unable to connect to domain. The site may be blocking automated requests or is unreachable. Try popular domains like google.com, github.com, or cloudflare.com');
        }
      }

      const headers = response.headers;

      // 1. SSL/TLS Check
      vulnerabilities.push({
        category: 'Transport Security',
        severity: 'critical',
        title: 'SSL/TLS Certificate',
        description: 'Website uses HTTPS encryption',
        recommendation: 'Ensure SSL certificate is valid and up to date',
        found: httpsUrl.startsWith('https'),
      });

      // 2. HSTS Header
      const hasHSTS = headers.has('strict-transport-security');
      vulnerabilities.push({
        category: 'Transport Security',
        severity: 'high',
        title: 'HTTP Strict Transport Security (HSTS)',
        description: hasHSTS ? 'HSTS header is present' : 'Missing HSTS header',
        recommendation: 'Enable HSTS to force HTTPS connections: Strict-Transport-Security: max-age=31536000; includeSubDomains',
        found: !hasHSTS,
      });

      // 3. X-Frame-Options
      const hasXFrame = headers.has('x-frame-options');
      vulnerabilities.push({
        category: 'Clickjacking Protection',
        severity: 'medium',
        title: 'X-Frame-Options Header',
        description: hasXFrame ? 'Clickjacking protection enabled' : 'Missing X-Frame-Options header',
        recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking',
        found: !hasXFrame,
      });

      // 4. X-Content-Type-Options
      const hasContentType = headers.has('x-content-type-options');
      vulnerabilities.push({
        category: 'MIME Sniffing Protection',
        severity: 'medium',
        title: 'X-Content-Type-Options Header',
        description: hasContentType ? 'MIME sniffing protection enabled' : 'Missing X-Content-Type-Options header',
        recommendation: 'Add X-Content-Type-Options: nosniff to prevent MIME type sniffing',
        found: !hasContentType,
      });

      // 5. X-XSS-Protection
      const hasXSS = headers.has('x-xss-protection');
      vulnerabilities.push({
        category: 'XSS Protection',
        severity: 'medium',
        title: 'X-XSS-Protection Header',
        description: hasXSS ? 'XSS filter enabled' : 'Missing X-XSS-Protection header',
        recommendation: 'Add X-XSS-Protection: 1; mode=block to enable XSS filtering',
        found: !hasXSS,
      });

      // 6. Content-Security-Policy
      const hasCSP = headers.has('content-security-policy');
      vulnerabilities.push({
        category: 'Content Security',
        severity: 'high',
        title: 'Content Security Policy (CSP)',
        description: hasCSP ? 'CSP header is configured' : 'Missing Content-Security-Policy header',
        recommendation: 'Implement a strict CSP to prevent XSS and data injection attacks',
        found: !hasCSP,
      });

      // 7. Referrer-Policy
      const hasReferrer = headers.has('referrer-policy');
      vulnerabilities.push({
        category: 'Privacy',
        severity: 'low',
        title: 'Referrer-Policy Header',
        description: hasReferrer ? 'Referrer policy is set' : 'Missing Referrer-Policy header',
        recommendation: 'Add Referrer-Policy: strict-origin-when-cross-origin to control referrer information',
        found: !hasReferrer,
      });

      // 8. Permissions-Policy
      const hasPermissions = headers.has('permissions-policy');
      vulnerabilities.push({
        category: 'Feature Control',
        severity: 'low',
        title: 'Permissions-Policy Header',
        description: hasPermissions ? 'Permissions policy is configured' : 'Missing Permissions-Policy header',
        recommendation: 'Add Permissions-Policy to control browser features',
        found: !hasPermissions,
      });

      // 9. Server Information Disclosure
      const serverHeader = headers.get('server');
      const hasServerInfo = !!(serverHeader && serverHeader.length > 0);
      vulnerabilities.push({
        category: 'Information Disclosure',
        severity: 'low',
        title: 'Server Header Exposure',
        description: hasServerInfo ? `Server information exposed: ${serverHeader}` : 'Server header is hidden',
        recommendation: 'Remove or obfuscate Server header to hide server information',
        found: hasServerInfo,
      });

      // 10. X-Powered-By Header
      const hasPoweredBy = headers.has('x-powered-by');
      vulnerabilities.push({
        category: 'Information Disclosure',
        severity: 'low',
        title: 'X-Powered-By Header',
        description: hasPoweredBy ? 'Technology stack exposed' : 'X-Powered-By header is hidden',
        recommendation: 'Remove X-Powered-By header to hide technology information',
        found: hasPoweredBy,
      });

      // 11. Cache-Control
      const hasCacheControl = headers.has('cache-control');
      vulnerabilities.push({
        category: 'Caching',
        severity: 'low',
        title: 'Cache-Control Header',
        description: hasCacheControl ? 'Cache control is configured' : 'Missing Cache-Control header',
        recommendation: 'Configure Cache-Control headers appropriately for sensitive pages',
        found: !hasCacheControl,
      });

      // 12. CORS Configuration
      const corsHeader = headers.get('access-control-allow-origin');
      const hasWildcardCORS = corsHeader === '*';
      vulnerabilities.push({
        category: 'CORS Security',
        severity: hasWildcardCORS ? 'medium' : 'info',
        title: 'CORS Configuration',
        description: hasWildcardCORS ? 'Wildcard CORS policy detected (*)' : 'CORS policy is restrictive or not set',
        recommendation: 'Avoid using wildcard (*) in Access-Control-Allow-Origin for sensitive resources',
        found: hasWildcardCORS,
      });

      // 13-15. Cookie Security Checks
      const setCookieHeaders = headers.get('set-cookie') || '';
      const hasSecureCookies = setCookieHeaders.toLowerCase().includes('secure');
      const hasHttpOnly = setCookieHeaders.toLowerCase().includes('httponly');
      const hasSameSite = setCookieHeaders.toLowerCase().includes('samesite');

      if (setCookieHeaders) {
        vulnerabilities.push({
          category: 'Cookie Security',
          severity: 'high',
          title: 'Secure Cookie Flag',
          description: hasSecureCookies ? 'Cookies have Secure flag' : 'Cookies missing Secure flag',
          recommendation: 'Add Secure flag to all cookies to ensure they are only sent over HTTPS',
          found: !hasSecureCookies,
        });

        vulnerabilities.push({
          category: 'Cookie Security',
          severity: 'high',
          title: 'HttpOnly Cookie Flag',
          description: hasHttpOnly ? 'Cookies have HttpOnly flag' : 'Cookies missing HttpOnly flag',
          recommendation: 'Add HttpOnly flag to prevent JavaScript access to sensitive cookies',
          found: !hasHttpOnly,
        });

        vulnerabilities.push({
          category: 'Cookie Security',
          severity: 'medium',
          title: 'SameSite Cookie Attribute',
          description: hasSameSite ? 'Cookies have SameSite attribute' : 'Cookies missing SameSite attribute',
          recommendation: 'Add SameSite attribute to cookies to prevent CSRF attacks',
          found: !hasSameSite,
        });
      }

      // 16. HTTP to HTTPS Redirect
      try {
        const httpResponse = await fetchWithTimeout(httpUrl, { redirect: 'manual' }, 5000);
        const redirectsToHTTPS = httpResponse.status >= 300 && httpResponse.status < 400 && 
          httpResponse.headers.get('location')?.startsWith('https://');
        
        vulnerabilities.push({
          category: 'Transport Security',
          severity: 'high',
          title: 'HTTP to HTTPS Redirect',
          description: redirectsToHTTPS ? 'HTTP traffic redirects to HTTPS' : 'No automatic HTTPS redirect',
          recommendation: 'Redirect all HTTP traffic to HTTPS automatically',
          found: !redirectsToHTTPS,
        });
      } catch (e) {
        console.log('HTTP redirect check failed:', e);
      }

      // 17. robots.txt Check
      try {
        const robotsResponse = await fetchWithTimeout(`${httpsUrl}/robots.txt`, {}, 5000);
        const robotsText = await robotsResponse.text();
        const hasDisallow = robotsText.includes('Disallow:');
        
        vulnerabilities.push({
          category: 'Information Disclosure',
          severity: 'info',
          title: 'robots.txt Configuration',
          description: hasDisallow ? 'robots.txt contains restrictions' : 'robots.txt may expose directory structure',
          recommendation: 'Review robots.txt for sensitive path disclosure',
          found: !hasDisallow,
        });
      } catch (e) {
        console.log('robots.txt check failed:', e);
      }

      // 18. security.txt Check
      try {
        const securityResponse = await fetchWithTimeout(`${httpsUrl}/.well-known/security.txt`, {}, 5000);
        const hasSecurityTxt = securityResponse.ok;
        
        vulnerabilities.push({
          category: 'Security Contact',
          severity: 'info',
          title: 'security.txt File',
          description: hasSecurityTxt ? 'security.txt file is present' : 'Missing security.txt file',
          recommendation: 'Add security.txt file to provide security contact information',
          found: !hasSecurityTxt,
        });
      } catch (e) {
        console.log('security.txt check failed:', e);
      }

      // 19. Mixed Content Check
      const bodyText = await response.text();
      const hasMixedContent = bodyText.includes('http://') && httpsUrl.startsWith('https://');
      vulnerabilities.push({
        category: 'Mixed Content',
        severity: hasMixedContent ? 'high' : 'info',
        title: 'Mixed Content Resources',
        description: hasMixedContent ? 'HTTP resources found on HTTPS page' : 'No obvious mixed content detected',
        recommendation: 'Ensure all resources are loaded over HTTPS',
        found: hasMixedContent,
      });

      // 20. Directory Listing Check
      vulnerabilities.push({
        category: 'Information Disclosure',
        severity: 'medium',
        title: 'Directory Listing',
        description: 'Directory listing check requires manual verification',
        recommendation: 'Ensure directory listing is disabled on your web server',
        found: false,
      });

      // 21. Error Message Disclosure
      const hasDetailedErrors = bodyText.toLowerCase().includes('error') && 
        (bodyText.includes('stack trace') || bodyText.includes('exception'));
      vulnerabilities.push({
        category: 'Information Disclosure',
        severity: 'medium',
        title: 'Error Message Disclosure',
        description: hasDetailedErrors ? 'Detailed error messages detected' : 'Error handling appears secure',
        recommendation: 'Ensure error messages do not expose sensitive information',
        found: hasDetailedErrors,
      });

      // 22. Feature-Policy (deprecated but still checked)
      const hasFeaturePolicy = headers.has('feature-policy');
      vulnerabilities.push({
        category: 'Feature Control',
        severity: 'info',
        title: 'Feature-Policy Header (Deprecated)',
        description: hasFeaturePolicy ? 'Using deprecated Feature-Policy' : 'Not using deprecated Feature-Policy',
        recommendation: 'Migrate to Permissions-Policy instead of Feature-Policy',
        found: hasFeaturePolicy,
      });

      // 23. Clear-Site-Data
      const hasClearSiteData = headers.has('clear-site-data');
      vulnerabilities.push({
        category: 'Privacy',
        severity: 'info',
        title: 'Clear-Site-Data Header',
        description: hasClearSiteData ? 'Clear-Site-Data header present' : 'No Clear-Site-Data header',
        recommendation: 'Consider using Clear-Site-Data on logout endpoints',
        found: false,
      });

      // 24. Cross-Origin Headers
      const hasCoep = headers.has('cross-origin-embedder-policy');
      const hasCoop = headers.has('cross-origin-opener-policy');
      const hasCorp = headers.has('cross-origin-resource-policy');
      
      vulnerabilities.push({
        category: 'Cross-Origin Security',
        severity: 'low',
        title: 'Cross-Origin Policies',
        description: (hasCoep && hasCoop && hasCorp) ? 'Cross-origin policies configured' : 'Missing some cross-origin headers',
        recommendation: 'Implement COEP, COOP, and CORP headers for enhanced isolation',
        found: !(hasCoep && hasCoop && hasCorp),
      });

      // 25. Subresource Integrity
      const hasSRI = bodyText.includes('integrity="sha');
      vulnerabilities.push({
        category: 'Resource Integrity',
        severity: 'low',
        title: 'Subresource Integrity (SRI)',
        description: hasSRI ? 'SRI detected on external resources' : 'No SRI detected',
        recommendation: 'Use SRI for external scripts and stylesheets',
        found: !hasSRI,
      });

    } catch (error) {
      console.error('Scan error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to scan domain: ${errorMessage}`);
    }

    // Calculate security score
    const totalVulnerabilities = vulnerabilities.length;
    const foundVulnerabilities = vulnerabilities.filter(v => v.found).length;
    const criticalCount = vulnerabilities.filter(v => v.found && v.severity === 'critical').length;
    const highCount = vulnerabilities.filter(v => v.found && v.severity === 'high').length;
    const mediumCount = vulnerabilities.filter(v => v.found && v.severity === 'medium').length;
    
    // Scoring algorithm: Start with 100, deduct points based on severity
    let securityScore = 100;
    securityScore -= criticalCount * 20;
    securityScore -= highCount * 10;
    securityScore -= mediumCount * 5;
    securityScore -= vulnerabilities.filter(v => v.found && v.severity === 'low').length * 2;
    securityScore = Math.max(0, securityScore); // Don't go below 0

    console.log(`Scan complete. Score: ${securityScore}, Vulnerabilities found: ${foundVulnerabilities}`);

    // Save to database
    const { data: scanData, error: scanError } = await supabase
      .from('scans')
      .insert({
        domain: normalizedDomain,
        security_score: securityScore,
        vulnerabilities_found: foundVulnerabilities,
        scan_status: 'completed',
      })
      .select()
      .single();

    if (scanError) {
      console.error('Error saving scan:', scanError);
      throw scanError;
    }

    // Save vulnerabilities
    const vulnerabilityRecords = vulnerabilities.map(v => ({
      scan_id: scanData.id,
      category: v.category,
      severity: v.severity,
      title: v.title,
      description: v.description,
      recommendation: v.recommendation,
      found: v.found,
    }));

    const { error: vulnError } = await supabase
      .from('vulnerabilities')
      .insert(vulnerabilityRecords);

    if (vulnError) {
      console.error('Error saving vulnerabilities:', vulnError);
      throw vulnError;
    }

    return new Response(
      JSON.stringify({
        scan_id: scanData.id,
        domain: normalizedDomain,
        security_score: securityScore,
        vulnerabilities_found: foundVulnerabilities,
        total_checks: totalVulnerabilities,
        vulnerabilities: vulnerabilities,
      }),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );

  } catch (error) {
    console.error('Error in scan-vulnerabilities function:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { 
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  }
});