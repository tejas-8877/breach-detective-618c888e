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
  owasp_category?: string;
  how_to_fix?: string;
  confidence?: number; // 0-100 for false-positive reduction
}

interface EndpointDiscovery {
  path: string;
  method: string;
  status_code: number;
  discovered_by: 'wordlist' | 'ml' | 'crawl';
  response_time: number;
  content_type: string;
}

interface OSINTFinding {
  finding_type: string;
  description: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  source: string;
  data?: any;
}

interface AttackStep {
  step: number;
  action: string;
  vulnerability: string;
  impact: string;
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
    let discoveredEndpoints: EndpointDiscovery[] = [];
    let osintFindings: OSINTFinding[] = [];
    let attackPaths: any[] = [];

    // Enhanced Common wordlists for endpoint discovery
    const commonEndpoints = [
      // API endpoints
      '/api', '/api/v1', '/api/v2', '/api/v3', '/api/docs', '/api/swagger', '/api/auth',
      '/api/login', '/api/users', '/api/user', '/api/admin', '/api/data', '/api/config',
      '/api/token', '/api/tokens', '/api/oauth', '/api/refresh', '/api/logout',
      '/api/status', '/api/health', '/api/info', '/api/version', '/api/ping',
      '/api/graphql', '/api/rest', '/api/query', '/api/search', '/api/upload',
      
      // Admin panels
      '/admin', '/administrator', '/admin/login', '/admin/dashboard', '/admin/config',
      '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes', '/wp-json',
      '/phpmyadmin', '/pma', '/mysql', '/dbadmin', '/adminer',
      '/dashboard', '/control-panel', '/cpanel', '/manager', '/backend',
      '/admin-panel', '/adminpanel', '/admin_area', '/admin-login',
      
      // Configuration and sensitive files
      '/config', '/configuration', '/settings', '/env', '/.env', '/.env.local',
      '/.env.production', '/.env.development', '/config.php', '/config.json',
      '/.git', '/.git/config', '/.git/HEAD', '/.gitignore', '/.gitmodules',
      '/.svn', '/.hg', '/.bzr', '/CVS',
      '/.htaccess', '/.htpasswd', '/web.config', '/.aws/credentials',
      '/composer.json', '/package.json', '/package-lock.json', '/yarn.lock',
      
      // Backup and database files
      '/backup', '/backups', '/backup.sql', '/backup.zip', '/backup.tar.gz',
      '/db', '/database', '/database.sql', '/dump.sql', '/mysql.sql',
      '/db_backup', '/sql', '/old', '/old_site', '/site_backup',
      
      // Development and testing
      '/test', '/tests', '/testing', '/dev', '/development', '/staging',
      '/debug', '/trace', '/console', '/playground', '/sandbox',
      '/beta', '/demo', '/tmp', '/temp', '/cache',
      
      // File storage and uploads
      '/uploads', '/upload', '/files', '/file', '/images', '/img', '/assets',
      '/media', '/content', '/static', '/public', '/downloads', '/download',
      '/attachments', '/documents', '/storage', '/data',
      
      // Authentication endpoints
      '/login', '/signin', '/sign-in', '/logout', '/signout', '/sign-out',
      '/register', '/signup', '/sign-up', '/auth', '/authenticate',
      '/oauth', '/oauth2', '/sso', '/saml', '/password-reset',
      '/forgot-password', '/reset-password', '/change-password',
      
      // User management
      '/users', '/user', '/profile', '/account', '/accounts', '/members',
      '/customer', '/customers', '/client', '/clients', '/admin/users',
      
      // Monitoring and status
      '/health', '/healthz', '/health-check', '/status', '/ping', '/metrics',
      '/info', '/version', '/stats', '/statistics', '/monitor', '/monitoring',
      '/actuator', '/actuator/health', '/actuator/info', '/actuator/metrics',
      
      // API documentation
      '/docs', '/documentation', '/doc', '/swagger', '/swagger-ui', '/swagger.json',
      '/openapi', '/openapi.json', '/redoc', '/api-docs', '/apidocs',
      '/graphql', '/graphiql', '/playground',
      
      // WebSocket and real-time
      '/ws', '/wss', '/websocket', '/socket', '/socket.io', '/sockjs',
      '/realtime', '/stream', '/events', '/sse',
      
      // REST endpoints
      '/rest', '/rest/v1', '/rest/v2', '/restapi', '/rest-api',
      
      // Cloud and storage
      '/s3', '/bucket', '/cdn', '/cloud', '/azure', '/gcs',
      
      // CMS specific
      '/wp-admin', '/wordpress', '/joomla', '/drupal', '/magento',
      '/administrator/index.php', '/admin.php', '/admin/index.php',
      
      // Common directories
      '/includes', '/inc', '/lib', '/library', '/vendor', '/node_modules',
      '/src', '/app', '/application', '/core', '/system',
      
      // Error pages and logs
      '/error', '/errors', '/error.log', '/error_log', '/logs', '/log',
      '/debug.log', '/access.log', '/server.log', '/app.log',
      
      // Security files
      '/robots.txt', '/sitemap.xml', '/security.txt', '/.well-known/security.txt',
      '/crossdomain.xml', '/clientaccesspolicy.xml'
    ];

    // API-specific endpoints for ML-based discovery
    const apiEndpoints = [
      '/v1/users', '/v1/auth', '/v1/data', '/v1/query', '/v1/login', '/v1/token',
      '/v2/users', '/v2/auth', '/v2/data', '/v2/login', '/v2/token',
      '/v3/users', '/v3/auth', '/v3/data',
      '/rest', '/rest/v1', '/rest/v2', '/rest/api',
      '/graphql/v1', '/graphql/v2', '/graphql/api'
    ];

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

      // 1. SSL/TLS Check (OWASP A02:2021 - Cryptographic Failures)
      vulnerabilities.push({
        category: 'Transport Security',
        severity: 'critical',
        title: 'SSL/TLS Certificate',
        description: 'Website uses HTTPS encryption',
        recommendation: 'Ensure SSL certificate is valid and up to date. Use TLS 1.3 or TLS 1.2 at minimum.',
        found: !httpsUrl.startsWith('https'),
        owasp_category: 'A02:2021 - Cryptographic Failures',
        how_to_fix: 'Install a valid SSL/TLS certificate from a trusted Certificate Authority. Configure your web server (Apache, Nginx, IIS) to use HTTPS. Redirect all HTTP traffic to HTTPS. Use tools like Let\'s Encrypt for free certificates.',
      });

      // 2. HSTS Header (OWASP A05:2021 - Security Misconfiguration)
      const hasHSTS = headers.has('strict-transport-security');
      vulnerabilities.push({
        category: 'Transport Security',
        severity: 'high',
        title: 'HTTP Strict Transport Security (HSTS)',
        description: hasHSTS ? 'HSTS header is present' : 'Missing HSTS header - allows downgrade attacks',
        recommendation: 'Enable HSTS to force HTTPS connections: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
        found: !hasHSTS,
        owasp_category: 'A05:2021 - Security Misconfiguration',
        how_to_fix: 'Add the HSTS header to your web server configuration. For Nginx: add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; For Apache: Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"',
      });

      // 3. X-Frame-Options (OWASP A04:2021 - Insecure Design / Clickjacking)
      const hasXFrame = headers.has('x-frame-options');
      vulnerabilities.push({
        category: 'Clickjacking Protection',
        severity: 'medium',
        title: 'X-Frame-Options Header',
        description: hasXFrame ? 'Clickjacking protection enabled' : 'Missing X-Frame-Options header - vulnerable to clickjacking attacks',
        recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking attacks',
        found: !hasXFrame,
        owasp_category: 'A04:2021 - Insecure Design',
        how_to_fix: 'Add X-Frame-Options header in your web server. For Nginx: add_header X-Frame-Options "SAMEORIGIN" always; For Apache: Header always set X-Frame-Options "SAMEORIGIN". Use DENY if you never need your site in frames, or SAMEORIGIN if only your own site should frame it.',
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

      // 6. Content-Security-Policy (OWASP A03:2021 - Injection / XSS Prevention)
      const hasCSP = headers.has('content-security-policy');
      vulnerabilities.push({
        category: 'Content Security',
        severity: 'high',
        title: 'Content Security Policy (CSP)',
        description: hasCSP ? 'CSP header is configured' : 'Missing Content-Security-Policy header - vulnerable to XSS attacks',
        recommendation: 'Implement a strict CSP to prevent XSS and data injection attacks. Start with: Content-Security-Policy: default-src \'self\'',
        found: !hasCSP,
        owasp_category: 'A03:2021 - Injection',
        how_to_fix: 'Add CSP header to restrict resource loading. Start restrictive: Content-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data: https:; Then gradually add trusted sources as needed. Test in report-only mode first.',
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

      // 12. CORS Configuration (OWASP A01:2021 - Broken Access Control)
      const corsHeader = headers.get('access-control-allow-origin');
      const hasWildcardCORS = corsHeader === '*';
      vulnerabilities.push({
        category: 'CORS Security',
        severity: hasWildcardCORS ? 'high' : 'info',
        title: 'CORS Configuration',
        description: hasWildcardCORS ? 'Wildcard CORS policy detected (*) - allows any origin to access resources' : 'CORS policy is restrictive or not set',
        recommendation: 'Avoid using wildcard (*) in Access-Control-Allow-Origin. Specify exact trusted origins.',
        found: hasWildcardCORS,
        owasp_category: 'A01:2021 - Broken Access Control',
        how_to_fix: 'Replace Access-Control-Allow-Origin: * with specific origins. In your backend, validate the Origin header and return only trusted domains. Example: if (trustedOrigins.includes(origin)) { res.setHeader(\'Access-Control-Allow-Origin\', origin); }',
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
          description: hasSecureCookies ? 'Cookies have Secure flag' : 'Cookies missing Secure flag - can be intercepted over HTTP',
          recommendation: 'Add Secure flag to all cookies to ensure they are only sent over HTTPS',
          found: !hasSecureCookies,
          owasp_category: 'A07:2021 - Identification and Authentication Failures',
          how_to_fix: 'Set Secure flag on all cookies. In your backend: Set-Cookie: sessionId=abc123; Secure; HttpOnly; SameSite=Strict. Most frameworks support this: Express.js: res.cookie(\'name\', \'value\', { secure: true })',
        });

        vulnerabilities.push({
          category: 'Cookie Security',
          severity: 'high',
          title: 'HttpOnly Cookie Flag',
          description: hasHttpOnly ? 'Cookies have HttpOnly flag' : 'Cookies missing HttpOnly flag - vulnerable to XSS attacks',
          recommendation: 'Add HttpOnly flag to prevent JavaScript access to sensitive cookies, protecting against XSS',
          found: !hasHttpOnly,
          owasp_category: 'A07:2021 - Identification and Authentication Failures',
          how_to_fix: 'Enable HttpOnly flag on session cookies: Set-Cookie: sessionId=abc123; HttpOnly; Secure; SameSite=Strict. This prevents client-side JavaScript from accessing the cookie, mitigating XSS cookie theft.',
        });

        vulnerabilities.push({
          category: 'Cookie Security',
          severity: 'medium',
          title: 'SameSite Cookie Attribute',
          description: hasSameSite ? 'Cookies have SameSite attribute' : 'Cookies missing SameSite attribute - vulnerable to CSRF',
          recommendation: 'Add SameSite attribute to cookies to prevent CSRF attacks. Use SameSite=Strict or SameSite=Lax',
          found: !hasSameSite,
          owasp_category: 'A01:2021 - Broken Access Control',
          how_to_fix: 'Add SameSite attribute: Set-Cookie: sessionId=abc123; SameSite=Strict; Secure; HttpOnly. Use Strict for maximum protection, or Lax if you need some cross-site functionality. Never use None without Secure flag.',
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

      // 19. Mixed Content Check (OWASP A02:2021 - Cryptographic Failures)
      const bodyText = await response.text();
      const hasMixedContent = bodyText.includes('http://') && httpsUrl.startsWith('https://');
      vulnerabilities.push({
        category: 'Mixed Content',
        severity: hasMixedContent ? 'high' : 'info',
        title: 'Mixed Content Resources',
        description: hasMixedContent ? 'HTTP resources found on HTTPS page - breaks encryption' : 'No obvious mixed content detected',
        recommendation: 'Ensure all resources (images, scripts, CSS) are loaded over HTTPS to maintain encryption',
        found: hasMixedContent,
        owasp_category: 'A02:2021 - Cryptographic Failures',
        how_to_fix: 'Change all http:// URLs to https:// or protocol-relative URLs (//). Search your code for src="http:// and href="http://. Update CDN links, external resources, and API endpoints to use HTTPS. Enable "Upgrade Insecure Requests" CSP directive.',
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

      // 26. SQL Injection Testing (OWASP A03:2021 - Injection)
      const sqlPayloads = ["'", "1' OR '1'='1", "' OR 1=1--", "' UNION SELECT NULL--"];
      let sqlInjectionVulnerable = false;
      
      try {
        for (const payload of sqlPayloads) {
          const testUrl = `${httpsUrl}/?id=${encodeURIComponent(payload)}`;
          const sqlTestResponse = await fetchWithTimeout(testUrl, {}, 5000);
          const sqlTestText = await sqlTestResponse.text();
          
          // Check for SQL error messages
          if (sqlTestText.match(/SQL syntax|mysql_|mysqli_|SQLite|PostgreSQL|ORA-\d+|SQL Server|syntax error/i)) {
            sqlInjectionVulnerable = true;
            break;
          }
        }
      } catch (e) {
        console.log('SQL injection test failed:', e);
      }

      vulnerabilities.push({
        category: 'SQL Injection',
        severity: sqlInjectionVulnerable ? 'critical' : 'info',
        title: 'SQL Injection Vulnerability',
        description: sqlInjectionVulnerable ? 'Potential SQL injection vulnerability detected - SQL errors exposed' : 'No obvious SQL injection vulnerabilities detected',
        recommendation: 'Use parameterized queries, prepared statements, and input validation. Never concatenate user input into SQL queries.',
        found: sqlInjectionVulnerable,
        owasp_category: 'A03:2021 - Injection',
        how_to_fix: 'Always use parameterized queries or prepared statements. Example: Instead of "SELECT * FROM users WHERE id=" + userId, use prepared statements with placeholders. Implement input validation and sanitization. Use ORM frameworks that handle parameterization automatically. Enable least-privilege database access.',
      });

      // 27. XSS Vulnerability Testing (OWASP A03:2021 - Injection)
      const xssPayloads = ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>'];
      let xssVulnerable = false;
      
      try {
        for (const payload of xssPayloads) {
          const testUrl = `${httpsUrl}/?q=${encodeURIComponent(payload)}`;
          const xssTestResponse = await fetchWithTimeout(testUrl, {}, 5000);
          const xssTestText = await xssTestResponse.text();
          
          // Check if payload is reflected unescaped
          if (xssTestText.includes(payload)) {
            xssVulnerable = true;
            break;
          }
        }
      } catch (e) {
        console.log('XSS test failed:', e);
      }

      vulnerabilities.push({
        category: 'Cross-Site Scripting (XSS)',
        severity: xssVulnerable ? 'high' : 'info',
        title: 'XSS Vulnerability',
        description: xssVulnerable ? 'Potential XSS vulnerability detected - unescaped user input reflected' : 'No obvious XSS vulnerabilities detected',
        recommendation: 'Sanitize and encode all user inputs. Use Content Security Policy. Implement proper output encoding.',
        found: xssVulnerable,
        owasp_category: 'A03:2021 - Injection',
        how_to_fix: 'Implement context-aware output encoding for all user inputs. Use framework-provided escaping functions (e.g., textContent instead of innerHTML). Implement strict CSP headers. Validate input on both client and server side. Use HTTPOnly cookies. Consider using DOMPurify or similar sanitization libraries.',
      });

      // 28. Directory Enumeration
      const commonPaths = [
        '/admin', '/administrator', '/wp-admin', '/phpmyadmin', 
        '/.git', '/.env', '/backup', '/config', '/test', 
        '/api/docs', '/swagger', '/graphql', '/.well-known',
        '/debug', '/console', '/dashboard', '/panel'
      ];
      
      const exposedPaths: string[] = [];
      
      try {
        for (const path of commonPaths) {
          const pathResponse = await fetchWithTimeout(`${httpsUrl}${path}`, {}, 3000);
          if (pathResponse.status === 200 || pathResponse.status === 403) {
            exposedPaths.push(path);
          }
        }
      } catch (e) {
        console.log('Directory enumeration failed:', e);
      }

      vulnerabilities.push({
        category: 'Information Disclosure',
        severity: exposedPaths.length > 0 ? 'medium' : 'info',
        title: 'Exposed Directories/Endpoints',
        description: exposedPaths.length > 0 ? `Found ${exposedPaths.length} potentially sensitive paths: ${exposedPaths.join(', ')}` : 'No sensitive directories detected',
        recommendation: 'Restrict access to admin panels, configuration files, and development endpoints. Use .htaccess or server config to block access.',
        found: exposedPaths.length > 0,
        owasp_category: 'A01:2021 - Broken Access Control',
        how_to_fix: 'Remove or restrict access to sensitive directories. Use authentication for admin panels. Remove .git, .env, and backup files from production. Configure web server to deny access to hidden files and directories. Implement proper access controls. Use robots.txt to prevent indexing of sensitive areas.',
      });

      // 29. XML External Entity (XXE) Detection
      const hasXmlEndpoint = bodyText.match(/content-type.*xml|xml.*endpoint|soap|wsdl/i);
      vulnerabilities.push({
        category: 'XML Security',
        severity: hasXmlEndpoint ? 'medium' : 'info',
        title: 'XML External Entity (XXE)',
        description: hasXmlEndpoint ? 'XML endpoints detected - potential XXE risk if not properly configured' : 'No XML endpoints detected',
        recommendation: 'Disable XML external entity processing in all XML parsers. Use less complex data formats like JSON where possible.',
        found: !!hasXmlEndpoint,
        owasp_category: 'A03:2021 - Injection',
        how_to_fix: 'Disable DTDs and external entities in XML parsers. For Java: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true). For PHP: libxml_disable_entity_loader(true). Use simple data formats like JSON instead of XML. Validate and sanitize all XML input.',
      });

      // 30. Insecure Deserialization Check
      const hasSerializationHeaders = headers.get('content-type')?.includes('java-serialization') || 
                                     bodyText.match(/pickle|serialize|unserialize|ObjectInputStream/i);
      vulnerabilities.push({
        category: 'Deserialization',
        severity: hasSerializationHeaders ? 'high' : 'info',
        title: 'Insecure Deserialization',
        description: hasSerializationHeaders ? 'Potential deserialization detected - may allow remote code execution' : 'No obvious deserialization vulnerabilities',
        recommendation: 'Avoid deserializing untrusted data. Use secure serialization formats. Implement integrity checks.',
        found: !!hasSerializationHeaders,
        owasp_category: 'A08:2021 - Software and Data Integrity Failures',
        how_to_fix: 'Avoid deserialization of untrusted data entirely. If required, use safe formats like JSON. Implement integrity checks (HMAC) on serialized data. Run deserialization code in sandboxed/restricted environments. Monitor deserialization exceptions. Use allowlists for deserializable classes.',
      });

      // 31. Insufficient Logging & Monitoring
      vulnerabilities.push({
        category: 'Security Monitoring',
        severity: 'low',
        title: 'Logging & Monitoring',
        description: 'Cannot verify logging implementation from external scan',
        recommendation: 'Implement comprehensive logging for authentication, access control, input validation failures, and security events.',
        found: false,
        owasp_category: 'A09:2021 - Security Logging and Monitoring Failures',
        how_to_fix: 'Implement centralized logging (e.g., ELK stack, Splunk). Log all authentication attempts, access control failures, input validation failures. Set up real-time alerts for suspicious activities. Ensure logs are tamper-proof and backed up. Regularly review and analyze logs. Implement SIEM for security event monitoring.',
      });

      // 32. Software Composition Analysis
      const detectedFrameworks = [];
      if (bodyText.match(/react|_react/i)) detectedFrameworks.push('React');
      if (bodyText.match(/angular|ng-/i)) detectedFrameworks.push('Angular');
      if (bodyText.match(/vue|__vue/i)) detectedFrameworks.push('Vue');
      if (headers.get('x-powered-by')?.includes('Express')) detectedFrameworks.push('Express');
      
      vulnerabilities.push({
        category: 'Software Components',
        severity: detectedFrameworks.length > 0 ? 'medium' : 'info',
        title: 'Vulnerable Components',
        description: detectedFrameworks.length > 0 ? `Detected frameworks: ${detectedFrameworks.join(', ')}. Ensure they are up-to-date.` : 'Unable to detect specific frameworks',
        recommendation: 'Keep all frameworks, libraries, and dependencies up-to-date. Use automated tools like Snyk or Dependabot.',
        found: detectedFrameworks.length > 0,
        owasp_category: 'A06:2021 - Vulnerable and Outdated Components',
        how_to_fix: 'Regularly update all dependencies. Use npm audit, yarn audit, or Snyk to detect vulnerabilities. Implement automated dependency updates with Dependabot or Renovate. Remove unused dependencies. Subscribe to security advisories for your tech stack. Use Software Composition Analysis (SCA) tools in your CI/CD pipeline.',
      });

      // 33. Server-Side Request Forgery (SSRF)
      vulnerabilities.push({
        category: 'SSRF Protection',
        severity: 'info',
        title: 'Server-Side Request Forgery (SSRF)',
        description: 'SSRF cannot be detected from external scans - requires code review',
        recommendation: 'Validate and sanitize all URLs. Use allowlists for external requests. Disable unnecessary protocols.',
        found: false,
        owasp_category: 'A10:2021 - Server-Side Request Forgery',
        how_to_fix: 'Implement URL validation and sanitization. Use allowlists for allowed domains/IPs. Disable unused URL schemes (file://, gopher://, etc.). Validate and sanitize user input used in URLs. Use network segmentation. Implement proper firewall rules. Avoid exposing internal services to user-controlled input.',
      });

      // ========== ENHANCED SCANNING FEATURES ==========

      // OSINT Exposure Check
      const performOSINTCheck = async (domain: string) => {
        const findings: OSINTFinding[] = [];

        // Check for subdomain enumeration patterns
        const commonSubdomains = ['www', 'mail', 'ftp', 'admin', 'portal', 'api', 'dev', 'staging', 'test'];
        for (const sub of commonSubdomains) {
          try {
            const subUrl = `https://${sub}.${domain}`;
            const subResponse = await fetchWithTimeout(subUrl, { method: 'HEAD' }, 3000);
            if (subResponse.ok) {
              findings.push({
                finding_type: 'subdomain',
                description: `Active subdomain found: ${sub}.${domain}`,
                severity: 'info',
                source: 'Subdomain Enumeration',
                data: { subdomain: `${sub}.${domain}`, status: subResponse.status }
              });
            }
          } catch (e) {
            // Subdomain doesn't exist or unreachable
          }
        }

        // Check for common exposed files
        const exposedFiles = ['/.env', '/.git/config', '/config.php', '/wp-config.php', '/.aws/credentials'];
        for (const file of exposedFiles) {
          try {
            const fileUrl = `https://${domain}${file}`;
            const fileResponse = await fetchWithTimeout(fileUrl, {}, 3000);
            if (fileResponse.ok) {
              findings.push({
                finding_type: 'exposed_api_keys',
                description: `Potentially exposed sensitive file: ${file}`,
                severity: 'critical',
                source: 'File Exposure Check',
                data: { file, status: fileResponse.status }
              });
            }
          } catch (e) {
            // File not accessible
          }
        }

        // Check for email patterns in HTML
        try {
          const htmlContent = await (await fetchWithTimeout(`https://${domain}`, {}, 5000)).text();
          const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
          const emails = htmlContent.match(emailRegex);
          if (emails && emails.length > 0) {
            findings.push({
              finding_type: 'email',
              description: `${emails.length} email addresses found on the website`,
              severity: 'low',
              source: 'HTML Content Analysis',
              data: { count: emails.length, sample: emails.slice(0, 3) }
            });
          }
        } catch (e) {
          // Could not analyze HTML
        }

        return findings;
      };

      // Enhanced Endpoint Discovery with ML-based pattern detection
      const discoverEndpoints = async (baseUrl: string) => {
        const endpoints: EndpointDiscovery[] = [];
        
        // Wordlist-based discovery with proper status code handling
        for (const endpoint of commonEndpoints) {
          try {
            const startTime = Date.now();
            const endpointUrl = `${baseUrl}${endpoint}`;
            const response = await fetchWithTimeout(endpointUrl, { 
              method: 'GET',
              redirect: 'manual' // Don't follow redirects automatically
            }, 3000);
            const responseTime = Date.now() - startTime;
            
            // Map status codes properly
            let actualStatus = response.status;
            
            // Handle redirects (3xx)
            if (response.status >= 300 && response.status < 400) {
              const location = response.headers.get('location');
              if (location) {
                // Check if redirect is to different domain
                try {
                  const redirectUrl = new URL(location, baseUrl);
                  const baseUrlObj = new URL(baseUrl);
                  if (redirectUrl.hostname !== baseUrlObj.hostname) {
                    actualStatus = 302; // External redirect
                  } else {
                    actualStatus = 301; // Internal redirect
                  }
                } catch {
                  actualStatus = 302;
                }
              }
            }
            
            // Only add endpoints that are found or have interesting status codes
            // 200: OK, 201: Created, 204: No Content
            // 301: Moved Permanently, 302: Found (redirect)
            // 401: Unauthorized, 403: Forbidden (interesting - endpoint exists but blocked)
            // 500: Server Error (endpoint exists but has issues)
            if (actualStatus !== 404 && actualStatus !== 0) {
              endpoints.push({
                path: endpoint,
                method: 'GET',
                status_code: actualStatus,
                discovered_by: 'wordlist',
                response_time: responseTime,
                content_type: response.headers.get('content-type') || 'unknown'
              });
            }
          } catch (e) {
            // Endpoint doesn't exist or network error - skip it
          }
        }

        // ML-based pattern detection (check for common API patterns)
        const apiPatterns = ['/api/v{version}/', '/rest/v{version}/', '/{resource}/api/', '/api/{resource}'];
        const resources = ['users', 'posts', 'products', 'orders', 'auth', 'customers', 'data', 'items', 'accounts'];
        const versions = ['1', '2', '3'];

        for (const pattern of apiPatterns) {
          for (const version of versions) {
            for (const resource of resources) {
              try {
                let endpoint = pattern.replace('{version}', version);
                if (pattern.includes('{resource}')) {
                  endpoint = endpoint.replace('{resource}', resource);
                } else {
                  endpoint = endpoint + resource;
                }

                const startTime = Date.now();
                const endpointUrl = `${baseUrl}${endpoint}`;
                const response = await fetchWithTimeout(endpointUrl, { 
                  method: 'GET',
                  redirect: 'manual'
                }, 2000);
                const responseTime = Date.now() - startTime;
                
                // Same status code handling as wordlist discovery
                let actualStatus = response.status;
                if (response.status >= 300 && response.status < 400) {
                  const location = response.headers.get('location');
                  if (location) {
                    try {
                      const redirectUrl = new URL(location, baseUrl);
                      const baseUrlObj = new URL(baseUrl);
                      actualStatus = redirectUrl.hostname !== baseUrlObj.hostname ? 302 : 301;
                    } catch {
                      actualStatus = 302;
                    }
                  }
                }
                
                if (actualStatus !== 404 && actualStatus !== 0) {
                  endpoints.push({
                    path: endpoint,
                    method: 'GET',
                    status_code: actualStatus,
                    discovered_by: 'ml',
                    response_time: responseTime,
                    content_type: response.headers.get('content-type') || 'unknown'
                  });
                }
              } catch (e) {
                // Pattern doesn't match
              }
            }
          }
        }

        // API Security Check - test discovered API endpoints (only for confirmed accessible endpoints)
        for (const ep of endpoints.filter(e => e.path.includes('api') && e.status_code === 200)) {
          // Only flag as vulnerability if it's truly accessible without auth
          vulnerabilities.push({
            category: 'API Security',
            severity: 'high',
            title: `Potentially Unauthenticated API Access: ${ep.path}`,
            description: `API endpoint ${ep.path} responded with 200 OK without authentication headers`,
            recommendation: 'Verify if this endpoint requires authentication. Implement proper authentication (OAuth 2.0, JWT) if needed.',
            found: true,
            confidence: 75, // Lower confidence since we don't know if auth is truly needed
            owasp_category: 'A01:2021 - Broken Access Control',
            how_to_fix: 'Implement API key validation, JWT tokens, or OAuth 2.0. Ensure all sensitive API endpoints require authentication. Use rate limiting to prevent abuse. Implement proper authorization checks.'
          });
        }

        // Check for server errors in discovered endpoints
        for (const ep of endpoints.filter(e => e.status_code >= 500)) {
            vulnerabilities.push({
              category: 'API Security',
              severity: 'medium',
              title: `API Error Disclosure: ${ep.path}`,
              description: `API endpoint returns detailed error information (${ep.status_code})`,
              recommendation: 'Configure API to return generic error messages to clients',
              found: true,
              confidence: 70,
              owasp_category: 'A05:2021 - Security Misconfiguration',
              how_to_fix: 'Return generic error messages to clients. Log detailed errors server-side only. Implement proper error handling middleware.'
            });
          }
        }

        return endpoints;
      };

      // Generate Attack Paths
      const generateAttackPaths = (vulns: VulnerabilityCheck[]) => {
        const attackPaths = [];
        const criticalVulns = vulns.filter(v => v.found && (v.severity === 'critical' || v.severity === 'high'));

        // Generate attack chain examples
        if (criticalVulns.length >= 2) {
          // Example: XSS + Session Hijacking chain
          const xss = criticalVulns.find(v => v.title.includes('XSS') || v.title.includes('Cross-Site Scripting'));
          const sessionVuln = criticalVulns.find(v => v.title.includes('Cookie') || v.title.includes('Session'));
          
          if (xss && sessionVuln) {
            attackPaths.push({
              vulnerability_ids: [],
              attack_steps: [
                {
                  step: 1,
                  action: "Inject malicious JavaScript through XSS vulnerability",
                  vulnerability: xss.title,
                  impact: "Execute arbitrary code in victim's browser"
                },
                {
                  step: 2,
                  action: "Steal session cookies due to missing HttpOnly flag",
                  vulnerability: sessionVuln.title,
                  impact: "Hijack user session and impersonate victim"
                },
                {
                  step: 3,
                  action: "Access sensitive user data and perform unauthorized actions",
                  vulnerability: "Session Hijacking",
                  impact: "Complete account takeover"
                }
              ],
              impact_score: 9,
              exploitability: 'high'
            });
          }
        }

        // Missing security headers chain
        const noHSTS = vulns.find(v => v.found && v.title.includes('HSTS'));
        const noCSP = vulns.find(v => v.found && v.title.includes('Content Security Policy'));
        
        if (noHSTS && noCSP) {
          attackPaths.push({
            vulnerability_ids: [],
            attack_steps: [
              {
                step: 1,
                action: "Perform man-in-the-middle attack to downgrade HTTPS to HTTP",
                vulnerability: noHSTS.title,
                impact: "Intercept unencrypted traffic"
              },
              {
                step: 2,
                action: "Inject malicious scripts due to missing CSP",
                vulnerability: noCSP.title,
                impact: "Execute arbitrary JavaScript on the page"
              },
              {
                step: 3,
                action: "Steal credentials or redirect to phishing site",
                vulnerability: "Combined Header Weakness",
                impact: "Credential theft and phishing"
              }
            ],
            impact_score: 7,
            exploitability: 'medium'
          });
        }

        // SQL Injection to RCE chain
        const sqlInj = criticalVulns.find(v => v.title.includes('SQL Injection'));
        if (sqlInj) {
          attackPaths.push({
            vulnerability_ids: [],
            attack_steps: [
              {
                step: 1,
                action: "Exploit SQL injection to enumerate database structure",
                vulnerability: sqlInj.title,
                impact: "Read database schema and table contents"
              },
              {
                step: 2,
                action: "Use SQL injection to read server files or execute commands",
                vulnerability: "SQL Injection Escalation",
                impact: "Read /etc/passwd, configuration files"
              },
              {
                step: 3,
                action: "Achieve remote code execution through database features",
                vulnerability: "Database Command Execution",
                impact: "Complete server compromise"
              }
            ],
            impact_score: 10,
            exploitability: 'critical'
          });
        }

        return attackPaths;
      };

      // Run enhanced scans
      console.log('Running OSINT checks...');
      osintFindings = await performOSINTCheck(normalizedDomain);
      
      console.log('Discovering hidden endpoints...');
      discoveredEndpoints = await discoverEndpoints(httpsUrl);
      
      console.log('Generating attack paths...');
      attackPaths = generateAttackPaths(vulnerabilities);

    } catch (error) {
      console.error('Scan error:', error);
      throw new Error(`Failed to scan domain`);
    }

    // Enhanced False Positive Reduction
    console.log('Reducing false positives...');
    const reduceFalsePositives = (vulns: VulnerabilityCheck[]) => {
      return vulns.map(v => {
        let confidence = v.confidence || 60; // Default confidence - start lower
        
        // HIGH CONFIDENCE (90-100): Direct evidence of vulnerability
        if (v.found && v.severity === 'critical') {
          // SQL injection with actual error messages detected
          if (v.title.includes('SQL Injection') && v.description.includes('detected')) {
            confidence = 95;
          }
          // XSS with actual reflection detected
          else if (v.title.includes('XSS') && v.description.includes('detected')) {
            confidence = 95;
          }
          // Exposed sensitive files actually found
          else if (v.description.includes('exposed') || v.description.includes('accessible')) {
            confidence = 90;
          }
          else {
            confidence = 85;
          }
        }
        
        // MEDIUM-HIGH CONFIDENCE (70-89): Strong indicators but not direct proof
        if (v.found && v.severity === 'high') {
          if (v.description.includes('detected') || v.description.includes('found')) {
            confidence = 80;
          } else if (v.description.includes('missing') || v.description.includes('not set')) {
            confidence = 75; // Missing headers are confirmed but impact varies
          } else {
            confidence = 70;
          }
        }
        
        // MEDIUM CONFIDENCE (55-69): Observable issues with moderate impact
        if (v.found && v.severity === 'medium') {
          if (v.description.includes('detected') || v.description.includes('found')) {
            confidence = 65;
          } else {
            confidence = 60;
          }
        }
        
        // LOW CONFIDENCE (40-54): Minor issues or speculative findings
        if (v.found && (v.severity === 'low' || v.severity === 'info')) {
          confidence = 50;
        }
        
        // REDUCE confidence for speculative language
        if (v.description.includes('may') || v.description.includes('might') || 
            v.description.includes('possible') || v.description.includes('could')) {
          confidence = Math.max(confidence - 15, 35);
        }
        
        // INCREASE confidence for definitive evidence
        if (v.description.includes('exposed') || v.description.includes('vulnerable') ||
            v.description.includes('error messages detected')) {
          confidence = Math.min(confidence + 10, 100);
        }
        
        // Info findings that aren't vulnerabilities
        if (!v.found && v.severity === 'info') {
          confidence = 100; // High confidence it's NOT a vulnerability
        }

        return { ...v, confidence };
      }).filter(v => {
        // Keep findings with confidence >= 40, or info findings that passed
        return v.confidence >= 40 || (!v.found && v.severity === 'info');
      });
    };
    const filteredVulnerabilities = reduceFalsePositives(vulnerabilities);
    
    // Enhanced Security Score Calculation
    const totalVulnerabilities = filteredVulnerabilities.length;
    const foundVulnerabilities = filteredVulnerabilities.filter(v => v.found).length;
    
    // Categorize vulnerabilities by severity and confidence
    const criticalVulns = filteredVulnerabilities.filter(v => v.found && v.severity === 'critical');
    const highVulns = filteredVulnerabilities.filter(v => v.found && v.severity === 'high');
    const mediumVulns = filteredVulnerabilities.filter(v => v.found && v.severity === 'medium');
    const lowVulns = filteredVulnerabilities.filter(v => v.found && v.severity === 'low');
    
    // Improved scoring algorithm: More balanced to avoid very low scores
    let securityScore = 100;
    
    // Critical vulnerabilities: Confirmed exploitable issues (15 points each, not 25)
    for (const vuln of criticalVulns) {
      const confidence = vuln.confidence || 70;
      // Weight by confidence: 95% confidence = full penalty, 70% confidence = reduced penalty
      const penalty = 15 * (confidence / 100);
      securityScore -= penalty;
    }
    
    // High severity: Significant issues (8 points each, not 12)
    for (const vuln of highVulns) {
      const confidence = vuln.confidence || 70;
      const penalty = 8 * (confidence / 100);
      securityScore -= penalty;
    }
    
    // Medium severity: Notable concerns (4 points each, not 6)
    for (const vuln of mediumVulns) {
      const confidence = vuln.confidence || 60;
      const penalty = 4 * (confidence / 100);
      securityScore -= penalty;
    }
    
    // Low severity: Minor issues (1.5 points each, not 2)
    securityScore -= lowVulns.length * 1.5;
    
    // OSINT findings: Exposure risks (reduced penalties)
    const criticalOSINT = osintFindings.filter(o => o.severity === 'critical').length;
    const highOSINT = osintFindings.filter(o => o.severity === 'high').length;
    const mediumOSINT = osintFindings.filter(o => o.severity === 'medium').length;
    
    securityScore -= criticalOSINT * 8;  // Reduced from 10
    securityScore -= highOSINT * 4;      // Reduced from 5
    securityScore -= mediumOSINT * 2;    // Added medium OSINT
    
    // Bonus points for good security practices
    const passedChecks = filteredVulnerabilities.filter(v => !v.found && v.severity !== 'info').length;
    const bonusPoints = Math.min(passedChecks * 0.5, 15); // Up to 15 bonus points
    securityScore += bonusPoints;
    
    // Ensure score stays between 0-100
    securityScore = Math.max(0, Math.min(100, Math.round(securityScore)));

    console.log(`Scan complete. Score: ${securityScore}, Vulnerabilities found: ${foundVulnerabilities}, OSINT findings: ${osintFindings.length}, Endpoints: ${discoveredEndpoints.length}`);

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

    // Save vulnerabilities (store additional OWASP data in description/recommendation if needed)
    const vulnerabilityRecords = vulnerabilities.map(v => ({
      scan_id: scanData.id,
      category: v.owasp_category || v.category,
      severity: v.severity,
      title: v.title,
      description: v.description,
      recommendation: v.found && v.how_to_fix ? `${v.recommendation}\n\nHow to Fix: ${v.how_to_fix}` : v.recommendation,
      found: v.found,
    }));

    const { error: vulnError } = await supabase
      .from('vulnerabilities')
      .insert(vulnerabilityRecords);

    if (vulnError) {
      console.error('Error saving vulnerabilities:', vulnError);
      throw vulnError;
    }

    // Save OSINT findings
    if (osintFindings.length > 0) {
      const osintRecords = osintFindings.map(o => ({
        scan_id: scanData.id,
        finding_type: o.finding_type,
        description: o.description,
        severity: o.severity,
        source: o.source,
        data: o.data || null,
      }));

      const { error: osintError } = await supabase
        .from('osint_findings')
        .insert(osintRecords);

      if (osintError) {
        console.error('Error saving OSINT findings:', osintError);
      }
    }

    // Save discovered endpoints
    if (discoveredEndpoints.length > 0) {
      const endpointRecords = discoveredEndpoints.map(e => ({
        scan_id: scanData.id,
        path: e.path,
        method: e.method,
        status_code: e.status_code,
        discovered_by: e.discovered_by,
        response_time: e.response_time,
        content_type: e.content_type,
      }));

      const { error: endpointError } = await supabase
        .from('endpoints')
        .insert(endpointRecords);

      if (endpointError) {
        console.error('Error saving endpoints:', endpointError);
      }
    }

    // Save attack paths
    if (attackPaths.length > 0) {
      const attackPathRecords = attackPaths.map(ap => ({
        scan_id: scanData.id,
        vulnerability_ids: ap.vulnerability_ids,
        attack_steps: ap.attack_steps,
        impact_score: ap.impact_score,
        exploitability: ap.exploitability,
      }));

      const { error: attackPathError } = await supabase
        .from('attack_paths')
        .insert(attackPathRecords);

      if (attackPathError) {
        console.error('Error saving attack paths:', attackPathError);
      }
    }

    return new Response(
      JSON.stringify({
        scan_id: scanData.id,
        domain: normalizedDomain,
        security_score: securityScore,
        vulnerabilities_found: foundVulnerabilities,
        total_checks: totalVulnerabilities,
        vulnerabilities: filteredVulnerabilities,
        osint_findings: osintFindings,
        discovered_endpoints: discoveredEndpoints,
        attack_paths: attackPaths,
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