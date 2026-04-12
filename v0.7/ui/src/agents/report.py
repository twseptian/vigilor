import os
import json
import re
from urllib.parse import urlparse
from src.agents.base import BaseAgent
from src.core.workspace import WorkspaceManager
from src.core.llm import OllamaEngine
from datetime import datetime


# ---------------------------------------------------------------------------
# OWASP Top 10 2021 reference mapping
# ---------------------------------------------------------------------------
_OWASP_REFS = [
    (r'idor|bola|broken.access|privilege.escal|path.traversal|lfi|local.file'
     r'|directory.traversal|open.redirect|forced.brows|missing.function.level',
     "A01:2021", "Broken Access Control",
     "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"),
    (r'crypt|hsts\b|tls\b|ssl\b|insecure.transm|cleartext|weak.cipher'
     r'|missing.https|secure.flag|insecure.cookie|missing.secure',
     "A02:2021", "Cryptographic Failures",
     "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"),
    (r'sql.inject|sqli\b|xss|cross.site.script|command.inject|rce\b|remote.code'
     r'|ssti|template.inject|xxe|xml.external|ldap.inject|nosql|html.inject',
     "A03:2021", "Injection",
     "https://owasp.org/Top10/A03_2021-Injection/"),
    (r'insecure.design|business.logic|mass.assign|race.condition|price.tamper'
     r'|workflow.bypass',
     "A04:2021", "Insecure Design",
     "https://owasp.org/Top10/A04_2021-Insecure_Design/"),
    (r'misconfigur|missing.header|clickjacking|x.frame|cors\b|csp\b'
     r'|server.version|information.disclos|x.powered.by|technology.disclos'
     r'|default.cred|verbose.error|file.upload|unrestricted.upload'
     r'|directory.list|phpinfo|server.banner|referrer.policy|permissions.policy'
     r'|x.content.type|mime.sniff',
     "A05:2021", "Security Misconfiguration",
     "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"),
    (r'outdated|vulnerable.component|known.cve|old.version|deprecated.version'
     r'|apache.*cve|php.*cve',
     "A06:2021", "Vulnerable and Outdated Components",
     "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"),
    (r'auth.bypass|authentication.bypass|brute.force|credential|session.fixat'
     r'|jwt\b|weak.password|password.policy|account.lockout|csrf'
     r'|cross.site.request.forgery|2fa.bypass|mfa.bypass|insecure.cookie',
     "A07:2021", "Identification and Authentication Failures",
     "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"),
    (r'deserializ|insecure.deserializ|pickle\b|java.serial|integrity.failure'
     r'|supply.chain|untrusted.data',
     "A08:2021", "Software and Data Integrity Failures",
     "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"),
    (r'logging.failure|monitoring.failure|audit.trail|rate.limit|no.log'
     r'|insufficient.log',
     "A09:2021", "Security Logging and Monitoring Failures",
     "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"),
    (r'ssrf\b|server.side.request.forgery|server-side.request',
     "A10:2021", "Server-Side Request Forgery (SSRF)",
     "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"),
]


def _get_owasp_refs(vuln_type: str) -> list:
    """Return list of (code, name, url) OWASP Top 10 2021 refs for a vuln type."""
    vt = re.sub(r'[\s\-/]', '.', vuln_type.lower())
    results = []
    seen = set()
    for pattern, code, name, url in _OWASP_REFS:
        if re.search(pattern, vt) and code not in seen:
            results.append((code, name, url))
            seen.add(code)
    return results


def _parse_cvss_vector(vector: str) -> dict:
    """Parse a CVSS 3.x vector string into a dict of metric abbreviation → value."""
    mapping = {}
    for part in vector.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            mapping[k] = v
    return mapping


_CVSS_METRIC_LABELS = {
    "AV": ("Attack Vector (AV)", {
        "N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical",
    }),
    "AC": ("Attack Complexity (AC)", {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required (PR)", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction (UI)", {"N": "None", "R": "Required"}),
    "S":  ("Scope (S)",             {"U": "Unchanged", "C": "Changed"}),
    "C":  ("Confidentiality (C)",   {"N": "None", "L": "Low", "H": "High"}),
    "I":  ("Integrity (I)",         {"N": "None", "L": "Low", "H": "High"}),
    "A":  ("Availability (A)",      {"N": "None", "L": "Low", "H": "High"}),
}


def _cvss_val(metrics: dict, key: str) -> str:
    label_map = _CVSS_METRIC_LABELS.get(key, (key, {}))
    abbrev = metrics.get(key, "N/A")
    return label_map[1].get(abbrev, abbrev)


# ---------------------------------------------------------------------------
# PoC → Prose narrative converter
# Converts the structured PoC block (with section headers) into a professional
# narrative paragraph suitable for the Proof of Concept section.
# ---------------------------------------------------------------------------

def _poc_to_narrative(poc_text: str, vuln_type: str, url: str, param: str,
                      has_screenshot: bool = False) -> str:
    """Convert a structured PoC text block into a professional prose narrative."""
    # Parse PoC sections
    _HEADERS = {"REPRODUCTION STEPS", "ATTACK REQUEST (cURL)",
                "OBSERVED EVIDENCE", "TECHNICAL NOTES", "VERIFICATION STATUS"}
    sections: dict = {}
    current = None
    buf: list = []
    for line in (poc_text or "").split("\n"):
        stripped = line.strip()
        if stripped in _HEADERS:
            if current:
                sections[current] = "\n".join(buf).strip()
            current = stripped
            buf = []
        elif current:
            buf.append(line)
    if current:
        sections[current] = "\n".join(buf).strip()

    evidence_raw = sections.get("OBSERVED EVIDENCE", "")
    # Clean evidence — strip bullet prefixes and blank lines, keep first 400 chars
    evidence_lines = [
        ln.lstrip("•-– \t").strip()
        for ln in evidence_raw.split("\n")
        if ln.strip() and not ln.strip().startswith("#")
    ]
    evidence_clean = " ".join(evidence_lines)[:400].strip()

    vt = vuln_type.lower()
    p = param or "input"
    screenshot_note = (
        " A screenshot capturing the application's response has been included as evidence below."
        if has_screenshot else ""
    )

    # ── Narrative templates per vuln family ──────────────────────────────────
    if any(k in vt for k in ["missing", "clickjacking", "hsts", "x-frame",
                              "x-content", "mime sniff", "referrer", "permissions",
                              "cookie flag", "insecure cookie", "httponly",
                              "server version", "x-powered-by", "technology disclosure",
                              "information disclosure"]):
        text = (
            f"During the assessment, an HTTP request was issued to {url} and the server's response "
            f"headers and cookie attributes were inspected. "
        )
        if evidence_clean:
            text += f"The analysis revealed that {evidence_clean.rstrip('.').lower()}. "
        text += (
            "This finding was consistently reproducible across multiple requests, confirming that "
            "the relevant security control is absent at the server configuration level."
        )

    elif any(k in vt for k in ["sql", "sqli"]):
        text = (
            f"During the assessment, the '{p}' parameter at {url} was identified as a candidate "
            f"for SQL injection. Crafted SQL payloads were submitted to the endpoint and the "
            f"application's responses were analysed for database error messages, timing anomalies, "
            f"and data exfiltration indicators. "
        )
        if evidence_clean:
            text += f"The server's response confirmed exploitability: {evidence_clean.rstrip('.')}. "
        text += (
            "These observations confirm that user-supplied input is not adequately sanitised "
            "prior to being incorporated into backend SQL queries."
        )

    elif any(k in vt for k in ["xss", "cross-site script", "stored xss",
                                "reflected xss", "dom xss"]):
        text = (
            f"During the assessment, a Cross-Site Scripting (XSS) payload was injected into "
            f"the '{p}' parameter at {url}. The application's response was inspected to determine "
            f"whether the injected script was reflected or stored without proper HTML encoding. "
        )
        if evidence_clean:
            text += f"The response confirmed successful payload injection: {evidence_clean.rstrip('.')}. "
        text += (
            "This confirms that user-supplied input is rendered in the application output without "
            "adequate contextual encoding, enabling client-side script injection attacks."
        )

    elif any(k in vt for k in ["file upload", "unrestricted upload", "unrestricted file"]):
        text = (
            f"During the assessment, the file upload functionality at {url} was assessed for "
            f"server-side restrictions on accepted file types and content. A test file with a "
            f"potentially dangerous extension was crafted and submitted through the upload interface. "
        )
        if evidence_clean:
            text += f"The server's response indicated: {evidence_clean.rstrip('.')}. "
        text += (
            "The absence of adequate server-side validation of uploaded file types and content "
            "presents a risk of malicious file upload, potentially leading to remote code execution."
        )

    elif any(k in vt for k in ["idor", "bola", "broken object", "broken access"]):
        text = (
            f"During the assessment, the '{p}' parameter at {url} was manipulated to reference "
            f"object identifiers belonging to other user accounts. "
            f"The application's responses were compared across multiple identifier values to "
            f"determine whether server-side authorisation checks were enforced. "
        )
        if evidence_clean:
            text += f"The response confirmed unauthorised data access: {evidence_clean.rstrip('.')}. "
        text += (
            "This confirms that the application does not enforce adequate object-level authorisation "
            "checks when retrieving user-owned resources, allowing horizontal privilege escalation."
        )

    elif any(k in vt for k in ["path traversal", "lfi", "directory traversal",
                                "local file inclusion"]):
        text = (
            f"During the assessment, the '{p}' parameter at {url} was manipulated using "
            f"directory traversal sequences to reference files outside the intended web root. "
            f"Various encoding variants (plain, URL-encoded, double-encoded) were tested to "
            f"assess whether the application's input validation could be bypassed. "
        )
        if evidence_clean:
            text += (
                f"The application returned the contents of the requested file, confirming the "
                f"vulnerability: {evidence_clean.rstrip('.')}. "
            )
        text += (
            "Successful traversal of the file system confirms that user-supplied file path input "
            "is not adequately validated or canonicalised by the application."
        )

    elif any(k in vt for k in ["csrf", "cross-site request forgery"]):
        text = (
            f"During the assessment, the state-changing request at {url} was examined for the "
            f"presence of CSRF tokens or equivalent request-origin validation mechanisms. "
            f"A forged cross-origin request was constructed and submitted without a valid CSRF "
            f"token to assess whether the server enforces origin validation. "
        )
        if evidence_clean:
            text += f"The server accepted the forged request: {evidence_clean.rstrip('.')}. "
        text += (
            "The absence of CSRF protection enables a malicious actor to craft a forged request "
            "that executes in the context of an authenticated user's session without their knowledge."
        )

    elif any(k in vt for k in ["open redirect"]):
        text = (
            f"During the assessment, the redirect parameter at {url} was set to an external "
            f"attacker-controlled domain. The server's HTTP response was inspected to determine "
            f"whether it issued a redirect to the supplied URL without validation. "
        )
        if evidence_clean:
            text += f"The response confirmed an unvalidated redirect: {evidence_clean.rstrip('.')}. "
        text += (
            "This confirms that the application does not validate redirect targets against a "
            "whitelist of trusted domains, enabling redirect-based phishing attacks."
        )

    elif any(k in vt for k in ["auth", "brute force", "credential",
                                "authentication bypass", "default credential"]):
        text = (
            f"During the assessment, the authentication endpoint at {url} was assessed for "
            f"susceptibility to credential-based attacks and authentication logic bypass. "
            f"Multiple payload variants were submitted to evaluate the effectiveness of the "
            f"application's authentication controls. "
        )
        if evidence_clean:
            text += f"The application's response confirmed a successful bypass: {evidence_clean.rstrip('.')}. "
        text += (
            "These observations indicate that the authentication mechanism does not adequately "
            "protect against credential guessing or logic-based bypass techniques."
        )

    elif any(k in vt for k in ["command injection", "rce", "remote code"]):
        text = (
            f"During the assessment, the '{p}' parameter at {url} was tested for operating system "
            f"command injection by injecting shell metacharacters and command sequences. "
            f"Responses were monitored for system command output, timing differences, and "
            f"out-of-band indicators. "
        )
        if evidence_clean:
            text += f"The server returned command execution output: {evidence_clean.rstrip('.')}. "
        text += (
            "This confirms that user-supplied input is passed unsanitised to a system shell or "
            "interpreter, enabling arbitrary operating system command execution."
        )

    elif any(k in vt for k in ["ssrf", "server-side request"]):
        text = (
            f"During the assessment, the '{p}' parameter at {url} was manipulated to supply "
            f"an internal or attacker-controlled URL. The application's responses and any "
            f"out-of-band interactions were monitored to determine whether the server issued "
            f"requests to the specified destination. "
        )
        if evidence_clean:
            text += f"Evidence of server-side request issuance was observed: {evidence_clean.rstrip('.')}. "
        text += (
            "This confirms that the application does not validate user-supplied URLs before "
            "initiating server-side HTTP requests, enabling internal network probing and "
            "potential access to cloud metadata services."
        )

    elif any(k in vt for k in ["deserializ", "insecure deserializ"]):
        text = (
            f"During the assessment, the serialised data at {url} was inspected and modified "
            f"to assess whether the application deserialises untrusted input without integrity "
            f"checks. Crafted serialised objects were submitted to observe the application's "
            f"behaviour. "
        )
        if evidence_clean:
            text += f"The application's response indicated: {evidence_clean.rstrip('.')}. "
        text += (
            "Insecure deserialisation of user-controlled data may enable remote code execution, "
            "privilege escalation, or denial-of-service depending on the deserialisation library used."
        )

    elif any(k in vt for k in ["web cache poison", "cache poison"]):
        text = (
            f"During the assessment, unkeyed HTTP headers were injected into requests sent to "
            f"{url} to assess whether the caching layer would store and serve poisoned responses "
            f"to subsequent users. Cache-poisoning payloads were supplied via headers such as "
            f"X-Forwarded-Host and the cached responses were inspected for reflected values. "
        )
        if evidence_clean:
            text += f"The analysis confirmed: {evidence_clean.rstrip('.')}. "
        text += (
            "This confirms that the caching layer stores responses containing attacker-influenced "
            "content, enabling cache-poisoning attacks against other users of the application."
        )

    else:
        # Generic fallback
        text = (
            f"During the assessment, the endpoint at {url} was tested for the presence of "
            f"{vuln_type}. "
        )
        if evidence_clean:
            text += f"{evidence_clean.rstrip('.')}. "
        text += (
            "The observations recorded during testing confirm the presence of this vulnerability "
            "in the assessed application."
        )

    return text + screenshot_note


# ---------------------------------------------------------------------------
# Narrative-only template — LLM generates prose sections, NOT the findings list.
# The findings table is built directly in Python from workspace.findings so that
# every confirmed finding appears in the report regardless of LLM limitations.
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Static lookup: vuln type keyword → (implications, recommendations)
# Used so every finding gets meaningful text without an LLM call per finding.
# ---------------------------------------------------------------------------
_VULN_GUIDANCE: list[tuple[str, str, str]] = [
    # (keyword_pattern, implications, recommendations)
    ("sql injection|sqli",
     "An attacker can read, modify, or delete database records, potentially leading to full database compromise, authentication bypass, and lateral movement to backend systems.",
     "Use parameterized queries or prepared statements. Apply an ORM. Implement a WAF rule for SQL metacharacters. Restrict DB user permissions (principle of least privilege)."),
    ("xss|cross.site script",
     "Attackers can hijack user sessions, steal credentials, redirect users to malicious sites, or perform actions on behalf of victims.",
     "Encode all user-supplied output using context-aware encoding (HTML, JS, URL). Implement a strict Content-Security-Policy. Set HttpOnly and Secure cookie flags."),
    ("command injection|rce|remote code",
     "Full server compromise, data exfiltration, installation of malware/backdoors, and lateral movement within the internal network.",
     "Never pass user input to shell commands. Use language-native APIs instead of system()/exec(). Whitelist allowed characters if shell execution is unavoidable. Run the application as a least-privileged user."),
    ("file upload|unrestricted upload",
     "Uploading a web shell grants full remote code execution. Malicious files may also affect other users (malware delivery) or overwrite critical server files.",
     "Validate file type server-side using magic bytes, not just extension. Rename uploaded files, store outside the web root, and serve via a content-delivery path that cannot execute scripts."),
    ("path traversal|lfi|local file",
     "Attackers can read sensitive files (e.g., /etc/passwd, application configuration, private keys) or include malicious files for code execution.",
     "Canonicalize file paths and compare against an allowed base directory. Never build file paths directly from user input. Disable allow_url_include in PHP."),
    ("ssrf|server.side request forgery",
     "Attackers can probe internal services, access cloud metadata endpoints (AWS IMDSv1), bypass firewalls, and potentially pivot to internal infrastructure.",
     "Validate and whitelist allowed URL schemes and destinations. Use a DNS-rebinding-resistant resolution approach. Disable access to internal IP ranges at the network layer."),
    ("csrf|cross.site request forgery",
     "Attackers can perform state-changing actions (password change, fund transfer, data deletion) on behalf of authenticated users without their knowledge.",
     "Implement CSRF tokens (synchronizer token pattern or double-submit cookie). Verify the Origin/Referer header for state-changing requests. Use SameSite=Strict or Lax cookie attribute."),
    ("idor|broken access control|privilege escalat",
     "Unauthorized access to other users' data, account takeover, and potential for mass data exfiltration by iterating object identifiers.",
     "Enforce server-side authorization checks on every resource access. Use indirect references (GUIDs instead of sequential IDs). Implement a centralized access control layer."),
    ("open redirect",
     "Attackers can redirect victims to phishing pages after clicking legitimate-looking links, enabling credential theft and malware distribution.",
     "Validate redirect targets against a whitelist of allowed domains. Avoid including user-controlled data in redirect URLs. Use relative redirects where possible."),
    ("missing.*header|clickjacking|x-frame|content-security|hsts|mime sniff|referrer|permissions-policy|x-xss",
     "Absence of security headers exposes users to browser-based attacks such as clickjacking, MIME-type confusion, XSS, and SSL-stripping.",
     "Set all recommended security headers in the web server or application middleware configuration. Use a CSP policy that restricts script sources. Enable HSTS with a long max-age and include subdomains."),
    ("server version|technology disclosure|x-powered-by|information disclosure",
     "Disclosed version information helps attackers target known CVEs without needing to discover the version through active probing.",
     "Configure the web server to suppress version disclosure headers (ServerTokens Prod in Apache, server_tokens off in nginx). Remove X-Powered-By headers at the framework level."),
    ("insecure cookie|cookie flag|httponly|secure flag",
     "Cookies without HttpOnly are accessible to JavaScript (XSS cookie theft). Cookies without Secure may be transmitted over unencrypted connections.",
     "Set HttpOnly and Secure flags on all session and authentication cookies. Apply SameSite=Strict or Lax to prevent CSRF. Review all Set-Cookie headers."),
    ("brute force|authentication bypass|credential",
     "Weak authentication controls allow attackers to guess or enumerate credentials, leading to account takeover.",
     "Implement account lockout after N failed attempts. Add rate limiting and CAPTCHA to login endpoints. Require MFA for privileged accounts."),
    ("jwt|token|session fixation|predictable session",
     "Weak or predictable session tokens allow attackers to hijack authenticated sessions without knowing the user's password.",
     "Use cryptographically random session identifiers. Regenerate session IDs after authentication. Validate JWT signatures with a strong secret; disable the 'none' algorithm."),
    ("business logic|price tamper|mass assignment",
     "Business logic flaws allow attackers to manipulate application workflows for financial gain, unauthorized access, or data corruption.",
     "Validate all business constraints server-side. Never trust client-supplied price or role data. Implement workflow state machines to prevent step-skipping."),
    ("xxe|xml external",
     "XXE can lead to local file read, SSRF, denial-of-service, and in some configurations remote code execution.",
     "Disable external entity processing in the XML parser configuration. Use a safe XML library with entity expansion disabled by default."),
    ("ssti|template injection",
     "Template injection can escalate to remote code execution depending on the template engine and sandbox configuration.",
     "Never pass user input directly into template rendering. Use template engines that sandbox user-controlled data. Validate and encode all dynamic template variables."),
    ("cors|origin",
     "Permissive CORS allows malicious sites to make credentialed requests to the application and read responses, bypassing the same-origin policy.",
     "Restrict Access-Control-Allow-Origin to a whitelist of trusted origins. Never reflect the Origin header directly. Avoid combining Access-Control-Allow-Credentials: true with wildcard origins."),
]

_DEFAULT_IMPLICATIONS = "This finding may expose the application or its users to security risks including data exposure, unauthorized access, or service disruption."
_DEFAULT_RECOMMENDATIONS = "Apply defence-in-depth controls specific to this vulnerability class. Consult the OWASP Testing Guide for detailed remediation steps. Perform regression testing after applying fixes."


def _get_guidance(vuln_type: str) -> tuple[str, str]:
    """Return (implications, recommendations) for a given vulnerability type."""
    vt = vuln_type.lower()
    for pattern, implications, recommendations in _VULN_GUIDANCE:
        if any(re.search(kw.strip(), vt) for kw in pattern.split("|")):
            return implications, recommendations
    return _DEFAULT_IMPLICATIONS, _DEFAULT_RECOMMENDATIONS


def _generate_narrative_fallback(
    py_findings: list,
    target: str,
    today: str,
    surface_map_str: str,
    structured_recon: dict = None,
) -> dict:
    """Generate professional narrative sections from structured data without LLM.

    Used as the primary narrative source for small Ollama models (which struggle
    with open-ended prose generation) and as a universal JSON-parse fallback.
    """
    structured_recon = structured_recon or {}
    count = len(py_findings)
    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    severity_counts: dict[str, int] = {}
    for f in py_findings:
        s = f["severity"]
        severity_counts[s] = severity_counts.get(s, 0) + 1

    critical = severity_counts.get("Critical", 0)
    high     = severity_counts.get("High", 0)
    medium   = severity_counts.get("Medium", 0)
    low      = severity_counts.get("Low", 0)

    # Highest-severity finding
    top_finding = None
    top_severity = "Informational"
    for sev in severity_order:
        for f in py_findings:
            if f["severity"] == sev:
                top_severity = sev
                top_finding  = f
                break
        if top_finding:
            break

    # ── Executive Summary ──────────────────────────────────────────────────
    if count == 0:
        exec_summary = (
            f"A web application penetration test was conducted against {target} on {today}. "
            "No confirmed vulnerabilities were identified during the assessment. "
            "The application demonstrated a satisfactory security posture; however, continued "
            "security monitoring and periodic reassessment are strongly recommended."
        )
    else:
        sev_parts = [f"{severity_counts[s]} {s}" for s in severity_order if severity_counts.get(s)]
        sev_text  = ", ".join(sev_parts)
        overall   = ("CRITICAL" if critical else ("HIGH" if high else ("MEDIUM" if medium else ("LOW" if low else "INFORMATIONAL"))))

        exec_summary = (
            f"A web application penetration test was conducted against {target} on {today}, "
            f"revealing {count} confirmed security {'finding' if count == 1 else 'findings'} "
            f"({sev_text}). "
        )
        if top_finding and top_severity in ("Critical", "High"):
            exec_summary += (
                f"The most significant issue is {top_finding['title']} identified at "
                f"{top_finding['location']}, which poses a direct {top_severity.lower()}-severity "
                "risk to the confidentiality, integrity, and availability of application data. "
            )
        exec_summary += (
            f"The overall risk posture is assessed as {overall}, requiring prompt remediation "
            "of the identified issues to reduce the exploitable attack surface."
        )

    # ── Attack Surface Overview ────────────────────────────────────────────
    # Build from structured recon data when available; fall back to surface_map text.
    links      = structured_recon.get("links_found", [])
    js_eps     = structured_recon.get("hidden_js_endpoints", [])
    forms      = structured_recon.get("forms", [])
    params     = structured_recon.get("query_params_seen", [])
    tech_hint  = structured_recon.get("technologies_hint", {})
    server     = structured_recon.get("server_header", "")
    xpb        = structured_recon.get("x_powered_by", "")
    miss_hdrs  = structured_recon.get("missing_security_headers", [])
    cookie_iss = structured_recon.get("cookie_security_issues", [])
    page_title = structured_recon.get("page_title", "")

    if links or forms or params:
        # ── technology string ──
        tech_parts = []
        if server and server != "Unknown":
            tech_parts.append(f"web server: {server}")
        if xpb:
            tech_parts.append(f"platform: {xpb}")
        if tech_hint:
            if isinstance(tech_hint, dict):
                tech_parts += [f"{k}: {v}" for k, v in list(tech_hint.items())[:3] if v]
            elif isinstance(tech_hint, list):
                tech_parts += [str(t) for t in tech_hint[:3] if t]
        tech_str = ("; ".join(tech_parts) + ".") if tech_parts else ""

        # ── endpoints ──
        all_eps = list(dict.fromkeys(links + js_eps))  # deduplicate, preserve order
        ep_count = len(all_eps)
        ep_sample = ", ".join(all_eps[:6])
        ep_str = (
            f"{ep_count} endpoint{'s' if ep_count != 1 else ''} were discovered "
            f"(including {len(js_eps)} JavaScript-sourced endpoint{'s' if len(js_eps) != 1 else ''} "
            f"not exposed in the HTML navigation); sample paths: {ep_sample}."
            if ep_count else "No additional endpoints were discovered beyond the root path."
        )

        # ── forms ──
        form_count = len(forms)
        if form_count:
            form_details = []
            for frm in forms[:5]:
                action  = frm.get("action", "/")
                method  = frm.get("method", "GET")
                inp_names = [i.get("name", "") for i in frm.get("inputs", []) if i.get("name")]
                inp_str   = ", ".join(inp_names[:6]) if inp_names else "no named inputs"
                form_details.append(f"{method} {action} [{inp_str}]")
            form_str = (
                f"{form_count} HTML form{'s' if form_count != 1 else ''} were identified: "
                + "; ".join(form_details) + "."
            )
        else:
            form_str = "No HTML forms were identified."

        # ── query parameters ──
        param_str = (
            f"The following query parameters were observed in traffic: {', '.join(params[:12])}."
            if params else "No query parameters were observed."
        )

        # ── security header gaps ──
        hdr_str = (
            f"The following security headers were absent from HTTP responses: {', '.join(miss_hdrs[:8])}."
            if miss_hdrs else ""
        )

        # ── cookie issues ──
        ck_str = (
            f"{len(cookie_iss)} cookie{'s' if len(cookie_iss) != 1 else ''} "
            "lacked the HttpOnly and/or Secure flag."
            if cookie_iss else ""
        )

        parts = [
            f"Reconnaissance of {target}"
            + (f" ({page_title})" if page_title else "")
            + f" was conducted on {today}."
            + (f" Identified technology stack — {tech_str}" if tech_str else ""),
            ep_str,
            form_str,
            param_str,
        ]
        if hdr_str:
            parts.append(hdr_str)
        if ck_str:
            parts.append(ck_str)

        surface_text = " ".join(parts)
    else:
        # Fallback: strip markdown noise from LLM surface_map and present as plain prose
        clean_lines = []
        for line in surface_map_str.splitlines():
            line = line.strip()
            if not line or line.startswith("```"):
                continue
            # Remove leading markdown list/heading markers for clean prose
            line = re.sub(r"^[#*>\-]+\s*", "", line)
            if line:
                clean_lines.append(line)
        surface_text = " ".join(clean_lines[:12]) or f"Reconnaissance of {target} identified standard web application components."

    # ── Remediation Roadmap ────────────────────────────────────────────────
    if count == 0:
        roadmap = (
            "No critical or high severity vulnerabilities were identified. "
            "Recommended actions: (1) Implement all recommended security headers (CSP, HSTS, X-Frame-Options). "
            "(2) Enforce HTTPS across all endpoints. "
            "(3) Establish a vulnerability management programme with periodic reassessment."
        )
    else:
        items = []
        for sev in severity_order:
            for f in [x for x in py_findings if x["severity"] == sev]:
                rec_short = f["recommendations"].split(".")[0] if f["recommendations"] else "Apply vendor patch"
                items.append(f"[{sev}] {f['id']} — {f['title']} ({f['location']}): {rec_short}.")
        roadmap = "\n".join(items)

    # ── Conclusion ─────────────────────────────────────────────────────────
    if count == 0:
        conclusion = (
            f"The penetration test of {target} confirmed no exploitable vulnerabilities at the "
            "time of assessment. Ongoing security practices, including regular patching and "
            "periodic retesting, are recommended to maintain this posture."
        )
    else:
        urgent = critical + high
        conclusion = (
            f"The penetration test of {target} identified {count} security "
            f"{'finding' if count == 1 else 'findings'} requiring remediation. "
        )
        if urgent:
            conclusion += (
                f"Immediate action is required for the {urgent} Critical/High severity "
                f"{'issue' if urgent == 1 else 'issues'} to prevent active exploitation. "
            )
        conclusion += (
            "A full retest should be conducted after remediation to verify that all "
            "identified vulnerabilities have been effectively resolved and no regressions introduced."
        )

    return {
        "executive_summary":      exec_summary,
        "attack_surface_overview": surface_text,
        "remediation_roadmap":     roadmap,
        "conclusion":              conclusion,
    }


# ---------------------------------------------------------------------------
# Cloud-provider prompts (OpenAI / Anthropic) — section-by-section generation.
# Cloud models can produce long, professional prose but JSON multi-key prompts
# often produce generic or truncated output.  Section-by-section calls give
# the model focused context and produce much richer narrative.
# ---------------------------------------------------------------------------

_CLOUD_SYSTEM_PROMPT = (
    "You are a senior penetration test report writer with 10+ years of experience writing "
    "executive-level security assessment reports for enterprise clients. "
    "Your writing is clear, professional, authoritative, and technically precise. "
    "Output ONLY the requested narrative text — no JSON, no markdown headers, no bullet points "
    "unless explicitly asked for a list, no labels, no preamble."
)

_CLOUD_EXEC_PROMPT = """\
Write a professional executive summary (4-6 sentences) for a penetration test report.

Context:
- Target application: {TARGET}
- Assessment date: {DATE}
- Total confirmed findings: {COUNT} ({SEVERITY_BREAKDOWN})
- Most critical finding: {TOP_FINDING}
- Overall risk rating: {OVERALL_RISK}

Your executive summary must:
1. Open by stating what was tested and when
2. State the total number of findings and their severity breakdown
3. Call out the most critical risk and its business impact
4. Conclude with an overall risk posture statement and urgency of remediation

Write in third person, past tense. Do NOT use bullet points. Begin your response with:
"A web application penetration test was conducted against {TARGET} on {DATE}"\
"""

_CLOUD_SURFACE_PROMPT = """\
Write a professional attack surface overview (4-6 sentences) for a penetration test report.

Context:
- Target: {TARGET}
- Web server: {SERVER}
- Platform / backend: {PLATFORM}
- Discovered endpoints ({EP_COUNT} total): {EP_SAMPLE}
- HTML forms identified: {FORM_COUNT} at {FORM_URLS}
- Query parameters observed: {PARAMS}
- Missing security headers: {MISSING_HEADERS}
- Cookie security issues: {COOKIE_ISSUES}

Your overview must:
1. Describe the technology stack and server environment
2. Summarise the number and nature of discovered endpoints and input vectors
3. Note any immediately visible security weaknesses in the HTTP headers or cookie configuration
4. Provide context on how the attack surface influenced the test scope

Write in third person, past tense. Do NOT use bullet points. Begin your response with:
"Reconnaissance of {TARGET} identified"\
"""

_CLOUD_CONCLUSION_PROMPT = """\
Write a professional conclusion (3-4 sentences) for a penetration test report.

Context:
- Target: {TARGET}
- Total findings: {COUNT} ({SEVERITY_BREAKDOWN})
- Critical/High severity issues: {URGENT} issue(s) requiring immediate remediation
- Remediation urgency: {ACTION_REQUIRED}

Your conclusion must:
1. Briefly recap the overall security posture
2. State what immediate action is required and why
3. Recommend a retest timeline after remediation
4. End with a forward-looking statement about ongoing security practices

Write in third person, past tense. Do NOT use bullet points. Begin your response with:
"The penetration test of {TARGET}"\
"""

_CLOUD_ROADMAP_PROMPT = """\
Write a prioritised remediation roadmap for a penetration test report.

The roadmap must:
- List each remediation item on its own line, prefixed with its priority number
- Order items from highest severity to lowest
- For each item include: the vulnerability name, affected URL/parameter, and one-line fix guidance
- Use this exact format per line: "N. [SEVERITY] Vulnerability Name at URL/parameter — Fix guidance"
- Do NOT use markdown, headers, or extra whitespace

Confirmed findings to remediate (ordered by severity):
{FINDINGS_LIST}
"""


async def _generate_narrative_cloud(
    engine,
    py_findings: list,
    target: str,
    today: str,
    surface_map_str: str,
    structured_recon: dict,
    operator_context: str = "",
) -> dict:
    """Generate each narrative section with a focused cloud LLM call.

    Strategy:
    - One API call per section (executive, surface, roadmap, conclusion)
    - Rich prompts with explicit structure requirements and sentence starters
    - max_tokens=600 per prose section keeps output focused but detailed
    - Python fallback per section if output is too short or malformed
    """
    count = len(py_findings)
    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    sev_counts: dict[str, int] = {}
    for f in py_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    sev_parts = [f"{sev_counts[s]} {s}" for s in severity_order if sev_counts.get(s)]
    severity_breakdown = ", ".join(sev_parts) if sev_parts else "no confirmed findings"

    top_finding = None
    for sev in severity_order:
        top_finding = next((f for f in py_findings if f["severity"] == sev), None)
        if top_finding:
            break

    top_finding_line = (
        f"{top_finding['title']} at {top_finding['location']} (CVSS {top_finding.get('cvss', 'N/A')}) "
        f"— {top_finding.get('implications', 'poses significant risk to the application and its data')[:120]}"
        if top_finding else "No critical/high severity findings identified"
    )
    overall_risk = (
        "CRITICAL" if sev_counts.get("Critical") else
        "HIGH" if sev_counts.get("High") else
        "MEDIUM" if sev_counts.get("Medium") else
        "LOW" if sev_counts.get("Low") else "INFORMATIONAL"
    )
    urgent = sev_counts.get("Critical", 0) + sev_counts.get("High", 0)
    action = (
        f"{urgent} Critical/High issue(s) require immediate remediation within 48-72 hours"
        if urgent else "No critical/high issues — harden medium and informational findings"
    )

    # Recon data
    links    = structured_recon.get("links_found", [])
    js_eps   = structured_recon.get("hidden_js_endpoints", [])
    forms    = structured_recon.get("forms", [])
    params   = structured_recon.get("query_params_seen", [])
    server   = structured_recon.get("server_header", "Unknown")
    xpb      = structured_recon.get("x_powered_by", "Unknown")
    miss_h   = structured_recon.get("missing_security_headers", [])
    ck_iss   = structured_recon.get("cookie_security_issues", [])

    all_eps   = list(dict.fromkeys(links + js_eps))
    ep_sample = ", ".join(all_eps[:6]) or "none discovered"
    form_urls = ", ".join(f.get("action", "/") for f in forms[:5]) or "none"
    params_str = ", ".join(params[:10]) or "none observed"
    miss_h_str = ", ".join(miss_h[:8]) if miss_h else "none"
    ck_str     = ", ".join(ck_iss[:4]) if ck_iss else "none"

    # Findings list for roadmap
    findings_list_lines = []
    for i, f in enumerate(
        sorted(py_findings, key=lambda x: severity_order.index(x["severity"]) if x["severity"] in severity_order else 99),
        1,
    ):
        param_str = f" param={f['parameter']}" if f.get("parameter") else ""
        findings_list_lines.append(
            f"{i}. [{f['severity'].upper()}] {f['title']} at {f['location']}{param_str}"
        )
    findings_list = "\n".join(findings_list_lines) or "No confirmed findings."

    fallback = _generate_narrative_fallback(py_findings, target, today, surface_map_str, structured_recon)

    _effective_cloud_system = (
        (f"=== ADDITIONAL CONTEXT FROM OPERATOR ===\n{operator_context}\n"
         f"=== END OPERATOR CONTEXT ===\n\n")
        + _CLOUD_SYSTEM_PROMPT
        if operator_context else _CLOUD_SYSTEM_PROMPT
    )

    async def _call(prompt: str, section_name: str, max_tok: int = 600) -> str:
        try:
            resp = await engine.generate_response(
                messages=[{"role": "user", "content": prompt}],
                system_prompt=_effective_cloud_system,
                max_tokens=max_tok,
                temperature=0.3,
            )
            raw = engine.extract_text(resp).strip()
            # Strip any stray markdown the model may add
            raw = re.sub(r'```[a-z]*\n?', '', raw).strip()
            if len(raw) < 80:
                print(f"[Report] Cloud {section_name} output too short ({len(raw)} chars), using fallback.")
                return ""
            return raw
        except Exception as exc:
            print(f"[Report] Cloud {section_name} LLM error: {exc}. Using fallback.")
            return ""

    exec_prompt = (
        _CLOUD_EXEC_PROMPT
        .replace("{TARGET}", target)
        .replace("{DATE}", today)
        .replace("{COUNT}", str(count))
        .replace("{SEVERITY_BREAKDOWN}", severity_breakdown)
        .replace("{TOP_FINDING}", top_finding_line)
        .replace("{OVERALL_RISK}", overall_risk)
    )
    surface_prompt = (
        _CLOUD_SURFACE_PROMPT
        .replace("{TARGET}", target)
        .replace("{SERVER}", server)
        .replace("{PLATFORM}", xpb or "Unknown")
        .replace("{EP_COUNT}", str(len(all_eps)))
        .replace("{EP_SAMPLE}", ep_sample)
        .replace("{FORM_COUNT}", str(len(forms)))
        .replace("{FORM_URLS}", form_urls)
        .replace("{PARAMS}", params_str)
        .replace("{MISSING_HEADERS}", miss_h_str)
        .replace("{COOKIE_ISSUES}", ck_str)
    )
    conclusion_prompt = (
        _CLOUD_CONCLUSION_PROMPT
        .replace("{TARGET}", target)
        .replace("{COUNT}", str(count))
        .replace("{SEVERITY_BREAKDOWN}", severity_breakdown)
        .replace("{URGENT}", str(urgent))
        .replace("{ACTION_REQUIRED}", action)
    )
    roadmap_prompt = (
        _CLOUD_ROADMAP_PROMPT
        .replace("{FINDINGS_LIST}", findings_list)
    )

    exec_text     = await _call(exec_prompt, "executive_summary", max_tok=500)
    surface_text  = await _call(surface_prompt, "attack_surface_overview", max_tok=500)
    roadmap_text  = await _call(roadmap_prompt, "remediation_roadmap", max_tok=800)
    conclusion_text = await _call(conclusion_prompt, "conclusion", max_tok=300)

    return {
        "executive_summary":      exec_text     or fallback["executive_summary"],
        "attack_surface_overview": surface_text  or fallback["attack_surface_overview"],
        "remediation_roadmap":    roadmap_text  or fallback["remediation_roadmap"],
        "conclusion":             conclusion_text or fallback["conclusion"],
    }


# ---------------------------------------------------------------------------
# Ollama-optimised prompts — one section per call, plain-text output.
# Small local models (7-13B) consistently fail at multi-key JSON but can
# produce reliable 2-4 sentence prose when given a tight fill-in-the-blank
# structure and a sentence starter to anchor the response.
# ---------------------------------------------------------------------------

_OLLAMA_EXEC_PROMPT = """\
Write a 2-3 sentence executive summary for a penetration test report.
Output ONLY the summary text — no JSON, no labels, no markdown.

Facts to include:
- Target: {TARGET}
- Test date: {DATE}
- Total findings: {COUNT} ({SEVERITY_BREAKDOWN})
{TOP_FINDING_LINE}

Begin your response with: "A web application penetration test conducted against {TARGET} on {DATE}"\
"""

_OLLAMA_SURFACE_PROMPT = """\
Write 2-3 sentences summarising the web application attack surface for a penetration test report.
Output ONLY the summary text — no JSON, no labels, no markdown.

Facts to include:
- Target: {TARGET}
- Web server: {SERVER}
- Platform: {PLATFORM}
- Endpoints discovered: {EP_COUNT} — sample paths: {EP_SAMPLE}
- HTML forms: {FORM_COUNT} ({FORM_URLS})
- Query parameters observed: {PARAMS}
{HDR_LINE}

Begin your response with: "Reconnaissance of {TARGET} identified"\
"""

_OLLAMA_CONCLUSION_PROMPT = """\
Write 1-2 sentences for the conclusion section of a penetration test report.
Output ONLY the conclusion text — no JSON, no labels, no markdown.

Facts to include:
- Target: {TARGET}
- Total findings: {COUNT}
- Critical and High severity issues: {URGENT}
- Action required: {ACTION_REQUIRED}

Begin your response with: "The penetration test of {TARGET}"\
"""


def _clean_ollama_text(text: str, min_len: int = 40) -> str:
    """Strip JSON/markdown artifacts from Ollama output and validate length."""
    if not text:
        return ""
    # Remove JSON-like wrappers the model may echo
    text = re.sub(r'```[a-z]*\n?', '', text)
    text = re.sub(r'^["{\[]+|[}"\]]+$', '', text.strip())
    # Remove leading label echoes like "Executive Summary:" or "Answer:"
    text = re.sub(r'^[A-Za-z ]{1,30}:\s*', '', text.strip())
    text = text.strip().strip('"').strip()
    if len(text) < min_len or '{' in text or '\\n' in text:
        return ""
    return text


async def _generate_narrative_ollama(
    engine,
    py_findings: list,
    target: str,
    today: str,
    surface_map_str: str,
    structured_recon: dict,
    operator_context: str = "",
) -> dict:
    """Generate each narrative section with a focused Ollama LLM call.

    Strategy:
    - One API call per section (executive, surface, conclusion)
    - Fill-in-the-blank prompts with a sentence starter — anchors the model
    - max_tokens=220 per call keeps the model from going off-rails
    - Output validated; Python fallback used for any section that fails
    - Remediation roadmap always built from Python (it's a structured list)
    """
    # Pre-compute data shared across prompts
    count = len(py_findings)
    severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
    sev_counts: dict[str, int] = {}
    for f in py_findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    sev_parts = [f"{sev_counts[s]} {s}" for s in severity_order if sev_counts.get(s)]
    severity_breakdown = ", ".join(sev_parts) if sev_parts else "0 findings"

    top_finding = None
    for sev in severity_order:
        top_finding = next((f for f in py_findings if f["severity"] == sev), None)
        if top_finding:
            break

    top_finding_line = (
        f"- Most critical issue: {top_finding['title']} at {top_finding['location']}"
        if top_finding and top_finding["severity"] in ("Critical", "High")
        else ""
    )

    links   = structured_recon.get("links_found", [])
    js_eps  = structured_recon.get("hidden_js_endpoints", [])
    forms   = structured_recon.get("forms", [])
    params  = structured_recon.get("query_params_seen", [])
    server  = structured_recon.get("server_header", "Unknown")
    xpb     = structured_recon.get("x_powered_by", "Unknown")
    miss_h  = structured_recon.get("missing_security_headers", [])

    all_eps   = list(dict.fromkeys(links + js_eps))
    ep_sample = ", ".join(all_eps[:5]) or "none"
    form_urls = ", ".join(f.get("action", "/") for f in forms[:4]) or "none"
    params_str = ", ".join(params[:8]) or "none"
    hdr_line  = f"- Missing security headers: {', '.join(miss_h[:6])}" if miss_h else ""

    urgent = sev_counts.get("Critical", 0) + sev_counts.get("High", 0)
    action = (
        f"{urgent} issue(s) require immediate remediation" if urgent
        else "No critical/high issues — harden Informational findings"
    )

    fallback = _generate_narrative_fallback(py_findings, target, today, surface_map_str, structured_recon)

    _ollama_base_system = (
        "You are a professional penetration test report writer. "
        "Output ONLY the requested text. No JSON. No markdown. No labels. "
        "Write in formal, third-person technical English."
    )
    _effective_ollama_system = (
        (f"=== ADDITIONAL CONTEXT FROM OPERATOR ===\n{operator_context}\n"
         f"=== END OPERATOR CONTEXT ===\n\n")
        + _ollama_base_system
        if operator_context else _ollama_base_system
    )

    async def _call(prompt: str, section_name: str) -> str:
        try:
            resp = await engine.generate_response(
                messages=[{"role": "user", "content": prompt}],
                system_prompt=_effective_ollama_system,
                max_tokens=220,
                temperature=0.2,
            )
            raw = engine.extract_text(resp)
            cleaned = _clean_ollama_text(raw)
            if cleaned:
                print(f"[Report/Ollama] {section_name} — LLM OK ({len(cleaned)} chars)")
                return cleaned
            print(f"[Report/Ollama] {section_name} — output invalid, using fallback")
        except Exception as exc:
            print(f"[Report/Ollama] {section_name} — error: {exc}, using fallback")
        return ""

    # ── 1. Executive Summary ──────────────────────────────────────────────
    exec_prompt = (
        _OLLAMA_EXEC_PROMPT
        .replace("{TARGET}", target)
        .replace("{DATE}", today)
        .replace("{COUNT}", str(count))
        .replace("{SEVERITY_BREAKDOWN}", severity_breakdown)
        .replace("{TOP_FINDING_LINE}", top_finding_line)
    )
    exec_text = await _call(exec_prompt, "executive_summary") or fallback["executive_summary"]

    # ── 2. Attack Surface Overview ────────────────────────────────────────
    surface_prompt = (
        _OLLAMA_SURFACE_PROMPT
        .replace("{TARGET}", target)
        .replace("{SERVER}", server or "Unknown")
        .replace("{PLATFORM}", xpb or "Unknown")
        .replace("{EP_COUNT}", str(len(all_eps)))
        .replace("{EP_SAMPLE}", ep_sample)
        .replace("{FORM_COUNT}", str(len(forms)))
        .replace("{FORM_URLS}", form_urls)
        .replace("{PARAMS}", params_str)
        .replace("{HDR_LINE}", hdr_line)
    )
    surface_text = await _call(surface_prompt, "attack_surface_overview") or fallback["attack_surface_overview"]

    # ── 3. Conclusion ─────────────────────────────────────────────────────
    conc_prompt = (
        _OLLAMA_CONCLUSION_PROMPT
        .replace("{TARGET}", target)
        .replace("{COUNT}", str(count))
        .replace("{URGENT}", str(urgent))
        .replace("{ACTION_REQUIRED}", action)
    )
    conclusion_text = await _call(conc_prompt, "conclusion") or fallback["conclusion"]

    # ── 4. Remediation Roadmap — always Python (structured list) ──────────
    roadmap_text = fallback["remediation_roadmap"]

    return {
        "executive_summary":       exec_text,
        "attack_surface_overview": surface_text,
        "remediation_roadmap":     roadmap_text,
        "conclusion":              conclusion_text,
    }


class ReportingAgent(BaseAgent):
    def __init__(self, engine):
        super().__init__(engine)
        self.system_prompt = (
            "You are an elite penetration test report writer. "
            "Output exactly valid JSON only — no prose, no markdown, no backticks."
        )

    def _get_target_folder(self, target_url: str) -> str:
        parsed = urlparse(target_url)
        hostname = parsed.hostname or target_url
        if parsed.port:
            hostname = f"{hostname}:{parsed.port}"
        return hostname.replace(":", "_")

    async def execute(self, workspace: WorkspaceManager):
        from docx import Document
        from docx.shared import Inches

        def _coerce(value) -> str:
            if isinstance(value, str):
                return value
            if isinstance(value, list):
                return "\n".join(item if isinstance(item, str) else json.dumps(item, ensure_ascii=False) for item in value)
            if isinstance(value, dict):
                return json.dumps(value, indent=2, ensure_ascii=False)
            return str(value) if value is not None else ""

        def add_paragraph(text, style=None, align=None):
            safe_text = _coerce(text)
            p = doc.add_paragraph(safe_text, style=style) if style else doc.add_paragraph(safe_text)
            if align is not None:
                p.alignment = align
            return p

        today = datetime.now().strftime("%d %B %Y")
        target = workspace.target_url
        surface_map      = workspace.recon_data.get("surface_map", "No recon data available.")
        structured_recon = workspace.recon_data.get("structured", {})

        # ── Build findings list directly from workspace (no LLM reformatting) ──
        # Static-only mode: build from hypotheses (no exploitation phase ran).
        # Full pipeline mode: build from confirmed workspace.findings only.
        py_findings = []
        if getattr(workspace, "static_only", False):
            for i, hypo in enumerate(workspace.hypotheses or []):
                vuln_type = hypo.get("type", "Unknown")
                severity  = hypo.get("severity", "Informational")
                implications, recommendations = _get_guidance(vuln_type)
                py_findings.append({
                    "id":               f"SA-{i + 1}",
                    "title":            vuln_type,
                    "severity":         severity,
                    "cvss_score":       hypo.get("cvss_score", 0.0),
                    "cvss_vector":      hypo.get("cvss_vector", ""),
                    "status":           "Static Finding",
                    "location":         hypo.get("location", "/"),
                    "parameter":        hypo.get("param", ""),
                    "description":      hypo.get("details", ""),
                    "proof_of_concept": "Static analysis pattern match — see source location in description.",
                    "screenshot_path":  "",
                    "implications":     implications,
                    "recommendations":  recommendations,
                })
        else:
            for i, raw in enumerate(workspace.findings or []):
                hypo = raw.get("hypothesis", {})
                vuln_type = hypo.get("type", "Unknown")
                severity  = hypo.get("severity", "Informational")
                implications, recommendations = _get_guidance(vuln_type)
                py_findings.append({
                    "id":                   f"WVAPT-{i + 1}",
                    "title":                vuln_type,
                    "severity":             severity,
                    "cvss_score":           hypo.get("cvss_score", 0.0),
                    "cvss_vector":          hypo.get("cvss_vector", ""),
                    "status":               "Open",
                    "location":             hypo.get("location", "/"),
                    "parameter":            hypo.get("param", ""),
                    "description":          hypo.get("details", ""),
                    "proof_of_concept":     raw.get("proof", ""),
                    "screenshot_path":      raw.get("screenshot_path", ""),
                    "screenshot_path_before": hypo.get("screenshot_before", ""),
                    "implications":         implications,
                    "recommendations":      recommendations,
                })

        # ── Enrich header-related findings with actual response headers ──────────
        _HEADER_VULN_KEYWORDS = re.compile(
            r"missing|cors|server.*version|technology.*disclosure|x-powered|"
            r"insecure.*cookie|cookie.*flag|hsts|x-frame|content-security|"
            r"referrer.policy|permissions.policy|x-content-type|x-xss",
            re.IGNORECASE,
        )
        _raw_http_headers: dict = workspace.get_recon_data("http_headers") or {}
        if _raw_http_headers:
            for _f in py_findings:
                if _HEADER_VULN_KEYWORDS.search(_f["title"]):
                    _f["response_headers"] = _raw_http_headers

        # ── Sort findings by severity (Critical → High → Medium → Low → Informational) ──
        _SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]
        py_findings.sort(key=lambda x: _SEV_ORDER.index(x["severity"]) if x["severity"] in _SEV_ORDER else len(_SEV_ORDER))
        # Renumber IDs to reflect new order
        _prefix = "SA" if getattr(workspace, "static_only", False) else "WVAPT"
        for _idx, _f in enumerate(py_findings):
            _f["id"] = f"{_prefix}-{_idx + 1}"

        # ── Generate narrative ─────────────────────────────────────────────────
        is_ollama = isinstance(self.engine, OllamaEngine)
        _op_context = getattr(workspace, "custom_prompt", "").strip()

        if is_ollama:
            print("[*] Ollama provider detected — using section-by-section LLM narrative generator.")
            narrative = await _generate_narrative_ollama(
                self.engine, py_findings, target, today, surface_map[:3000], structured_recon,
                operator_context=_op_context,
            )
        else:
            # Cloud providers (OpenAI / Anthropic) — section-by-section rich generation.
            # This produces far better output than a single flat JSON request because:
            #   - Each section gets full context and focused instructions
            #   - No JSON parsing brittleness (plain text per call)
            #   - Per-section fallback if LLM output is invalid
            print(f"[*] Cloud provider detected — using section-by-section narrative generator.")
            narrative = await _generate_narrative_cloud(
                self.engine, py_findings, target, today, surface_map[:3000], structured_recon,
                operator_context=_op_context,
            )

        # ── Build DOCX ─────────────────────────────────────────────────────────
        from docx.shared import Pt, Inches, RGBColor, Cm
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL

        doc = Document()

        # ── Page margins (2.54 cm / 1 inch all sides) ─────────────────────────
        for section in doc.sections:
            section.top_margin    = Cm(2.54)
            section.bottom_margin = Cm(2.54)
            section.left_margin   = Cm(2.54)
            section.right_margin  = Cm(2.54)

        # ── Default body font (Calibri 11pt) + explicit paragraph spacing ───────
        _normal = doc.styles["Normal"]
        _normal.font.name = "Calibri"
        _normal.font.size = Pt(11)
        _normal.paragraph_format.space_before = Pt(0)
        _normal.paragraph_format.space_after  = Pt(6)

        # Heading styles — explicit spacing so no blank paragraphs are needed
        for _h, _sb, _sa in [("Heading 1", 14, 6), ("Heading 2", 12, 6),
                              ("Heading 3", 10, 4)]:
            _hs = doc.styles[_h]
            _hs.paragraph_format.space_before = Pt(_sb)
            _hs.paragraph_format.space_after  = Pt(_sa)

        # Caption — small gap above, normal gap below
        try:
            _cap = doc.styles["Caption"]
            _cap.paragraph_format.space_before = Pt(4)
            _cap.paragraph_format.space_after  = Pt(6)
        except Exception:
            pass

        # List styles — tight spacing
        for _ls in ("List Bullet", "List Number"):
            try:
                _st = doc.styles[_ls]
                _st.paragraph_format.space_before = Pt(0)
                _st.paragraph_format.space_after  = Pt(2)
            except Exception:
                pass

        # ── Helper: page break with zero spacing ──────────────────────────────
        def _pgbrk():
            doc.add_page_break()
            # The paragraph added by add_page_break inherits Normal spacing;
            # override it to zero so it doesn't add a blank line at top of page.
            p = doc.paragraphs[-1]
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after  = Pt(0)

        # ── Helper: set cell background colour ────────────────────────────────
        def _cell_bg(cell, hex_color: str):
            tc   = cell._tc
            tcPr = tc.get_or_add_tcPr()
            shd  = OxmlElement("w:shd")
            shd.set(qn("w:val"),   "clear")
            shd.set(qn("w:color"), "auto")
            shd.set(qn("w:fill"),  hex_color)
            tcPr.append(shd)

        # ── Helper: bold + optionally coloured cell text ───────────────────────
        def _bold_cell(cell, text: str, font_color_hex: str = None,
                       align: WD_ALIGN_PARAGRAPH = None):
            cell.text = ""
            p = cell.paragraphs[0]
            run = p.add_run(text)
            run.bold = True
            if font_color_hex:
                r, g, b = (int(font_color_hex[i:i+2], 16) for i in (0, 2, 4))
                run.font.color.rgb = RGBColor(r, g, b)
            if align is not None:
                p.alignment = align

        # ── Helper: cover-page-only spacer paragraph ──────────────────────────
        # (Use only for cover page visual spacing — not inside body sections)
        def _spacer(size_pt: float = 4.0):
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after  = Pt(size_pt)

        # ── Helper: small vertical gap between two adjacent tables ────────────
        def _tbl_gap():
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(0)
            p.paragraph_format.space_after  = Pt(4)

        # ── Severity → colour map ─────────────────────────────────────────────
        _SEV_COLOUR = {
            "Critical":      "C00000",
            "High":          "FF0000",
            "Medium":        "FF6600",
            "Low":           "FFD700",
            "Informational": "4472C4",
            "None":          "808080",
        }

        # ── Cover page ─────────────────────────────────────────────────────────
        # Large top margin for visual balance
        _spacer(60)
        p_title = doc.add_paragraph()
        p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run_title = p_title.add_run(target)
        run_title.bold = True
        run_title.font.size = Pt(24)
        run_title.font.name = "Calibri"

        _spacer(6)
        p_sub = doc.add_paragraph()
        p_sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run_sub = p_sub.add_run(
            "Web Vulnerability Assessment and Penetration Testing (WVAPT) Report"
        )
        run_sub.font.size = Pt(14)
        run_sub.font.name = "Calibri"
        run_sub.font.color.rgb = RGBColor(0x2E, 0x74, 0xB5)

        _spacer(40)
        for label, value in [
            ("Prepared for:", target),
            ("Report Date:", today),
            ("Version:", "1.0"),
            ("Classification:", "CONFIDENTIAL"),
        ]:
            p_info = doc.add_paragraph()
            p_info.alignment = WD_ALIGN_PARAGRAPH.CENTER
            r_lbl = p_info.add_run(f"{label}  ")
            r_lbl.bold = True
            r_lbl.font.size = Pt(11)
            r_val = p_info.add_run(value)
            r_val.font.size = Pt(11)
        _pgbrk()

        # ── 1. Document Control ────────────────────────────────────────────────
        doc.add_heading("Document Control", 1)
        add_paragraph(
            "The following section outlines the document control information, including details "
            "such as version history, description, review dates, authorship and any relevant "
            "updates made throughout the lifecycle of this report."
        )
        add_paragraph("Table 1: Version History.", style="Caption",
                      align=WD_ALIGN_PARAGRAPH.CENTER)
        vtable = doc.add_table(rows=2, cols=4)
        vtable.style = "Table Grid"
        vtable.alignment = WD_TABLE_ALIGNMENT.CENTER
        for txt, cell in zip(["Version", "Description", "Date", "Author"],
                             vtable.rows[0].cells):
            _bold_cell(cell, txt, align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(cell, "2E74B5")
            cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        vrow = vtable.rows[1].cells
        vrow[0].text = "1.0"
        vrow[1].text = "Initial Report"
        vrow[2].text = today
        vrow[3].text = "AI-Assisted Pentest Engine"
        for cell in vtable.rows[1].cells:
            cell.paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        _pgbrk()

        # ── 2. Disclaimer ──────────────────────────────────────────────────────
        doc.add_heading("Disclaimer", 1)
        for para in [
            "A security test is considered a snapshot in time. The findings and recommendations "
            "reflect the information gathered during the assessment and not any changes or "
            "modifications made outside of that period.",
            "A time-bound assessment approach does not allow for a full evaluation of all security "
            "controls. The assessment prioritised the identification of the weakest security "
            "controls an attacker could exploit. Similar assessments on an annual basis are "
            "recommended to ensure the continued effectiveness of security controls.",
            "Recommendations and references enclosed are not meant to be comprehensive or "
            "exhaustive in nature. The technical implementation of recommendations should be "
            "assessed before deployment in the affected environment (especially production). "
            "The assessor shall not be liable for the implementation of the recommendations adopted.",
            "References provided neither indicate endorsement nor support for the approaches "
            "to meet the recommendations but are provided to allow the client to understand "
            "viable solutions to the recommendations.",
        ]:
            add_paragraph(para)
        _pgbrk()

        # ── 3. Executive Summary ───────────────────────────────────────────────
        doc.add_heading("Executive Summary", 1)
        add_paragraph(
            f"{target} has engaged the security assessment team to conduct security testing "
            "with the following information:"
        )
        add_paragraph("Table 2: Details of the security testing.", style="Caption",
                      align=WD_ALIGN_PARAGRAPH.CENTER)
        dtable = doc.add_table(rows=7, cols=2)
        dtable.style = "Table Grid"
        dtable.alignment = WD_TABLE_ALIGNMENT.CENTER
        _details = [
            ("Type", "Web Vulnerability Assessment and Penetration Testing (WVAPT)"),
            ("System Name", target),
            ("Testing Period", today),
            ("System Environment", target),
            ("Approach", "Black-box / Grey-box"),
            ("Method", "Automated + Manual Validation"),
            ("No. of User Role(s)", "1 (Authenticated user)"),
        ]
        for i, (k, v) in enumerate(_details):
            _bold_cell(dtable.rows[i].cells[0], k)
            _cell_bg(dtable.rows[i].cells[0], "D9E1F2")
            dtable.rows[i].cells[1].text = v

        add_paragraph(
            "The purpose of security testing is to identify any potential weaknesses or "
            "vulnerabilities. The results of the security testing shall be used to guide "
            "remediation efforts and support the strengthening of the overall security posture. "
            "The classification of the findings identified is summarised in the table below."
        )
        add_paragraph("Table 3: Summary of Findings.", style="Caption",
                      align=WD_ALIGN_PARAGRAPH.CENTER)

        sev_order = ["Critical", "High", "Medium", "Low", "Informational", "None"]
        sev_counts_rep: dict = {s: 0 for s in sev_order}
        for f in py_findings:
            sev_counts_rep[f["severity"]] = sev_counts_rep.get(f["severity"], 0) + 1

        stable = doc.add_table(rows=3, cols=6)
        stable.style = "Table Grid"
        stable.alignment = WD_TABLE_ALIGNMENT.CENTER
        # Header row — merged title
        hdr1 = stable.rows[0].cells
        hdr1[0].merge(hdr1[5])
        _bold_cell(hdr1[0], "Severity Rating", font_color_hex="FFFFFF",
                   align=WD_ALIGN_PARAGRAPH.CENTER)
        _cell_bg(hdr1[0], "2E74B5")
        # Sub-header row
        hdr2 = stable.rows[1].cells
        for i, sev in enumerate(["Critical", "High", "Medium", "Low", "None", "Total"]):
            _bold_cell(hdr2[i], sev, align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(hdr2[i], "D9E1F2")
        # Count row — colour each cell by severity
        row3 = stable.rows[2].cells
        none_count = sev_counts_rep.get("Informational", 0) + sev_counts_rep.get("None", 0)
        count_vals = [
            ("Critical", str(sev_counts_rep["Critical"]), "C00000"),
            ("High",     str(sev_counts_rep["High"]),     "FF0000"),
            ("Medium",   str(sev_counts_rep["Medium"]),   "FF6600"),
            ("Low",      str(sev_counts_rep["Low"]),      "FFD700"),
            ("None",     str(none_count),                 "4472C4"),
            ("Total",    str(len(py_findings)),            "2E74B5"),
        ]
        for i, (sev, val, col) in enumerate(count_vals):
            row3[i].text = val
            row3[i].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            if int(val) > 0 or sev == "Total":
                _cell_bg(row3[i], col)
                row3[i].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                row3[i].paragraphs[0].runs[0].bold = True

        add_paragraph(narrative.get("executive_summary", ""))

        # ── 3.1 Scope ──────────────────────────────────────────────────────────
        doc.add_heading("Scope", 2)
        add_paragraph(
            "The security testing focused on identifying vulnerabilities within the target "
            "application, with attention to potential risks exposed to internal and external "
            "threats. The following hosts were included in the scope of this assessment:"
        )
        add_paragraph("Table 4: List of URLs in scope.", style="Caption",
                      align=WD_ALIGN_PARAGRAPH.CENTER)
        sctable = doc.add_table(rows=2, cols=3)
        sctable.style = "Table Grid"
        sctable.alignment = WD_TABLE_ALIGNMENT.CENTER
        for txt, cell in zip(["SN.", "URL", "Remarks"], sctable.rows[0].cells):
            _bold_cell(cell, txt, align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(cell, "D9E1F2")
        sctable.rows[1].cells[0].text = "1"
        sctable.rows[1].cells[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
        sctable.rows[1].cells[1].text = target
        sctable.rows[1].cells[2].text = "Primary target"

        # ── 3.2 Attack Surface Overview ────────────────────────────────────────
        doc.add_heading("Attack Surface Overview", 2)
        add_paragraph(narrative.get("attack_surface_overview", ""))

        _pgbrk()

        # ── 4. Methodology ─────────────────────────────────────────────────────
        doc.add_heading("Methodology (WVAPT)", 1)
        add_paragraph(
            "The Web Vulnerability Assessment and Penetration Test is based on OWASP Top 10 "
            "(2021) standards. The methodology is designed to be adaptable towards the "
            "application environment and security requirements."
        )
        add_paragraph("The methodology can be summarised as a five-step approach:")
        for phase in [
            "Planning and Preparation — Confirm project scope, objectives, and timelines.",
            "Information Gathering, Mapping, and Profiling — Enumerate application endpoints, "
            "parameters, and the technology stack.",
            "Execution and Testing — Automated vulnerability scanning followed by manual "
            "validation and exploitation attempts covering all OWASP Top 10 2021 categories.",
            "Analysis and Reporting — Document all security weaknesses identified with "
            "severity ratings, evidence, and remediation guidance.",
            "Follow-up (Optional) — Retest to validate the effectiveness of remediation efforts.",
        ]:
            p = doc.add_paragraph(style="List Number")
            p.add_run(phase)

        _pgbrk()

        # ── 5. Severity Classification ──────────────────────────────────────────
        doc.add_heading("Severity Classification & Rating", 1)
        add_paragraph(
            "Analysis on the criticality severity of the findings was performed based on the "
            "Common Vulnerability Scoring System 3.1 (CVSS v3.1). The final rating scale is "
            "categorised into five severity levels according to CVSS scoring as follows:"
        )
        add_paragraph("Table 5: Severity rating scale according to CVSS 3.1.", style="Caption",
                      align=WD_ALIGN_PARAGRAPH.CENTER)
        srtable = doc.add_table(rows=1, cols=3)
        srtable.style = "Table Grid"
        srtable.alignment = WD_TABLE_ALIGNMENT.CENTER
        for txt, cell in zip(["Rating", "CVSS Score", "Description"],
                             srtable.rows[0].cells):
            _bold_cell(cell, txt, align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(cell, "2E74B5")
            cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        for sev_name, score_range, desc, bg_col in [
            ("Critical",      "9.0 – 10.0", "Exploitation is straightforward and usually results in system-level compromise. Patch immediately.",                                    "C00000"),
            ("High",          "7.0 – 8.9",  "Exploitation is more difficult but could cause elevated privileges and data loss. Patch as soon as possible.",                         "FF0000"),
            ("Medium",        "4.0 – 6.9",  "Vulnerabilities exist but may require extra steps to exploit. Patch after high-priority issues are resolved.",                         "FF6600"),
            ("Low",           "0.1 – 3.9",  "Non-exploitable vulnerabilities that increase the attack surface. Address during the next maintenance window.",                        "FFD700"),
            ("Informational", "0.0",         "No vulnerability exists. Informational findings and security observations with no direct risk.",                                       "4472C4"),
        ]:
            r = srtable.add_row().cells
            _bold_cell(r[0], sev_name, font_color_hex="FFFFFF", align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(r[0], bg_col)
            r[1].text = score_range
            r[1].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            r[2].text = desc

        _pgbrk()

        # ── 6. List of Findings ────────────────────────────────────────────────
        doc.add_heading("List of Findings", 1)
        add_paragraph(
            "The following table presents a comprehensive summary of the findings identified "
            "during the assessment, detailing each issue's severity rating, CVSS score, and status."
        )
        add_paragraph("Table 6: List of severity findings.", style="Caption",
                      align=WD_ALIGN_PARAGRAPH.CENTER)
        lftable = doc.add_table(rows=1, cols=5)
        lftable.style = "Table Grid"
        lftable.alignment = WD_TABLE_ALIGNMENT.CENTER
        for txt, cell in zip(
            ["SN.", "Findings", "Severity Rating", "CVSS Score", "Finding Status"],
            lftable.rows[0].cells,
        ):
            _bold_cell(cell, txt, align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(cell, "2E74B5")
            cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        for f in py_findings:
            r = lftable.add_row().cells
            r[0].text = f["id"]
            r[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            r[1].text = f"{f['id']}: {f['title']}"
            sev_bg = _SEV_COLOUR.get(f["severity"], "808080")
            _bold_cell(r[2], f["severity"], font_color_hex="FFFFFF" if f["severity"] != "Low" else "000000",
                       align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(r[2], sev_bg)
            r[3].text = str(f["cvss_score"])
            r[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            r[4].text = f["status"]
            r[4].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

        # ── 6.1 Finding Status Description ─────────────────────────────────────
        doc.add_heading("Finding Status Description", 2)
        add_paragraph("Table 7: List of finding statuses.", style="Caption",
                      align=WD_ALIGN_PARAGRAPH.CENTER)
        fstable = doc.add_table(rows=1, cols=2)
        fstable.style = "Table Grid"
        fstable.alignment = WD_TABLE_ALIGNMENT.CENTER
        _bold_cell(fstable.rows[0].cells[0], "Finding Status",
                   align=WD_ALIGN_PARAGRAPH.CENTER)
        _cell_bg(fstable.rows[0].cells[0], "2E74B5")
        fstable.rows[0].cells[0].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        _bold_cell(fstable.rows[0].cells[1], "Description")
        _cell_bg(fstable.rows[0].cells[1], "2E74B5")
        fstable.rows[0].cells[1].paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        for status, desc in [
            ("Open",              "The issue or vulnerability has been identified but has not yet been addressed or remediated."),
            ("Resolved",          "The risk finding has been remediated; mitigation measures have been implemented with minimal residual risk."),
            ("Partially Resolved","Remediation measures have been implemented but further action is required to fully address the issue."),
            ("Risk Accepted",     "Management has acknowledged and accepted the inherent risk for this finding."),
            ("Closed",            "Management has determined the risk finding to be irrelevant, not applicable, or a false positive."),
        ]:
            r = fstable.add_row().cells
            r[0].text = status
            r[1].text = desc

        _pgbrk()

        # ── 7. Security Test Findings ───────────────────────────────────────────
        doc.add_heading("Security Test Findings", 1)

        fig_counter = [1]  # mutable counter for figure numbering

        for idx, f in enumerate(py_findings):
            # Each finding on its own page (after the section heading on the first)
            if idx > 0:
                _pgbrk()

            # ── H2: WVAPT-N: Title ────────────────────────────────────────────
            doc.add_heading(f"{f['id']}: {f['title']}", 2)

            # ── CVSS Scoring Table ─────────────────────────────────────────────
            cvss_metrics = _parse_cvss_vector(f.get("cvss_vector", ""))
            cvss_tbl = doc.add_table(rows=6, cols=4)
            cvss_tbl.style = "Table Grid"
            cvss_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
            sev_col = _SEV_COLOUR.get(f["severity"], "808080")
            txt_col = "FFFFFF" if f["severity"] != "Low" else "000000"

            r0 = cvss_tbl.rows[0].cells
            _bold_cell(r0[0], "Base Score", align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(r0[0], "D9E1F2")
            r0[1].merge(r0[2]).merge(r0[3])
            _bold_cell(r0[1], f"{f['severity']}  ({f['cvss_score']})",
                       font_color_hex=txt_col, align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(r0[1], sev_col)

            r1 = cvss_tbl.rows[1].cells
            _bold_cell(r1[0], "CVSS Vector", align=WD_ALIGN_PARAGRAPH.CENTER)
            _cell_bg(r1[0], "D9E1F2")
            r1[1].merge(r1[2]).merge(r1[3])
            r1[1].text = f.get("cvss_vector", "N/A")
            if r1[1].paragraphs[0].runs:
                r1[1].paragraphs[0].runs[0].font.name = "Courier New"
                r1[1].paragraphs[0].runs[0].font.size = Pt(9)

            left_keys  = ["AV", "AC", "PR", "UI"]
            right_keys = ["S",  "C",  "I",  "A"]
            for row_i, (lk, rk) in enumerate(zip(left_keys, right_keys), start=2):
                row = cvss_tbl.rows[row_i].cells
                _bold_cell(row[0], _CVSS_METRIC_LABELS[lk][0])
                _cell_bg(row[0], "EBF3FB")
                row[1].text = _cvss_val(cvss_metrics, lk)
                _bold_cell(row[2], _CVSS_METRIC_LABELS[rk][0])
                _cell_bg(row[2], "EBF3FB")
                row[3].text = _cvss_val(cvss_metrics, rk)

            # ── H3: Observations ──────────────────────────────────────────────
            doc.add_heading("Observations", 3)
            obs_text = f.get("description", "").strip()
            if not obs_text or len(obs_text) < 30:
                obs_text = (
                    f"The application was found to be susceptible to {f['title']}. "
                    f"During the assessment, testing of the endpoint at {f['location']} "
                    f"confirmed the presence of this vulnerability. "
                    f"{f.get('implications', '')[:200]}"
                ).strip()
            add_paragraph(obs_text)

            # ── H3: Affected Hosts / Services ─────────────────────────────────
            doc.add_heading("Affected Hosts/Services", 3)
            add_paragraph(
                "Evidence supporting this observation was collected from the following URL(s):"
            )
            ahtable = doc.add_table(rows=2, cols=4)
            ahtable.style = "Table Grid"
            ahtable.alignment = WD_TABLE_ALIGNMENT.CENTER
            for txt, cell in zip(["No.", "Affected URL", "Parameter", "Status"],
                                 ahtable.rows[0].cells):
                _bold_cell(cell, txt, align=WD_ALIGN_PARAGRAPH.CENTER)
                _cell_bg(cell, "D9E1F2")
            ahr = ahtable.rows[1].cells
            ahr[0].text = "1"
            ahr[0].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            ahr[1].text = f["location"]
            ahr[2].text = f.get("parameter", "N/A") or "N/A"
            ahr[2].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER
            ahr[3].text = f["status"]
            ahr[3].paragraphs[0].alignment = WD_ALIGN_PARAGRAPH.CENTER

            # ── H3: Proof of Concept ──────────────────────────────────────────
            doc.add_heading("Proof of Concept", 3)
            poc_narrative = _poc_to_narrative(
                poc_text=f.get("proof_of_concept", ""),
                vuln_type=f["title"],
                url=f["location"],
                param=f.get("parameter", ""),
                has_screenshot=bool(f.get("screenshot_path")),
            )
            add_paragraph(poc_narrative)

            # ── Response Headers table (header-related findings only) ─────────
            _resp_hdrs = f.get("response_headers")
            if _resp_hdrs:
                add_paragraph(
                    "The following HTTP response headers were observed from the target during reconnaissance:",
                )
                _hdr_tbl = doc.add_table(rows=1, cols=2)
                _hdr_tbl.style = "Table Grid"
                _hdr_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
                # Header row
                _hdr_row = _hdr_tbl.rows[0].cells
                _bold_cell(_hdr_row[0], "Header Name", align=WD_ALIGN_PARAGRAPH.CENTER)
                _bold_cell(_hdr_row[1], "Value",       align=WD_ALIGN_PARAGRAPH.CENTER)
                _cell_bg(_hdr_row[0], "2E74B5")
                _cell_bg(_hdr_row[1], "2E74B5")
                for _c in _hdr_row:
                    _c.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
                # Data rows — one per header, sorted alphabetically
                for _hname, _hval in sorted(_resp_hdrs.items(), key=lambda x: x[0].lower()):
                    _dr = _hdr_tbl.add_row().cells
                    for _dc, _txt in ((_dr[0], _hname), (_dr[1], str(_hval))):
                        _dc.paragraphs[0].clear()
                        _rn = _dc.paragraphs[0].add_run(_txt)
                        _rn.font.name = "Courier New"
                        _rn.font.size = Pt(9)
                    # Alternate row shading
                    _row_idx = len(_hdr_tbl.rows) - 1
                    if _row_idx % 2 == 0:
                        _cell_bg(_dr[0], "EBF3FB")
                        _cell_bg(_dr[1], "EBF3FB")

            pic_path_before = f.get("screenshot_path_before", "")
            pic_path        = f.get("screenshot_path", "")
            _has_before = pic_path_before and os.path.exists(pic_path_before)
            _has_after  = pic_path        and os.path.exists(pic_path)

            # Before/after pair for auth, injection, and XSS findings
            if _has_before or _has_after:
                _title_lower = f["title"].lower()
                _is_auth = any(k in _title_lower for k in [
                    "default cred", "weak cred", "brute", "credential stuff",
                    "auth bypass", "login bypass", "authentication bypass",
                ])
                _is_sqli = any(k in _title_lower for k in [
                    "sql", "sqli", "injection", "sql injection",
                ])
                _is_xss = any(k in _title_lower for k in ["xss", "cross-site scripting"])

                # Determine labels based on finding type
                if _is_sqli and not _is_auth:
                    _lbl_before = "Before — Form with SQL Injection Payload (Pre-Submit):"
                    _lbl_after  = "After — Application Response / Authenticated State (Post-Exploitation):"
                    _cap_before = f"Figure {{n}}: SQL Injection payload visible in form field prior to submission ({f['id']} — {f['title']})."
                    _cap_after  = f"Figure {{n}}: Authenticated state following successful SQL Injection bypass ({f['id']} — {f['title']})."
                elif _is_sqli or _is_auth:
                    _lbl_before = "Before — Login Form with Payload (Pre-Submit):"
                    _lbl_after  = "After — Authenticated Dashboard (Post-Exploitation):"
                    _cap_before = f"Figure {{n}}: Login form showing injected payload before form submission ({f['id']} — {f['title']})."
                    _cap_after  = f"Figure {{n}}: Authenticated session obtained following successful bypass ({f['id']} — {f['title']})."
                elif _is_xss:
                    _lbl_before = "Before — Input Form with XSS Payload:"
                    _lbl_after  = "After — XSS Confirmed in Response:"
                    _cap_before = f"Figure {{n}}: XSS payload visible in input field at vulnerable endpoint ({f['id']} — {f['title']})."
                    _cap_after  = f"Figure {{n}}: XSS payload reflected/executed in application response ({f['id']} — {f['title']})."
                else:
                    _lbl_before = "Before — Pre-Exploitation State:"
                    _lbl_after  = "After — Post-Exploitation Evidence:"
                    _cap_before = f"Figure {{n}}: Application state before exploitation ({f['id']} — {f['title']})."
                    _cap_after  = f"Figure {{n}}: Exploitation evidence ({f['id']} — {f['title']})."

                _show_pair = _has_before and _has_after
                if _show_pair:
                    # "Before" screenshot
                    try:
                        p_lbl = add_paragraph(_lbl_before)
                        p_lbl.runs[0].bold = True
                        p_pic_b = doc.add_paragraph()
                        p_pic_b.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        p_pic_b.paragraph_format.space_before = Pt(6)
                        p_pic_b.add_run().add_picture(pic_path_before, width=Inches(5.5))
                        p_cap_b = doc.add_paragraph(
                            _cap_before.replace("{n}", str(fig_counter[0])),
                            style="Caption",
                        )
                        p_cap_b.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        fig_counter[0] += 1
                    except Exception as e:
                        add_paragraph(f"[Before screenshot unavailable: {e}]")
                    # "After" screenshot
                    try:
                        p_lbl2 = add_paragraph(_lbl_after)
                        p_lbl2.runs[0].bold = True
                        p_pic_a = doc.add_paragraph()
                        p_pic_a.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        p_pic_a.paragraph_format.space_before = Pt(6)
                        p_pic_a.add_run().add_picture(pic_path, width=Inches(5.5))
                        p_cap_a = doc.add_paragraph(
                            _cap_after.replace("{n}", str(fig_counter[0])),
                            style="Caption",
                        )
                        p_cap_a.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        fig_counter[0] += 1
                    except Exception as e:
                        add_paragraph(f"[After screenshot unavailable: {e}]")
                else:
                    # Single screenshot — only one side available
                    _pic = pic_path if _has_after else pic_path_before
                    try:
                        p_pic = doc.add_paragraph()
                        p_pic.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        p_pic.paragraph_format.space_before = Pt(6)
                        p_pic.add_run().add_picture(_pic, width=Inches(5.5))
                        p_cap = doc.add_paragraph(
                            f"Figure {fig_counter[0]}: Evidence screenshot for "
                            f"{f['id']} — {f['title']}.",
                            style="Caption",
                        )
                        p_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
                        fig_counter[0] += 1
                    except Exception as e:
                        add_paragraph(f"[Screenshot unavailable: {e}]")

            # ── H3: Implications ──────────────────────────────────────────────
            doc.add_heading("Implications", 3)
            add_paragraph(f["implications"])

            # ── H3: Recommendations ───────────────────────────────────────────
            doc.add_heading("Recommendations", 3)
            add_paragraph(f["recommendations"])

            # ── H3: References ────────────────────────────────────────────────
            doc.add_heading("References", 3)
            owasp_refs = _get_owasp_refs(f["title"])
            if not owasp_refs:
                owasp_refs = [("", "OWASP Top 10 2021",
                               "https://owasp.org/www-project-top-ten/")]
            for code, name, url_ref in owasp_refs:
                p = doc.add_paragraph(style="List Bullet")
                ref_label = f"{code} – {name}" if code else name
                p.add_run(f"{ref_label} — {url_ref}")
            p = doc.add_paragraph(style="List Bullet")
            p.add_run("CVSS v3.1 Calculator — https://www.first.org/cvss/calculator/3.1")

            # ── H3: Remarks ───────────────────────────────────────────────────
            doc.add_heading("Remarks", 3)
            for i_rem, header_text in enumerate([
                "Management Comments (To be filled in by the client)",
                "Post Review Observations (To be filled in by the assessor)",
            ]):
                if i_rem > 0:
                    _tbl_gap()   # small gap between the two remark tables
                rem_tbl = doc.add_table(rows=3, cols=2)
                rem_tbl.style = "Table Grid"
                rem_tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
                hdr_row = rem_tbl.rows[0].cells
                hdr_row[0].merge(hdr_row[1])
                _bold_cell(hdr_row[0], header_text)
                _cell_bg(hdr_row[0], "D9E1F2")
                _bold_cell(rem_tbl.rows[1].cells[0], "Date",
                           align=WD_ALIGN_PARAGRAPH.CENTER)
                _bold_cell(rem_tbl.rows[1].cells[1], "Comment")
                rem_tbl.rows[2].cells[0].text = ""
                rem_tbl.rows[2].cells[1].text = ""

        _pgbrk()

        # ── 8. Remediation Roadmap ─────────────────────────────────────────────
        doc.add_heading("Remediation Roadmap", 1)
        add_paragraph(
            "The following remediation items are listed in order of priority, from highest to "
            "lowest severity. The organisation is advised to address Critical and High severity "
            "findings within 48–72 hours and schedule Medium and Low severity items for the next "
            "available maintenance window."
        )
        roadmap_raw = narrative.get("remediation_roadmap", "")
        if roadmap_raw:
            for line in roadmap_raw.split("\n"):
                line = line.strip()
                if not line:
                    continue
                p = doc.add_paragraph(style="List Number")
                p.add_run(re.sub(r"^\d+\.\s*", "", line))
        else:
            _sev_order_rm = ["Critical", "High", "Medium", "Low", "Informational", "None"]
            for f in sorted(py_findings,
                            key=lambda x: _sev_order_rm.index(x["severity"])
                            if x["severity"] in _sev_order_rm else 99):
                p = doc.add_paragraph(style="List Number")
                p.add_run(
                    f"[{f['severity']}] {f['title']} at {f['location']} — "
                    f"{f['recommendations'].split('.')[0].rstrip()}."
                )

        _pgbrk()

        # ── 9. Conclusion ──────────────────────────────────────────────────────
        doc.add_heading("Conclusion", 1)
        add_paragraph(narrative.get(
            "conclusion",
            f"The penetration test of {target} identified {len(py_findings)} findings requiring "
            "remediation. Prompt action on Critical and High severity issues is strongly recommended. "
            "A full retest should be conducted after remediation to verify that all identified "
            "vulnerabilities have been effectively resolved."
        ))

        target_folder = self._get_target_folder(target)
        out_base = workspace.repo_path or "."
        report_dir = os.path.join(out_base, "reports", target_folder)
        os.makedirs(report_dir, exist_ok=True)
        filename = os.path.join(report_dir, f"pentest_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx")

        doc.save(filename)
        print(f"[+] Report generated: {filename}  ({len(py_findings)} findings)")
