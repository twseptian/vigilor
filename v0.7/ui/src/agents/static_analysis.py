"""
StaticAnalysisAgent — Phase 1.5: OWASP Top 10 source code static analysis.

Walks workspace.source_path, scans supported source files with deterministic
regex patterns aligned to OWASP Top 10 (2021), and adds hypotheses directly
into the workspace.  No LLM call required.

OWASP Coverage:
  A01 — Broken Access Control   (IDOR, missing auth, session fixation, open redirect)
  A02 — Cryptographic Failures  (weak hashing, TLS disabled, cleartext HTTP, insecure random)
  A03 — Injection               (SQL, NoSQL, Command, LDAP, XPath, SSTI, XXE, Path Traversal, eval())
  A05 — Security Misconfiguration (debug mode, verbose errors, default creds, dir listing)
  A07 — Auth Failures           (plaintext passwords, insecure cookies, JWT weak secret)
  A08 — Software Integrity      (insecure deserialization: pickle, yaml.load, PHP unserialize, Java ObjectInputStream)
  A09 — Logging Failures        (sensitive data in logs, exception details in response)
  A10 — SSRF                    (requests/httpx/curl with user-controlled URL)

Findings are stored in workspace["static_findings"] so the report can
reference file:line locations.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import List, Tuple

from src.agents.base import BaseAgent
from src.core.workspace import WorkspaceManager


# ── Pattern registry ──────────────────────────────────────────────────────────
# Each entry: (file_glob, compiled_re, vuln_type, cvss_score, cvss_vector, detail)

_PATTERNS: List[Tuple[str, re.Pattern, str, float, str, str]] = []


def _reg(glob: str, pattern: str, vuln_type: str, cvss: float, vector: str, detail: str) -> None:
    _PATTERNS.append((glob, re.compile(pattern, re.IGNORECASE), vuln_type, cvss, vector, detail))


# ── SQL Injection ─────────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:execute|cursor\.execute)\s*\(\s*(?:f["\']|["\'].*%s|["\'].*\.format)',
     "SQL Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "String-formatted SQL query — user input likely reaches the DB without parameterisation.")

_reg("*.php",
     r'(?:mysql_query|mysqli_query|pg_query|PDO::query|->query)\s*\(.*(?:\$_GET|\$_POST|\$_REQUEST)',
     "SQL Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Dynamic SQL constructed with unsanitised $_GET/$_POST/$_REQUEST variable.")

# SQL Injection — variable passed as query argument (two-step pattern: $q = ...; mysqli_query($c, $q))
_reg("*.php",
     r'(?:mysqli_query|mysql_query|pg_query)\s*\([^,)]+,\s*\$\w+',
     "SQL Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "mysqli_query called with a variable query argument — verify the query is not built from user input.")

# SQL Injection — SQL keyword inside a PHP string containing a variable (catches "$id" interpolation)
_reg("*.php",
     r'["\'][^"\']*(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP)\b[^"\']*\$\w+',
     "SQL Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "SQL query string contains a PHP variable — if that variable originates from user input, SQL injection is possible.")

_reg("*.js",
     r'(?:\.query|db\.run|db\.all|db\.get|pool\.query)\s*\([`"\'].*\$\{',
     "SQL Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Template-literal SQL — variable interpolation inside the query string.")

_reg("*.java",
     r'(?:Statement|prepareStatement)\s*\(.*\+\s*(?:request\.getParameter|req\.getParameter)',
     "SQL Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "JDBC statement built via string concatenation with request parameter.")

# ── Command Injection ─────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:os\.system|subprocess\.(?:call|run|Popen|check_output))\s*\(.*shell\s*=\s*True',
     "Command Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "subprocess called with shell=True — if command string contains user input, RCE is possible.")

_reg("*.php",
     r'(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_SERVER)',
     "Command Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "PHP shell execution function called directly with unsanitised user-supplied variable.")

# Command Injection — string concatenation with a variable (catches: shell_exec('ping ' . $target))
_reg("*.php",
     r'(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\([^)]*\.\s*\$\w+',
     "Command Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Shell function called with string concatenation — if the concatenated variable is user-controlled, RCE is possible.")

_reg("*.rb",
     r'(?:system|exec|`|Kernel\.system|IO\.popen)\s*(?:\(|).*params\[',
     "Command Injection (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Ruby shell execution with params[] — command injection if input not sanitised.")

# ── Path Traversal / LFI ──────────────────────────────────────────────────────
_reg("*.py",
     r'open\s*\(\s*(?:os\.path\.join\s*\(.*(?:request|args|form|values|json)|f["\'].*(?:request|args|form))',
     "Path Traversal (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "File opened with path derived from request parameters — ../../../ traversal may be possible.")

_reg("*.php",
     r'(?:file_get_contents|include|require|require_once|include_once|readfile|fopen)\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)',
     "Path Traversal (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "PHP file inclusion with unsanitised user input — LFI/RFI or path traversal possible.")

# Path Traversal / LFI — include/require with a plain variable (catches: include($file))
_reg("*.php",
     r'(?:include|require|require_once|include_once)\s*\(\s*\$(?!_SESSION|_SERVER|_COOKIE|_ENV)\w+\s*\)',
     "Path Traversal (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "PHP file inclusion with a variable argument — if the variable originates from user input, LFI/RFI is possible.")

# ── Insecure Deserialization ──────────────────────────────────────────────────
_reg("*.py",
     r'pickle\.loads?\s*\(',
     "Insecure Deserialization (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "pickle.load() — deserialising attacker-controlled data leads to arbitrary code execution.")

_reg("*.py",
     r'yaml\.load\s*\([^)]*\)(?!\s*,\s*Loader\s*=\s*yaml\.SafeLoader)',
     "Insecure Deserialization (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "yaml.load() without SafeLoader — arbitrary Python object construction possible.")

_reg("*.php",
     r'unserialize\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST|\$_COOKIE)',
     "Insecure Deserialization (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "PHP unserialize() with user-controlled input — PHP object injection / RCE possible.")

_reg("*.java",
     r'ObjectInputStream\s*\(',
     "Insecure Deserialization (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Java ObjectInputStream detected — Java deserialization RCE if data is attacker-controlled.")

# ── XXE ───────────────────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:etree\.parse|lxml\.etree\.parse|minidom\.parse|parseString)\s*\(',
     "XXE Injection (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "XML parser detected — verify external entity resolution is disabled (defusedxml recommended).")

_reg("*.php",
     r'(?:simplexml_load_string|simplexml_load_file|DOMDocument)\s*',
     "XXE Injection (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "PHP XML parser — LIBXML_NOENT flag or missing entity substitution disabling may allow XXE.")

# ── SSTI ──────────────────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:render_template_string|Template\s*\()\s*.*(?:request\.|format\s*\(|\%\s)',
     "SSTI (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Jinja2/Mako template rendered with user-controlled string — SSTI leading to RCE.")

_reg("*.php",
     r'(?:Twig|Smarty|Blade)\s*.*(?:render|display)\s*\(.*(?:\$_GET|\$_POST|\$_REQUEST)',
     "SSTI (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "PHP template engine rendering user-supplied input — SSTI / RCE possible.")

# ── Weak Cryptography & Insecure Randomness ───────────────────────────────────
_reg("*.py",
     r'hashlib\.(?:md5|sha1)\s*\(',
     "Weak Cryptography (Source)", 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "MD5/SHA-1 used — collision-prone; replace with SHA-256 or bcrypt for password hashing.")

_reg("*.py",
     r'random\.(?:random|randint|choice|shuffle|sample)\s*\(',
     "Insecure Randomness (Source)", 5.3,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Non-cryptographic random() used — predictable; use secrets module for tokens/nonces.")

_reg("*.js",
     r'Math\.random\s*\(\s*\)',
     "Insecure Randomness (Source)", 5.3,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Math.random() is not cryptographically secure; use crypto.getRandomValues() for tokens.")

# ── Hardcoded Secrets ─────────────────────────────────────────────────────────
_reg("*",
     r'(?:password|passwd|secret|api_key|apikey|token|private_key|auth_token|access_key)\s*=\s*["\'][^"\']{8,}["\']',
     "Hardcoded Secret (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Credential or API key hardcoded in source — exposed via repo access, error pages, or JS bundles.")

# ── PHP Taint Source — user input assigned to variable ────────────────────────
# Informational: marks where user input enters the application.
# Useful for tracing two-step patterns (assign → use in dangerous call).
_reg("*.php",
     r'\$\w+\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
     "User Input Taint Source (PHP)", 0.0,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
     "User-supplied value assigned to a variable — trace this variable to confirm it reaches a dangerous sink (SQL, shell, include, echo).")

# ── XSS (server-side) ─────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:Markup|mark_safe)\s*\(\s*.*(?:request\.|f["\']|format\s*\()',
     "XSS (Source)", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "User input rendered without escaping via Markup/mark_safe — reflected or stored XSS possible.")

_reg("*.js",
     r'(?:innerHTML|outerHTML|document\.write)\s*=\s*.*(?:location\.|search|hash|\.param\(|URLSearchParams)',
     "XSS (Source)", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "DOM-based XSS: user-controlled source (location/search) flows into an innerHTML sink.")

# XSS (PHP) — echo/print directly outputting $_GET/$_POST/$_REQUEST without escaping
_reg("*.php",
     r'(?:echo|print)\b[^;]*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[',
     "XSS (Source)", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "PHP echo/print outputs user-supplied input directly — reflected XSS if output is not HTML-escaped.")

# XSS (PHP) — echo/print with string concat involving a variable (catches: echo '...' . $name . '...')
_reg("*.php",
     r'(?:echo|print)\b[^;]*\'\s*\.\s*\$\w+\s*\.',
     "XSS (Source)", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "PHP echo/print concatenates a variable into HTML output — potential XSS if the variable is user-controlled and unescaped.")

# ── JWT Weak Secret ───────────────────────────────────────────────────────────
_reg("*",
     r'(?:jwt\.encode|jwt\.sign|\.sign\s*\()\s*.*["\'](?:secret|password|changeme|123456|test|key|default)["\']',
     "JWT Weak Secret (Source)", 8.1,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "JWT signed with trivially guessable secret string — token forgery and privilege escalation possible.")

# ── Prototype Pollution ───────────────────────────────────────────────────────
_reg("*.js",
     r'Object\.assign\s*\(\s*(?:req\.|request\.|body\.|params\.|query\.|\{\})',
     "Prototype Pollution (Source)", 6.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
     "Object.assign with user-controlled input — prototype pollution if __proto__ key not filtered.")

# ── CORS Misconfiguration ─────────────────────────────────────────────────────
_reg("*",
     r'Access-Control-Allow-Origin["\s]*[:=]["\s]*\*',
     "CORS Misconfiguration (Source)", 6.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
     "Wildcard CORS header set in source — any origin can read authenticated API responses.")

# ── Mass Assignment ───────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:Model|User|Account|Profile)\s*\.\s*(?:create|update)\s*\(\s*\*\*(?:request\.|data\.|form\.)',
     "Mass Assignment (Source)", 8.8,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "ORM model created/updated with unpacked request dict — attacker can inject privileged fields.")

_reg("*.js",
     r'(?:new\s+\w+\s*\(|\.create\s*\(|\.update\s*\()\s*(?:req\.body|request\.body)',
     "Mass Assignment (Source)", 8.8,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "Model instantiation directly from req.body — mass assignment of internal fields possible.")

# ── SSRF ──────────────────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:requests\.get|requests\.post|httpx\.get|urllib\.request\.urlopen)\s*\(.*(?:request\.|args\[|form\[|json\.)',
     "SSRF (Source)", 8.6,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
     "HTTP client called with URL derived from user input — SSRF to internal services possible.")

_reg("*.php",
     r'(?:file_get_contents|curl_setopt.*CURLOPT_URL|file\s*\()\s*\(\s*(?:\$_GET|\$_POST|\$_REQUEST)',
     "SSRF (Source)", 8.6,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
     "PHP HTTP fetch with user-controlled URL — SSRF to internal hosts or cloud metadata.")


# ══════════════════════════════════════════════════════════════════════════════
# OWASP Top 10 (2021) — Extended Coverage
# ══════════════════════════════════════════════════════════════════════════════

# ── A01:2021 — Broken Access Control ──────────────────────────────────────────

# IDOR — direct DB query using user-supplied ID without intermediate auth check
_reg("*.php",
     r'WHERE\s+(?:id|user_id|account_id|order_id|record_id)\s*=\s*[\'"]?\s*\{\s*\$\w+|\bWHERE\s+\w+\s*=\s*\$_(?:GET|POST|REQUEST)',
     "A01 - IDOR / Broken Access Control", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
     "SQL query uses user-supplied ID directly — no ownership/role check detected, horizontal privilege escalation possible.")

_reg("*.py",
     r'(?:filter|get|objects\.get)\s*\(\s*(?:id|pk|user_id)\s*=\s*(?:request\.|data\.|args\[)',
     "A01 - IDOR / Broken Access Control", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
     "ORM lookup uses user-supplied ID directly — verify ownership before returning the object.")

# Missing authentication decorator (Flask/Django routes exposed without login_required)
_reg("*.py",
     r'@(?:app|blueprint)\.route\s*\([^)]+\)\s*\ndef\s+\w+',
     "A01 - Missing Auth Check (Route)", 6.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
     "Route defined without @login_required or equivalent decorator — verify this endpoint enforces authentication.")

# Session fixation — session ID set from user input
_reg("*.php",
     r'session_id\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)',
     "A01 - Session Fixation", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
     "session_id() called with user-supplied value — attacker can fixate the session ID to hijack authenticated sessions.")

# Open Redirect
_reg("*.php",
     r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$_(?:GET|POST|REQUEST)',
     "A01 - Open Redirect", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "HTTP Location header set from user-controlled input — open redirect for phishing / OAuth token theft.")

_reg("*.py",
     r'(?:redirect|HttpResponseRedirect|url_for)\s*\(.*(?:request\.|args\[|form\[|get\s*\()',
     "A01 - Open Redirect", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "Redirect target derived from user input — validate against an allowlist of trusted destinations.")

_reg("*.js",
     r'(?:res\.redirect|window\.location)\s*\(?\s*(?:req\.query|req\.body|req\.params)',
     "A01 - Open Redirect", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "Redirect uses user-controlled request value — open redirect possible.")

# ── A02:2021 — Cryptographic Failures ─────────────────────────────────────────

# SSL/TLS verification disabled
_reg("*.py",
     r'(?:verify\s*=\s*False|ssl_verify\s*=\s*False|check_hostname\s*=\s*False|CERT_NONE)',
     "A02 - TLS Verification Disabled", 7.4,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "SSL/TLS certificate verification disabled — connection vulnerable to MITM attacks.")

_reg("*.php",
     r'CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)|CURLOPT_SSL_VERIFYHOST\s*,\s*0',
     "A02 - TLS Verification Disabled", 7.4,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "cURL SSL verification disabled — MITM interception of HTTPS traffic possible.")

_reg("*.js",
     r'rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["\']?0',
     "A02 - TLS Verification Disabled", 7.4,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "Node.js TLS verification disabled — HTTPS connections accept any certificate.")

# Cleartext HTTP used for sensitive endpoints in config/code
_reg("*",
     r'["\']http://[^"\']*(?:login|auth|api|token|password|secret|admin|dashboard)',
     "A02 - Cleartext Transmission of Sensitive Data", 5.9,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Sensitive endpoint referenced over HTTP (not HTTPS) — credentials or tokens may be transmitted in cleartext.")

# Password hashed with MD5/SHA1 (already in weak crypto, add A02 label for clarity)
_reg("*.php",
     r'(?:md5|sha1)\s*\(\s*\$(?:_POST|_GET|_REQUEST|pass|password)',
     "A02 - Weak Password Hashing", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Password hashed with MD5/SHA1 — use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2ID instead.")

_reg("*.py",
     r'hashlib\.(?:md5|sha1)\s*\(.*(?:password|passwd|pass)',
     "A02 - Weak Password Hashing", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Password hashed with MD5/SHA1 — use bcrypt, scrypt, or argon2 for password storage.")

# ── A03:2021 — Injection (extended) ───────────────────────────────────────────

# NoSQL Injection (MongoDB/Mongoose)
_reg("*.js",
     r'\.(?:find|findOne|findById|update|deleteOne|deleteMany)\s*\(\s*(?:req\.body|req\.query|req\.params)',
     "A03 - NoSQL Injection", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "MongoDB query uses request object directly — operator injection ($where, $gt, $regex) may bypass authentication or leak data.")

_reg("*.php",
     r'->(?:find|findOne|update|remove|deleteMany)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
     "A03 - NoSQL Injection", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "MongoDB PHP query uses unsanitised user input — NoSQL operator injection possible.")

# LDAP Injection
_reg("*.php",
     r'ldap_search\s*\([^,]+,[^,]+,[^)]*\$_(?:GET|POST|REQUEST)',
     "A03 - LDAP Injection", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "LDAP search filter constructed with user input — LDAP injection may allow authentication bypass or directory traversal.")

_reg("*.py",
     r'(?:ldap\.search|connection\.search|conn\.search)\s*\(.*(?:request\.|args\[|form\[)',
     "A03 - LDAP Injection", 8.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "Python LDAP search with user-controlled filter — sanitise with ldap.filter.escape_filter_chars().")

# XPath Injection
_reg("*.php",
     r'(?:xpath|XPath|DOMXPath|->evaluate)\s*\([^)]*\$_(?:GET|POST|REQUEST)',
     "A03 - XPath Injection", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "XPath expression built with user input — injection may expose full XML document content.")

_reg("*.java",
     r'(?:xpath\.evaluate|XPath\.compile|xpathExpr)\s*\([^)]*(?:request\.getParameter|req\.getParameter)',
     "A03 - XPath Injection", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Java XPath evaluation with request parameter — parameterise queries or use allowlist validation.")

# Code Injection via eval()
_reg("*.php",
     r'eval\s*\(\s*\$(?:_GET|_POST|_REQUEST|\w+)',
     "A03 - Code Injection via eval()", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "eval() executes a variable as PHP code — if the variable is user-controlled, arbitrary PHP code execution is possible.")

_reg("*.py",
     r'eval\s*\(\s*.*(?:request\.|args\[|form\[|input\s*\()',
     "A03 - Code Injection via eval()", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Python eval() with user-controlled input — arbitrary code execution. Replace with ast.literal_eval() or avoid entirely.")

_reg("*.js",
     r'eval\s*\(\s*(?:req\.|request\.|body\.|query\.|params\.|\$_)',
     "A03 - Code Injection via eval()", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "JavaScript eval() with request-derived input — server-side code injection via Node.js.")

# ── A05:2021 — Security Misconfiguration ──────────────────────────────────────

# Debug mode enabled in production code
_reg("*.py",
     r'(?:app\.run|DEBUG\s*=\s*True|debug\s*=\s*True)',
     "A05 - Debug Mode Enabled", 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Debug mode enabled — stack traces, environment variables, and source code may be exposed to users.")

_reg("*.php",
     r'(?:display_errors\s*=\s*(?:On|1)|ini_set\s*\(\s*["\']display_errors["\']\s*,\s*["\']?(?:1|On|true))',
     "A05 - Verbose Error Display", 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "PHP error display enabled — full stack traces and file paths exposed to users in production.")

# Default / trivially guessable credentials in source
_reg("*",
     r'(?:password|passwd|secret|db_pass)\s*[=:]\s*["\'](?:admin|password|123456|root|test|changeme|default|pass|1234)["\']',
     "A05 - Default Credentials", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Default or trivially guessable credential found in source — must be changed before production deployment.")

# Directory listing / server signature via config
_reg("*",
     r'(?:Options\s+.*Indexes|autoindex\s+on|serveIndex\s*\(\s*)',
     "A05 - Directory Listing Enabled", 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Directory listing enabled in server configuration — file and directory names exposed to unauthenticated users.")

# ── A07:2021 — Identification and Authentication Failures ─────────────────────

# Password stored or compared in plaintext
_reg("*.php",
     r'(?:INSERT|UPDATE)\b[^;]*\bpassword\b[^;]*=\s*["\']?\s*\$(?:_POST|_GET|_REQUEST)\b(?![^;]*(?:md5|sha|hash|crypt|password_hash))',
     "A07 - Plaintext Password Storage", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Password written to database without hashing — use password_hash() with PASSWORD_BCRYPT.")

_reg("*.py",
     r'(?:User\.|user\[.password.\]|password\s*=)\s*(?:request\.|data\.|form\.)[^#\n]*(?!(?:hash|bcrypt|pbkdf2|argon|scrypt))',
     "A07 - Plaintext Password Storage", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Password stored without hashing — use bcrypt.hashpw() or Django's make_password().")

# Insecure cookie flags (no HttpOnly / Secure)
_reg("*.php",
     r'setcookie\s*\([^)]+\)(?![^;]*(?:true\s*,\s*true|httponly|secure))',
     "A07 - Insecure Cookie Configuration", 5.4,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
     "Cookie set without HttpOnly and/or Secure flags — vulnerable to XSS session theft and MITM interception.")

_reg("*.py",
     r'set_cookie\s*\([^)]+\)(?![^)]*(?:httponly\s*=\s*True|secure\s*=\s*True))',
     "A07 - Insecure Cookie Configuration", 5.4,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
     "Cookie set without httponly=True and/or secure=True — set both flags on all session cookies.")

# Hard-coded JWT secret (already exists but add A07 label)
_reg("*.py",
     r'(?:jwt\.encode|PyJWT\.encode)\s*\([^)]*["\'](?:secret|key|password|changeme|test)["\']',
     "A07 - JWT Weak Secret", 8.1,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "JWT signed with weak/hardcoded secret — brute-force or dictionary attack allows token forgery.")

# ── A09:2021 — Security Logging and Monitoring Failures ───────────────────────

# Sensitive data written to logs
_reg("*",
     r'(?:log|logger|logging\.(?:info|debug|warning|error)|console\.log|print)\s*\(.*(?:password|passwd|secret|token|api_key|credit_card|ssn|cvv)',
     "A09 - Sensitive Data in Logs", 4.3,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
     "Sensitive value (password, token, secret) written to application log — may be exposed in log files, SIEM, or log aggregators.")

# Exception details exposed in HTTP response
_reg("*.py",
     r'(?:return|jsonify|Response)\s*\(\s*str\s*\(\s*(?:e|err|error|exception)\s*\)',
     "A09 - Exception Detail Exposed in Response", 4.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Raw exception message returned to the client — stack traces reveal internal paths, libraries, and logic.")

_reg("*.php",
     r'(?:echo|print)\s+.*(?:\$e->getMessage\(\)|mysql_error\(\)|mysqli_error\()',
     "A09 - Exception Detail Exposed in Response", 4.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "Raw database or exception error printed to the HTTP response — exposes schema, query structure, and file paths.")

# ── Prototype Pollution ───────────────────────────────────────────────────────
_reg("*.js",
     r'(?:Object\.assign|merge|deepmerge|extend)\s*\([^)]*(?:req\.|request\.|body\.|query\.|params\.)',
     "Prototype Pollution (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
     "Object.assign/merge with user-controlled input — may allow __proto__ pollution leading to privilege escalation.")

_reg("*.js",
     r'__proto__\s*\[|prototype\s*\[|constructor\s*\[',
     "Prototype Pollution (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
     "Direct __proto__ or constructor property assignment — prototype pollution vector.")

# ── SSTI (Server-Side Template Injection) ────────────────────────────────────
_reg("*.py",
     r'render_template_string\s*\(',
     "SSTI - Unsafe render_template_string (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "render_template_string() with user-supplied input allows Jinja2 template injection → RCE.")

_reg("*.py",
     r'jinja2\.Template\s*\(\s*(?:request\.|f["\']|.*(?:args|form|data)\[)',
     "SSTI - Dynamic Jinja2 Template (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Jinja2.Template instantiated with user-controlled string — template injection to RCE.")

_reg("*.js",
     r'(?:\.render|res\.render|ejs\.render|pug\.render|handlebars\.compile)\s*\([^)]*(?:req\.|body\.|query\.|params\.)',
     "SSTI - Template Engine with User Input (Source)", 9.8,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "Template engine render called with user-controlled input — SSTI may lead to RCE.")

# ── GraphQL Introspection / Injection ─────────────────────────────────────────
_reg("*.js",
     r'introspection\s*[:=]\s*true|allowIntrospection\s*[:=]\s*true',
     "GraphQL Introspection Enabled (Source)", 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "GraphQL introspection enabled in production — schema enumeration allows attackers to discover all types, queries, and mutations.")

_reg("*.py",
     r'Graphene|graphql_sync|graphql\s*\(|strawberry\.Schema',
     "GraphQL Endpoint Detected (Source)", 5.3,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
     "GraphQL endpoint found — verify introspection is disabled and all resolvers enforce authorisation.")

# ── CORS Misconfiguration ─────────────────────────────────────────────────────
_reg("*.py",
     r'(?:allow_origins|CORS_ORIGIN|Access-Control-Allow-Origin)\s*[=:]\s*["\']?\*["\']?',
     "CORS Wildcard Origin (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "CORS policy set to wildcard (*) — combined with credentials this allows cross-origin data theft.")

_reg("*.js",
     r'(?:cors|allowOrigin|Access-Control-Allow-Origin)\s*[=:]\s*["\']?\*["\']?',
     "CORS Wildcard Origin (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Express CORS wildcard origin — restrict to trusted domains and avoid with credentials: true.")

_reg("*.php",
     r'header\s*\(\s*["\']Access-Control-Allow-Origin:\s*\*',
     "CORS Wildcard Origin (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "PHP header sets ACAO: * — use an explicit allowlist of trusted origins.")

# ── Mass Assignment ────────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:update|create|save)\s*\(\s*\*\*(?:request\.json|request\.form|data|kwargs)',
     "Mass Assignment (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
     "Model update/create with unpacked user-supplied dict — attacker may inject admin/is_admin fields.")

_reg("*.js",
     r'(?:\.save|\.create|\.update)\s*\(\s*(?:req\.body|body|data)\s*\)',
     "Mass Assignment (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
     "ORM save/create with entire request body — attacker may inject protected fields (role, isAdmin).")

# ── JWT Algorithm Confusion ───────────────────────────────────────────────────
_reg("*.js",
     r'(?:verify|sign)\s*\([^)]*(?:algorithm[s]?\s*[:=]\s*["\']none["\']|algorithms\s*[:=]\s*\[["\']none)',
     "JWT alg=none Vulnerability (Source)", 9.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
     "JWT verified or signed with alg=none — signature verification is skipped, allowing arbitrary token forgery.")

_reg("*.py",
     r'jwt\.decode\s*\([^)]*algorithms\s*=\s*\[["\'](?:HS256|RS256)["\']',
     "JWT Algorithm Hardcoded (Source)", 5.3,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "JWT decode with hardcoded algorithm — ensure algorithm confusion attacks (RS256→HS256) cannot occur.")

# ── Open Redirect ─────────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:redirect|return redirect)\s*\(\s*(?:request\.|args\[|form\[|data\[)[^)]*\)',
     "Open Redirect (Source)", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "redirect() called with user-controlled URL parameter — validate against allowlist of internal paths.")

_reg("*.php",
     r'header\s*\(\s*["\']Location:\s*["\']?\s*\.\s*\$(?:_GET|_POST|_REQUEST)',
     "Open Redirect (Source)", 6.1,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "Location header set from unvalidated user input — attacker can redirect victims to phishing pages.")

# ── Race Condition ────────────────────────────────────────────────────────────
_reg("*.py",
     r'(?:time\.sleep|asyncio\.sleep)\s*\(\s*0?\s*\).*(?:db\.|session\.|balance|credit|coupon)',
     "Race Condition Risk (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
     "State-modifying operation with timing gap — concurrent requests may exploit TOCTOU race condition.")

# ── HTTP Host Header Injection ────────────────────────────────────────────────
_reg("*.py",
     r'(?:request\.host|request\.META\[.HTTP_HOST.\]|request\.headers\[.Host.\])',
     "HTTP Host Header Injection Risk (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Application uses HTTP Host header directly — verify it is not used in password reset links or cache keys without validation.")

_reg("*.php",
     r'\$_SERVER\[.HTTP_HOST.\]',
     "HTTP Host Header Injection Risk (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "PHP application uses $_SERVER['HTTP_HOST'] — if used in email links or redirects, Host header injection is possible.")

# ── Web Cache Poisoning ───────────────────────────────────────────────────────
_reg("*.py",
     r'(?:X-Forwarded-Host|X-Original-URL|X-Rewrite-URL|X-Forwarded-For)\s*=\s*(?:request\.headers|request\.META)',
     "Web Cache Poisoning Risk (Source)", 7.5,
     "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N",
     "Response varies based on unkeyed header (X-Forwarded-Host etc.) — may allow cache poisoning.")

# ── Insecure File Upload ───────────────────────────────────────────────────────
_reg("*.php",
     r'move_uploaded_file\s*\([^)]*\$_FILES',
     "Unrestricted File Upload (Source)", 9.0,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
     "move_uploaded_file without extension/MIME validation — attacker may upload PHP webshell.")

_reg("*.py",
     r'(?:file\.save|save_file|\.write\s*\(.*(?:file|upload|attachment))',
     "Unrestricted File Upload Risk (Source)", 9.0,
     "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
     "File saved from user upload — verify extension and MIME type are allowlisted before saving.")

# ── WebSocket Security ─────────────────────────────────────────────────────────
_reg("*.js",
     r'new\s+WebSocket\s*\(|io\s*\(\s*["\']',
     "WebSocket Endpoint (Source)", 6.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "WebSocket endpoint detected — verify Origin header validation and authentication on connection upgrade.")

_reg("*.py",
     r'(?:websockets\.serve|WebSocketServerProtocol|@websocket)',
     "WebSocket Endpoint (Source)", 6.5,
     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "Python WebSocket server — ensure CSRF-like Origin checks and session-level authentication are enforced.")

# ── Supported extensions ──────────────────────────────────────────────────────
_SUPPORTED_EXTS = {".py", ".php", ".js", ".ts", ".java", ".rb", ".go"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", "vendor", "venv", ".venv", "dist", "build"}
_MAX_FILE_BYTES = 512 * 1024  # skip files > 512 KB
_MAX_FILES = 1000


def _ext_matches(glob: str, ext: str) -> bool:
    if glob == "*":
        return True
    if glob.startswith("*."):
        return ext == glob[1:]
    return False


def _severity(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return "Informational"


class StaticAnalysisAgent(BaseAgent):
    """Phase 1.5 — deterministic source code static analysis.

    Scans the repo_path provided on the CLI.  Adds confirmed pattern-match
    findings as hypotheses (with file:line location) and stores the raw list
    in workspace["static_findings"] for the report.
    """

    def __init__(self, engine):
        super().__init__(engine)

    async def execute(self, workspace: WorkspaceManager) -> None:
        repo = workspace.source_path
        if not repo or not os.path.isdir(repo):
            print("[*] StaticAnalysis: source_path not set or not a directory — skipping.")
            return

        print(f"[*] StaticAnalysisAgent: scanning '{repo}' ...")
        raw_findings: list = []
        files_scanned = 0

        for dirpath, dirs, filenames in os.walk(repo):
            # Prune noise directories in-place
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]

            for fname in filenames:
                ext = Path(fname).suffix.lower()
                if ext not in _SUPPORTED_EXTS:
                    continue
                full_path = os.path.join(dirpath, fname)
                try:
                    if os.path.getsize(full_path) > _MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                if files_scanned >= _MAX_FILES:
                    print(f"[*] StaticAnalysis: file limit ({_MAX_FILES}) reached.")
                    break
                files_scanned += 1

                try:
                    text = Path(full_path).read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue

                for line_no, line in enumerate(text.splitlines(), start=1):
                    for glob, pattern, vuln_type, cvss, vector, detail in _PATTERNS:
                        if not _ext_matches(glob, ext):
                            continue
                        if pattern.search(line):
                            rel = os.path.relpath(full_path, repo)
                            raw_findings.append(
                                {
                                    "type": vuln_type,
                                    "location": f"{rel}:{line_no}",
                                    "cvss": cvss,
                                    "vector": vector,
                                    "detail": detail,
                                    "snippet": line.strip()[:220],
                                }
                            )

        if not raw_findings:
            print(f"[*] StaticAnalysis: {files_scanned} file(s) scanned — no patterns matched.")
            return

        # Deduplicate: same (type, location) pair
        seen: set = set()
        unique: list = []
        for f in raw_findings:
            key = (f["type"], f["location"])
            if key not in seen:
                seen.add(key)
                unique.append(f)

        workspace.add_recon_data("static_findings", unique)

        for f in unique:
            details = (
                f"{f['detail']}\n"
                f"Source location : {f['location']}\n"
                f"Matched snippet : {f['snippet']}"
            )
            workspace.add_hypothesis(
                vuln_type=f["type"],
                details=details,
                location=f["location"],
                cvss_score=f["cvss"],
                cvss_vector=f["vector"],
                severity=_severity(f["cvss"]),
            )

        print(
            f"[+] StaticAnalysis: {files_scanned} file(s) scanned → "
            f"{len(unique)} finding(s) added as hypotheses."
        )
