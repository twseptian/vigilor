"""
services/attack_workflow.py — Attack workflow / attack chain generator.

Turns a completed scan's findings into:

  • an attack-path GRAPH   — target → stages → findings → impact nodes
  • ATTACK CHAINS          — multi-step vulnerability chaining scenarios
  • a MERMAID flowchart    — portable source for reports / external tools
  • a per-finding FLOW     — step-by-step exploitation path of one finding

Design rule (anti-hallucination): the graph and every chain step are derived
DETERMINISTICALLY from findings that actually exist in the database.  The LLM
is only allowed to (a) write the narrative summary and (b) propose extra chains
that reference EXISTING finding refs — anything referencing an unknown ref is
dropped before persistence.  Each chain carries a confidence score and an
`evidence_backed` flag computed from the participating findings' PoC evidence.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

# ── Stages (kill-chain columns, left → right) ────────────────────────────────

STAGES: list[tuple[str, str]] = [
    ("recon",    "Reconnaissance"),
    ("access",   "Initial Access"),
    ("exploit",  "Exploitation"),
    ("escalate", "Privilege Escalation"),
    ("impact",   "Impact"),
]
_STAGE_COLUMN = {key: i + 1 for i, (key, _) in enumerate(STAGES)}   # target occupies column 0
_STAGE_LABEL = dict(STAGES)

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Informational"]


def _sev_rank(sev: str | None) -> int:
    try:
        return SEVERITY_ORDER.index(sev or "Informational")
    except ValueError:
        return len(SEVERITY_ORDER) - 1


def _max_sev(sevs: Iterable[str | None]) -> str:
    best = "Informational"
    for s in sevs:
        if _sev_rank(s) < _sev_rank(best):
            best = s or "Informational"
    return best


def _downgrade(sev: str) -> str:
    idx = min(_sev_rank(sev) + 1, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[idx]


# ── Vulnerability categorisation ─────────────────────────────────────────────

_CATEGORY_PATTERNS: list[tuple[str, str]] = [
    ("upload",     r"file.?upload|unrestricted.upload|arbitrary.file.write"),
    ("traversal",  r"path.travers|directory.travers|\blfi\b|local.file.inclusion|\brfi\b|arbitrary.file.read"),
    ("rce",        r"\brce\b|remote.code|command.inject|os.command|code.execution|webshell|shell.upload"),
    ("sqli",       r"sql.inject|\bsqli\b|nosql.inject|blind.sql"),
    ("xss",        r"\bxss\b|cross.site.script|html.inject"),
    ("idor",       r"\bidor\b|insecure.direct.object|\bbola\b|object.level.author"),
    ("bac",        r"broken.access|missing.function.level|forced.brows|privilege.escal|authoriz.*bypass|\bbfla\b"),
    ("ssrf",       r"\bssrf\b|server.side.request"),
    ("redirect",   r"open.redirect|unvalidated.redirect"),
    ("oauth",      r"\boauth\b|\bsso\b|\boidc\b|\bsaml\b"),
    ("authbypass", r"auth\w*.bypass|authentication.bypass|login.bypass|default.credential|weak.password|brute.force"),
    ("jwt",        r"\bjwt\b|json.web.token|algorithm.confusion|none.algorithm"),
    ("session",    r"session.fixat|session.hijack|httponly|samesite|missing.secure|insecure.cookie|cookie.*flag"),
    ("csrf",       r"\bcsrf\b|cross.site.request.forgery"),
    ("xxe",        r"\bxxe\b|xml.external"),
    ("ssti",       r"\bssti\b|template.inject"),
    ("deser",      r"deserializ|pickle|gadget.chain"),
    ("secrets",    r"api.?key|secret|hardcoded|\.env\b|private.key|credential.*(expos|leak)|token.*expos"),
    ("infoleak",   r"information.disclos|verbose.error|stack.trace|debug|directory.listing|version.disclos"
                   r"|banner|phpinfo|source.code.disclos|backup.file|\.git\b|swagger|actuator"),
    ("cors",       r"\bcors\b|cross.origin.resource"),
    ("clickjack",  r"clickjack|x.frame.options|frame.?able"),
    ("ratelimit",  r"rate.limit|throttl|account.lockout"),
    ("crypto",     r"weak.cipher|\btls\b|\bssl\b|\bhsts\b|cleartext|insecure.transm|weak.hash|\bmd5\b|\bsha1\b"),
    ("misconfig",  r"misconfigur|missing.*header|security.header|content.security.policy|\bcsp\b"
                   r"|permissions.policy|referrer.policy|x.content.type|mime.sniff"),
    ("massassign", r"mass.assign|parameter.pollut|http.parameter"),
    ("race",       r"race.condition|toctou"),
    ("bizlogic",   r"business.logic|workflow.bypass|price.tamper|insecure.design"),
]

_CATEGORY_STAGE: dict[str, str] = {
    "infoleak": "recon", "misconfig": "recon", "crypto": "recon",
    "clickjack": "recon", "cors": "recon", "secrets": "recon",
    "authbypass": "access", "jwt": "access", "session": "access",
    "ratelimit": "access", "oauth": "access", "redirect": "access", "csrf": "access",
    "sqli": "exploit", "xss": "exploit", "ssrf": "exploit", "xxe": "exploit",
    "ssti": "exploit", "deser": "exploit", "upload": "exploit", "traversal": "exploit",
    "rce": "exploit", "race": "exploit", "bizlogic": "exploit", "massassign": "exploit",
    "idor": "escalate", "bac": "escalate",
}

_CATEGORY_LABEL: dict[str, str] = {
    "upload": "File Upload", "traversal": "Path Traversal", "rce": "Code Execution",
    "sqli": "SQL Injection", "xss": "Cross-Site Scripting", "idor": "IDOR",
    "bac": "Broken Access Control", "ssrf": "SSRF", "redirect": "Open Redirect",
    "oauth": "OAuth / SSO", "authbypass": "Authentication Weakness", "jwt": "JWT Weakness",
    "session": "Session Handling", "csrf": "CSRF", "xxe": "XXE", "ssti": "Template Injection",
    "deser": "Insecure Deserialization", "secrets": "Exposed Secrets",
    "infoleak": "Information Disclosure", "cors": "CORS Misconfiguration",
    "clickjack": "Clickjacking", "ratelimit": "Missing Rate Limiting",
    "crypto": "Transport / Crypto Weakness", "misconfig": "Security Misconfiguration",
    "massassign": "Mass Assignment", "race": "Race Condition", "bizlogic": "Business Logic Flaw",
}


def _categories(finding: Any) -> list[str]:
    """All categories a finding matches, from its title / type / location."""
    haystack = " ".join(
        str(x or "") for x in (
            getattr(finding, "title", ""),
            getattr(finding, "vuln_type", ""),
            getattr(finding, "owasp_name", ""),
            getattr(finding, "location", ""),
        )
    ).lower()
    haystack = re.sub(r"[\s\-/_]+", ".", haystack)
    return [cat for cat, pattern in _CATEGORY_PATTERNS if re.search(pattern, haystack)]


def _stage_for(cats: list[str], finding: Any) -> str:
    for cat in cats:
        stage = _CATEGORY_STAGE.get(cat)
        if stage:
            return stage
    # No category matched — place by severity: real issues sit in exploitation,
    # informational noise stays in recon.
    return "recon" if _sev_rank(getattr(finding, "severity", None)) >= 3 else "exploit"


# ── Chain templates ──────────────────────────────────────────────────────────
# requires: list of groups; each group is satisfied by one DISTINCT finding
#           matching any category in that group.
# steps:    (action text, index into `requires` — which finding the step uses)

_CHAIN_TEMPLATES: list[dict[str, Any]] = [
    {
        "id": "upload-rce",
        "name": "Malicious Upload → File Inclusion → Remote Code Execution",
        "requires": [["upload"], ["traversal", "rce"]],
        "severity": "Critical",
        "terminal": "Remote code execution / full host takeover",
        "impact": "An attacker gains arbitrary command execution on the application server, "
                  "leading to full compromise of the host and any data or credentials it holds.",
        "steps": [
            ("Upload a server-side script (webshell) through the unrestricted upload endpoint", 0),
            ("Locate the stored file and reach it through the file inclusion / traversal primitive", 1),
            ("Invoke the uploaded shell to execute operating-system commands on the host", 1),
        ],
        "supersedes": ["code-exec"],
    },
    {
        "id": "code-exec",
        "name": "Injection Flaw → Remote Code Execution → Host Compromise",
        "requires": [["rce", "deser", "ssti"]],
        "severity": "Critical",
        "terminal": "Remote code execution / full host takeover",
        "impact": "Direct command execution on the application server allows the attacker to read "
                  "application secrets, pivot into the internal network and persist on the host.",
        "steps": [
            ("Deliver the injection payload to the vulnerable parameter", 0),
            ("Confirm out-of-band or in-band command execution on the server", 0),
            ("Read application configuration/secrets and establish persistence", 0),
        ],
    },
    {
        "id": "sqli-ato",
        "name": "SQL Injection → Credential Dump → Administrative Account Takeover",
        "requires": [["sqli"], ["authbypass", "jwt", "oauth", "session", "bac"]],
        "severity": "Critical",
        "terminal": "Administrative account takeover",
        "impact": "Database contents including credential hashes are exfiltrated and replayed against "
                  "the weak authentication layer, giving the attacker privileged application access.",
        "steps": [
            ("Confirm the injection point and enumerate database schema", 0),
            ("Dump the user/credential tables through the injection", 0),
            ("Replay the recovered credentials against the weak authentication surface", 1),
            ("Authenticate as a privileged user and access administrative functionality", 1),
        ],
        "supersedes": ["sqli-dump"],
    },
    {
        "id": "sqli-dump",
        "name": "SQL Injection → Database Exfiltration",
        "requires": [["sqli"]],
        "severity": "Critical",
        "terminal": "Mass data exfiltration",
        "impact": "The full contents of the backing database — including personal data and credential "
                  "material — can be read by an unauthenticated attacker.",
        "steps": [
            ("Confirm the injection point and determine the DBMS", 0),
            ("Enumerate schema, tables and columns", 0),
            ("Exfiltrate sensitive records (users, credentials, business data)", 0),
        ],
    },
    {
        "id": "xss-ato",
        "name": "Cross-Site Scripting → Session Theft → Account Takeover",
        "requires": [["xss"], ["session", "authbypass", "jwt", "bac"]],
        "severity": "High",
        "terminal": "Account takeover / privileged session hijack",
        "impact": "Script execution in a victim's browser combined with weak session protection lets "
                  "the attacker steal an authenticated session and act as that user, including admins.",
        "steps": [
            ("Inject the payload into the vulnerable parameter and confirm execution", 0),
            ("Weaponise the payload to read the session cookie or bearer token", 1),
            ("Deliver the payload to an authenticated (ideally administrative) user", 0),
            ("Replay the captured session to operate as the victim", 1),
        ],
        "supersedes": ["xss-session"],
    },
    {
        "id": "xss-session",
        "name": "Cross-Site Scripting → Client-Side Compromise",
        "requires": [["xss"]],
        "severity": "High",
        "terminal": "Client-side compromise of application users",
        "impact": "Attacker-controlled JavaScript runs in the origin of the application, enabling "
                  "credential phishing, request forgery in the victim's context and data theft.",
        "steps": [
            ("Inject the payload into the vulnerable parameter and confirm execution", 0),
            ("Escalate to a persistent/stored delivery vector where possible", 0),
            ("Perform actions in the victim's authenticated context", 0),
        ],
    },
    {
        "id": "ssrf-cloud",
        "name": "SSRF → Internal Service / Cloud Metadata → Credential Theft",
        "requires": [["ssrf"]],
        "severity": "Critical",
        "terminal": "Cloud credential theft / internal network access",
        "impact": "The server can be coerced into requesting internal endpoints, exposing cloud instance "
                  "credentials and internal services that are unreachable from the internet.",
        "steps": [
            ("Confirm the server issues attacker-controlled outbound requests", 0),
            ("Pivot to the cloud metadata service (169.254.169.254) or internal hosts", 0),
            ("Extract instance credentials / internal service responses", 0),
            ("Reuse the credentials against the cloud control plane", 0),
        ],
    },
    {
        "id": "leak-idor",
        "name": "Information Leak → Identifier Enumeration → IDOR Mass Data Exposure",
        "requires": [["infoleak", "secrets"], ["idor", "bac"]],
        "severity": "High",
        "terminal": "Mass exposure of other users' data",
        "impact": "Leaked identifiers make the access-control flaw trivially enumerable, turning a "
                  "single-record exposure into bulk extraction of other tenants' data.",
        "steps": [
            ("Harvest object/user identifiers from the disclosure", 0),
            ("Substitute the harvested identifiers into the vulnerable endpoint", 1),
            ("Iterate over the identifier space to extract records at scale", 1),
        ],
        "supersedes": ["idor-mass"],
    },
    {
        "id": "idor-mass",
        "name": "Broken Access Control → Horizontal / Vertical Privilege Escalation",
        "requires": [["idor", "bac"]],
        "severity": "High",
        "terminal": "Unauthorised access to other users' data and functions",
        "impact": "Authorisation is enforced client-side or not at all, so any authenticated (or "
                  "unauthenticated) actor can read and modify resources belonging to other users.",
        "steps": [
            ("Establish a baseline request as a low-privileged user", 0),
            ("Tamper with the object identifier / role parameter", 0),
            ("Confirm access to another user's or an administrative resource", 0),
        ],
    },
    {
        "id": "redirect-oauth",
        "name": "Open Redirect → OAuth Redirect Abuse → Token Theft",
        "requires": [["redirect"], ["oauth"]],
        "severity": "High",
        "terminal": "Authorisation token theft / account takeover",
        "impact": "The redirect primitive satisfies the OAuth redirect_uri allow-list while forwarding "
                  "the authorisation code to an attacker-controlled host.",
        "steps": [
            ("Confirm arbitrary external redirection on the vulnerable parameter", 0),
            ("Craft an authorisation request whose redirect_uri points at the redirector", 1),
            ("Capture the forwarded authorisation code / access token", 1),
            ("Exchange the token and take over the victim's account", 1),
        ],
    },
    {
        "id": "traversal-secrets",
        "name": "Path Traversal → Configuration Disclosure → Authenticated Access",
        "requires": [["traversal"], ["secrets", "authbypass", "jwt"]],
        "severity": "High",
        "terminal": "Authenticated access with recovered secrets",
        "impact": "Arbitrary file read exposes configuration material (database credentials, signing "
                  "keys, API tokens) which is then replayed to authenticate as a privileged principal.",
        "steps": [
            ("Read application configuration files through the traversal primitive", 0),
            ("Recover credentials, API keys or session signing secrets", 1),
            ("Forge or replay authentication material to gain privileged access", 1),
        ],
    },
    {
        "id": "secrets-privesc",
        "name": "Exposed Secret → Token Forgery → Privilege Escalation",
        "requires": [["secrets"], ["jwt", "authbypass", "bac", "oauth"]],
        "severity": "High",
        "terminal": "Privileged application access",
        "impact": "A disclosed signing key or API credential allows the attacker to mint valid tokens "
                  "and bypass the authentication and authorisation layers entirely.",
        "steps": [
            ("Retrieve the exposed key/credential material", 0),
            ("Forge or replay an authentication token with elevated claims", 1),
            ("Access administrative functionality with the forged identity", 1),
        ],
    },
    {
        "id": "ratelimit-cred",
        "name": "Missing Rate Limiting → Credential Stuffing → Account Takeover",
        "requires": [["ratelimit"], ["authbypass", "oauth", "jwt"]],
        "severity": "Medium",
        "terminal": "Account takeover through automated guessing",
        "impact": "Unbounded authentication attempts allow large-scale credential stuffing and brute "
                  "force against accounts with weak or reused passwords.",
        "steps": [
            ("Confirm the endpoint accepts unlimited authentication attempts", 0),
            ("Run a credential-stuffing / password-spraying set against the login surface", 1),
            ("Authenticate with a recovered credential pair", 1),
        ],
    },
    {
        "id": "csrf-privilege",
        "name": "CSRF → Forced State Change → Privilege Grant",
        "requires": [["csrf"], ["bac", "idor", "authbypass"]],
        "severity": "Medium",
        "terminal": "Attacker-controlled privilege or configuration change",
        "impact": "A victim's browser is coerced into performing a state-changing request, which the "
                  "missing authorisation check then executes with the victim's privileges.",
        "steps": [
            ("Build a cross-origin request for the unprotected state-changing endpoint", 0),
            ("Lure an authenticated (ideally administrative) victim to trigger it", 0),
            ("Confirm the privilege/configuration change took effect", 1),
        ],
    },
    {
        "id": "cors-exfil",
        "name": "CORS Misconfiguration → Cross-Origin Data Theft",
        "requires": [["cors"], ["idor", "bac", "secrets"]],
        "severity": "High",
        "terminal": "Cross-origin exfiltration of authenticated data",
        "impact": "Any origin can read authenticated API responses, so a malicious page can silently "
                  "exfiltrate the victim's data through their own browser session.",
        "steps": [
            ("Confirm the API reflects arbitrary origins with credentials allowed", 0),
            ("Host a page that issues credentialed cross-origin reads", 0),
            ("Exfiltrate the authenticated response data of visiting users", 1),
        ],
    },
    {
        "id": "xxe-exfil",
        "name": "XXE → Local File Read / SSRF Pivot",
        "requires": [["xxe"]],
        "severity": "High",
        "terminal": "Server file disclosure and internal network pivot",
        "impact": "External entity processing lets the attacker read server-side files and reach "
                  "internal-only endpoints from the application server.",
        "steps": [
            ("Submit XML containing an external entity declaration", 0),
            ("Read local files (/etc/passwd, application config) via the entity", 0),
            ("Pivot to internal HTTP endpoints through the same primitive", 0),
        ],
    },
    {
        "id": "bizlogic-abuse",
        "name": "Business Logic Flaw → Workflow Abuse",
        "requires": [["bizlogic", "race", "massassign"]],
        "severity": "High",
        "terminal": "Financial / integrity impact through workflow abuse",
        "impact": "The application's business rules can be violated through request manipulation, "
                  "causing financial loss or integrity damage without any memory-safety style bug.",
        "steps": [
            ("Map the intended workflow and its state transitions", 0),
            ("Replay, reorder or tamper with the requests that drive the workflow", 0),
            ("Confirm the invalid end state is accepted and persisted", 0),
        ],
    },
    {
        "id": "crypto-session",
        "name": "Transport / Cookie Weakness → Session Interception",
        "requires": [["crypto"], ["session"]],
        "severity": "Medium",
        "terminal": "Session interception on hostile networks",
        "impact": "Session material can traverse or be read outside a protected channel, exposing "
                  "authenticated sessions to network-position attackers.",
        "steps": [
            ("Confirm the weak transport / missing cookie protection", 0),
            ("Position on the network path or trigger a downgrade", 0),
            ("Capture and replay the victim's session identifier", 1),
        ],
    },
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _f_dict(f: Any, index: int) -> dict[str, Any]:
    """Normalise a Finding ORM object into a plain dict used by the builder."""
    cats = _categories(f)
    return {
        "id": getattr(f, "id", None),
        "ref": getattr(f, "finding_ref", None) or f"F-{index + 1}",
        "title": getattr(f, "title", "") or "Untitled finding",
        "vuln_type": getattr(f, "vuln_type", None) or "",
        "severity": getattr(f, "severity", "Informational") or "Informational",
        "location": getattr(f, "location", None) or "",
        "cvss_score": getattr(f, "cvss_score", None),
        "owasp_category": getattr(f, "owasp_category", None),
        "confidence_score": int(getattr(f, "confidence_score", 0) or 0),
        "has_poc": bool(getattr(f, "has_poc", False)),
        "verification_status": getattr(f, "verification_status", "Unverified") or "Unverified",
        "source_phase": getattr(f, "source_phase", None),
        "source_tool": getattr(f, "source_tool", None),
        "categories": cats,
        "stage": _stage_for(cats, f),
    }


def _short_location(loc: str, limit: int = 64) -> str:
    if not loc:
        return ""
    loc = re.sub(r"^https?://", "", loc)
    return loc if len(loc) <= limit else loc[: limit - 1] + "…"


def _mermaid_escape(text: str) -> str:
    text = re.sub(r"[\"'`\[\]{}()|<>#;]", " ", str(text or ""))
    text = re.sub(r"\s+", " ", text).strip()
    return text[:70]


_MERMAID_CLASS = {
    "Critical": "sevCrit", "High": "sevHigh", "Medium": "sevMed",
    "Low": "sevLow", "Informational": "sevInfo",
}

_MERMAID_CLASSDEFS = (
    "classDef sevCrit fill:#fee2e2,stroke:#dc2626,color:#7f1d1d;\n"
    "classDef sevHigh fill:#ffedd5,stroke:#ea580c,color:#7c2d12;\n"
    "classDef sevMed  fill:#fef3c7,stroke:#d97706,color:#78350f;\n"
    "classDef sevLow  fill:#dbeafe,stroke:#2563eb,color:#1e3a8a;\n"
    "classDef sevInfo fill:#f1f5f9,stroke:#64748b,color:#0f172a;\n"
    "classDef target  fill:#eef2ff,stroke:#6366f1,color:#312e81;\n"
    "classDef impact  fill:#fdf2f8,stroke:#be185d,color:#831843;\n"
)


# ── Chain construction ───────────────────────────────────────────────────────

def _match_template(tpl: dict[str, Any], by_cat: dict[str, list[dict]]) -> list[dict] | None:
    """Return one finding per `requires` group, all distinct — or None."""
    picked: list[dict] = []
    taken: set[str] = set()
    for group in tpl["requires"]:
        chosen = None
        for cat in group:
            for f in by_cat.get(cat, []):
                if f["id"] not in taken:
                    chosen = f
                    break
            if chosen:
                break
        if chosen is None:
            return None
        taken.add(chosen["id"])
        picked.append(chosen)
    return picked


def _build_chain(tpl: dict[str, Any], picked: list[dict], order: int) -> dict[str, Any]:
    participants = {f["id"]: f for f in picked}
    confidences = [f["confidence_score"] for f in picked]
    base_conf = int(sum(confidences) / len(confidences)) if confidences else 0
    all_poc = all(f["has_poc"] for f in picked)
    if all_poc:
        base_conf = min(100, base_conf + 10)

    severity = tpl["severity"]
    if all(_sev_rank(f["severity"]) >= 3 for f in picked):     # only Low/Info participants
        severity = _downgrade(severity)

    steps = []
    for i, (action, req_idx) in enumerate(tpl["steps"]):
        f = picked[req_idx]
        steps.append({
            "order": i + 1,
            "stage": f["stage"],
            "stage_label": _STAGE_LABEL.get(f["stage"], f["stage"]),
            "action": action,
            "finding_id": f["id"],
            "finding_ref": f["ref"],
            "finding_title": f["title"],
            "severity": f["severity"],
            "location": f["location"],
            "evidence": "PoC captured" if f["has_poc"] else "No PoC evidence",
        })

    return {
        "id": tpl["id"],
        "name": tpl["name"],
        "severity": severity,
        "confidence": base_conf,
        "evidence_backed": all_poc,
        "source": "heuristic",
        "order": order,
        "terminal": tpl["terminal"],
        "impact": tpl["impact"],
        "finding_ids": list(participants.keys()),
        "finding_refs": [f["ref"] for f in picked],
        "steps": steps,
    }


def _detect_chains(findings: list[dict]) -> list[dict[str, Any]]:
    by_cat: dict[str, list[dict]] = {}
    for f in findings:
        for cat in f["categories"]:
            by_cat.setdefault(cat, []).append(f)
    # Prefer higher-severity, evidence-backed findings inside each category
    for cat in by_cat:
        by_cat[cat].sort(key=lambda f: (_sev_rank(f["severity"]), -f["confidence_score"]))

    chains: list[dict[str, Any]] = []
    superseded: set[str] = set()
    for tpl in _CHAIN_TEMPLATES:
        if tpl["id"] in superseded:
            continue
        picked = _match_template(tpl, by_cat)
        if not picked:
            continue
        chains.append(_build_chain(tpl, picked, order=len(chains)))
        superseded.update(tpl.get("supersedes", []))

    # Drop chains that a later-matched template supersedes
    chains = [c for c in chains if c["id"] not in superseded]
    chains.sort(key=lambda c: (_sev_rank(c["severity"]), -c["confidence"]))
    for i, c in enumerate(chains):
        c["order"] = i + 1
    return chains


# ── Graph construction ───────────────────────────────────────────────────────

def _build_graph(target_url: str, findings: list[dict], chains: list[dict]) -> dict[str, Any]:
    host = re.sub(r"^https?://", "", target_url or "target").rstrip("/")
    nodes: list[dict[str, Any]] = [{
        "id": "target",
        "kind": "target",
        "label": host[:48] or "Target",
        "detail": target_url,
        "stage": "target",
        "stage_label": "Target",
        "column": 0,
        "row": 0,
        "severity": None,
        "finding_id": None,
        "finding_ref": None,
        "chains": [],
    }]
    edges: list[dict[str, Any]] = []
    node_by_finding: dict[str, str] = {}
    seen_edges: set[tuple[str, str]] = set()

    def _add_edge(src: str, dst: str, label: str, chain_id: str | None, kind: str) -> None:
        key = (src, dst)
        if key in seen_edges:
            for e in edges:
                if e["source"] == src and e["target"] == dst:
                    if chain_id and chain_id not in e["chains"]:
                        e["chains"].append(chain_id)
            return
        seen_edges.add(key)
        edges.append({
            "id": f"e{len(edges)}",
            "source": src,
            "target": dst,
            "label": label,
            "kind": kind,
            "chains": [chain_id] if chain_id else [],
        })

    for i, f in enumerate(findings):
        nid = f"f{i}"
        node_by_finding[f["id"]] = nid
        cat_label = _CATEGORY_LABEL.get(f["categories"][0], f["vuln_type"] or "Finding") if f["categories"] else (f["vuln_type"] or "Finding")
        nodes.append({
            "id": nid,
            "kind": "finding",
            "label": f["title"][:70],
            "detail": _short_location(f["location"]),
            "stage": f["stage"],
            "stage_label": _STAGE_LABEL.get(f["stage"], f["stage"]),
            "column": _STAGE_COLUMN.get(f["stage"], 3),
            "row": 0,
            "severity": f["severity"],
            "category": cat_label,
            "finding_id": f["id"],
            "finding_ref": f["ref"],
            "has_poc": f["has_poc"],
            "confidence": f["confidence_score"],
            "chains": [],
        })

    chained_ids: set[str] = set()
    for chain_idx, chain in enumerate(chains):
        prev_node = "target"
        for step in chain["steps"]:
            nid = node_by_finding.get(step["finding_id"])
            if not nid:
                continue
            chained_ids.add(step["finding_id"])
            node = next(n for n in nodes if n["id"] == nid)
            if chain["id"] not in node["chains"]:
                node["chains"].append(chain["id"])
            if nid != prev_node:
                _add_edge(prev_node, nid,
                          "entry point" if prev_node == "target" else f"step {step['order']}",
                          chain["id"], "chain")
                prev_node = nid
        impact_id = f"i{chain_idx}"
        nodes.append({
            "id": impact_id,
            "kind": "impact",
            "label": chain["terminal"][:70],
            "detail": chain["name"],
            "stage": "impact",
            "stage_label": "Impact",
            "column": _STAGE_COLUMN["impact"],
            "row": 0,
            "severity": chain["severity"],
            "finding_id": None,
            "finding_ref": None,
            "chains": [chain["id"]],
        })
        _add_edge(prev_node, impact_id, "results in", chain["id"], "chain")

    # Findings not part of any chain still hang off the target as direct exposure
    for f in findings:
        if f["id"] in chained_ids:
            continue
        nid = node_by_finding[f["id"]]
        _add_edge("target", nid, "direct exposure", None, "standalone")

    # Impact nodes must sit right of the last chain step
    max_col = max((n["column"] for n in nodes if n["kind"] != "impact"), default=4)
    for n in nodes:
        if n["kind"] == "impact":
            n["column"] = max(max_col + 1, _STAGE_COLUMN["impact"])

    # Row assignment inside each column (deterministic, severity-first)
    by_col: dict[int, list[dict]] = {}
    for n in nodes:
        by_col.setdefault(n["column"], []).append(n)
    for col, group in by_col.items():
        group.sort(key=lambda n: (_sev_rank(n["severity"]) if n["severity"] else 0, n["label"]))
        for row, n in enumerate(group):
            n["row"] = row

    columns = [
        {"column": 0, "key": "target", "label": "Target"},
        *[{"column": _STAGE_COLUMN[k], "key": k, "label": v} for k, v in STAGES],
    ]
    used_cols = {n["column"] for n in nodes}
    if any(n["kind"] == "impact" for n in nodes):
        impact_col = max(used_cols)
        for c in columns:
            if c["key"] == "impact":
                c["column"] = impact_col
    columns = [c for c in columns if c["column"] in used_cols]
    columns.sort(key=lambda c: c["column"])

    return {"nodes": nodes, "edges": edges, "columns": columns}


def _build_mermaid(graph: dict[str, Any]) -> str:
    lines = ["flowchart LR"]
    for n in graph["nodes"]:
        label = _mermaid_escape(
            f"{n['finding_ref']} · {n['label']}" if n.get("finding_ref") else n["label"]
        )
        if n["kind"] == "target":
            lines.append(f'    {n["id"]}(["{label}"])')
        elif n["kind"] == "impact":
            lines.append(f'    {n["id"]}[/"{label}"/]')
        else:
            lines.append(f'    {n["id"]}["{label}"]')
    for e in graph["edges"]:
        label = _mermaid_escape(e["label"])
        arrow = "-->" if e["kind"] == "chain" else "-.->"
        lines.append(f'    {e["source"]} {arrow}|{label}| {e["target"]}')
    lines.append("")
    lines.extend(_MERMAID_CLASSDEFS.strip().split("\n"))
    for n in graph["nodes"]:
        if n["kind"] == "target":
            lines.append(f'    class {n["id"]} target;')
        elif n["kind"] == "impact":
            lines.append(f'    class {n["id"]} impact;')
        elif n.get("severity"):
            cls = _MERMAID_CLASS.get(n["severity"], "sevInfo")
            lines.append(f'    class {n["id"]} {cls};')
    return "\n".join(lines)


def _heuristic_summary(target_url: str, findings: list[dict], chains: list[dict]) -> str:
    host = re.sub(r"^https?://", "", target_url or "the target").rstrip("/")
    if not findings:
        return f"No findings were recorded for {host}, so no attack path could be derived."
    sev_counts: dict[str, int] = {}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
    sev_txt = ", ".join(f"{sev_counts[s]} {s}" for s in SEVERITY_ORDER if sev_counts.get(s))
    if not chains:
        return (
            f"{len(findings)} finding(s) ({sev_txt}) were confirmed on {host}. No multi-step "
            f"attack chain could be derived from them — the issues appear to be independent "
            f"exposures rather than a linked path."
        )
    top = chains[0]
    stages_used = sorted({s["stage"] for c in chains for s in c["steps"]},
                         key=lambda k: _STAGE_COLUMN.get(k, 9))
    stage_txt = " → ".join(_STAGE_LABEL.get(s, s) for s in stages_used)
    return (
        f"{len(findings)} finding(s) ({sev_txt}) on {host} combine into {len(chains)} attack "
        f"chain(s) spanning {stage_txt}. The highest-risk path is “{top['name']}” "
        f"({top['severity']}, confidence {top['confidence']}%), which ends in "
        f"{top['terminal'].lower()}. {top['impact']}"
    )


# ── LLM enrichment (optional) ────────────────────────────────────────────────

_LLM_SYSTEM = (
    "You are a senior penetration tester writing the attack-path analysis section of a report. "
    "You are given the CONFIRMED findings of one assessment and the attack chains already derived "
    "by deterministic rules. Return ONLY a JSON object with these keys:\n"
    '  "summary"      — 2 to 4 sentences describing how an attacker would move through the target, '
    "referencing finding refs (e.g. WVAPT-2). No markdown.\n"
    '  "extra_chains" — JSON array (may be empty) of ADDITIONAL multi-step chains the rules missed. '
    "Each element: {\"name\": str, \"severity\": Critical|High|Medium|Low, \"terminal\": str, "
    "\"impact\": str, \"steps\": [{\"finding_ref\": str, \"action\": str}]}\n"
    "HARD RULES:\n"
    "- Every finding_ref you output MUST appear in the provided finding list. Never invent a ref.\n"
    "- Never invent vulnerabilities that are not in the list.\n"
    "- A chain needs at least 2 steps; skip anything you cannot ground in the listed findings.\n"
    "- If nothing extra can be grounded, return an empty extra_chains array.\n"
    "Return ONLY valid JSON. No markdown fences, no commentary."
)


def _llm_payload(target_url: str, findings: list[dict], chains: list[dict]) -> str:
    lines = [f"Target: {target_url}", "", "CONFIRMED FINDINGS:"]
    for f in findings:
        lines.append(
            f"- {f['ref']} | {f['severity']} | {f['title']} | type={f['vuln_type'] or 'n/a'} "
            f"| location={_short_location(f['location'], 80) or 'n/a'} "
            f"| poc={'yes' if f['has_poc'] else 'no'}"
        )
    lines.append("")
    lines.append("CHAINS ALREADY DERIVED BY RULES:")
    if chains:
        for c in chains:
            lines.append(f"- {c['name']} [{', '.join(c['finding_refs'])}]")
    else:
        lines.append("- (none)")
    lines.append("")
    lines.append("Return the JSON object now.")
    return "\n".join(lines)


def _strip_json(text: str) -> str:
    cleaned = re.sub(r"```[a-z]*\n?", "", text or "").replace("```", "").strip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        cleaned = match.group(0)
    return re.sub(r",\s*([}\]])", r"\1", cleaned)


async def _llm_enrich(
    engine: Any,
    target_url: str,
    findings: list[dict],
    chains: list[dict],
) -> tuple[str | None, list[dict], str | None]:
    """Return (summary, extra_chains, model_name). Never raises."""
    if engine is None or not findings:
        return None, [], None
    try:
        is_ollama = type(engine).__name__ == "OllamaEngine"
        resp = await engine.generate_response(
            messages=[{"role": "user", "content": _llm_payload(target_url, findings, chains)}],
            system_prompt=_LLM_SYSTEM,
            max_tokens=900 if is_ollama else 1600,
        )
        data = json.loads(_strip_json(engine.extract_text(resp)))
    except Exception:
        return None, [], None

    if not isinstance(data, dict):
        return None, [], None

    model = (
        getattr(engine, "model", None)
        or getattr(engine, "model_name", None)
        or None
    )

    summary = data.get("summary")
    summary = summary.strip() if isinstance(summary, str) and summary.strip() else None

    by_ref = {f["ref"]: f for f in findings}
    known_names = {c["name"].lower() for c in chains}
    extra: list[dict] = []
    for i, raw in enumerate(data.get("extra_chains") or []):
        if not isinstance(raw, dict):
            continue
        name = str(raw.get("name") or "").strip()
        raw_steps = raw.get("steps") or []
        if not name or name.lower() in known_names or not isinstance(raw_steps, list):
            continue
        steps: list[dict] = []
        used: list[dict] = []
        for raw_step in raw_steps:
            if not isinstance(raw_step, dict):
                continue
            f = by_ref.get(str(raw_step.get("finding_ref") or "").strip())
            if not f:
                continue     # ungrounded ref → drop the step
            used.append(f)
            steps.append({
                "order": len(steps) + 1,
                "stage": f["stage"],
                "stage_label": _STAGE_LABEL.get(f["stage"], f["stage"]),
                "action": str(raw_step.get("action") or "").strip()[:400] or "Exploit the finding",
                "finding_id": f["id"],
                "finding_ref": f["ref"],
                "finding_title": f["title"],
                "severity": f["severity"],
                "location": f["location"],
                "evidence": "PoC captured" if f["has_poc"] else "No PoC evidence",
            })
        if len(steps) < 2:
            continue     # not a chain
        severity = str(raw.get("severity") or "").strip().capitalize()
        if severity not in SEVERITY_ORDER:
            severity = _max_sev([f["severity"] for f in used])
        confs = [f["confidence_score"] for f in used]
        extra.append({
            "id": f"llm-{i + 1}",
            "name": name[:160],
            "severity": severity,
            "confidence": max(0, int(sum(confs) / len(confs)) - 15),   # inferred → discount
            "evidence_backed": all(f["has_poc"] for f in used),
            "source": "llm",
            "order": 0,
            "terminal": str(raw.get("terminal") or "Compromise of the affected component")[:160],
            "impact": str(raw.get("impact") or "")[:600],
            "finding_ids": [f["id"] for f in used],
            "finding_refs": [f["ref"] for f in used],
            "steps": steps,
        })
        known_names.add(name.lower())

    return summary, extra, model


# ── Per-finding exploitation flow ────────────────────────────────────────────

_REQUEST_RE = re.compile(
    r"^\s*(?:curl\s|GET\s|POST\s|PUT\s|PATCH\s|DELETE\s|HEAD\s|http[s]?://)", re.I | re.M
)


def _extract_request(finding: Any) -> str:
    """Pull the most request-like fragment out of the evidence, without inventing one."""
    raw_req = (getattr(finding, "raw_request", None) or "").strip()
    if raw_req:
        return raw_req[:600]
    poc = (getattr(finding, "proof_of_concept", None) or "").strip()
    if not poc:
        return ""
    lines = poc.splitlines()
    hits = [ln.strip() for ln in lines if _REQUEST_RE.match(ln)]
    if hits:
        return "\n".join(hits[:4])[:600]
    indented = [ln.strip() for ln in lines if ln.startswith("    ") and ln.strip()]
    if indented:
        return "\n".join(indented[:4])[:600]
    return ""


def _extract_response(finding: Any) -> str:
    raw_resp = (getattr(finding, "raw_response", None) or "").strip()
    if raw_resp:
        return raw_resp[:600]
    poc = (getattr(finding, "proof_of_concept", None) or "").strip()
    match = re.search(r"HTTP/[0-9.]+\s+\d{3}.*", poc, re.S)
    return match.group(0)[:600] if match else ""


def build_finding_flow(scan: Any, finding: Any) -> dict[str, Any]:
    """Deterministic step-by-step exploitation flow for a single finding."""
    fd = _f_dict(finding, 0)
    cat_label = _CATEGORY_LABEL.get(fd["categories"][0]) if fd["categories"] else None
    location = fd["location"] or getattr(scan, "target_url", "") or ""
    request = _extract_request(finding)
    response = _extract_response(finding)
    phase = (fd["source_phase"] or "exploit").lower()
    tool = fd["source_tool"]

    steps: list[dict[str, Any]] = []

    def _add(stage: str, title: str, action: str, evidence: str = "", kind: str = "step") -> None:
        steps.append({
            "order": len(steps) + 1,
            "stage": stage,
            "stage_label": _STAGE_LABEL.get(stage, stage.title()),
            "title": title,
            "action": action,
            "evidence": evidence,
            "kind": kind,
        })

    discovery = {
        "recon": "Discovered during reconnaissance — crawling and response/header analysis of the target.",
        "static": "Discovered during static analysis of the application source or client-side assets.",
        "exploit": "Discovered during the active exploitation phase by the agent's tool-calling loop.",
    }.get(phase, "Discovered during automated assessment of the target.")
    if tool:
        discovery += f" Tooling fingerprint: {tool}."
    _add("recon", "Discovery", discovery, kind="discovery")

    _add(
        "access", "Entry point",
        f"Attack surface: {location or 'not recorded'}"
        + (f" — classified as {cat_label}." if cat_label else "."),
        evidence=location,
        kind="entry",
    )

    _add(
        fd["stage"] if fd["stage"] in _STAGE_COLUMN else "exploit",
        "Exploitation",
        f"Send the crafted request that triggers the {fd['vuln_type'] or fd['title']} condition."
        if request else
        f"Trigger the {fd['vuln_type'] or fd['title']} condition on the endpoint above. "
        "No raw request was captured for this finding.",
        evidence=request,
        kind="exploit",
    )

    _add(
        "exploit", "Verification",
        "Server response confirms the vulnerable behaviour."
        if response else
        ("Proof of concept recorded by the agent." if fd["has_poc"]
         else "No proof-of-concept evidence was captured — treat this finding as unverified."),
        evidence=response or (getattr(finding, "proof_of_concept", None) or "")[:600],
        kind="verify",
    )

    implications = (getattr(finding, "implications", None) or "").strip()
    _add(
        "impact", "Impact",
        implications[:600] or "Impact not documented for this finding.",
        kind="impact",
    )

    recommendations = (getattr(finding, "recommendations", None) or "").strip()
    if recommendations:
        _add("impact", "Break the chain", recommendations[:600], kind="remediation")

    # Linear graph for the same flow
    nodes = [{
        "id": "target",
        "kind": "target",
        "label": re.sub(r"^https?://", "", getattr(scan, "target_url", "") or "Target").rstrip("/")[:48],
        "detail": getattr(scan, "target_url", ""),
        "stage": "target", "stage_label": "Target", "column": 0, "row": 0,
        "severity": None, "finding_id": None, "finding_ref": None, "chains": [],
    }]
    edges = []
    prev = "target"
    for i, step in enumerate(steps):
        nid = f"s{i}"
        nodes.append({
            "id": nid,
            "kind": "impact" if step["kind"] in ("impact", "remediation") else "finding",
            "label": step["title"],
            "detail": step["action"][:90],
            "stage": step["stage"],
            "stage_label": step["stage_label"],
            "column": i + 1,
            "row": 0,
            "severity": fd["severity"] if step["kind"] not in ("remediation",) else "Informational",
            "finding_id": fd["id"],
            "finding_ref": fd["ref"],
            "chains": ["finding-flow"],
        })
        edges.append({
            "id": f"e{i}", "source": prev, "target": nid,
            "label": f"step {i + 1}", "kind": "chain", "chains": ["finding-flow"],
        })
        prev = nid

    columns = [{"column": 0, "key": "target", "label": "Target"}] + [
        {"column": i + 1, "key": f"step{i+1}", "label": s["title"]} for i, s in enumerate(steps)
    ]
    graph = {"nodes": nodes, "edges": edges, "columns": columns}

    chain = {
        "id": "finding-flow",
        "name": f"{fd['ref']} · {fd['title']}",
        "severity": fd["severity"],
        "confidence": fd["confidence_score"],
        "evidence_backed": fd["has_poc"],
        "source": "heuristic",
        "order": 1,
        "terminal": (implications[:120] or "Impact not documented"),
        "impact": implications[:600],
        "finding_ids": [fd["id"]],
        "finding_refs": [fd["ref"]],
        "steps": [
            {
                "order": s["order"], "stage": s["stage"], "stage_label": s["stage_label"],
                "action": f"{s['title']} — {s['action']}",
                "finding_id": fd["id"], "finding_ref": fd["ref"],
                "finding_title": fd["title"], "severity": fd["severity"],
                "location": fd["location"], "evidence": s["evidence"],
            }
            for s in steps
        ],
    }

    summary = (
        f"{fd['ref']} ({fd['severity']}) at {_short_location(location) or 'the target'} is exploited in "
        f"{len(steps)} step(s): {' → '.join(s['title'] for s in steps)}."
    )

    return {
        "kind": "finding",
        "generator": "heuristic",
        "llm_model": None,
        "summary": summary,
        "graph": graph,
        "chains": [chain],
        "steps": steps,
        "mermaid": _build_mermaid(graph),
        "stages": [{"key": k, "label": v} for k, v in STAGES],
    }


# ── Public API ───────────────────────────────────────────────────────────────

async def build_scan_workflow(
    scan: Any,
    findings: list[Any],
    engine: Any | None = None,
) -> dict[str, Any]:
    """Build the scan-level attack workflow. `engine` is optional (LLM narrative)."""
    target_url = getattr(scan, "target_url", "") or ""
    usable = [
        _f_dict(f, i) for i, f in enumerate(findings)
        if (getattr(f, "verification_status", "") or "") != "False Positive"
    ]
    usable.sort(key=lambda f: (_sev_rank(f["severity"]), f["ref"]))

    chains = _detect_chains(usable)
    generator = "heuristic"
    llm_model: str | None = None
    summary: str | None = None

    if engine is not None and usable:
        llm_summary, extra_chains, model = await _llm_enrich(engine, target_url, usable, chains)
        if llm_summary or extra_chains:
            generator = "heuristic+llm"
            llm_model = model
        summary = llm_summary
        if extra_chains:
            chains.extend(extra_chains)
            chains.sort(key=lambda c: (_sev_rank(c["severity"]), -c["confidence"]))
            for i, c in enumerate(chains):
                c["order"] = i + 1

    if not summary:
        summary = _heuristic_summary(target_url, usable, chains)

    graph = _build_graph(target_url, usable, chains)
    return {
        "kind": "scan",
        "generator": generator,
        "llm_model": llm_model,
        "summary": summary,
        "graph": graph,
        "chains": chains,
        "mermaid": _build_mermaid(graph),
        "stages": [{"key": k, "label": v} for k, v in STAGES],
    }


async def save_workflow(
    db: Any,
    scan_id: str,
    finding_id: str | None,
    workflow: dict[str, Any],
) -> Any:
    """Upsert the AttackWorkflow row for (scan_id, finding_id). Commits."""
    from sqlalchemy import select

    from backend.models.workflow import AttackWorkflow

    graph = workflow.get("graph") or {}
    chains = workflow.get("chains") or []

    stmt = select(AttackWorkflow).where(AttackWorkflow.scan_id == scan_id)
    stmt = stmt.where(
        AttackWorkflow.finding_id.is_(None) if finding_id is None
        else AttackWorkflow.finding_id == finding_id
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        row = AttackWorkflow(scan_id=scan_id, finding_id=finding_id)
        db.add(row)

    row.kind = workflow.get("kind") or ("finding" if finding_id else "scan")
    row.generator = workflow.get("generator") or "heuristic"
    row.llm_model = workflow.get("llm_model")
    row.summary = workflow.get("summary") or ""
    row.graph_json = json.dumps(graph)
    row.chains_json = json.dumps(chains)
    row.mermaid = workflow.get("mermaid") or ""
    row.node_count = len(graph.get("nodes") or [])
    row.edge_count = len(graph.get("edges") or [])
    row.chain_count = len(chains)
    await db.commit()
    return row


def row_to_dict(row: Any) -> dict[str, Any]:
    """Deserialise an AttackWorkflow row back into the API/report shape."""
    def _load(raw: str | None, fallback: Any) -> Any:
        try:
            return json.loads(raw) if raw else fallback
        except (ValueError, TypeError):
            return fallback

    return {
        "id": row.id,
        "scan_id": row.scan_id,
        "finding_id": row.finding_id,
        "kind": row.kind,
        "generator": row.generator,
        "llm_model": row.llm_model,
        "summary": row.summary or "",
        "graph": _load(row.graph_json, {"nodes": [], "edges": [], "columns": []}),
        "chains": _load(row.chains_json, []),
        "mermaid": row.mermaid or "",
        "node_count": row.node_count,
        "edge_count": row.edge_count,
        "chain_count": row.chain_count,
        "stages": [{"key": k, "label": v} for k, v in STAGES],
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }
