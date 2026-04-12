"""
services/scan_runner.py — Wraps PentestOrchestrator with DB persistence and
real-time WebSocket broadcasting.

Integration strategy:
  - Monkey-patches ScanTracer to push log rows to DB + WS on every .log() call
  - Persists findings from workspace.findings after run_pipeline() completes
  - Updates scan.status / scan.phase throughout the lifecycle
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import datetime
from typing import Any

# Add the pentest engine path (sibling development/ folder)
_ENGINE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../../../development")
)
if _ENGINE_PATH not in sys.path:
    sys.path.insert(0, _ENGINE_PATH)

from sqlalchemy.ext.asyncio import AsyncSession

from backend.database import AsyncSessionLocal
from backend.models.scan import Scan, ScanLog
from backend.models.finding import Finding
from backend.websocket.manager import manager


# ── Severity normalisation ────────────────────────────────────────────────────

_SEV_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
    "info": "Informational",
}


def _norm_sev(raw: str) -> str:
    return _SEV_MAP.get(raw.lower(), "Informational")


# ── OWASP Top 10 2021 mapping (mirrors src/agents/report.py) ─────────────────

import re as _re

_OWASP_REFS = [
    (r'idor|bola|broken.access|privilege.escal|path.traversal|lfi|local.file'
     r'|directory.traversal|open.redirect|forced.brows|missing.function.level',
     "A01:2021", "Broken Access Control"),
    (r'crypt|hsts\b|tls\b|ssl\b|insecure.transm|cleartext|weak.cipher'
     r'|missing.https|secure.flag|insecure.cookie|missing.secure',
     "A02:2021", "Cryptographic Failures"),
    (r'sql.inject|sqli\b|xss|cross.site.script|command.inject|rce\b|remote.code'
     r'|ssti|template.inject|xxe|xml.external|ldap.inject|nosql|html.inject',
     "A03:2021", "Injection"),
    (r'insecure.design|business.logic|mass.assign|race.condition|price.tamper'
     r'|workflow.bypass',
     "A04:2021", "Insecure Design"),
    (r'misconfigur|missing.header|clickjacking|x.frame|cors\b|csp\b'
     r'|server.version|information.disclos|x.powered.by|technology.disclos'
     r'|default.cred|verbose.error|file.upload|unrestricted.upload'
     r'|directory.list|phpinfo|server.banner|referrer.policy|permissions.policy'
     r'|x.content.type|mime.sniff',
     "A05:2021", "Security Misconfiguration"),
    (r'outdated|vulnerable.component|known.cve|old.version|deprecated.version',
     "A06:2021", "Vulnerable and Outdated Components"),
    (r'auth.bypass|authentication.bypass|brute.force|credential|session.fixat'
     r'|jwt\b|weak.password|password.policy|account.lockout|csrf'
     r'|cross.site.request.forgery|2fa.bypass|mfa.bypass',
     "A07:2021", "Identification and Authentication Failures"),
    (r'deserializ|insecure.deserializ|pickle\b|integrity.failure|supply.chain',
     "A08:2021", "Software and Data Integrity Failures"),
    (r'logging.failure|monitoring.failure|audit.trail|rate.limit|no.log'
     r'|insufficient.log',
     "A09:2021", "Security Logging and Monitoring Failures"),
    (r'ssrf\b|server.side.request.forgery|server-side.request',
     "A10:2021", "Server-Side Request Forgery (SSRF)"),
]


def _resolve_owasp(vuln_type: str) -> tuple[str | None, str | None]:
    """Return (owasp_category, owasp_name) for a vuln type string, or (None, None)."""
    vt = _re.sub(r'[\s\-/]', '.', vuln_type.lower())
    for pattern, code, name in _OWASP_REFS:
        if _re.search(pattern, vt):
            return code, name
    return None, None


# ── ScanTracer hook ──────────────────────────────────────────────────────────

def _make_tracer_hook(scan_id: str, loop: asyncio.AbstractEventLoop):
    """Returns a callable that ScanTracer.log() will invoke for every log line."""

    def _hook(level: str, phase: str, message: str, **_kwargs: Any) -> None:
        # Write to DB asynchronously without blocking the scanner
        asyncio.run_coroutine_threadsafe(
            _persist_log(scan_id, level, phase, message), loop
        )
        # Broadcast to WebSocket subscribers
        asyncio.run_coroutine_threadsafe(
            manager.send_log(scan_id, level, phase, message), loop
        )

    return _hook


async def _persist_log(scan_id: str, level: str, phase: str, message: str) -> None:
    async with AsyncSessionLocal() as db:
        db.add(ScanLog(scan_id=scan_id, level=level, phase=phase, message=message))
        await db.commit()


# ── Main runner ──────────────────────────────────────────────────────────────

async def run_scan(scan_id: str) -> None:
    """
    Background task: load scan config from DB, run orchestrator, persist results.
    Called as asyncio.create_task() from the scan router.
    """
    from backend.routers.scans import get_cancel_flag
    cancel_flag = get_cancel_flag(scan_id)

    def _check_cancelled():
        """Raise CancelledError if the cancel flag has been set."""
        if cancel_flag.is_set():
            raise asyncio.CancelledError(f"Scan {scan_id} cancelled by user")

    loop = asyncio.get_event_loop()

    async with AsyncSessionLocal() as db:
        scan: Scan | None = await db.get(Scan, scan_id)
        if scan is None:
            return

        # Mark running
        scan.status = "running"
        scan.started_at = datetime.utcnow()
        scan.phase = "initializing"
        await db.commit()

    await manager.send_phase_change(scan_id, "initializing", "Setting up scan environment")

    try:
        _check_cancelled()
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)

            # Build orchestrator kwargs from scan config
            scope_include = json.loads(scan.scope_include or "[]")
            scope_exclude = json.loads(scan.scope_exclude or "[]")
            headers = json.loads(scan.headers or "{}")
            cookies = json.loads(scan.cookies or "{}")

            # Resolve LLM provider env vars from global_settings
            from backend.models.settings import GlobalSettings
            from backend.services.crypto import decrypt_value
            gs = await db.get(GlobalSettings, 1)

        # Set LLM environment variables for the engine
        _setup_llm_env(scan, gs)

        # Import engine and agents (deferred to avoid import at module load time)
        from src.core.llm import ClaudeEngine, OpenAIEngine, OllamaEngine
        from src.core.orchestrator import PentestOrchestrator
        from src.agents.recon import ReconAgent
        from src.agents.static_analysis import StaticAnalysisAgent
        from src.agents.vuln import VulnAnalyzerAgent
        from src.agents.exploit import ExploitAgent
        from src.agents.report import ReportingAgent

        # Initialize LLM engine
        provider = scan.llm_provider
        try:
            if provider in ("openai", "openrouter"):
                # openrouter: env OPENAI_API_KEY + OPENAI_BASE_URL already set
                engine = OpenAIEngine()
            elif provider == "ollama":
                ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
                ollama_model = os.environ.get("OLLAMA_MODEL", "")
                engine = OllamaEngine(base_url=ollama_url, model=ollama_model)
            else:
                engine = ClaudeEngine()
        except Exception as e:
            raise RuntimeError(f"Failed to initialize {provider} LLM engine: {e}") from e

        static_only = (scan.scan_mode == "static_only")

        orchestrator = PentestOrchestrator(
            target_url=scan.target_url,
            repo_path=scan.repo_path or "",
            headers=headers,
            cookies=cookies,
            scope_include=scope_include,
            scope_exclude=scope_exclude,
            static_only=static_only,
            max_parallel_exploits=scan.max_parallel,
            max_feedback_iterations=scan.feedback_iter,
        )

        # Build custom prompt prefix (if provided by user)
        custom_prompt = (scan.custom_prompt or "").strip()

        def _inject_prompt(agent: Any) -> Any:
            """Prepend user's custom prompt to ALL system_prompt attributes on the agent."""
            if not custom_prompt:
                return agent
            prefix = (
                f"=== ADDITIONAL CONTEXT FROM OPERATOR ===\n{custom_prompt}\n"
                f"=== END OPERATOR CONTEXT ===\n\n"
            )
            # Primary system prompt (all agents)
            if hasattr(agent, "system_prompt"):
                agent.system_prompt = prefix + agent.system_prompt
            # Ollama-specific system prompt (ExploitAgent uses a separate one for Ollama)
            if hasattr(agent, "ollama_system_prompt"):
                agent.ollama_system_prompt = prefix + agent.ollama_system_prompt
            return agent

        # Register agents
        if static_only:
            orchestrator.register_agent("static_analysis", _inject_prompt(StaticAnalysisAgent(engine)))
            orchestrator.register_agent("report", _inject_prompt(ReportingAgent(engine)))
        else:
            orchestrator.register_agent("recon", _inject_prompt(ReconAgent(engine)))
            orchestrator.register_agent("static_analysis", _inject_prompt(StaticAnalysisAgent(engine)))
            orchestrator.register_agent("vuln", _inject_prompt(VulnAnalyzerAgent(engine, max_llm_hypotheses=scan.max_hypotheses)))
            orchestrator.register_agent("exploit", _inject_prompt(ExploitAgent(engine)))
            orchestrator.register_agent("report", _inject_prompt(ReportingAgent(engine)))

        # Set per-scan output directory so evidence screenshots go to persisted storage
        scan_output_dir = os.path.join(_SCANS_BASE, scan_id)
        os.makedirs(scan_output_dir, exist_ok=True)
        orchestrator.workspace.repo_path = scan_output_dir

        # Store custom_prompt in workspace so ReportingAgent can prepend it to its
        # inline system prompts (which don't use self.system_prompt directly).
        orchestrator.workspace.custom_prompt = custom_prompt

        # ── Persistent cross-scan memory & corpus ─────────────────────────────
        # Re-point memory and corpus to the shared DATA_BASE volume so knowledge
        # accumulates across scans and container restarts.  WorkspaceManager
        # initially writes next to repo_path (which is per-scan); by replacing
        # these instances here we redirect all subsequent reads/writes to the
        # persistent volume without touching the engine internals.
        from src.core.memory import ScanMemory
        from src.core.corpus import PayloadCorpus
        os.makedirs(_DATA_BASE, exist_ok=True)
        orchestrator.workspace.memory = ScanMemory(path=_MEMORY_FILE)
        orchestrator.workspace.corpus = PayloadCorpus(path=_CORPUS_FILE)

        # Inject log hook into ScanTracer by wrapping its .log() method
        tracer = orchestrator.workspace.tracer
        _orig_log = tracer.log

        def _patched_log(level: str, phase: str, message: str, data: Any = None) -> None:
            _orig_log(level, phase, message, data)
            asyncio.run_coroutine_threadsafe(
                _persist_log(scan_id, level, phase, message), loop
            )
            asyncio.run_coroutine_threadsafe(
                manager.send_log(scan_id, level, phase, message), loop
            )

        tracer.log = _patched_log  # type: ignore[method-assign]

        # Patch phase_start for broadcasting phase changes
        _orig_phase_start = tracer.phase_start

        def _patched_phase_start(phase_name: str) -> None:
            _orig_phase_start(phase_name)
            asyncio.run_coroutine_threadsafe(
                manager.send_phase_change(scan_id, phase_name), loop
            )
            asyncio.run_coroutine_threadsafe(
                _update_scan_phase(scan_id, phase_name), loop
            )

        tracer.phase_start = _patched_phase_start  # type: ignore[method-assign]

        # Patch phase_end to check cancel flag between phases
        _orig_phase_end = tracer.phase_end

        def _patched_phase_end(phase_name: str, **kwargs: Any) -> None:
            _orig_phase_end(phase_name, **kwargs)
            _check_cancelled()

        tracer.phase_end = _patched_phase_end  # type: ignore[method-assign]

        # Run the pipeline
        await orchestrator.run_pipeline()

        # Enrich findings with LLM-generated description, severity, cvss, references
        await _enrich_findings(orchestrator.workspace, engine, scan_id)

        # Persist findings from workspace
        await _persist_findings(scan_id, orchestrator.workspace)

        # Mark complete — count severity from DB (post-enrichment) for accuracy
        summary = _build_summary(orchestrator.workspace)
        async with AsyncSessionLocal() as db:
            from sqlalchemy import select as _select, func as _func
            sev_rows = await db.execute(
                _select(Finding.severity, _func.count().label("cnt"))
                .where(Finding.scan_id == scan_id)
                .group_by(Finding.severity)
            )
            db_sev: dict[str, int] = {r.severity.lower(): r.cnt for r in sev_rows}

            scan = await db.get(Scan, scan_id)
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            scan.phase = "completed"
            if scan.started_at:
                delta = scan.completed_at - scan.started_at
                scan.duration_seconds = delta.total_seconds()
            scan.hypotheses_total = summary.get("hypotheses_total", 0)
            scan.hypotheses_confirmed = summary.get("hypotheses_confirmed", 0)
            # Use DB counts (post-enrichment) so snapshots match the Finding table
            scan.findings_critical = db_sev.get("critical", 0)
            scan.findings_high     = db_sev.get("high", 0)
            scan.findings_medium   = db_sev.get("medium", 0)
            scan.findings_low      = db_sev.get("low", 0)
            scan.findings_info     = db_sev.get("informational", 0)
            await db.commit()

        await manager.send_complete(scan_id, "completed", summary)

    except asyncio.CancelledError:
        # DB status already set to "cancelled" by the cancel endpoint.
        # Ensure it's marked even if task.cancel() fired before the endpoint wrote.
        try:
            async with AsyncSessionLocal() as db:
                scan = await db.get(Scan, scan_id)
                if scan and scan.status not in ("cancelled",):
                    scan.status = "cancelled"
                    scan.completed_at = datetime.utcnow()
                    scan.phase = "cancelled"
                    await db.commit()
        except Exception:
            pass
        await manager.send_complete(scan_id, "cancelled", {})

    except Exception as exc:
        err_msg = str(exc)
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan:
                scan.status = "failed"
                scan.completed_at = datetime.utcnow()
                scan.error_message = err_msg[:1000]
                await db.commit()
        await manager.send_error(scan_id, err_msg)
        raise


async def _update_scan_phase(scan_id: str, phase: str) -> None:
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.phase = phase
            await db.commit()


def _to_relative_path(abs_path: str | None) -> str | None:
    """Convert an absolute screenshot path to a path relative to _DATA_BASE for serving."""
    if not abs_path:
        return None
    try:
        rel = os.path.relpath(abs_path, _DATA_BASE)
        # Reject paths that escape _DATA_BASE (contain ..)
        if rel.startswith(".."):
            return None
        return rel
    except ValueError:
        return None


async def _persist_findings(scan_id: str, workspace: Any) -> None:
    """Save all findings from workspace to the findings table."""
    from backend.websocket.manager import manager as ws_mgr
    async with AsyncSessionLocal() as db:
        for i, raw in enumerate(getattr(workspace, "findings", [])):
            hypo = raw.get("hypothesis", {})
            vuln_type = hypo.get("type", "")
            title = hypo.get("title") or vuln_type or "Unknown"
            # Resolve OWASP from vuln_type (hypothesis dict doesn't carry owasp fields)
            owasp_cat, owasp_nm = _resolve_owasp(title + " " + vuln_type)

            cvss_vector = hypo.get("cvss_vector")
            cvss4_vector = hypo.get("cvss4_vector")

            # Compute accurate scores from vector strings; fall back to LLM value
            cvss_score = _calc_cvss_score(cvss_vector) or _parse_float(hypo.get("cvss_score"))
            cvss4_score = _calc_cvss_score(cvss4_vector) or _parse_float(hypo.get("cvss4_score"))

            # Screenshot paths: store relative to _DATA_BASE so the evidence endpoint can serve them
            ss_before_raw = raw.get("screenshot_before") or hypo.get("screenshot_before")
            ss_after_raw = (raw.get("screenshot_after") or raw.get("screenshot_path")
                            or raw.get("screenshot") or hypo.get("screenshot_after"))

            finding = Finding(
                scan_id=scan_id,
                finding_ref=f"WVAPT-{i + 1}",
                title=title,
                vuln_type=vuln_type,
                severity=_norm_sev(hypo.get("severity", "Informational")),
                cvss_score=cvss_score,
                cvss_vector=cvss_vector,
                status="Open",
                location=hypo.get("location", ""),
                description=hypo.get("description", ""),
                proof_of_concept=raw.get("proof", ""),
                implications=hypo.get("impact", ""),
                recommendations=hypo.get("remediation", ""),
                owasp_category=hypo.get("owasp_id") or owasp_cat,
                owasp_name=hypo.get("owasp_name") or owasp_nm,
                cvss4_score=cvss4_score,
                cvss4_vector=cvss4_vector,
                cve=hypo.get("cve"),
                references=hypo.get("references") if isinstance(hypo.get("references"), str) else (
                    "\n".join(hypo["references"]) if isinstance(hypo.get("references"), list) else None
                ),
                screenshot_before=_to_relative_path(ss_before_raw),
                screenshot_after=_to_relative_path(ss_after_raw),
            )
            db.add(finding)
            await ws_mgr.send_finding(scan_id, {
                "title": finding.title,
                "severity": finding.severity,
                "location": finding.location,
            })
        await db.commit()


_ENRICH_SYSTEM = (
    "You are a senior penetration tester writing structured finding reports. "
    "Given a confirmed vulnerability type, location, proof, and exploitation details, "
    "return a single JSON object with these exact keys. "
    "Keep all text values SHORT (1-2 sentences max) to avoid truncation:\n"
    '  "title"         — concise vulnerability title (max 10 words)\n'
    '  "severity"      — one of: Critical, High, Medium, Low, Informational\n'
    '  "cvss_score"    — numeric CVSS v3.1 base score (0.0–10.0)\n'
    '  "cvss_vector"   — CVSS v3.1 vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")\n'
    '  "cvss4_score"   — numeric CVSS v4.0 base score (0.0–10.0)\n'
    '  "cvss4_vector"  — CVSS v4.0 vector string (e.g. "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")\n'
    '  "description"   — 1-2 sentences explaining what the vulnerability is\n'
    '  "impact"        — 1-2 sentences on business/security impact\n'
    '  "remediation"   — 1-2 sentences with concrete fix steps\n'
    '  "cve"           — relevant CVE ID if known (e.g. "CVE-2021-44228"), or null\n'
    '  "references"    — JSON array of 2-3 URLs (OWASP, CWE, NVD)\n'
    "Return ONLY valid JSON. No markdown. No explanation. No extra text outside the JSON object."
)

_POC_SYSTEM = (
    "You are a senior penetration tester writing a professional Proof of Concept (PoC) for a confirmed vulnerability. "
    "Based on the raw exploit evidence provided, write a detailed, structured PoC in plain text using the following exact sections.\n\n"
    "Use the ACTUAL data from the evidence — do NOT fabricate or invent details not present in the input. "
    "Be factual, precise, and technically rigorous. Use real URLs, payloads, parameters, and response fragments from the evidence.\n\n"
    "REQUIRED SECTIONS (include ALL of them):\n\n"
    "VULNERABILITY SUMMARY\n"
    "  One paragraph confirming the vulnerability, the affected component, and what was achieved.\n\n"
    "AFFECTED ENDPOINT\n"
    "  - URL: <full URL including parameters>\n"
    "  - Method: <HTTP method>\n"
    "  - Vulnerable Parameter: <exact parameter name>\n"
    "  - Technology: <identified server/framework if known>\n\n"
    "STEPS TO REPRODUCE\n"
    "  Numbered steps that any pentester can follow to reproduce from scratch, including prerequisites.\n\n"
    "ATTACK REQUEST\n"
    "  Full curl command or raw HTTP request with actual payload used.\n\n"
    "OBSERVED SERVER RESPONSE\n"
    "  Relevant excerpt from the server response that proves exploitation (status code, error message, redirected URL, injected content, file content, etc.).\n\n"
    "PROOF OF EXPLOITATION\n"
    "  Clear statement of what was achieved: e.g. authentication bypassed, arbitrary file read, script executed in victim's browser, etc.\n\n"
    "ROOT CAUSE ANALYSIS\n"
    "  Technical explanation of WHY this vulnerability exists (missing sanitization, improper query construction, misconfigured header, etc.).\n\n"
    "Return ONLY plain text. No JSON. No markdown code fences. Use the section headers exactly as written above."
)


async def _enrich_findings(workspace: Any, engine: Any, scan_id: str) -> None:
    """Call LLM to enrich each confirmed finding with description, severity, cvss, etc."""
    import json as _json
    import re as _re

    findings = getattr(workspace, "findings", [])
    if not findings:
        return

    for raw in findings:
        hypo = raw.get("hypothesis", {})
        proof = raw.get("proof", "")
        vuln_type = hypo.get("type", "Unknown")
        details = hypo.get("details", "")
        location = hypo.get("location", "/")

        prompt = (
            f"Vulnerability Type: {vuln_type}\n"
            f"Location: {location}\n"
            f"Details: {details[:500]}\n"
            f"Proof: {proof[:600]}\n\n"
            "Return JSON only. Keep each text value to 1-2 sentences max."
        )

        try:
            response = await engine.generate_response(
                messages=[{"role": "user", "content": prompt}],
                system_prompt=_ENRICH_SYSTEM,
                max_tokens=2048,
            )
            result_text = engine.extract_text(response)

            # Extract JSON from response
            cleaned = _re.sub(r"```[a-z]*\n?", "", result_text).strip()
            match = _re.search(r"\{.*\}", cleaned, _re.DOTALL)
            if match:
                cleaned = match.group(0)

            # Retry once with shorter prompt if JSON is invalid
            try:
                enriched = _json.loads(cleaned)
            except (_json.JSONDecodeError, ValueError):
                retry_prompt = (
                    f"Vulnerability: {vuln_type} at {location}\n"
                    "Return ONLY a compact JSON object with keys: "
                    "title, severity, cvss_score, cvss_vector, description, impact, remediation, cve, references. "
                    "Each string value must be under 100 characters. references must be a JSON array."
                )
                retry_resp = await engine.generate_response(
                    messages=[{"role": "user", "content": retry_prompt}],
                    system_prompt=_ENRICH_SYSTEM,
                    max_tokens=1024,
                )
                retry_text = engine.extract_text(retry_resp)
                cleaned2 = _re.sub(r"```[a-z]*\n?", "", retry_text).strip()
                m2 = _re.search(r"\{.*\}", cleaned2, _re.DOTALL)
                if m2:
                    cleaned2 = m2.group(0)
                enriched = _json.loads(cleaned2)

            # Merge enrichment data back into the hypothesis dict
            hypo["title"] = enriched.get("title") or vuln_type
            hypo["severity"] = enriched.get("severity", "Informational")
            # Store LLM-provided vectors, then compute accurate scores from them
            hypo["cvss_vector"] = enriched.get("cvss_vector")
            hypo["cvss4_vector"] = enriched.get("cvss4_vector")
            hypo["cvss_score"] = (
                _calc_cvss_score(hypo["cvss_vector"])
                or _parse_float(enriched.get("cvss_score"))
            )
            hypo["cvss4_score"] = (
                _calc_cvss_score(hypo["cvss4_vector"])
                or _parse_float(enriched.get("cvss4_score"))
            )
            hypo["description"] = enriched.get("description", "")
            hypo["impact"] = enriched.get("impact", "")
            hypo["remediation"] = enriched.get("remediation", "")
            hypo["cve"] = enriched.get("cve")
            refs = enriched.get("references")
            if isinstance(refs, list):
                hypo["references"] = "\n".join(r for r in refs if isinstance(r, str))
            elif isinstance(refs, str):
                hypo["references"] = refs
            else:
                hypo["references"] = None

            await manager.send_log(scan_id, "INFO", "report",
                                   f"[+] Enriched finding: {hypo['title']}")

            # ── PoC enrichment ─────────────────────────────────────────────
            try:
                poc_prompt = (
                    f"Vulnerability Type: {hypo.get('title', vuln_type)}\n"
                    f"Severity: {hypo.get('severity', 'Unknown')}\n"
                    f"Target URL: {location}\n"
                    f"Vulnerable Parameter / Component: {hypo.get('details', details)[:400]}\n\n"
                    f"RAW EXPLOIT EVIDENCE:\n{proof[:2000]}\n\n"
                    "Write a detailed professional PoC using the required sections."
                )
                poc_resp = await engine.generate_response(
                    messages=[{"role": "user", "content": poc_prompt}],
                    system_prompt=_POC_SYSTEM,
                    max_tokens=3000,
                )
                enriched_poc = engine.extract_text(poc_resp).strip()
                if enriched_poc:
                    raw["proof"] = enriched_poc
                await manager.send_log(scan_id, "INFO", "report",
                                       f"[+] PoC written for: {hypo['title']}")
            except Exception as poc_exc:
                await manager.send_log(scan_id, "WARN", "report",
                                       f"[!] PoC enrichment failed for '{vuln_type}': {poc_exc}")

        except Exception as exc:
            # Non-fatal: if enrichment fails, the finding is still saved with partial data
            await manager.send_log(scan_id, "WARN", "report",
                                   f"[!] Failed to enrich finding '{vuln_type}': {exc}")


def _build_summary(workspace: Any) -> dict[str, Any]:
    counts: dict[str, int] = {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0
    }
    for raw in getattr(workspace, "findings", []):
        sev = _norm_sev(raw.get("hypothesis", {}).get("severity", ""))
        counts[sev.lower()] = counts.get(sev.lower(), 0) + 1

    hypos = getattr(workspace, "hypotheses", [])
    # Workspace uses "exploited" for confirmed findings, "potential" for partial
    confirmed = sum(1 for h in hypos if h.get("status") in ("exploited", "confirmed"))
    return {
        **counts,
        "total_findings": sum(counts.values()),
        "hypotheses_total": len(hypos),
        "hypotheses_confirmed": confirmed,
    }


def _parse_float(val: Any) -> float | None:
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _calc_cvss_score(vector: str | None) -> float | None:
    """Calculate an accurate CVSS score from a vector string using the cvss library."""
    if not vector or not isinstance(vector, str):
        return None
    try:
        from cvss import CVSS3, CVSS4
        v = vector.strip()
        if v.startswith("CVSS:4.0"):
            obj = CVSS4(v)
        else:
            obj = CVSS3(v)
        score = obj.base_score
        return float(score) if score is not None else None
    except Exception:
        return None


# Absolute base dir for per-scan evidence (screenshots, traces, reports)
_DATA_BASE = os.environ.get("DATA_BASE", "/app/data")
_SCANS_BASE = os.path.join(_DATA_BASE, "scans")

# Shared persistent files — survive container restarts via the DATA_BASE volume
_MEMORY_FILE = os.path.join(_DATA_BASE, "memory.json")
_CORPUS_FILE  = os.path.join(_DATA_BASE, "corpus.json")


def _setup_llm_env(scan: Scan, gs: Any) -> None:
    """Set environment variables the LLM engine reads at import time."""
    from backend.services.crypto import decrypt_value
    provider = scan.llm_provider
    if provider == "anthropic" and gs and gs.anthropic_api_key_enc:
        os.environ["ANTHROPIC_API_KEY"] = decrypt_value(gs.anthropic_api_key_enc)
        os.environ["LLM_PROVIDER"] = "anthropic"
        if scan.llm_model:
            os.environ["ANTHROPIC_MODEL"] = scan.llm_model
        if gs.anthropic_base_url:
            os.environ["ANTHROPIC_BASE_URL"] = gs.anthropic_base_url
        else:
            os.environ.pop("ANTHROPIC_BASE_URL", None)
        os.environ["ANTHROPIC_MAX_TOKENS"] = str(gs.anthropic_max_tokens or 4096)
    elif provider == "openai" and gs and gs.openai_api_key_enc:
        os.environ["OPENAI_API_KEY"] = decrypt_value(gs.openai_api_key_enc)
        os.environ["LLM_PROVIDER"] = "openai"
        if scan.llm_model:
            os.environ["OPENAI_MODEL"] = scan.llm_model
        if gs.openai_base_url:
            os.environ["OPENAI_BASE_URL"] = gs.openai_base_url
        else:
            os.environ.pop("OPENAI_BASE_URL", None)
        os.environ["OPENAI_MAX_TOKENS"] = str(gs.openai_max_tokens or 4096)
    elif provider == "openrouter" and gs and gs.openrouter_api_key_enc:
        os.environ["OPENAI_API_KEY"] = decrypt_value(gs.openrouter_api_key_enc)
        os.environ["LLM_PROVIDER"] = "openai"
        os.environ["OPENAI_BASE_URL"] = gs.openrouter_base_url or "https://openrouter.ai/api/v1"
        model = scan.llm_model or gs.openrouter_default_model or "openai/gpt-4o"
        os.environ["OPENAI_MODEL"] = model
        os.environ["OPENAI_MAX_TOKENS"] = str(gs.openrouter_max_tokens or 4096)
    elif provider == "ollama":
        os.environ["LLM_PROVIDER"] = "ollama"
        if gs and gs.ollama_base_url:
            os.environ["OLLAMA_BASE_URL"] = gs.ollama_base_url
        if scan.llm_model:
            os.environ["OLLAMA_MODEL"] = scan.llm_model
        elif gs and gs.ollama_default_model:
            os.environ["OLLAMA_MODEL"] = gs.ollama_default_model
        if gs and gs.ollama_temperature is not None:
            os.environ["OLLAMA_TEMPERATURE"] = str(gs.ollama_temperature)
        if gs and gs.ollama_num_ctx is not None:
            os.environ["OLLAMA_NUM_CTX"] = str(gs.ollama_num_ctx)
        if gs and gs.ollama_max_tokens is not None:
            os.environ["OLLAMA_MAX_TOKENS"] = str(gs.ollama_max_tokens)
