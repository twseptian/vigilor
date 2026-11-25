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


# ── OpenAI-compatible providers ───────────────────────────────────────────────
# These five share OpenAIEngine via the OPENAI_* env vars (one generic branch in
# _setup_llm_env). Each maps to its default base URL. openai/openrouter keep their
# own bespoke env branches but also run on OpenAIEngine.
_OAI_COMPAT_DEFAULTS = {
    "mistral": "https://api.mistral.ai/v1",
    "groq": "https://api.groq.com/openai/v1",
    "xai": "https://api.x.ai/v1",
    "deepseek": "https://api.deepseek.com",
    "kimi": "https://api.moonshot.ai/v1",
    "zai": "https://api.z.ai/api/paas/v4",
}
# Fallback model per provider — used only when neither a per-scan model nor a saved
# default is set. Prevents OpenAIEngine's own default ("gpt-4o", invalid on these
# providers) from being sent, which would fail every call with "model not found".
_OAI_COMPAT_DEFAULT_MODELS = {
    "mistral": "mistral-large-latest",
    "groq": "llama-3.3-70b-versatile",
    "xai": "grok-4.6",
    "deepseek": "deepseek-chat",
    "kimi": "kimi-latest",
    "zai": "glm-4.7",
}
# Every provider that maps onto OpenAIEngine.
_OPENAI_ENGINE_PROVIDERS = ("openai", "openrouter") + tuple(_OAI_COMPAT_DEFAULTS)


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


def _kill_proc(proc) -> None:
    try:
        proc.kill()
    except Exception:
        pass


async def _clone_repo(repo_url: str, dest: str, scan_id: str, timeout: int = 180) -> str:
    """Shallow-clone a public git repo into `dest` for Source Code Review.

    Returns `dest` on success; raises RuntimeError on any failure. Auth prompts are
    disabled so a private/unreachable repo fails fast instead of hanging."""
    import shutil
    if os.path.exists(dest):
        shutil.rmtree(dest, ignore_errors=True)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    await _persist_log(scan_id, "INFO", "clone", f"Cloning repository {repo_url} …")
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "/bin/true"}
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "clone", "--depth", "1", "--single-branch", repo_url, dest,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT, env=env,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("git is not installed in the backend container") from exc
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        _kill_proc(proc)
        raise RuntimeError(f"git clone timed out after {timeout}s") from exc
    except BaseException:
        # Includes CancelledError when the scan is cancelled mid-clone: kill the
        # orphaned git process (and let the caller's finally remove the partial
        # checkout) instead of leaking a detached subprocess.
        _kill_proc(proc)
        raise
    if proc.returncode != 0:
        tail = (out or b"").decode("utf-8", "replace").strip()[-400:]
        raise RuntimeError(f"git clone failed (exit {proc.returncode}): {tail}")
    await _persist_log(scan_id, "INFO", "clone", f"Repository cloned to {dest}")
    return dest


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

        # Set LLM environment variables for the engine; capture the resolved
        # OpenAI-compatible config to pass explicitly into OpenAIEngine below.
        oai_cfg = _setup_llm_env(scan, gs)
        _setup_scan_safety_env(gs)

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
            if provider in _OPENAI_ENGINE_PROVIDERS:
                # openrouter/mistral/groq/xai/deepseek/kimi: pass this scan's config
                # explicitly so a concurrent scan on another provider can't have
                # clobbered the shared OPENAI_* env between setup and construction.
                engine = OpenAIEngine(**(oai_cfg or {}))
            elif provider == "ollama":
                ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
                ollama_model = os.environ.get("OLLAMA_MODEL", "")
                engine = OllamaEngine(base_url=ollama_url, model=ollama_model)
            else:
                engine = ClaudeEngine()
        except Exception as e:
            raise RuntimeError(f"Failed to initialize {provider} LLM engine: {e}") from e

        static_only = (scan.scan_mode == "static_only")

        # ── Source Code Review: clone the repo and point static analysis at it ──
        # A source review runs static (regex) + LLM (vuln + report) on the cloned
        # code — no live crawl/exploit — so it needs static_only=False (to reach the
        # vuln phase) but the recon/exploit agents are simply not registered below.
        is_source_review = bool(scan.source_repo_url)
        source_path = ""
        if is_source_review:
            _clone_dest = os.path.join(_SCANS_BASE, scan_id, "source")
            source_path = await _clone_repo(scan.source_repo_url, _clone_dest, scan_id)

        orchestrator = PentestOrchestrator(
            target_url=scan.target_url,
            repo_path=scan.repo_path or "",
            source_path=source_path,
            headers=headers,
            cookies=cookies,
            scope_include=scope_include,
            scope_exclude=scope_exclude,
            static_only=(False if is_source_review else static_only),
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
        if is_source_review:
            # Source Code Review: static (regex OWASP over the cloned source) + LLM
            # vuln analysis + report. No recon/exploit agents → the orchestrator's
            # per-phase `if "<agent>" in self.agents` guards skip the live phases.
            orchestrator.register_agent("static_analysis", _inject_prompt(StaticAnalysisAgent(engine)))
            orchestrator.register_agent("vuln", _inject_prompt(VulnAnalyzerAgent(engine, max_llm_hypotheses=scan.max_hypotheses)))
            orchestrator.register_agent("report", _inject_prompt(ReportingAgent(engine)))
        elif static_only:
            orchestrator.register_agent("static_analysis", _inject_prompt(StaticAnalysisAgent(engine)))
            orchestrator.register_agent("report", _inject_prompt(ReportingAgent(engine)))
        else:
            orchestrator.register_agent("recon", _inject_prompt(ReconAgent(engine)))
            orchestrator.register_agent("static_analysis", _inject_prompt(StaticAnalysisAgent(engine)))
            orchestrator.register_agent("vuln", _inject_prompt(VulnAnalyzerAgent(engine, max_llm_hypotheses=scan.max_hypotheses)))
            os.environ["EXPLOIT_HYPO_TIMEOUT"] = str(scan.exploit_hypo_timeout or 240)
            os.environ["EXPLOIT_MAX_TURNS"] = str(scan.exploit_max_turns or 8)
            os.environ["EXPLOIT_HYPO_CAP"] = str(scan.exploit_hypo_cap or 25)
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

        # Patch record_hypothesis to stream live progress. The tracer already keeps
        # running _hypo_stats; mirror them onto the scan row (picked up by the UI's
        # 3s poll) and push a WS 'progress' event for instant updates. This is the
        # difference between a bar that only fills in at the end and one you can
        # actually watch while the exploit phase runs.
        _orig_record = tracer.record_hypothesis

        def _patched_record(action, hypo_type="", location=""):
            _orig_record(action, hypo_type, location)
            st = dict(tracer._hypo_stats)
            resolved = st["confirmed"] + st["failed"] + st["potential"] + st["skipped"]
            asyncio.run_coroutine_threadsafe(
                _update_scan_progress(scan_id, st.get("added", 0), resolved, st["confirmed"]),
                loop,
            )
            asyncio.run_coroutine_threadsafe(
                manager.send_progress(scan_id, st), loop
            )

        tracer.record_hypothesis = _patched_record  # type: ignore[method-assign]

        # Patch phase_end to check cancel flag between phases
        _orig_phase_end = tracer.phase_end

        def _patched_phase_end(phase_name: str, **kwargs: Any) -> None:
            _orig_phase_end(phase_name, **kwargs)
            _check_cancelled()

        tracer.phase_end = _patched_phase_end  # type: ignore[method-assign]

        # Run the pipeline
        await orchestrator.run_pipeline()

        # Enrichment is a long tail of LLM calls (one+ per finding) that runs AFTER
        # the pipeline, so the in-pipeline phase-boundary cancel checks don't cover
        # it. Check here and inside the enrichment loops so a Cancel during the
        # "Generating findings report" phase actually stops instead of running on.
        _check_cancelled()

        # Enrich findings with LLM-generated description, severity, cvss, references
        await _enrich_findings(orchestrator.workspace, engine, scan_id, cancel_flag,
                               is_source_review=is_source_review)

        _check_cancelled()

        # Persist findings from workspace
        await _persist_findings(scan_id, orchestrator.workspace)

        # Derive the attack workflow (attack chains + graph) from the persisted findings
        await _persist_attack_workflow(scan_id, engine)

        # Final cancel gate: never overwrite a user's "cancelled" with "completed".
        _check_cancelled()

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
            # Final tested count = every hypothesis that reached a terminal state,
            # so a completed scan's progress bar reads a true 100%.
            _hs = summary.get("hypothesis_stats", {}) or {}
            scan.hypotheses_tested = (
                _hs.get("confirmed", 0) + _hs.get("failed", 0)
                + _hs.get("potential", 0) + _hs.get("skipped", 0)
            ) or scan.hypotheses_total
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

    finally:
        # Source Code Review only: the cloned checkout is scan INPUT, not a
        # deliverable. Remove it on completion/failure/cancel so repositories
        # don't accumulate unbounded on the data volume. Screenshots and other
        # evidence under the scan directory are kept.
        try:
            import shutil as _shutil
            _src_dir = os.path.join(_SCANS_BASE, scan_id, "source")
            if os.path.isdir(_src_dir):
                _shutil.rmtree(_src_dir, ignore_errors=True)
        except Exception:
            pass


async def _persist_attack_workflow(scan_id: str, engine: Any) -> None:
    """Build and store the scan's attack workflow. Never fails the scan."""
    from sqlalchemy import select as _select

    from backend.services import attack_workflow as awf

    try:
        async with AsyncSessionLocal() as db:
            scan = await db.get(Scan, scan_id)
            if scan is None:
                return
            rows = await db.execute(_select(Finding).where(Finding.scan_id == scan_id))
            findings = list(rows.scalars().all())
            if not findings:
                await manager.send_log(scan_id, "INFO", "report",
                                       "[*] No findings — attack workflow skipped")
                return

            await manager.send_log(scan_id, "INFO", "report",
                                   f"[*] Building attack workflow from {len(findings)} finding(s)")
            workflow = await awf.build_scan_workflow(scan, findings, engine)
            await awf.save_workflow(db, scan_id, None, workflow)

            chains = workflow.get("chains") or []
            await manager.send_log(
                scan_id, "INFO", "report",
                f"[+] Attack workflow: {len(chains)} chain(s), "
                f"{len(workflow['graph']['nodes'])} node(s) [{workflow['generator']}]"
            )
            for chain in chains[:5]:
                await manager.send_log(
                    scan_id, "INFO", "report",
                    f"    ↳ [{chain['severity']}] {chain['name']} "
                    f"({' → '.join(chain['finding_refs'])})"
                )
    except Exception as exc:
        await manager.send_log(scan_id, "WARN", "report",
                               f"[!] Attack workflow generation failed: {exc}")


async def _update_scan_phase(scan_id: str, phase: str) -> None:
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.phase = phase
            await db.commit()


async def _update_scan_progress(scan_id: str, total: int, tested: int, confirmed: int) -> None:
    """Persist live hypothesis progress so a reload / the 3s poll shows it too.

    Only ever moves counters forward — a late-arriving event from a slower thread
    can't make the bar jump backwards.
    """
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan:
            scan.hypotheses_total     = max(scan.hypotheses_total or 0, total)
            scan.hypotheses_tested    = max(scan.hypotheses_tested or 0, tested)
            scan.hypotheses_confirmed = max(scan.hypotheses_confirmed or 0, confirmed)
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


_TOOL_PATTERNS = [
    ("sqlmap",      "sqlmap"),
    ("nikto",       "nikto"),
    ("dirb",        "dirb"),
    ("gobuster",    "gobuster"),
    ("wfuzz",       "wfuzz"),
    ("ffuf",        "ffuf"),
    ("nmap",        "nmap"),
    ("nuclei",      "nuclei"),
    ("playwright",  "playwright"),
    ("burp",        "burp"),
    ("zap",         "zap"),
    ("curl",        "curl"),
    ("wget",        "wget"),
]


def _detect_source_tool(proof: str) -> str | None:
    """Heuristically identify the tool that produced the finding from proof text."""
    lowered = proof.lower()
    for keyword, tool_name in _TOOL_PATTERNS:
        if keyword in lowered:
            return tool_name
    return None


_EVIDENCE_SIGNATURES = (
    "uid=", "gid=", "root:x:0:0:", "sql syntax", "mysql_", "postgresql",
    "alert(", "<script", "onerror=", "accesskeyid", "169.254.169.254",
    "-----begin", "traceback", "phpinfo()", "www-data", "/etc/passwd",
    "http/1.1", "http/2 ", "status: 200", "status: 500",
)


def _has_concrete_evidence(proof: str, raw_request: str | None, raw_response: str | None) -> bool:
    """True only when we have HTTP capture or hard technical signatures — not LLM prose."""
    blob = " ".join(filter(None, [proof or "", raw_request or "", raw_response or ""])).lower()
    if raw_request and raw_response and len(raw_request) > 20 and len(raw_response) > 20:
        return True
    return any(sig in blob for sig in _EVIDENCE_SIGNATURES)


def _compute_confidence(
    proof: str,
    is_potential: bool,
    source_phase: str | None,
    *,
    has_http_evidence: bool = False,
) -> int:
    """Compute 0–100 confidence from observable evidence — not narration length."""
    proof_l = (proof or "").lower()
    score = 0

    if has_http_evidence:
        score += 30
    if any(k in proof_l for k in ("attack request", "observed evidence", "raw response", "http/1.")):
        score += 15
    if any(sig in proof_l for sig in _EVIDENCE_SIGNATURES):
        score += 20
    # Long prose alone must NOT inflate confidence (was the main FP booster).
    if len((proof or "").strip()) >= 120 and has_http_evidence:
        score += 10

    if is_potential:
        return min(score, 40)

    if source_phase == "exploit" and has_http_evidence:
        score += 15
    elif source_phase == "exploit":
        score += 5

    if any(w in proof_l for w in (
        "might be", "possible", "potential", "inconclusive", "could not confirm",
        "further testing", "needs verification", "partial evidence",
        "identified by source code review", "not runtime-confirmed",
    )):
        score = min(score, 45)

    return max(0, min(score, 100))


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

            # Evidence quality signals
            proof_text = raw.get("proof", "")
            is_potential = bool(raw.get("is_potential", False))
            hypo_status = hypo.get("status", "")
            # source_phase: auto-confirmed header findings = "recon", exploit loop = "exploit"
            if hypo_status == "confirmed":
                source_phase = "recon"
            else:
                source_phase = raw.get("source_phase") or "exploit"
            source_tool = raw.get("source_tool") or _detect_source_tool(proof_text)
            raw_request = raw.get("raw_request")
            raw_response = raw.get("raw_response")
            has_http_evidence = _has_concrete_evidence(proof_text, raw_request, raw_response)
            has_poc = bool(has_http_evidence or len(proof_text.strip()) >= 80)
            confidence_score = _compute_confidence(
                proof_text, is_potential, source_phase, has_http_evidence=has_http_evidence,
            )
            # Demote narrative-only "confirmed" findings (no HTTP capture / signatures)
            # — these were the bulk of false positives (acme.com /admin, hallucinated XSS).
            if (not is_potential) and (not has_http_evidence):
                is_potential = True
                title = title if title.lower().startswith("potential ") else f"Potential {title}"
                confidence_score = min(confidence_score, 35)
                has_poc = False
            if is_potential:
                # Potentials must not land as Critical/High without runtime proof
                sev = _norm_sev(hypo.get("severity", "Informational"))
                if sev in ("Critical", "High"):
                    hypo = {**hypo, "severity": "Medium"}
                confidence_score = min(confidence_score, 40)
            # Source-review findings carry the vulnerable code snippet in the static
            # hypothesis 'details' ("Matched snippet : <code>"); enrichment overwrites
            # 'description', so capture the snippet here as raw evidence for the
            # report's Vulnerable-Code box and the UI evidence card.
            if not raw_request:
                for _ln in (hypo.get("details", "") or "").splitlines():
                    if _ln.strip().lower().startswith("matched snippet"):
                        raw_request = (_ln.split(":", 1)[1].strip() if ":" in _ln
                                       else _ln.strip())
                        break

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
                proof_of_concept=proof_text,
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
                has_poc=has_poc,
                confidence_score=confidence_score,
                source_phase=source_phase,
                source_tool=source_tool,
                raw_request=raw_request,
                raw_response=raw_response,
                verification_status="Unverified",
            )
            db.add(finding)
            await ws_mgr.send_finding(scan_id, {
                "title": finding.title,
                "severity": finding.severity,
                "location": finding.location,
            })
        await db.commit()


# ── Enrichment prompts ────────────────────────────────────────────────────────

# Full schema prompt — used by Claude / OpenAI / OpenRouter
_ENRICH_BATCH_SYSTEM = (
    "You are a senior penetration tester writing structured finding reports. "
    "Given a numbered list of vulnerabilities (some may be Potential / weakly evidenced), "
    "return a JSON ARRAY where each element "
    "corresponds to the same-index input finding (index 0 = Finding 1, etc.). "
    "Do NOT invent stronger evidence than provided. If the input is labeled Potential or "
    "lacks a concrete PoC, keep severity conservative (≤ Medium) and say so in description. "
    "Every element must have these exact keys. Keep all text values SHORT (1-2 sentences):\n"
    '  "title"        — concise vulnerability title (max 10 words)\n'
    '  "severity"     — one of: Critical, High, Medium, Low, Informational\n'
    '  "cvss_score"   — numeric CVSS v3.1 base score (0.0–10.0)\n'
    '  "cvss_vector"  — CVSS v3.1 vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N")\n'
    '  "cvss4_score"  — numeric CVSS v4.0 base score (0.0–10.0)\n'
    '  "cvss4_vector" — CVSS v4.0 vector string (e.g. "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N")\n'
    '  "description"  — 1-2 sentences explaining the vulnerability\n'
    '  "impact"       — 1-2 sentences on business/security impact\n'
    '  "remediation"  — 1-2 sentences with concrete fix steps\n'
    '  "cve"          — REAL published CVE (e.g. CVE-2021-44228). Set null for generic classes (XSS, SQLi, IDOR, missing headers). NEVER invent a CVE ID.\n'
    '  "references"   — JSON array of 2-3 URLs (OWASP, CWE, NVD)\n'
    "Return ONLY a valid JSON array. No markdown. No explanation. No extra text."
)

_ENRICH_SINGLE_SYSTEM = (
    "You are a senior penetration tester writing structured finding reports. "
    "Given a confirmed vulnerability, return a single JSON object with these exact keys. "
    "Keep all text values SHORT (1-2 sentences max):\n"
    '  "title"        — concise vulnerability title (max 10 words)\n'
    '  "severity"     — one of: Critical, High, Medium, Low, Informational\n'
    '  "cvss_score"   — numeric CVSS v3.1 base score (0.0–10.0)\n'
    '  "cvss_vector"  — CVSS v3.1 vector string\n'
    '  "cvss4_score"  — numeric CVSS v4.0 base score (0.0–10.0)\n'
    '  "cvss4_vector" — CVSS v4.0 vector string\n'
    '  "description"  — 1-2 sentences explaining the vulnerability\n'
    '  "impact"       — 1-2 sentences on business/security impact\n'
    '  "remediation"  — 1-2 sentences with concrete fix steps\n'
    '  "cve"          — REAL published CVE (e.g. CVE-2021-44228). Set null for generic classes (XSS, SQLi, IDOR, missing headers). NEVER invent a CVE ID.\n'
    '  "references"   — JSON array of 2-3 URLs (OWASP, CWE, NVD)\n'
    "Return ONLY valid JSON. No markdown. No explanation."
)

# Compact schema for Ollama — drops cvss4 fields to reduce output length.
# cvss4 vectors are long (~80 chars) and push small models over their token limit.
_ENRICH_BATCH_SYSTEM_OLLAMA = (
    "You are a penetration tester. For each finding in the numbered list, "
    "return a JSON ARRAY where index 0 = Finding 1. "
    "Each object must have ONLY these keys (keep strings under 80 chars):\n"
    '  "title"       — vulnerability name, max 8 words\n'
    '  "severity"    — Critical, High, Medium, Low, or Informational\n'
    '  "cvss_score"  — CVSS v3.1 base score number (0.0-10.0)\n'
    '  "cvss_vector" — CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:./C:./I:./A:.\n'
    '  "description" — one sentence max\n'
    '  "impact"      — one sentence max\n'
    '  "remediation" — one sentence max\n'
    '  "cve"         — real CVE only (e.g. CVE-2021-44228), null if none known. Never invent.\n'
    '  "references"  — array of 1-2 URLs\n'
    "Return ONLY a valid JSON array. No markdown. No text outside the array."
)

_ENRICH_SINGLE_SYSTEM_OLLAMA = (
    "You are a penetration tester. Return a single JSON object for this vulnerability. "
    "Use ONLY these keys (keep strings under 80 chars):\n"
    '  "title"       — vulnerability name, max 8 words\n'
    '  "severity"    — Critical, High, Medium, Low, or Informational\n'
    '  "cvss_score"  — CVSS v3.1 base score number (0.0-10.0)\n'
    '  "cvss_vector" — CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:./C:./I:./A:.\n'
    '  "description" — one sentence max\n'
    '  "impact"      — one sentence max\n'
    '  "remediation" — one sentence max\n'
    '  "cve"         — real CVE only (e.g. CVE-2021-44228), null if none known. Never invent.\n'
    '  "references"  — array of 1-2 URLs\n'
    "Return ONLY valid JSON. No markdown. No text outside the object."
)

# Source Code Review — appended to the enrichment/PoC system prompt so the AI
# writes code-oriented findings: the vulnerable code, and a remediation that fixes
# the SOURCE (secure code), not generic web/WAF advice.
_SOURCE_REVIEW_ENRICH_DIRECTIVE = (
    "\n\nCONTEXT: This is a SOURCE CODE REVIEW finding, not a live web test. The "
    "'location' is a file:line and the input includes the vulnerable code snippet. "
    "Write 'description' about why THAT code is insecure. Make 'remediation' a "
    "CONCRETE CODE-LEVEL FIX: name the insecure construct and give the corrected, "
    "secure code for that language (e.g. a parameterized/prepared query, output "
    "encoding, a safe API, input validation). Do NOT give generic web-server, WAF, "
    "or network advice."
)
_SOURCE_REVIEW_POC_DIRECTIVE = (
    "\n\nCONTEXT: This is a SOURCE CODE REVIEW finding. There is no live HTTP "
    "exploit. Instead, structure the write-up as: (1) the vulnerable code with its "
    "file:line, (2) why it is exploitable, (3) the corrected secure code. Use fenced "
    "code blocks (```lang ... ```) for both the vulnerable and the fixed code."
)


def _src_sys(base: str, is_source_review: bool) -> str:
    return base + _SOURCE_REVIEW_ENRICH_DIRECTIVE if is_source_review else base


# Token floors for enrichment — independent of OLLAMA_MAX_TOKENS (which is tuned
# for exploit turns and is typically too low for structured JSON output).
_OLLAMA_ENRICH_SINGLE_TOKENS = 900   # enough for ~8 short fields + CVSS vector
_OLLAMA_ENRICH_BATCH_TOKENS  = 800   # per finding in a batch

_POC_SYSTEM = (
    "You are a senior penetration tester writing the Proof of Concept section of a professional WVAPT report. "
    "Write in flowing technical paragraphs — no section headers, no bullet lists, no numbered steps. "
    "Be direct and concise. Every sentence must add technical value. Cut filler phrases.\n\n"
    "STRUCTURE (as continuous prose, no headers):\n\n"
    "Paragraph 1 — What was found and where: state the vulnerability type, the exact endpoint "
    "(method + URL + vulnerable parameter), and what was confirmed. One or two sentences maximum.\n\n"
    "Code block — The exact attack request: the actual curl command or raw HTTP request with the real payload used. "
    "Indent with 4 spaces so it renders as monospace.\n\n"
    "Code block — The server response excerpt: the relevant HTTP status line and response body fragment "
    "that proves exploitation (error message, injected content, file content, delayed response time, etc.). "
    "Indent with 4 spaces.\n\n"
    "Paragraph 2 — Impact and root cause: one or two sentences on what an attacker achieves and why the "
    "vulnerability exists (unsanitized input, missing validation, misconfiguration, etc.).\n\n"
    "RULES:\n"
    "- Use ONLY data present in the evidence. Never fabricate payloads, URLs, or responses.\n"
    "- No section headers, no bold labels, no markdown fences.\n"
    "- Indent code lines with exactly 4 spaces.\n"
    "- Total length: 100–200 words maximum.\n"
    "Return ONLY plain text."
)

# Default batch size for non-Ollama providers (Claude / OpenAI / OpenRouter).
# Ollama uses a smaller batch because local models are less reliable at multi-item JSON arrays.
_ENRICH_BATCH_SIZE        = 4   # Claude / OpenAI / OpenRouter
_ENRICH_BATCH_SIZE_OLLAMA = 2   # Ollama — smaller = fewer parse failures


def _is_ollama(engine: Any) -> bool:
    """True when the active engine is a local Ollama model."""
    return type(engine).__name__ == "OllamaEngine"


def _ollama_max_tokens(default: int) -> int:
    """Return the user-configured OLLAMA_MAX_TOKENS, clamped to at least `default`."""
    import os as _os
    try:
        return max(int(_os.environ.get("OLLAMA_MAX_TOKENS", default)), default)
    except (ValueError, TypeError):
        return default


def _fix_json_string_literals(text: str) -> str:
    """Escape literal control characters inside JSON string values.

    LLMs (especially via OpenRouter) emit raw newlines/tabs inside string
    values instead of the \\n/\\t escape sequences required by the JSON spec.
    Also normalises smart/curly quotes used as string delimiters.
    """
    text = (text
            .replace('\u201c', '"').replace('\u201d', '"')
            .replace('\u2018', "'").replace('\u2019', "'")
            .replace('\u00ab', '"').replace('\u00bb', '"'))
    result: list = []
    in_string = False
    prev_backslash = False
    for ch in text:
        if prev_backslash:
            result.append(ch)
            prev_backslash = False
            continue
        if ch == '\\' and in_string:
            result.append(ch)
            prev_backslash = True
            continue
        if ch == '"':
            in_string = not in_string
            result.append(ch)
            continue
        if in_string:
            if ch == '\n':
                result.append('\\n')
            elif ch == '\r':
                result.append('\\r')
            elif ch == '\t':
                result.append('\\t')
            elif ord(ch) < 0x20:
                result.append(' ')
            else:
                result.append(ch)
        else:
            result.append(ch)
    return ''.join(result)


def _recover_partial_json(text: str) -> dict:
    """Extract key-value pairs from a truncated JSON string via regex.
    Returns whatever fields were output before the truncation point."""
    import re as _re
    result: dict = {}
    # String fields
    for key in ("title", "severity", "cvss_vector", "description",
                "impact", "remediation", "cve"):
        m = _re.search(rf'"{key}"\s*:\s*"([^"]*)"', text)
        if m:
            result[key] = m.group(1)
    # Numeric fields
    for key in ("cvss_score", "cvss4_score"):
        m = _re.search(rf'"{key}"\s*:\s*([0-9]+(?:\.[0-9]+)?)', text)
        if m:
            result[key] = float(m.group(1))
    # References array — grab whatever URLs were output
    m = _re.search(r'"references"\s*:\s*(\[[^\]]*)', text)
    if m:
        try:
            import json as _j
            raw_arr = m.group(1)
            if not raw_arr.endswith("]"):
                # Close any open string and the array
                raw_arr = _re.sub(r'[^"]*$', '', raw_arr).rstrip(",") + "]"
            result["references"] = _j.loads(raw_arr)
        except Exception:
            pass
    return result


def _apply_enrichment(hypo: dict, enriched: dict, vuln_type: str) -> None:
    """Merge a single enrichment dict into the hypothesis dict in-place."""
    hypo["title"]       = enriched.get("title") or vuln_type
    hypo["severity"]    = enriched.get("severity", "Informational")
    hypo["cvss_vector"] = enriched.get("cvss_vector")
    hypo["cvss4_vector"]= enriched.get("cvss4_vector")
    hypo["cvss_score"]  = (
        _calc_cvss_score(hypo["cvss_vector"])
        or _parse_float(enriched.get("cvss_score"))
    )
    hypo["cvss4_score"] = (
        _calc_cvss_score(hypo["cvss4_vector"])
        or _parse_float(enriched.get("cvss4_score"))
    )
    hypo["description"] = enriched.get("description", "")
    hypo["impact"]      = enriched.get("impact", "")
    hypo["remediation"] = enriched.get("remediation", "")
    hypo["cve"]         = _validate_cve(enriched.get("cve"))
    refs = enriched.get("references")
    if isinstance(refs, list):
        hypo["references"] = "\n".join(r for r in refs if isinstance(r, str))
    elif isinstance(refs, str):
        hypo["references"] = refs
    else:
        hypo["references"] = None


async def _enrich_metadata_batch(
    batch: list, engine: Any, scan_id: str, is_source_review: bool = False
) -> None:
    """Enrich metadata for up to _ENRICH_BATCH_SIZE findings in one LLM call.
    Falls back to individual calls if the batch parse fails."""
    import json as _json
    import re as _re

    # Build a numbered list prompt — more context for higher-severity items
    lines = []
    for i, raw in enumerate(batch, 1):
        hypo = raw.get("hypothesis", {})
        sev  = (hypo.get("severity") or "").lower()
        # Medium gets moderate context; Low/Info gets minimal
        det_limit   = 400 if sev == "medium" else 200
        proof_limit = 400 if sev == "medium" else 200
        lines.append(
            f"Finding {i}:\n"
            f"  Type: {hypo.get('type', 'Unknown')}\n"
            f"  Location: {hypo.get('location', '/')}\n"
            f"  Details: {hypo.get('details', '')[:det_limit]}\n"
            f"  Proof snippet: {raw.get('proof', '')[:proof_limit]}"
        )
    ollama  = _is_ollama(engine)
    sys_prompt = _src_sys(_ENRICH_BATCH_SYSTEM_OLLAMA if ollama else _ENRICH_BATCH_SYSTEM,
                          is_source_review)
    prompt = (
        f"Enrich the following {len(batch)} findings. "
        f"Return a JSON array of exactly {len(batch)} objects (index 0 = Finding 1).\n\n"
        + "\n\n".join(lines)
    )

    # For Ollama: use a fixed floor independent of OLLAMA_MAX_TOKENS (which is tuned
    # for exploit turns and is too low for structured JSON).
    if ollama:
        max_tok = _OLLAMA_ENRICH_BATCH_TOKENS * len(batch)
    else:
        max_tok = min(600 * len(batch) + 256, 4096)

    try:
        response = await engine.generate_response(
            messages=[{"role": "user", "content": prompt}],
            system_prompt=sys_prompt,
            max_tokens=max_tok,
        )
        text = engine.extract_text(response)
        cleaned = _re.sub(r"```[a-z]*\n?", "", text).strip()
        cleaned = _re.sub(r"```", "", cleaned).strip()
        arr_match = _re.search(r"\[.*\]", cleaned, _re.DOTALL)
        if arr_match:
            cleaned = arr_match.group(0)
        cleaned = _fix_json_string_literals(cleaned)
        cleaned = _re.sub(r",\s*([}\]])", r"\1", cleaned)  # trailing commas
        enriched_list = _json.loads(cleaned)

        if not isinstance(enriched_list, list) or len(enriched_list) != len(batch):
            raise ValueError(f"Expected array of {len(batch)}, got {type(enriched_list)}")

        for raw, enriched in zip(batch, enriched_list):
            hypo = raw.get("hypothesis", {})
            _apply_enrichment(hypo, enriched, hypo.get("type", "Unknown"))
            await manager.send_log(scan_id, "INFO", "report",
                                   f"[+] Enriched: {hypo['title']}")

    except Exception as batch_exc:
        # Batch parse failed — fall back to individual calls for this batch
        await manager.send_log(scan_id, "WARN", "report",
                               f"[!] Batch enrich failed ({batch_exc}), falling back to individual calls")
        for raw in batch:
            await _enrich_metadata_single(raw, engine, scan_id, is_source_review)


async def _enrich_metadata_single(raw: dict, engine: Any, scan_id: str,
                                  is_source_review: bool = False) -> None:
    """Enrich metadata for a single finding.

    For Ollama: uses a compact schema (no cvss4), a fixed token floor that is
    independent of OLLAMA_MAX_TOKENS, and falls back to regex-based partial
    JSON recovery when output is truncated.
    """
    import json as _json
    import re as _re

    ollama    = _is_ollama(engine)
    hypo      = raw.get("hypothesis", {})
    vuln_type = hypo.get("type", "Unknown")
    location  = hypo.get("location", "/")
    sys_prompt = _src_sys(_ENRICH_SINGLE_SYSTEM_OLLAMA if ollama else _ENRICH_SINGLE_SYSTEM,
                          is_source_review)
    # Ollama: shorter input to leave more room for output within the context window
    det_limit   = 200 if ollama else 300
    proof_limit = 250 if ollama else 400
    prompt = (
        f"Vulnerability Type: {vuln_type}\n"
        f"Location: {location}\n"
        f"Details: {hypo.get('details', '')[:det_limit]}\n"
        f"Proof: {raw.get('proof', '')[:proof_limit]}\n\n"
        "Return JSON only."
    )
    try:
        # For Ollama use the enrichment floor, NOT OLLAMA_MAX_TOKENS
        single_max = _OLLAMA_ENRICH_SINGLE_TOKENS if ollama else 1024
        resp = await engine.generate_response(
            messages=[{"role": "user", "content": prompt}],
            system_prompt=sys_prompt,
            max_tokens=single_max,
        )
        text    = engine.extract_text(resp)
        cleaned = _re.sub(r"```[a-z]*\n?", "", text).strip()
        cleaned = _re.sub(r"```", "", cleaned).strip()
        m       = _re.search(r"\{.*\}", cleaned, _re.DOTALL)
        if m:
            cleaned = m.group(0)
        cleaned = _fix_json_string_literals(cleaned)
        cleaned = _re.sub(r",\s*([}\]])", r"\1", cleaned)

        enriched: dict = {}
        try:
            enriched = _json.loads(cleaned)
        except (_json.JSONDecodeError, ValueError):
            if ollama:
                # Ollama truncation recovery: extract whatever fields were output
                enriched = _recover_partial_json(text) or {}
                if enriched:
                    await manager.send_log(scan_id, "WARN", "report",
                                           f"[~] Partial JSON recovery for '{vuln_type}': "
                                           f"got {list(enriched.keys())}")
                else:
                    raise
            else:
                raise  # non-Ollama: propagate to outer except → logged as warning

        _apply_enrichment(hypo, enriched, vuln_type)
        await manager.send_log(scan_id, "INFO", "report",
                               f"[+] Enriched: {hypo['title']}")
    except Exception as exc:
        await manager.send_log(scan_id, "WARN", "report",
                               f"[!] Failed to enrich '{vuln_type}': {exc}")


async def _enrich_poc_single(raw: dict, engine: Any, scan_id: str,
                             is_source_review: bool = False) -> None:
    """Write professional PoC prose for one finding (all severities).

    Critical/High: full proof context + generous output budget.
    Medium:        moderate context.
    Low/Info:      trimmed context — PoC is shorter by nature.
    """
    hypo      = raw.get("hypothesis", {})
    proof     = raw.get("proof", "")
    vuln_type = hypo.get("type", "Unknown")
    location  = hypo.get("location", "/")
    sev       = (hypo.get("severity") or "").lower()

    ollama = _is_ollama(engine)

    if sev in ("critical", "high"):
        proof_limit = 1000 if ollama else 2000
        det_limit   = 300  if ollama else 500
        max_tok     = _ollama_max_tokens(512) if ollama else 1500
    elif sev == "medium":
        proof_limit = 800  if ollama else 1500
        det_limit   = 250  if ollama else 400
        max_tok     = _ollama_max_tokens(512) if ollama else 1200
    else:  # low / informational
        proof_limit = 500  if ollama else 800
        det_limit   = 200  if ollama else 300
        max_tok     = _ollama_max_tokens(384) if ollama else 900

    _loc_label = "Source location (file:line)" if is_source_review else "Target URL"
    poc_prompt = (
        f"Vulnerability Type: {hypo.get('title', vuln_type)}\n"
        f"Severity: {hypo.get('severity', 'Unknown')}\n"
        f"{_loc_label}: {location}\n"
        f"Vulnerable Code / Component: {hypo.get('details', '')[:det_limit]}\n\n"
        f"{'VULNERABLE CODE / EVIDENCE' if is_source_review else 'RAW EXPLOIT EVIDENCE'}:"
        f"\n{proof[:proof_limit]}\n\n"
        "Write a professional PoC following the required structure."
    )
    try:
        poc_resp = await engine.generate_response(
            messages=[{"role": "user", "content": poc_prompt}],
            system_prompt=_POC_SYSTEM + (_SOURCE_REVIEW_POC_DIRECTIVE if is_source_review else ""),
            max_tokens=max_tok,
        )
        enriched_poc = engine.extract_text(poc_resp).strip()
        if enriched_poc:
            raw["proof"] = enriched_poc
        await manager.send_log(scan_id, "INFO", "report",
                               f"[+] PoC written for: {hypo.get('title', vuln_type)}")
    except Exception as poc_exc:
        await manager.send_log(scan_id, "WARN", "report",
                               f"[!] PoC failed for '{vuln_type}': {poc_exc}")


async def _enrich_findings(workspace: Any, engine: Any, scan_id: str, cancel_flag: Any = None,
                           is_source_review: bool = False) -> None:
    """Enrich all confirmed findings.

    Metadata strategy:
      Critical / High  → individual LLM calls (full context, maximum accuracy)
      Medium / Low / Informational → batched calls (4 per call, saves tokens)

    PoC strategy:
      All severities → individual calls with severity-aware proof context.
    """
    findings = getattr(workspace, "findings", [])
    if not findings:
        return

    ollama     = _is_ollama(engine)
    batch_size = _ENRICH_BATCH_SIZE_OLLAMA if ollama else _ENRICH_BATCH_SIZE
    provider   = "Ollama" if ollama else "Claude/OpenAI"

    high_sev      = {"critical", "high"}
    critical_high = [f for f in findings if (f.get("hypothesis", {}).get("severity") or "").lower() in high_sev]
    lower_sev     = [f for f in findings if (f.get("hypothesis", {}).get("severity") or "").lower() not in high_sev]

    n_batches = (len(lower_sev) + batch_size - 1) // batch_size
    await manager.send_log(
        scan_id, "INFO", "report",
        f"[*] Enriching {len(findings)} finding(s) via {provider} "
        f"(batch_size={batch_size}): "
        f"{len(critical_high)} Critical/High (individual) + "
        f"{len(lower_sev)} Medium/Low/Info ({n_batches} batch(es))"
    )

    def _cancelled() -> bool:
        return cancel_flag is not None and cancel_flag.is_set()

    # ── Phase 1a: Critical/High — individual metadata calls (full accuracy) ──
    for raw in critical_high:
        if _cancelled():
            raise asyncio.CancelledError(f"Scan {scan_id} cancelled during enrichment")
        await _enrich_metadata_single(raw, engine, scan_id, is_source_review)

    # ── Phase 1b: Medium/Low/Info — batched metadata calls ───────────────────
    for i in range(0, len(lower_sev), batch_size):
        if _cancelled():
            raise asyncio.CancelledError(f"Scan {scan_id} cancelled during enrichment")
        batch     = lower_sev[i:i + batch_size]
        batch_num = i // batch_size + 1
        await manager.send_log(scan_id, "INFO", "report",
                               f"[*] Metadata batch {batch_num}: {len(batch)} finding(s)")
        await _enrich_metadata_batch(batch, engine, scan_id, is_source_review)

    # ── Phase 2: PoC for ALL findings (severity-aware context/token budget) ──
    for raw in findings:
        if _cancelled():
            raise asyncio.CancelledError(f"Scan {scan_id} cancelled during enrichment")
        await _enrich_poc_single(raw, engine, scan_id, is_source_review)


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


def _validate_cve(cve: Any) -> str | None:
    """Return the CVE string only if it looks like a real published CVE.

    Rejects:
    - Non-string / empty values
    - Values that don't match CVE-YYYY-NNNNN format
    - Obvious placeholder numbers (12345, 00001, 99999, all-same digits)
    - Suspiciously low sequential IDs that LLMs tend to hallucinate
    """
    import re as _re
    if not cve or not isinstance(cve, str):
        return None
    cve = cve.strip()
    m = _re.match(r'^(CVE-\d{4}-(\d{4,}))$', cve, _re.IGNORECASE)
    if not m:
        return None
    num = m.group(2)
    # Reject obvious placeholders: 12345, 00001, 11111, 99999, 0000x, etc.
    _PLACEHOLDER = {"12345", "00001", "00000", "99999", "11111", "22222",
                    "33333", "44444", "55555", "66666", "77777", "88888"}
    if num in _PLACEHOLDER:
        return None
    if len(set(num)) == 1:   # all same digit, e.g. 1111, 0000
        return None
    return m.group(1).upper()


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


def create_engine_for_scan(scan: Scan, gs: Any) -> Any:
    """Set the provider env vars and construct the matching LLM engine.

    Used by on-demand services (e.g. attack workflow regeneration) that need the
    same engine the scan itself ran with.
    """
    oai_cfg = _setup_llm_env(scan, gs)
    from src.core.llm import ClaudeEngine, OpenAIEngine, OllamaEngine

    provider = scan.llm_provider
    if provider in _OPENAI_ENGINE_PROVIDERS:
        return OpenAIEngine(**(oai_cfg or {}))
    if provider == "ollama":
        return OllamaEngine(
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=os.environ.get("OLLAMA_MODEL", ""),
        )
    return ClaudeEngine()


def _setup_scan_safety_env(gs: Any) -> None:
    """Outbound pacing for the engine.

    0 or unset keeps the previous unthrottled behaviour; a positive value caps
    browser navigations and network-bound shell tools at that many per second.
    """
    rps = getattr(gs, "scan_max_rps", None) if gs else None
    if rps and rps > 0:
        os.environ["SCAN_MAX_RPS"] = str(rps)
    else:
        os.environ.pop("SCAN_MAX_RPS", None)


def _setup_llm_env(scan: Scan, gs: Any) -> dict | None:
    """Set the env vars the LLM engine reads, and return the resolved OpenAI-compatible
    config (api_key/base_url/model/…) when the active provider funnels through
    OpenAIEngine. The web backend passes that config explicitly into the engine so
    concurrent scans on different providers never read each other's OPENAI_* values
    out of the shared process environment. Returns None for anthropic/ollama."""
    from backend.services.crypto import decrypt_value
    provider = scan.llm_provider
    oai_cfg: dict | None = None
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
        os.environ["ANTHROPIC_TEMPERATURE"] = str(gs.anthropic_temperature if gs.anthropic_temperature is not None else 0.7)
        if gs.anthropic_top_p is not None:
            os.environ["ANTHROPIC_TOP_P"] = str(gs.anthropic_top_p)
        else:
            os.environ.pop("ANTHROPIC_TOP_P", None)
    elif provider == "openai" and gs and gs.openai_api_key_enc:
        _key = decrypt_value(gs.openai_api_key_enc)
        os.environ["OPENAI_API_KEY"] = _key
        os.environ["LLM_PROVIDER"] = "openai"
        # Per-scan choice wins, otherwise the Settings default. Previously only the
        # per-scan value was honoured, so the "Default Model" saved in Settings was
        # silently ignored and the engine fell back to its own hardcoded gpt-4o.
        _model = scan.llm_model or gs.openai_default_model
        if _model:
            os.environ["OPENAI_MODEL"] = _model
        else:
            os.environ.pop("OPENAI_MODEL", None)
        if gs.openai_base_url:
            _oai_url = gs.openai_base_url.rstrip("/")
            if not _oai_url.endswith("/v1"):
                _oai_url += "/v1"
            os.environ["OPENAI_BASE_URL"] = _oai_url
        else:
            os.environ.pop("OPENAI_BASE_URL", None)
        os.environ["OPENAI_MAX_TOKENS"] = str(gs.openai_max_tokens or 4096)
        os.environ["OPENAI_TEMPERATURE"] = str(gs.openai_temperature if gs.openai_temperature is not None else 0.7)
        if gs.openai_top_p is not None:
            os.environ["OPENAI_TOP_P"] = str(gs.openai_top_p)
        else:
            os.environ.pop("OPENAI_TOP_P", None)
        os.environ["OPENAI_FREQUENCY_PENALTY"] = str(gs.openai_frequency_penalty if gs.openai_frequency_penalty is not None else 0.0)
        os.environ["OPENAI_PRESENCE_PENALTY"] = str(gs.openai_presence_penalty if gs.openai_presence_penalty is not None else 0.0)
        oai_cfg = {
            "api_key": _key,
            "base_url": gs.openai_base_url or None,
            "model": _model or None,
            "max_tokens": gs.openai_max_tokens or 4096,
            "temperature": gs.openai_temperature if gs.openai_temperature is not None else 0.7,
            "top_p": gs.openai_top_p,
            "frequency_penalty": gs.openai_frequency_penalty if gs.openai_frequency_penalty is not None else 0.0,
            "presence_penalty": gs.openai_presence_penalty if gs.openai_presence_penalty is not None else 0.0,
        }
    elif provider == "openrouter" and gs and gs.openrouter_api_key_enc:
        _key = decrypt_value(gs.openrouter_api_key_enc)
        os.environ["OPENAI_API_KEY"] = _key
        os.environ["LLM_PROVIDER"] = "openai"
        os.environ["OPENAI_BASE_URL"] = gs.openrouter_base_url or "https://openrouter.ai/api/v1"
        model = scan.llm_model or gs.openrouter_default_model or "anthropic/claude-sonnet-5"
        os.environ["OPENAI_MODEL"] = model
        os.environ["OPENAI_MAX_TOKENS"] = str(gs.openrouter_max_tokens or 4096)
        os.environ["OPENAI_TEMPERATURE"] = str(gs.openrouter_temperature if gs.openrouter_temperature is not None else 0.7)
        if gs.openrouter_top_p is not None:
            os.environ["OPENAI_TOP_P"] = str(gs.openrouter_top_p)
        else:
            os.environ.pop("OPENAI_TOP_P", None)
        os.environ.pop("OPENAI_FREQUENCY_PENALTY", None)
        os.environ.pop("OPENAI_PRESENCE_PENALTY", None)
        oai_cfg = {
            "api_key": _key,
            "base_url": gs.openrouter_base_url or "https://openrouter.ai/api/v1",
            "model": model,
            "max_tokens": gs.openrouter_max_tokens or 4096,
            "temperature": gs.openrouter_temperature if gs.openrouter_temperature is not None else 0.7,
            "top_p": gs.openrouter_top_p,
        }
    elif provider in _OAI_COMPAT_DEFAULTS and gs and getattr(gs, f"{provider}_api_key_enc", None):
        # Mistral / Groq / xAI / DeepSeek / Kimi — all OpenAI-compatible, so they
        # funnel through OpenAIEngine via the shared OPENAI_* env vars. The engine
        # normalises the base URL (appends /v1 if missing), so pass it through raw.
        _key = decrypt_value(getattr(gs, f"{provider}_api_key_enc"))
        os.environ["OPENAI_API_KEY"] = _key
        os.environ["LLM_PROVIDER"] = "openai"
        _base = getattr(gs, f"{provider}_base_url", None) or _OAI_COMPAT_DEFAULTS[provider]
        os.environ["OPENAI_BASE_URL"] = _base
        _model = (scan.llm_model or getattr(gs, f"{provider}_default_model", None)
                  or _OAI_COMPAT_DEFAULT_MODELS.get(provider))
        if _model:
            os.environ["OPENAI_MODEL"] = _model
        else:
            os.environ.pop("OPENAI_MODEL", None)
        os.environ["OPENAI_MAX_TOKENS"] = str(getattr(gs, f"{provider}_max_tokens", None) or 4096)
        _temp = getattr(gs, f"{provider}_temperature", None)
        os.environ["OPENAI_TEMPERATURE"] = str(_temp if _temp is not None else 0.7)
        _top_p = getattr(gs, f"{provider}_top_p", None)
        if _top_p is not None:
            os.environ["OPENAI_TOP_P"] = str(_top_p)
        else:
            os.environ.pop("OPENAI_TOP_P", None)
        os.environ.pop("OPENAI_FREQUENCY_PENALTY", None)
        os.environ.pop("OPENAI_PRESENCE_PENALTY", None)
        oai_cfg = {
            "api_key": _key,
            "base_url": _base,
            "model": _model or None,
            "max_tokens": getattr(gs, f"{provider}_max_tokens", None) or 4096,
            "temperature": _temp if _temp is not None else 0.7,
            "top_p": _top_p,
        }
    elif provider == "ollama":
        os.environ["LLM_PROVIDER"] = "ollama"
        # local  → self-hosted server, no auth
        # cloud  → ollama.com, bearer token required
        mode = (gs.ollama_mode if gs and gs.ollama_mode else "local").lower()
        os.environ["OLLAMA_MODE"] = mode
        if mode == "cloud" and gs and gs.ollama_api_key_enc:
            os.environ["OLLAMA_API_KEY"] = decrypt_value(gs.ollama_api_key_enc)
        else:
            os.environ.pop("OLLAMA_API_KEY", None)
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
        if gs and gs.ollama_top_p is not None:
            os.environ["OLLAMA_TOP_P"] = str(gs.ollama_top_p)
        else:
            os.environ.pop("OLLAMA_TOP_P", None)
        if gs and gs.ollama_top_k is not None:
            os.environ["OLLAMA_TOP_K"] = str(gs.ollama_top_k)
        else:
            os.environ.pop("OLLAMA_TOP_K", None)
        if gs and gs.ollama_repeat_penalty is not None:
            os.environ["OLLAMA_REPEAT_PENALTY"] = str(gs.ollama_repeat_penalty)
        else:
            os.environ.pop("OLLAMA_REPEAT_PENALTY", None)

    return oai_cfg
