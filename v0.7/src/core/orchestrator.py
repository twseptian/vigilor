"""
orchestrator.py — 5-phase pentest pipeline with feedback loop and observability.

Improvements over the linear v0.4 pipeline:

  1. Feedback loop (max 2 iterations after Phase 3):
       ExploitAgent publishes NEW_ENDPOINT / PATTERN_FOUND / AUTH_BYPASS events
       onto workspace.events.  After Phase 3 the orchestrator consumes those
       events, generates targeted hypotheses, and re-runs exploitation on the
       new "pending" hypotheses — creating an adaptive, iterative loop.

  2. Inter-agent communication via EventBus:
       Events flow through workspace.events.  Any agent can publish; the
       orchestrator dispatches consequences.  No agent needs direct knowledge
       of another agent's internals.

  3. Observability via ScanTracer:
       Every phase is timed.  Hypothesis stats (added/tested/confirmed/failed/
       skipped), token estimates, and all structured log entries are written to
       reports/<hostname>/trace_<id>.json after the scan completes.

  4. Parallel exploit dispatch via ExploitDispatcher:
       Hypotheses are grouped by attack category (injection, xss, traversal,
       auth, access_control, ssrf_upload, info, misc) and run concurrently —
       each category gets its own ExploitAgent instance and Playwright browser.
       Bounded by a configurable semaphore (default: 3 parallel categories).
"""
from __future__ import annotations

import re as _re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from src.core.workspace import WorkspaceManager
from src.core.event_bus import EventBus
import src.core.cli_ui as ui


class PentestOrchestrator:
    def __init__(
        self,
        target_url: str = "",
        repo_path: str = "",
        source_path: str = "",
        headers: Dict[str, str] = None,
        cookies: Dict[str, str] = None,
        scope_include: List[str] = None,
        scope_exclude: List[str] = None,
        static_only: bool = False,
        max_parallel_exploits: int = 3,
        max_feedback_iterations: int = 2,
    ):
        self.static_only              = static_only
        self.max_parallel_exploits    = max_parallel_exploits
        self.max_feedback_iterations  = max_feedback_iterations

        self.workspace = WorkspaceManager(
            target_url=target_url,
            repo_path=repo_path,
            source_path=source_path,
            headers=headers,
            cookies=cookies,
            scope_include=scope_include,
            scope_exclude=scope_exclude,
            static_only=static_only,
        )
        self.agents: Dict[str, Any] = {}

    def register_agent(self, phase: str, agent: Any) -> None:
        self.agents[phase] = agent

    # ── Main pipeline ─────────────────────────────────────────────────────

    async def run_pipeline(self) -> None:
        ws  = self.workspace
        tr  = ws.tracer

        import time as _time
        import os as _os
        _pipeline_start = _time.monotonic()

        # ── Cross-scan memory: register scan start ────────────────────────
        if not self.static_only and ws.target_url:
            ws.memory.start_scan(ws.target_url)

        # ─────────────────────────────────────────────────────────────────
        # Phase 1 — Reconnaissance
        # ─────────────────────────────────────────────────────────────────
        if not self.static_only:
            ui.phase_start("recon")
            tr.phase_start("recon")
            if "recon" in self.agents:
                await self.agents["recon"].execute(ws)
            _links = len(ws.recon_data.get("structured", {}).get("links_found", []))
            tr.phase_end("recon", links=_links)
            ui.phase_end("recon", endpoints_found=_links)

        # ─────────────────────────────────────────────────────────────────
        # Phase 1.5 — Static Source Code Analysis
        # ─────────────────────────────────────────────────────────────────
        ui.phase_start("static_analysis")
        tr.phase_start("static_analysis")
        if "static_analysis" in self.agents:
            await self.agents["static_analysis"].execute(ws)
        tr.phase_end("static_analysis", hypotheses=len(ws.hypotheses))
        ui.phase_end("static_analysis", hypotheses_added=len(ws.hypotheses))

        if not self.static_only:
            # ─────────────────────────────────────────────────────────────
            # Phase 2 — Vulnerability Analysis
            # ─────────────────────────────────────────────────────────────
            ui.phase_start("vuln")
            tr.phase_start("vuln")
            if "vuln" in self.agents:
                await self.agents["vuln"].execute(ws)
            for h in ws.hypotheses:
                tr.record_hypothesis("added", h.get("type", ""), h.get("location", ""))
            tr.phase_end("vuln", hypotheses=len(ws.hypotheses))
            ui.phase_end("vuln", hypotheses_generated=len(ws.hypotheses))

            # ─────────────────────────────────────────────────────────────
            # Phase 3 — Exploitation  (parallel dispatch)
            # ─────────────────────────────────────────────────────────────
            ui.phase_start("exploit")
            tr.phase_start("exploit")
            await self._run_exploit(ws)
            _confirmed = len([f for f in ws.findings if not f.get("potential")])
            _potential = len([f for f in ws.findings if f.get("potential")])
            tr.phase_end("exploit", confirmed=_confirmed, total=len(ws.hypotheses))
            ui.phase_end(
                "exploit",
                confirmed=_confirmed,
                potential=_potential,
                tested=len(ws.hypotheses),
            )

            # ─────────────────────────────────────────────────────────────
            # Feedback Loop — up to max_feedback_iterations adaptive cycles
            # ─────────────────────────────────────────────────────────────
            for _fb_iter in range(self.max_feedback_iterations):
                new_hypos_added = await self._process_feedback(ws, _fb_iter + 1)
                if not new_hypos_added:
                    break
                ws.tracer.feedback_iterations += 1
                ui.feedback_loop(_fb_iter + 1, new_hypos_added)
                tr.phase_start(f"exploit:feedback_{_fb_iter + 1}")
                await self._run_exploit(ws)
                tr.phase_end(
                    f"exploit:feedback_{_fb_iter + 1}",
                    new_hypos=new_hypos_added,
                )

        # ─────────────────────────────────────────────────────────────────
        # Pre-report — Deduplicate findings
        # ─────────────────────────────────────────────────────────────────
        if not self.static_only:
            self._deduplicate_findings(ws)

        # ─────────────────────────────────────────────────────────────────
        # Phase 4 — Reporting
        # ─────────────────────────────────────────────────────────────────
        ui.phase_start("report")
        tr.phase_start("report")
        if "report" in self.agents:
            await self.agents["report"].execute(ws)
        tr.phase_end("report", findings=len(ws.findings))
        ui.phase_end("report", findings_reported=len(ws.findings))

        # ── Cross-scan memory: register scan end ──────────────────────────
        if not self.static_only and ws.target_url:
            ws.memory.end_scan(
                findings_count=len(ws.findings),
                hypotheses_count=len(ws.hypotheses),
            )
            trend = ws.memory.trend_summary()
            if trend:
                ui.info(f"Memory  ·  {trend}")

        # ── Observability: save trace ─────────────────────────────────────
        _out_base = ws.repo_path or "."
        _report_path = ""
        try:
            _host = urlparse(ws.target_url).netloc.replace(":", "_") or "static"
            _trace_dir = _os.path.join(_out_base, "reports", _host)
            tr.save(_trace_dir)
            # Find newest report file
            import glob as _glob
            _docx = sorted(
                _glob.glob(_os.path.join(_trace_dir, "pentest_report_*.docx")),
                key=_os.path.getmtime, reverse=True,
            )
            if _docx:
                _report_path = _docx[0]
        except Exception:
            pass

        # ── Final summary ─────────────────────────────────────────────────
        _total_elapsed = _time.monotonic() - _pipeline_start
        ui.print_summary(
            target_url=ws.target_url,
            findings=ws.findings,
            hypotheses=ws.hypotheses,
            report_path=_report_path,
            total_elapsed=_total_elapsed,
            feedback_iterations=ws.tracer.feedback_iterations,
            event_summary=ws.events.summary() if not self.static_only else "",
        )

    # ── Pre-report deduplication ──────────────────────────────────────────

    @staticmethod
    def _deduplicate_findings(ws: WorkspaceManager) -> None:
        """Remove duplicate findings from workspace.findings before reporting.

        Two findings are considered duplicates when they share the same
        normalised vulnerability type AND the same normalised location
        (URL path, ignoring scheme/host differences and trailing slashes).

        When duplicates are found the one with the strongest evidence is kept:
          - Screenshot present > no screenshot
          - Longer proof text  > shorter proof text
        """
        from urllib.parse import urlparse as _urlparse

        def _norm_type(t: str) -> str:
            return _re.sub(r"[^a-z0-9]", "", t.lower())

        def _norm_loc(loc: str) -> str:
            try:
                p = _urlparse(loc)
                # Normalise to path only, lowercase, strip trailing slash
                path = p.path.lower().rstrip("/") or "/"
                # Include query string only for findings that are param-specific
                qs = ("?" + p.query) if p.query else ""
                return path + qs
            except Exception:
                return loc.lower().rstrip("/")

        def _evidence_score(raw: dict) -> int:
            score = 0
            if raw.get("screenshot_path") and _re.search(r"\.(png|jpg|jpeg)$",
                                                           raw["screenshot_path"], _re.I):
                score += 10
            score += min(len(raw.get("proof", "")), 500)
            return score

        def _extract_payload(proof: str) -> str:
            """Extract the first quoted payload from a proof string, e.g. "Payload 'X'"."""
            m = _re.search(r"[Pp]ayload ['\"](.+?)['\"]", proof)
            return m.group(1).strip()[:80] if m else ""

        def _proof_sig(raw: dict) -> str:
            """Return a normalised signature of the proof for similarity dedup.

            Only returns a non-empty sig when an explicit injected payload is
            present in the proof text.  We intentionally do NOT fall back to a
            normalised substring of the proof because header/informational findings
            all share a common long preamble that makes the first 120 chars
            identical across distinct findings at the same location, causing
            valid unique findings to be incorrectly merged.
            """
            proof = raw.get("proof", "")
            payload = _extract_payload(proof)
            return payload if payload else ""

        seen: dict = {}   # key → index of best finding kept so far
        keep: list = []

        for raw in ws.findings:
            hypo = raw.get("hypothesis", {})
            loc_key = _norm_loc(hypo.get("location", ""))
            type_key = _norm_type(hypo.get("type", ""))
            # Primary key: normalised type + location (exact duplicate)
            key = (type_key, loc_key)

            # Secondary key: same location + same proof signature (same payload/evidence,
            # different type names — e.g. "Auth Bypass / SQLi" vs "Auth Bypass / Brute Force")
            proof_key = (loc_key, _proof_sig(raw))

            # Check both keys
            matched_key = None
            if key in seen:
                matched_key = key
            elif proof_key[1] and proof_key in seen:
                matched_key = proof_key

            if matched_key is None:
                seen[key] = len(keep)
                if proof_key[1]:
                    seen[proof_key] = len(keep)
                keep.append(raw)
            else:
                existing_idx = seen[matched_key]
                existing     = keep[existing_idx]
                if _evidence_score(raw) > _evidence_score(existing):
                    keep[existing_idx] = raw
                    # Update proof_key mapping too
                    if proof_key[1] and proof_key not in seen:
                        seen[proof_key] = existing_idx
                print(
                    f"[Dedup] Removed duplicate: [{hypo.get('type', '')}] "
                    f"at {hypo.get('location', '')} — keeping strongest evidence."
                )

        removed = len(ws.findings) - len(keep)
        if removed:
            print(f"[Dedup] {removed} duplicate finding(s) removed. "
                  f"{len(keep)} unique finding(s) remain.")
        else:
            print("[Dedup] No duplicate findings detected.")

        ws.findings = keep

    # ── Exploit runner (wraps dispatcher) ────────────────────────────────

    async def _run_exploit(self, ws: WorkspaceManager) -> None:
        """Run exploitation using ExploitDispatcher for parallel categories."""
        from src.agents.exploit_dispatcher import ExploitDispatcher
        if "exploit" in self.agents:
            # Use dispatcher for parallel category execution.
            # The registered agent's engine is reused for all sub-agents.
            engine = self.agents["exploit"].engine
            dispatcher = ExploitDispatcher(engine, max_parallel=self.max_parallel_exploits)
            await dispatcher.execute(ws)

    # ── Feedback loop ─────────────────────────────────────────────────────

    async def _process_feedback(self, ws: WorkspaceManager, iteration: int) -> int:
        """Consume events published by ExploitAgent and generate new hypotheses.

        Returns the number of new hypotheses added (0 = no further iteration needed).
        """
        new_endpoint_events = ws.events.consume(EventBus.NEW_ENDPOINT)
        pattern_events      = ws.events.consume(EventBus.PATTERN_FOUND)
        auth_events         = ws.events.consume(EventBus.AUTH_BYPASS)

        if not new_endpoint_events and not pattern_events and not auth_events:
            return 0

        print(
            f"[Feedback iter {iteration}] "
            f"{len(new_endpoint_events)} new endpoint(s), "
            f"{len(pattern_events)} pattern(s), "
            f"{len(auth_events)} auth bypass signal(s)."
        )
        ws.tracer.log(
            "INFO", "feedback",
            f"Iteration {iteration}: processing {len(new_endpoint_events)} endpoints, "
            f"{len(pattern_events)} patterns, {len(auth_events)} auth events",
        )

        hypotheses_before = len(ws.hypotheses)

        # ── 1. New endpoints → structural hypothesis injection ────────────
        seen_eps = {h.get("location", "") for h in ws.hypotheses}
        for ev in new_endpoint_events:
            ep_url = ev["payload"].get("url", "")
            if not ep_url or ep_url in seen_eps or not ws.in_scope(ep_url):
                continue
            seen_eps.add(ep_url)
            # Simple path-based heuristic (same logic as VulnAgent PATH_KEYWORD_MAP)
            _path = urlparse(ep_url).path.lower()
            vuln_type, sev, score, vector = self._infer_vuln_from_path(_path)
            ws.add_hypothesis(
                vuln_type,
                f"[Feedback loop] Newly discovered endpoint during exploitation: {ep_url}. "
                f"Probe for {vuln_type}.",
                ep_url,
                cvss_score=score,
                cvss_vector=vector,
                severity=sev,
            )
            print(f"[Feedback] Added hypothesis [{vuln_type}] for new endpoint: {ep_url}")

        # ── 2. Pattern events → sibling-endpoint hypotheses ────────────────
        for ev in pattern_events:
            prefix  = ev["payload"].get("affected_prefix", "")
            pattern = ev["payload"].get("pattern", "")
            conf_url = ev["payload"].get("confirmed_url", "")
            if not prefix:
                continue
            # Add hypotheses for sibling paths not yet tested
            for known_ep in list(ws.memory.get_known_endpoints()):
                if not known_ep.startswith(prefix) or known_ep == conf_url:
                    continue
                if any(h.get("location") == known_ep for h in ws.hypotheses):
                    continue
                if not ws.in_scope(known_ep):
                    continue
                ws.add_hypothesis(
                    pattern.title(),
                    f"[Feedback loop] Pattern '{pattern}' confirmed at {conf_url}. "
                    f"Sibling endpoint {known_ep} may share the same vulnerability.",
                    known_ep,
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    severity="High",
                )
                print(f"[Feedback] Pattern '{pattern}' → added sibling hypothesis: {known_ep}")

        # ── 3. Auth bypass → IDOR chain hypotheses ─────────────────────────
        for ev in auth_events:
            bypass_url = ev["payload"].get("url", "")
            if not bypass_url:
                continue
            _host = urlparse(bypass_url).netloc
            # Look for user/profile/account endpoints in known_endpoints
            for known_ep in list(ws.memory.get_known_endpoints()):
                if urlparse(known_ep).netloc != _host:
                    continue
                _ep_path = urlparse(known_ep).path.lower()
                if not any(kw in _ep_path for kw in ["/user", "/profile", "/account", "/api/", "/admin"]):
                    continue
                if any(h.get("location") == known_ep for h in ws.hypotheses):
                    continue
                ws.add_hypothesis(
                    "IDOR / Privilege Escalation",
                    f"[Feedback loop] Auth bypass confirmed at {bypass_url}. "
                    f"Authenticated endpoint {known_ep} may be accessible without proper authorisation.",
                    known_ep,
                    cvss_score=8.1,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    severity="High",
                )
                print(f"[Feedback] Auth bypass chain → added IDOR hypothesis: {known_ep}")

        new_count = len(ws.hypotheses) - hypotheses_before
        return new_count

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _infer_vuln_from_path(path: str):
        """Return (vuln_type, severity, cvss_score, cvss_vector) from a URL path."""
        _MAP = [
            (r"admin|panel|manage|dashboard|staff",
             "Broken Access Control",              "Critical", 9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            (r"upload|attach|import",
             "Unrestricted File Upload",            "Critical", 9.0, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"),
            (r"sql|query|db|database",
             "SQL Injection",                       "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            (r"exec|cmd|shell|command|run",
             "Command Injection / RCE",             "Critical", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            (r"redirect|goto|return|next|forward",
             "Open Redirect / SSRF",                "Medium",   6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"),
            (r"search|find|query|filter",
             "XSS / SQL Injection via Search",      "High",     7.2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
            (r"api|v1|v2|v3|graphql",
             "API Security (IDOR / Injection)",     "High",     8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            (r"download|export|file|image|static",
             "Path Traversal",                      "High",     7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
        ]
        for pattern, vuln_type, sev, score, vector in _MAP:
            if _re.search(pattern, path, _re.IGNORECASE):
                return vuln_type, sev, score, vector
        return "Information Disclosure", "Low", 3.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
