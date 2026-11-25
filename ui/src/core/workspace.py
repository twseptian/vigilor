import re as _re
from typing import Dict, Any, List

# URLs that terminate the session. Visiting one of these during a crawl is how an
# authenticated scan silently turns into an anonymous one: the crawler follows
# "Logout" early on, and every protected area explored afterwards looks empty —
# producing a clean-looking report for entirely the wrong reason.
#
# The pattern errs towards over-blocking: "/logout-history" is skipped along with
# "/logout-all". That asymmetry is deliberate — a skipped URL is recorded and
# reported (so it can be re-tested on purpose), whereas a destroyed session is
# silent and invalidates everything after it.
_SESSION_DESTROYING_RE = _re.compile(
    r"(?:^|[/_\-?&=])"
    r"(?:log[\-_]?out|sign[\-_]?out|log[\-_]?off|sign[\-_]?off"
    r"|end[\-_]?session|destroy[\-_]?session|revoke[\-_]?session|deconnexion)"
    r"(?:$|[/_\-?&=.])",
    _re.IGNORECASE,
)


class WorkspaceManager:
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
    ):
        self.target_url = target_url
        self.static_only = static_only
        # source_path is the directory scanned by StaticAnalysisAgent.
        # Falls back to repo_path if not explicitly set.
        self.source_path = source_path or repo_path
        self.repo_path = repo_path
        self.headers = headers or {}
        self.cookies = cookies or {}

        # ── Scope rules (Feature: configurable scope) ─────────────────────────
        # scope_include: if non-empty, URL must match at least one pattern
        # scope_exclude: if non-empty, URL must NOT match any pattern
        self._scope_include = [
            _re.compile(p, _re.IGNORECASE) for p in (scope_include or [])
        ]
        self._scope_exclude = [
            _re.compile(p, _re.IGNORECASE) for p in (scope_exclude or [])
        ]

        # ── Session guard ─────────────────────────────────────────────────────
        # Set OFF only when the logout flow itself is the thing under test.
        import os as _os_sg
        self.allow_session_destroying: bool = (
            _os_sg.environ.get("ALLOW_SESSION_DESTROYING", "").lower() in ("1", "true", "yes")
        )
        self.session_guard_skipped: List[str] = []

        # ── Shared agent state ────────────────────────────────────────────────
        self.recon_data: Dict[str, Any] = {}
        self.hypotheses: List[dict] = []
        self.exploits: List[dict] = []
        self.findings: List[dict] = []

        # ── Multi-page context (Feature: chained attacks) ──────────────────────
        # Keyed by page URL; each value is a dict with forms, params, links,
        # title, has_file_upload, has_admin_path, auth_indicators.
        self.page_contexts: Dict[str, dict] = {}

        # ── Payload corpus (Feature: payload learning) ─────────────────────────
        import os as _os
        from src.core.corpus import PayloadCorpus
        _base_dir = repo_path or "."
        self.corpus = PayloadCorpus(path=_os.path.join(_base_dir, "corpus.json"))

        # ── Cross-scan memory (Feature: long-term efficiency) ──────────────────
        from src.core.memory import ScanMemory
        self.memory = ScanMemory(path=_os.path.join(_base_dir, "memory.json"))

        # ── Inter-agent event bus (Feature: feedback loop & communication) ────
        from src.core.event_bus import EventBus
        self.events = EventBus()

        # ── Scan tracer (Feature: observability) ──────────────────────────────
        from src.core.tracer import ScanTracer
        self.tracer = ScanTracer(target_url=target_url)

    # ── Scope filtering ───────────────────────────────────────────────────────

    def in_scope(self, url: str) -> bool:
        """Return True if *url* passes all configured scope rules.

        Rules:
        - Session-destroying URLs (logout, end-session, …) are never in scope,
          unless ALLOW_SESSION_DESTROYING is set. Skips are recorded so they can
          be reported rather than silently dropped.
        - If scope_exclude patterns are set, the URL must not match any of them.
        - If scope_include patterns are set, the URL must match at least one.
        - If neither is set, all URLs are in scope (default-permit).
        """
        if not self.allow_session_destroying and _SESSION_DESTROYING_RE.search(url):
            if url not in self.session_guard_skipped:
                self.session_guard_skipped.append(url)
            return False
        if self._scope_exclude:
            if any(p.search(url) for p in self._scope_exclude):
                return False
        if self._scope_include:
            return any(p.search(url) for p in self._scope_include)
        return True

    # ── Recon data ────────────────────────────────────────────────────────────

    def add_recon_data(self, key: str, data: Any) -> None:
        """Store reconnaissance data (endpoints, tech stack, headers, etc.)."""
        self.recon_data[key] = data

    def get_recon_data(self, key: str) -> Any:
        return self.recon_data.get(key)

    # ── Multi-page context ────────────────────────────────────────────────────

    def add_page_context(self, url: str, context: dict) -> None:
        """Store per-page recon context for cross-page chain analysis.

        Expected keys in *context*:
            title           str
            forms           list[dict]   (action, method, inputs)
            params          list[str]    (query param names)
            links           list[str]    (same-origin links on this page)
            has_file_upload bool
            has_admin_path  bool
            auth_indicators list[str]
        """
        self.page_contexts[url] = context

    def get_page_contexts(self) -> Dict[str, dict]:
        """Return the full {url: context} mapping."""
        return self.page_contexts

    # ── Hypotheses ────────────────────────────────────────────────────────────

    @staticmethod
    def _hypo_key(vuln_type: str, location: str) -> tuple:
        """Canonical dedup key: (normalised_type, url_path_without_query)."""
        try:
            from urllib.parse import urlparse
            path = urlparse(location).path.rstrip("/") or "/"
        except Exception:
            path = location
        ntype = _re.sub(r"[\s\-/]+", "_", vuln_type.lower().strip())
        return (ntype, path)

    def add_hypothesis(
        self,
        vuln_type: str,
        details: str,
        location: str,
        cvss_score: float = 0.0,
        cvss_vector: str = "",
        severity: str = "Informational",
    ) -> bool:
        """Add a hypothesis. Returns False (and skips) if an identical
        (type, path) pair was already registered — prevents duplicate exploit runs."""
        key = self._hypo_key(vuln_type, location)
        if not hasattr(self, "_hypo_seen"):
            self._hypo_seen: set = set()
        if key in self._hypo_seen:
            return False
        self._hypo_seen.add(key)
        self.hypotheses.append(
            {
                "type": vuln_type,
                "details": details,
                "location": location,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity": severity,
                "status": "pending",
            }
        )
        return True

    # ── Exploit results ───────────────────────────────────────────────────────

    def add_potential_result(
        self,
        hypothesis_index: int,
        proof: str,
        screenshot_path: str = None,
    ) -> None:
        """Record a finding with partial/ambiguous evidence as 'Potential <VulnType>'.

        The finding is added to workspace.findings (so it appears in the report)
        with ``is_potential=True``.  The hypothesis status is set to ``"potential"``
        so it will not be re-tested in subsequent feedback-loop passes.
        """
        if 0 <= hypothesis_index < len(self.hypotheses):
            hypo = self.hypotheses[hypothesis_index]
            hypo["status"] = "potential"
            if not hypo["type"].startswith("Potential "):
                hypo["type"] = f"Potential {hypo['type']}"
            self.findings.append(
                {
                    "hypothesis": hypo,
                    "proof": proof,
                    "screenshot_path": screenshot_path,
                    "is_potential": True,
                }
            )

    def add_auto_finding(
        self,
        vuln_type: str,
        details: str,
        location: str,
        severity: str = "Informational",
        cvss_score: float = 0.0,
        cvss_vector: str = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    ) -> None:
        """Add a confirmed finding that does NOT go through the exploit pipeline.
        Used for header misconfigurations and other passively-detectable issues
        so they don't consume LLM hypothesis slots."""
        self.findings.append({
            "hypothesis": {
                "type": vuln_type,
                "details": details,
                "location": location,
                "severity": severity,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "status": "confirmed",
            },
            "proof": f"Auto-confirmed: passively detected from HTTP response headers/cookies.",
        })

    def promote_hypotheses_to_findings(self, skip_url_locations: bool = False) -> int:
        """Convert every hypothesis into a finding without an exploitation step.

        Used by source-code-review scans: there is no live target to confirm
        against, so the static (regex) + AI hypotheses ARE the findings — reported
        as identified-from-source. Skips hypotheses already present in findings.

        skip_url_locations: drop hypotheses whose location is an http(s) URL. For a
        source review these are the AI agent's live-endpoint guesses (it had no
        recon data), which are noise — the real findings carry file:line locations."""
        existing = {
            (f.get("hypothesis", {}).get("type", ""),
             f.get("hypothesis", {}).get("location", ""))
            for f in self.findings
        }
        promoted = 0
        for hypo in self.hypotheses:
            loc = (hypo.get("location", "") or "")
            if skip_url_locations and loc.lower().startswith(("http://", "https://")):
                continue
            key = (hypo.get("type", ""), loc)
            if key in existing:
                continue
            hypo.setdefault("status", "potential")
            self.findings.append({
                "hypothesis": hypo,
                "proof": ("Identified by source code review (static pattern + AI "
                          "analysis). Not runtime-confirmed — review the source location."),
                "is_potential": True,
            })
            existing.add(key)
            promoted += 1
        return promoted

    def add_exploit_result(
        self,
        hypothesis_index: int,
        success: bool,
        proof: str,
        screenshot_path: str = None,
    ) -> None:
        if 0 <= hypothesis_index < len(self.hypotheses):
            self.hypotheses[hypothesis_index]["status"] = (
                "exploited" if success else "failed"
            )
            if success:
                self.findings.append(
                    {
                        "hypothesis": self.hypotheses[hypothesis_index],
                        "proof": proof,
                        "screenshot_path": screenshot_path,
                    }
                )
