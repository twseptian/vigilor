"""
memory.py — Cross-scan persistent memory for the pentest agent.

Persists to <repo_path>/memory.json (same directory as the application).

What is stored per target (hostname):
  - tech_stack       : technologies detected across scans (deduplicated list)
  - known_endpoints  : all URLs discovered in previous scans
  - security_headers : header audit results from last scan
  - confirmed_vulns  : vulnerabilities confirmed exploited in past scans
  - false_positives  : hypothesis type + url + param combos that proved FP
  - scan_history     : per-scan summary records (timestamp, findings, hypotheses)

How each phase benefits:
  Phase 1  (Recon)       — known_endpoints loaded as seed hints; new endpoints are deltas
  Phase 2  (Vuln)        — hypotheses filtered against false_positive registry
  Phase 3  (Exploit)     — confirmed_vulns flagged as "previously confirmed";
                           false_positives skipped immediately
  Phase 4  (Report)      — confirmed_vulns annotated with "first confirmed" date
  Orchestrator           — start_scan() / end_scan() bookend every run
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse


_DEFAULT_MEMORY_PATH = Path.home() / ".pentest-ai-agent" / "memory.json"


class ScanMemory:
    """Persistent cross-scan knowledge base.

    Top-level structure of memory.json:
    {
      "<hostname>": {
        "first_seen":        int,          # unix timestamp
        "last_seen":         int,
        "scan_count":        int,
        "tech_stack":        [str, ...],   # deduplicated
        "known_endpoints":   [str, ...],   # all seen URLs
        "security_headers":  {str: bool},  # header name → present?
        "confirmed_vulns":   [{...}, ...],
        "false_positives":   [{...}, ...],
        "scan_history":      [{...}, ...],
      }
    }
    """

    def __init__(self, path: Optional[str] = None):
        self._path = Path(path) if path else _DEFAULT_MEMORY_PATH
        self._data: Dict[str, dict] = {}
        self._current_host: str = ""
        self._scan_start: int = 0
        self._load()

    # ── Scan lifecycle ────────────────────────────────────────────────────────

    def start_scan(self, target_url: str) -> None:
        """Call at the beginning of every pipeline run."""
        self._current_host = self._host(target_url)
        self._scan_start = int(time.time())
        if not self._current_host:
            return

        profile = self._profile()
        now = int(time.time())
        if "first_seen" not in profile:
            profile["first_seen"] = now
        profile["last_seen"] = now
        profile["scan_count"] = profile.get("scan_count", 0) + 1

        count = profile["scan_count"]
        print(
            f"[Memory] Target '{self._current_host}' — scan #{count} "
            f"({len(profile.get('known_endpoints', []))} known endpoints, "
            f"{len(profile.get('confirmed_vulns', []))} prior confirmed vulns, "
            f"{len(profile.get('potential_vulns', []))} potential findings, "
            f"{len(profile.get('false_positives', []))} known false positives)"
        )
        self._save()

    def end_scan(self, findings_count: int, hypotheses_count: int) -> None:
        """Call at the end of every pipeline run with summary stats."""
        if not self._current_host:
            return
        profile = self._profile()
        profile.setdefault("scan_history", []).append(
            {
                "timestamp": self._scan_start,
                "duration_s": int(time.time()) - self._scan_start,
                "findings": findings_count,
                "hypotheses": hypotheses_count,
            }
        )
        # Keep last 20 scan records to avoid unbounded growth
        profile["scan_history"] = profile["scan_history"][-20:]
        self._save()
        print(
            f"[Memory] Scan summary saved for '{self._current_host}' "
            f"— {findings_count} finding(s), {hypotheses_count} hypothesis(es)."
        )

    # ── Endpoint memory ───────────────────────────────────────────────────────

    def add_endpoints(self, urls: List[str]) -> List[str]:
        """Merge *urls* into known_endpoints.

        Returns the subset of *urls* that are NEW (not seen in prior scans)
        so the caller can highlight delta attack surface.
        """
        if not self._current_host:
            return urls
        profile = self._profile()
        known: List[str] = profile.setdefault("known_endpoints", [])
        known_set = set(known)
        new_urls = [u for u in urls if u not in known_set]
        if new_urls:
            known.extend(new_urls)
            self._save()
            print(f"[Memory] +{len(new_urls)} new endpoint(s) for '{self._current_host}'")
        return new_urls

    def get_known_endpoints(self, target_url: str = "") -> List[str]:
        """Return all URLs seen in previous scans for this target."""
        host = self._host(target_url) if target_url else self._current_host
        return list(self._data.get(host, {}).get("known_endpoints", []))

    # ── Technology stack memory ───────────────────────────────────────────────

    def update_tech_stack(self, techs: List[str]) -> None:
        """Merge newly detected technologies into the persistent tech stack."""
        if not self._current_host or not techs:
            return
        profile = self._profile()
        existing: List[str] = profile.setdefault("tech_stack", [])
        existing_lower = {t.lower() for t in existing}
        added = []
        for t in techs:
            if t.lower() not in existing_lower:
                existing.append(t)
                added.append(t)
        if added:
            self._save()
            print(f"[Memory] Tech stack updated for '{self._current_host}': {added}")

    def get_tech_stack(self, target_url: str = "") -> List[str]:
        """Return previously detected tech stack for this target."""
        host = self._host(target_url) if target_url else self._current_host
        return list(self._data.get(host, {}).get("tech_stack", []))

    # ── Security header memory ────────────────────────────────────────────────

    def update_security_headers(self, headers: Dict[str, bool]) -> None:
        """Persist the latest security header audit results."""
        if not self._current_host or not headers:
            return
        self._profile()["security_headers"] = headers
        self._save()

    # ── Confirmed vulnerability memory ───────────────────────────────────────

    def record_confirmed_vuln(
        self,
        vuln_type: str,
        url: str,
        param: str = "",
        payload: str = "",
        severity: str = "",
    ) -> None:
        """Persist a confirmed vulnerability so it appears in future reports."""
        if not self._current_host:
            return
        profile = self._profile()
        confirmed: List[dict] = profile.setdefault("confirmed_vulns", [])

        # Deduplicate by type + url + param
        for entry in confirmed:
            if (
                entry.get("type") == vuln_type
                and entry.get("url") == url
                and entry.get("param") == param
            ):
                entry["last_confirmed"] = int(time.time())
                entry["confirm_count"] = entry.get("confirm_count", 1) + 1
                self._save()
                return

        confirmed.append(
            {
                "type": vuln_type,
                "url": url,
                "param": param,
                "payload": payload,
                "severity": severity,
                "first_confirmed": int(time.time()),
                "last_confirmed": int(time.time()),
                "confirm_count": 1,
            }
        )
        self._save()
        print(f"[Memory] Confirmed vuln recorded: [{vuln_type}] {url} param='{param}'")

    def was_previously_confirmed(self, vuln_type: str, url: str, param: str = "") -> bool:
        """Return True if this exact finding was confirmed in a previous scan."""
        if not self._current_host:
            return False
        for entry in self._profile().get("confirmed_vulns", []):
            if (
                entry.get("type") == vuln_type
                and entry.get("url") == url
                and entry.get("param") == param
            ):
                return True
        return False

    def get_confirmed_vulns(self, target_url: str = "") -> List[dict]:
        """Return all confirmed vulnerabilities for this target."""
        host = self._host(target_url) if target_url else self._current_host
        return list(self._data.get(host, {}).get("confirmed_vulns", []))

    # ── Potential vulnerability memory ───────────────────────────────────────

    def record_potential_vuln(
        self,
        vuln_type: str,
        url: str,
        param: str = "",
        evidence: str = "",
        severity: str = "",
    ) -> None:
        """Persist a 'Potential' finding — evidence was partial, not definitive.

        On subsequent scans the exploit agent will receive a memory hint to try
        harder on this exact hypothesis.
        """
        if not self._current_host:
            return
        # Strip "Potential " prefix for canonical storage so look-ups work with
        # either the raw or prefixed type name.
        _clean_type = vuln_type.removeprefix("Potential ").strip()
        profile = self._profile()
        potentials: List[dict] = profile.setdefault("potential_vulns", [])

        for entry in potentials:
            if (
                entry.get("type") == _clean_type
                and entry.get("url") == url
                and entry.get("param") == param
            ):
                entry["last_seen"] = int(time.time())
                entry["seen_count"] = entry.get("seen_count", 1) + 1
                entry["evidence"] = evidence  # update to latest evidence
                self._save()
                return

        potentials.append(
            {
                "type": _clean_type,
                "url": url,
                "param": param,
                "evidence": evidence,
                "severity": severity,
                "first_seen": int(time.time()),
                "last_seen": int(time.time()),
                "seen_count": 1,
            }
        )
        self._save()
        print(f"[Memory] Potential vuln recorded: [{_clean_type}] {url} param='{param}'")

    def was_previously_potential(
        self, vuln_type: str, url: str, param: str = ""
    ) -> Optional[dict]:
        """Return the stored entry if this hypothesis was seen as 'Potential' before, else None."""
        if not self._current_host:
            return None
        _clean_type = vuln_type.removeprefix("Potential ").strip()
        for entry in self._profile().get("potential_vulns", []):
            if (
                entry.get("type") == _clean_type
                and entry.get("url") == url
                and entry.get("param") == param
            ):
                return entry
        return None

    def get_potential_vulns(self, target_url: str = "") -> List[dict]:
        """Return all 'Potential' findings for this target."""
        host = self._host(target_url) if target_url else self._current_host
        return list(self._data.get(host, {}).get("potential_vulns", []))

    # ── False positive registry ───────────────────────────────────────────────

    def record_false_positive(
        self, vuln_type: str, url: str, param: str = "", reason: str = ""
    ) -> None:
        """Mark a hypothesis as a false positive to skip in future scans."""
        if not self._current_host:
            return
        profile = self._profile()
        fps: List[dict] = profile.setdefault("false_positives", [])

        for entry in fps:
            if (
                entry.get("type") == vuln_type
                and entry.get("url") == url
                and entry.get("param") == param
            ):
                return  # already recorded

        fps.append(
            {
                "type": vuln_type,
                "url": url,
                "param": param,
                "reason": reason,
                "recorded_at": int(time.time()),
            }
        )
        self._save()
        print(f"[Memory] False positive recorded: [{vuln_type}] {url} param='{param}'")

    def is_false_positive(self, vuln_type: str, url: str, param: str = "") -> bool:
        """Return True if this combination is a known false positive."""
        if not self._current_host:
            return False
        for entry in self._profile().get("false_positives", []):
            if (
                entry.get("type") == vuln_type
                and entry.get("url") == url
                and entry.get("param") == param
            ):
                return True
        return False

    # ── Scan history / trend ──────────────────────────────────────────────────

    def get_scan_history(self, target_url: str = "") -> List[dict]:
        """Return the list of past scan summary records for this target."""
        host = self._host(target_url) if target_url else self._current_host
        return list(self._data.get(host, {}).get("scan_history", []))

    def trend_summary(self) -> str:
        """Return a one-line trend summary for the current target."""
        if not self._current_host:
            return ""
        history = self.get_scan_history()
        if len(history) < 2:
            return ""
        last = history[-1]
        prev = history[-2]
        delta = last["findings"] - prev["findings"]
        arrow = f"+{delta}" if delta > 0 else str(delta)
        return (
            f"Findings trend for '{self._current_host}': "
            f"{prev['findings']} → {last['findings']} ({arrow}) "
            f"over last 2 scans."
        )

    # ── Convenience ──────────────────────────────────────────────────────────

    def summary(self) -> str:
        targets = len(self._data)
        total_confirmed = sum(
            len(v.get("confirmed_vulns", [])) for v in self._data.values()
        )
        total_potential = sum(
            len(v.get("potential_vulns", [])) for v in self._data.values()
        )
        total_fps = sum(
            len(v.get("false_positives", [])) for v in self._data.values()
        )
        total_endpoints = sum(
            len(v.get("known_endpoints", [])) for v in self._data.values()
        )
        return (
            f"{targets} target(s) | "
            f"{total_endpoints} known endpoint(s) | "
            f"{total_confirmed} confirmed vuln(s) | "
            f"{total_potential} potential finding(s) | "
            f"{total_fps} false positive(s)"
        )

    # ── Private helpers ───────────────────────────────────────────────────────

    def _profile(self) -> dict:
        """Return (creating if absent) the profile dict for the current host."""
        return self._data.setdefault(self._current_host, {})

    @staticmethod
    def _host(url: str) -> str:
        """Extract normalised hostname from a URL."""
        try:
            return urlparse(url).netloc.lower().strip()
        except Exception:
            return ""

    def _load(self) -> None:
        try:
            if self._path.exists():
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
                print(f"[Memory] Loaded: {self.summary()} — from {self._path}")
            else:
                print(f"[Memory] No memory file at {self._path} — starting fresh.")
        except Exception as exc:
            print(f"[Memory] Warning: could not load memory ({exc}) — starting fresh.")
            self._data = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            print(f"[Memory] Warning: could not save memory: {exc}")
