"""
Payload corpus — learns from previous scan results.

Persists to <repo_path>/corpus.json (same directory as the application).  Tracks successful payloads
per vulnerability type so future scans try proven payloads first.
On each scan, get_candidates() returns payloads sorted by historical
success count (with fuzzy URL-path and param-name bonuses).
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse


_DEFAULT_CORPUS_PATH = Path.home() / ".pentest-ai-agent" / "corpus.json"


class PayloadCorpus:
    """Persistent cross-scan payload success tracker.

    Entry shape inside corpus[vuln_type]:
        {
            payload:       str,
            url_pattern:   str,   # full URL of the successful probe
            param:         str,   # parameter name that accepted the payload
            success_count: int,
            last_used:     int,   # unix timestamp
        }
    """

    def __init__(self, path: Optional[str] = None):
        self._path = Path(path) if path else _DEFAULT_CORPUS_PATH
        self._data: Dict[str, List[dict]] = {}
        self._load()

    # ── public API ────────────────────────────────────────────────────────────

    def get_candidates(
        self,
        vuln_type: str,
        url: str = "",
        param: str = "",
    ) -> List[str]:
        """Return payloads for *vuln_type* sorted by historical success.

        Scoring bonuses applied:
          +5  if stored url_pattern path appears anywhere in the current url path
          +3  if stored param matches the current param name (case-insensitive)
        """
        key = self._normalise_type(vuln_type)
        entries = self._data.get(key, [])
        if not entries:
            return []

        url_path = urlparse(url).path.lower() if url else ""
        scored: List[tuple] = []
        for e in entries:
            bonus = 0
            stored_path = urlparse(e.get("url_pattern", "")).path.lower()
            if url_path and stored_path and stored_path in url_path:
                bonus += 5
            if param and e.get("param", "").lower() == param.lower():
                bonus += 3
            scored.append((e["success_count"] + bonus, e["payload"]))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [p for _, p in scored]

    def record_success(
        self,
        vuln_type: str,
        payload: str,
        url: str = "",
        param: str = "",
    ) -> None:
        """Record a confirmed successful payload and persist to disk."""
        if not payload:
            return
        key = self._normalise_type(vuln_type)
        entries = self._data.setdefault(key, [])
        for e in entries:
            if e["payload"] == payload and e.get("url_pattern") == url:
                e["success_count"] += 1
                e["last_used"] = int(time.time())
                self._save()
                print(f"[Corpus] Updated: [{key}] '{payload[:60]}' count={e['success_count']}")
                return
        entries.append(
            {
                "payload": payload,
                "url_pattern": url,
                "param": param,
                "success_count": 1,
                "last_used": int(time.time()),
            }
        )
        self._save()
        print(f"[Corpus] Recorded new: [{key}] '{payload[:60]}'")

    def summary(self) -> str:
        total = sum(len(v) for v in self._data.values())
        return f"{total} payload(s) across {len(self._data)} vuln type(s)"

    # ── private helpers ───────────────────────────────────────────────────────

    def _load(self) -> None:
        try:
            if self._path.exists():
                raw = self._path.read_text(encoding="utf-8")
                self._data = json.loads(raw)
                print(f"[Corpus] Loaded {self.summary()} from {self._path}")
            else:
                print(f"[Corpus] No corpus file found at {self._path} — starting fresh.")
        except Exception as exc:
            print(f"[Corpus] Warning: could not load corpus ({exc}) — starting fresh.")
            self._data = {}

    def _save(self) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._path.write_text(
                json.dumps(self._data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception as exc:
            print(f"[Corpus] Warning: could not save corpus: {exc}")

    @staticmethod
    def _normalise_type(vuln_type: str) -> str:
        """Normalise vuln type to a stable dict key."""
        return re.sub(r"[^a-z0-9]", "_", vuln_type.lower()).strip("_")
