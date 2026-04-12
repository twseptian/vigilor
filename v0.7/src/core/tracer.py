"""
tracer.py — Structured observability for the pentest pipeline.

Emits a machine-readable trace file per scan so results can be
audited, replayed, and used for data-driven pipeline improvement.

Trace file location: <repo_path>/reports/<hostname>/trace_<id>.json

Metrics tracked:
  - trace_id          : UUID per scan
  - phase timings     : start/end/duration per pipeline phase
  - hypothesis stats  : added / tested / confirmed / potential / failed / skipped
  - event log         : timestamped structured log entries
  - token estimates   : rough LLM token usage per phase
  - feedback_iterations: how many feedback loop cycles ran
"""
from __future__ import annotations

import json
import os
import time
import uuid
from typing import Any, Dict, List, Optional


class ScanTracer:
    """Collects and persists structured trace data for a single scan run."""

    def __init__(self, target_url: str = "", trace_id: Optional[str] = None) -> None:
        self.trace_id     = trace_id or str(uuid.uuid4())[:12]
        self.target_url   = target_url
        self.start_time   = int(time.time())

        # Phase timings  {phase_name: {start, end, duration_s}}
        self._phases:   Dict[str, dict] = {}
        # Structured event log
        self._events:   List[dict]      = []
        # Hypothesis counters
        self._hypo_stats = {"added": 0, "tested": 0, "confirmed": 0, "potential": 0, "failed": 0, "skipped": 0}
        # Token usage per phase
        self._tokens:   Dict[str, int]  = {}
        # Feedback loop iterations ran
        self.feedback_iterations: int   = 0

    # ── Phase lifecycle ────────────────────────────────────────────────────

    def phase_start(self, phase: str) -> None:
        self._phases[phase] = {"start": int(time.time()), "end": None, "duration_s": None}
        self.log("INFO", phase, f"Phase started")

    def phase_end(self, phase: str, **extra_metrics) -> None:
        if phase in self._phases:
            end = int(time.time())
            self._phases[phase]["end"] = end
            self._phases[phase]["duration_s"] = end - self._phases[phase]["start"]
            if extra_metrics:
                self._phases[phase].update(extra_metrics)
        self.log("INFO", phase, f"Phase ended", extra_metrics or None)

    # ── Structured logging ─────────────────────────────────────────────────

    def log(
        self,
        level: str,
        phase: str,
        message: str,
        data: Optional[Any] = None,
    ) -> None:
        """Append a structured log entry."""
        self._events.append(
            {
                "ts":      int(time.time()),
                "level":   level.upper(),
                "phase":   phase,
                "msg":     message,
                "data":    data,
            }
        )

    # ── Hypothesis tracking ────────────────────────────────────────────────

    def record_hypothesis(self, action: str, hypo_type: str = "", location: str = "") -> None:
        """Track a hypothesis lifecycle event.

        *action* must be one of: added | tested | confirmed | potential | failed | skipped
        """
        if action in self._hypo_stats:
            self._hypo_stats[action] += 1
        self._events.append(
            {
                "ts":      int(time.time()),
                "level":   "HYPO",
                "phase":   "exploit",
                "msg":     f"hypothesis.{action}",
                "data":    {"type": hypo_type, "location": location},
            }
        )

    # ── Token usage ────────────────────────────────────────────────────────

    def record_tokens(self, phase: str, tokens: int) -> None:
        self._tokens[phase] = self._tokens.get(phase, 0) + tokens

    # ── Summary & persistence ──────────────────────────────────────────────

    def summary(self) -> dict:
        end = int(time.time())
        total_tokens = sum(self._tokens.values())
        return {
            "trace_id":             self.trace_id,
            "target_url":           self.target_url,
            "scan_start":           self.start_time,
            "scan_end":             end,
            "total_duration_s":     end - self.start_time,
            "phases":               self._phases,
            "hypothesis_stats":     self._hypo_stats,
            "token_usage":          self._tokens,
            "total_tokens":         total_tokens,
            "feedback_iterations":  self.feedback_iterations,
            "events_total":         len(self._events),
        }

    def print_summary(self) -> None:
        s = self.summary()
        print(f"\n{'='*60}")
        print(f"  SCAN TRACE  —  {self.trace_id}")
        print(f"{'='*60}")
        print(f"  Target   : {s['target_url']}")
        print(f"  Duration : {s['total_duration_s']}s")
        for phase, info in s["phases"].items():
            dur = info.get("duration_s", "?")
            print(f"  Phase [{phase:<14}] : {dur}s")
        hs = s["hypothesis_stats"]
        print(
            f"  Hypotheses: {hs['added']} added | "
            f"{hs['tested']} tested | "
            f"{hs['confirmed']} confirmed | "
            f"{hs['potential']} potential | "
            f"{hs['failed']} failed | "
            f"{hs['skipped']} skipped"
        )
        if s["total_tokens"]:
            print(f"  Est. tokens: {s['total_tokens']:,}")
        if s["feedback_iterations"]:
            print(f"  Feedback loops: {s['feedback_iterations']}")
        print(f"{'='*60}\n")

    def save(self, output_dir: str) -> str:
        """Save full trace JSON to *output_dir*.  Returns the file path."""
        try:
            os.makedirs(output_dir, exist_ok=True)
            path = os.path.join(output_dir, f"trace_{self.trace_id}.json")
            payload = self.summary()
            payload["event_log"] = self._events
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False, default=str)
            print(f"[Tracer] Trace saved: {path}")
            return path
        except Exception as exc:
            print(f"[Tracer] Warning: could not save trace: {exc}")
            return ""
