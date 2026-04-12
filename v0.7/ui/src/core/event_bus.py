"""
event_bus.py — In-process event bus for inter-agent communication.

Agents publish typed events; the orchestrator and downstream agents
consume them to enable feedback loops and cross-phase signalling.

Event flow examples:
  ExploitAgent    → NEW_ENDPOINT        → Orchestrator triggers targeted Vuln+Exploit
  ExploitAgent    → PATTERN_FOUND       → VulnAgent generates additional hypotheses
  ExploitAgent    → AUTH_BYPASS         → Orchestrator triggers IDOR chain testing
  ExploitAgent    → HIGH_VALUE_PATH     → Orchestrator prioritises the discovered path
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional


class EventBus:
    """Lightweight publish/consume event bus with typed events."""

    # ── Event type constants ────────────────────────────────────────────────
    NEW_ENDPOINT     = "new_endpoint_discovered"
    PATTERN_FOUND    = "vulnerability_pattern_found"
    AUTH_BYPASS      = "auth_bypass_confirmed"
    HIGH_VALUE_PATH  = "high_value_path"
    PHASE_COMPLETE   = "phase_complete"

    def __init__(self) -> None:
        self._events: List[dict] = []

    # ── Publishing ──────────────────────────────────────────────────────────

    def publish(
        self,
        event_type: str,
        source: str,
        payload: Dict[str, Any],
    ) -> str:
        """Publish an event.  Returns the unique event ID."""
        event_id = str(uuid.uuid4())[:8]
        self._events.append(
            {
                "id":        event_id,
                "type":      event_type,
                "source":    source,
                "payload":   payload,
                "timestamp": int(time.time()),
                "consumed":  False,
            }
        )
        print(f"[EventBus] Published [{event_type}] from {source}: {str(payload)[:120]}")
        return event_id

    # ── Consuming ───────────────────────────────────────────────────────────

    def consume(self, event_type: Optional[str] = None) -> List[dict]:
        """Return and mark-as-consumed all events matching *event_type*.

        If *event_type* is None, returns all unconsumed events.
        """
        results = []
        for ev in self._events:
            if ev["consumed"]:
                continue
            if event_type is None or ev["type"] == event_type:
                ev["consumed"] = True
                results.append(ev)
        return results

    def peek(self, event_type: Optional[str] = None) -> List[dict]:
        """Return events without consuming them."""
        return [
            ev for ev in self._events
            if not ev["consumed"] and (event_type is None or ev["type"] == event_type)
        ]

    # ── Introspection ───────────────────────────────────────────────────────

    def pending_count(self, event_type: Optional[str] = None) -> int:
        return len(self.peek(event_type))

    def all_events(self) -> List[dict]:
        return list(self._events)

    def summary(self) -> str:
        total   = len(self._events)
        pending = sum(1 for e in self._events if not e["consumed"])
        by_type: Dict[str, int] = {}
        for ev in self._events:
            by_type[ev["type"]] = by_type.get(ev["type"], 0) + 1
        type_str = ", ".join(f"{t}×{c}" for t, c in sorted(by_type.items()))
        return f"{total} event(s) total, {pending} pending | {type_str or 'none'}"
