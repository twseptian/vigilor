"""
core/throttle.py — outbound request pacing.

The exploit loop had no client-side throttle of any kind: payloads went out as
fast as the agent could issue them. Against a client's production application
that is indistinguishable from a denial-of-service attempt, and it is the kind
of thing that ends an engagement badly regardless of what the contract says.

This module provides one process-wide limiter that paces every outbound action
the engine controls: browser navigations/clicks and network-bound shell tools.

Configuration (set by the CLI or by scan_runner from the scan's settings):
    SCAN_MAX_RPS   maximum outbound actions per second. Unset or <= 0 disables
                   pacing entirely, preserving the previous behaviour.

Deliberate limitation: tools like sqlmap and ffuf drive their own request loops
internally, so only their *invocation* is paced here. Use each tool's own delay
flag when a target needs gentler treatment than that.
"""
from __future__ import annotations

import asyncio
import os
import time

# Shell tools that generate network traffic. Anything not listed here (ls, cat,
# grep on a local file) is not paced — throttling local commands would just make
# the agent slower without protecting the target.
_NETWORK_TOOLS = (
    "curl", "wget", "httpie", "http ", "nmap", "sqlmap", "nikto", "nuclei",
    "ffuf", "gobuster", "dirb", "feroxbuster", "wpscan", "whatweb", "wfuzz",
    "hydra", "medusa", "testssl", "sslscan", "amass", "subfinder", "httpx",
)


def is_network_command(command: str) -> bool:
    """True when a shell command is expected to generate outbound traffic."""
    c = (command or "").strip().lower()
    return any(c.startswith(t) or f" {t}" in c or f"|{t}" in c for t in _NETWORK_TOOLS)


class RateLimiter:
    """Minimum-interval limiter. Serialises waiters so bursts cannot slip through."""

    def __init__(self, max_rps: float | None = None):
        self._interval = 1.0 / max_rps if max_rps and max_rps > 0 else 0.0
        self._last = 0.0
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return self._interval > 0.0

    @property
    def max_rps(self) -> float:
        return (1.0 / self._interval) if self._interval else 0.0

    async def acquire(self) -> None:
        """Wait until another outbound action is allowed."""
        if not self.enabled:
            return
        async with self._lock:
            now = time.monotonic()
            wait = self._last + self._interval - now
            if wait > 0:
                await asyncio.sleep(wait)
                now = time.monotonic()
            self._last = now


_limiter: RateLimiter | None = None


def get_limiter() -> RateLimiter:
    """Process-wide limiter, built from SCAN_MAX_RPS on first use."""
    global _limiter
    if _limiter is None:
        try:
            rps = float(os.environ.get("SCAN_MAX_RPS", "") or 0)
        except ValueError:
            rps = 0.0
        _limiter = RateLimiter(rps)
    return _limiter


def reset_limiter() -> None:
    """Drop the cached limiter so a new SCAN_MAX_RPS takes effect (tests, reruns)."""
    global _limiter
    _limiter = None


async def pace() -> None:
    """Await the shared limiter. No-op when pacing is disabled."""
    await get_limiter().acquire()
