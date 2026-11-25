"""
cli_ui.py — Enterprise CLI presentation layer for Agentic Web Pentest.

Provides:
  - Banner / startup display
  - Phase headers and completion lines with elapsed time
  - Coloured status prefixes  (✔ ✘ ⚡ ◈ ◉ …)
  - Final scan summary table with severity bar chart
  - All styling via plain ANSI codes — zero extra dependencies.
"""
from __future__ import annotations

import os
import sys
import time
from datetime import datetime
from typing import Optional

# ── Version ───────────────────────────────────────────────────────────────────
VERSION = "0.5.0"

# ── ANSI colour palette ───────────────────────────────────────────────────────
_NO_COLOR = not sys.stdout.isatty() or os.environ.get("NO_COLOR")

def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def bold(t: str)       -> str: return _c("1", t)
def dim(t: str)        -> str: return _c("2", t)
def red(t: str)        -> str: return _c("91", t)
def green(t: str)      -> str: return _c("92", t)
def yellow(t: str)     -> str: return _c("93", t)
def blue(t: str)       -> str: return _c("94", t)
def magenta(t: str)    -> str: return _c("95", t)
def cyan(t: str)       -> str: return _c("96", t)
def white(t: str)      -> str: return _c("97", t)
def bold_cyan(t: str)  -> str: return _c("1;96", t)
def bold_green(t: str) -> str: return _c("1;92", t)
def bold_red(t: str)   -> str: return _c("1;91", t)
def bold_yellow(t: str)-> str: return _c("1;93", t)

_SEV_COLOR = {
    "critical":      bold_red,
    "high":          red,
    "medium":        yellow,
    "low":           blue,
    "informational": dim,
    "info":          dim,
}

def sev_color(severity: str, text: str) -> str:
    fn = _SEV_COLOR.get(severity.lower(), white)
    return fn(text)

# ── Width ─────────────────────────────────────────────────────────────────────
_W = min(os.get_terminal_size().columns if sys.stdout.isatty() else 88, 88)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _hr(char: str = "─") -> str:
    return dim(char * _W)

def _ts() -> str:
    return dim(f"[{datetime.now().strftime('%H:%M:%S')}]")

def _elapsed(secs: float) -> str:
    if secs < 60:
        return dim(f"(+{int(secs)}s)")
    m, s = divmod(int(secs), 60)
    return dim(f"(+{m}m {s:02d}s)")

def _pad_right(text: str, width: int) -> str:
    """Pad plain (stripped) text to width, accounting for ANSI codes."""
    visible = _strip_ansi(text)
    padding = max(0, width - len(visible))
    return text + " " * padding

def _strip_ansi(text: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", text)

# ── Banner ────────────────────────────────────────────────────────────────────

_LOGO = r"""
   ___                   __  _        _      __     __
  / _ | ___ ____ ___  / /_(_)___   | | /| / /__  / /
 / __ |/ _ `/ -_) _ \/ __/ / __/  | |/ |/ / -_)/ _ \
/_/ |_|\_,_/\__/_//_/\__/_/\__/   |__/|__/\__/_.__/

   ____             __           __
  / __ \___  ____  / /____  ___ / /_
 / /_/ / -_)/ _ \/ __/ -_)(_-</ __/
 \____/\__/ .__/\__/\__//___/\__/
          /_/
"""

def print_banner(
    target_url: str = "",
    provider: str = "anthropic",
    mode: str = "full",
    max_parallel: int = 3,
    scope_include: list = None,
    scope_exclude: list = None,
) -> None:
    """Print the startup banner with session metadata."""
    print()

    # Logo lines — centred
    for line in _LOGO.splitlines():
        if line.strip():
            pad = max(0, (_W - len(line)) // 2)
            print(" " * pad + bold_cyan(line))

    # Tagline
    tagline = "Enterprise-Grade  ·  Autonomous  ·  AI-Driven Penetration Testing"
    pad = max(0, (_W - len(tagline)) // 2)
    print(" " * pad + dim(tagline))
    print(" " * pad + dim(f"v{VERSION}  ·  OWASP Top 10  ·  PortSwigger Academy"))
    print()
    print(_hr("═"))

    # Session info table
    _provider_label = {
        "anthropic": "Anthropic Claude  (claude-sonnet-5)",
        "openai":    "OpenAI GPT-4o",
        "ollama":    "Ollama  (local model)",
        "mock":      "Mock LLM  (offline testing)",
    }.get(provider.lower(), provider)

    _mode_label = {
        "full":        "Full Pipeline  —  Recon → Static → Vuln → Exploit → Report",
        "static_only": "Static Analysis + Report  (no crawl / active exploitation)",
    }.get(mode, mode)

    _scope = "All paths (default-permit)"
    if scope_include:
        _scope = f"INCLUDE: {' | '.join(scope_include)}"
    if scope_exclude:
        _scope += ("  " if scope_include else "") + f"EXCLUDE: {' | '.join(scope_exclude)}"

    rows = [
        ("Target",       bold_cyan(target_url) if target_url else dim("(none — static-only mode)")),
        ("Provider",     cyan(_provider_label)),
        ("Mode",         white(_mode_label)),
        ("Parallelism",  white(f"{max_parallel} concurrent exploit worker(s)")),
        ("Scope",        dim(_scope)),
        ("Started",      dim(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))),
    ]

    label_w = max(len(r[0]) for r in rows) + 2
    for label, value in rows:
        print(f"  {bold(label.ljust(label_w))} {value}")

    print()
    print(_hr())
    print()

# ── Phase headers ─────────────────────────────────────────────────────────────

_PHASE_ICONS = {
    "recon":           "◈",
    "static_analysis": "◈",
    "vuln":            "◈",
    "exploit":         "⚡",
    "report":          "◈",
    "feedback":        "↺",
}

_PHASE_LABELS = {
    "recon":           "Phase 1    —  Reconnaissance",
    "static_analysis": "Phase 1.5  —  Static Source Code Analysis",
    "vuln":            "Phase 2    —  Vulnerability Analysis",
    "exploit":         "Phase 3    —  Exploitation",
    "report":          "Phase 4    —  Reporting",
    "feedback":        "Feedback Loop  —  Adaptive Re-Exploitation",
}

# Track phase start times
_phase_starts: dict[str, float] = {}


def phase_start(phase: str, label: str = "") -> None:
    _phase_starts[phase] = time.monotonic()
    icon  = _PHASE_ICONS.get(phase, "◈")
    text  = label or _PHASE_LABELS.get(phase, phase.replace("_", " ").title())
    print(f"  {bold_cyan(icon)}  {bold(text)}  {_ts()}")


def phase_end(phase: str, **stats) -> None:
    elapsed = time.monotonic() - _phase_starts.get(phase, time.monotonic())
    _parts = []
    for k, v in stats.items():
        _parts.append(f"{k.replace('_', ' ')}: {bold(str(v))}")
    detail = "  ·  ".join(_parts) if _parts else ""
    suffix = f"  {detail}" if detail else ""
    print(
        f"  {bold_green('✔')}  {dim('Phase complete')}  "
        f"{dim(suffix)}  {_elapsed(elapsed)}"
    )
    print()


def phase_skipped(phase: str, reason: str = "") -> None:
    text = _PHASE_LABELS.get(phase, phase)
    print(f"  {dim('○')}  {dim(text)}  —  {dim(reason or 'skipped')}")
    print()

# ── In-phase status lines ─────────────────────────────────────────────────────

def info(msg: str) -> None:
    print(f"  {dim('·')}  {msg}")

def success(msg: str) -> None:
    print(f"  {bold_green('[+]')}  {msg}")

def warn(msg: str) -> None:
    print(f"  {bold_yellow('[!]')}  {msg}")

def error(msg: str) -> None:
    print(f"  {bold_red('[✘]')}  {msg}")

def finding(vuln_type: str, location: str, severity: str) -> None:
    sev_label = sev_color(severity, f"[{severity.upper():<13}]")
    print(f"  {bold_green('[+]')}  {sev_label}  {bold(vuln_type)}  {dim('at')}  {cyan(location)}")

def potential(vuln_type: str, location: str) -> None:
    print(f"  {bold_yellow('[~]')}  {yellow('[POTENTIAL     ]')}  {vuln_type}  {dim('at')}  {cyan(location)}")

def failed(vuln_type: str, location: str) -> None:
    print(f"  {dim('[-]')}  {dim('[NOT EXPLOITABLE]')}  {dim(vuln_type)}  {dim('at')}  {dim(location)}")

def feedback_loop(iteration: int, count: int) -> None:
    print(f"  {cyan('↺')}  {bold(f'Feedback iteration {iteration}')}  —  {count} new hypothesis(es) queued")

# ── Final summary ─────────────────────────────────────────────────────────────

def _bar(count: int, max_count: int, width: int = 20) -> str:
    if max_count == 0:
        return dim("─" * width)
    filled = max(1, round(count / max_count * width)) if count > 0 else 0
    return green("█" * filled) + dim("░" * (width - filled))

def print_summary(
    target_url: str,
    findings: list,
    hypotheses: list,
    report_path: str = "",
    total_elapsed: float = 0.0,
    feedback_iterations: int = 0,
    event_summary: str = "",
) -> None:
    """Print the final post-pipeline summary table."""

    confirmed = [f for f in findings if not f.get("potential")]
    potentials = [f for f in findings if f.get("potential")]

    sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in confirmed:
        sev = f.get("hypothesis", {}).get("severity", "Informational")
        key = sev.capitalize()
        if key in sev_counts:
            sev_counts[key] += 1
        elif "info" in sev.lower():
            sev_counts["Informational"] += 1

    max_sev = max(sev_counts.values()) if sev_counts else 1

    # Duration
    if total_elapsed >= 3600:
        h, rem = divmod(int(total_elapsed), 3600)
        m, s = divmod(rem, 60)
        duration_str = f"{h}h {m:02d}m {s:02d}s"
    elif total_elapsed >= 60:
        m, s = divmod(int(total_elapsed), 60)
        duration_str = f"{m}m {s:02d}s"
    else:
        duration_str = f"{int(total_elapsed)}s"

    inner_w = _W - 4  # 2 border chars + 2 spaces each side

    def _row(label: str, value: str) -> None:
        content = f"  {bold(label.ljust(14))} {value}"
        visible_len = len(_strip_ansi(content))
        pad = max(0, inner_w - visible_len)
        print(f"  │{content}{' ' * pad}  │")

    def _blank() -> None:
        print(f"  │{'':>{inner_w + 2}}│")

    def _divider() -> None:
        print(f"  ├{'─' * (inner_w + 2)}┤")

    border_top = f"  ┌{'─' * (inner_w + 2)}┐"
    border_bot = f"  └{'─' * (inner_w + 2)}┘"

    print()
    print(_hr("═"))
    print()
    print(f"  {bold_cyan('SCAN SUMMARY')}")
    print()
    print(border_top)
    _row("Target",    cyan(target_url) if target_url else dim("(static-only)"))
    _row("Duration",  white(duration_str))
    _row("Hypotheses",
         f"{bold(str(len(hypotheses)))} generated  "
         f"{bold_green(str(len(confirmed)))} confirmed  "
         f"{bold_yellow(str(len(potentials)))} potential  "
         f"{dim(str(len(hypotheses) - len(confirmed) - len(potentials)))} not exploitable")
    if feedback_iterations:
        _row("Feedback",  dim(f"{feedback_iterations} adaptive re-exploitation loop(s) run"))
    _divider()

    # Severity chart
    sev_line = f"  {'SEVERITY BREAKDOWN'.ljust(14 + 2)}"
    visible = len(_strip_ansi(sev_line))
    pad = max(0, inner_w - visible)
    print(f"  │{sev_line}{' ' * pad}  │")

    _SEV_DOT = {
        "Critical":      bold_red("●"),
        "High":          red("●"),
        "Medium":        yellow("●"),
        "Low":           blue("●"),
        "Informational": dim("●"),
    }
    for sev, count in sev_counts.items():
        dot   = _SEV_DOT[sev]
        bar   = _bar(count, max_sev)
        label = sev.ljust(13)
        cnt   = bold(str(count)) if count else dim("0")
        content = f"  {dot} {dim(label)} {cnt}  {bar}"
        visible_len = len(_strip_ansi(content))
        pad = max(0, inner_w - visible_len)
        print(f"  │{content}{' ' * pad}  │")

    if report_path:
        _divider()
        _row("Report", green(report_path))

    if event_summary:
        _blank()
        ev_content = f"  {dim(event_summary)}"
        ev_visible = len(_strip_ansi(ev_content))
        ev_pad = max(0, inner_w - ev_visible)
        print(f"  │{ev_content}{' ' * ev_pad}  │")

    print(border_bot)
    print()
    print(
        f"  {dim('Powered by')}  {bold_cyan('Agentic Web Pentest')}  "
        f"{dim(f'v{VERSION}')}  {dim('·  OWASP Top 10  ·  PortSwigger Academy')}"
    )
    print()

# ── Error / abort ─────────────────────────────────────────────────────────────

def print_abort(reason: str) -> None:
    print()
    print(f"  {bold_red('ABORTED')}  {dim('—')}  {reason}")
    print()

def print_cancelled() -> None:
    print()
    print(f"  {bold_yellow('[ CANCELLED ]')}  {dim('Operation cancelled by user.')}")
    print()
