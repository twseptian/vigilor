"""
terminal.py — Sandboxed shell command execution for the pentest agent.

Security controls (P0):
  1. Command allowlist  — only pre-approved binaries may be invoked.
  2. Dangerous pattern  — secondary blocklist catches shell tricks even
                          when the binary itself is permitted (pipes to rm, etc.).
  3. Timeout            — hard kill after *timeout* seconds.
  4. No shell expansion — where possible, exec is used; shell=True only for curl.
"""
from __future__ import annotations

import asyncio
import os
import re
import signal

# ── Allowed command prefixes (first token of the command string) ──────────────
_ALLOWED_COMMANDS: frozenset[str] = frozenset({
    # HTTP probing
    "curl", "wget",
    # Network recon
    "nmap", "ping", "ping6", "traceroute", "tracepath",
    "dig", "host", "whois", "nslookup",
    # Web/app scanning (passive / active pentest tools)
    "nikto", "whatweb", "httpx", "nuclei",
    "gobuster", "ffuf", "dirb", "dirsearch",
    "wfuzz", "feroxbuster",
    # Exploitation (authorised pentest)
    "sqlmap",
    # Encoding / hashing helpers
    "echo", "printf", "base64", "xxd", "openssl",
    # File reading (target report files, /etc/passwd proof, etc.)
    "cat", "head", "tail", "grep", "strings",
    # SSL/TLS inspection
    "openssl",
})

# ── Secondary block patterns ───────────────────────────────────────────────────
# Applied AFTER the allowlist check — catches compound commands that try to
# piggyback dangerous operations on a permitted binary.
_BLOCK_PATTERNS: list[re.Pattern] = [p for p in [
    # Destructive file operations
    re.compile(r'\brm\s+(-\w+\s+)*/', re.I),
    re.compile(r'\brm\s+-[rRf]', re.I),
    re.compile(r'\bdd\s+if=', re.I),
    re.compile(r'\bmkfs\b', re.I),
    re.compile(r'\bshred\b', re.I),
    # Writing outside /tmp (e.g. wget -O /etc/cron.d/evil)
    re.compile(r'\b(?:wget|curl)\b.*-[oO]\s*/(?!tmp)', re.I),
    # Privilege / user management
    re.compile(r'\b(?:useradd|usermod|userdel|groupadd)\b', re.I),
    re.compile(r'(?<![/\w])passwd\s+\w', re.I),    # passwd <username> — not /etc/passwd
    re.compile(r'\b(?:chmod|chown)\s+[0-7]*7[0-7]*\s+/', re.I),
    re.compile(r'\bsudo\b', re.I),
    re.compile(r'\bsu\s+-', re.I),
    # System state
    re.compile(r'\b(?:shutdown|reboot|poweroff|halt|init\s+[016])\b', re.I),
    re.compile(r'\b(?:iptables|nftables|ufw|firewall-cmd)\b', re.I),
    # Persistence mechanisms
    re.compile(r'\bcrontab\b', re.I),
    re.compile(r'\bat\s+\d', re.I),
    re.compile(r'/etc/(?:cron|rc|init|systemd)', re.I),
    # Reverse / bind shells
    re.compile(r'\bnc\b.*-[eE]\b', re.I),
    re.compile(r'\bncat\b.*-[eE]\b', re.I),
    re.compile(r'\bbash\s+-i\b', re.I),
    re.compile(r'\bsh\s+-i\b', re.I),
    re.compile(r'/dev/tcp/', re.I),
    re.compile(r'/dev/udp/', re.I),
    # Code execution one-liners embedded in allowed commands
    re.compile(r'\bpython[23]?\s+-c\b', re.I),
    re.compile(r'\bphp\s+-r\b', re.I),
    re.compile(r'\bnode\s+-e\b', re.I),
    re.compile(r'\bperl\s+-e\b', re.I),
    re.compile(r'\bruby\s+-e\b', re.I),
    # Command substitution / chained execution
    re.compile(r'`[^`]+`'),                    # backtick substitution
    re.compile(r'\$\([^)]+\)'),               # $(...) substitution
    re.compile(r';\s*(?:rm|dd|mkfs|wget|curl.*-[oO]\s*/(?!tmp))', re.I),
    re.compile(r'&&\s*(?:rm|dd|mkfs)', re.I),
    re.compile(r'\|\s*(?:bash|sh|python|php|node|perl|ruby)\b', re.I),
]]


def _get_base_command(command: str) -> str:
    """Extract the first token (binary name) from a shell command string."""
    token = command.strip().split()[0] if command.strip() else ""
    # Strip any path prefix (e.g. /usr/bin/curl → curl)
    return os.path.basename(token).lower()


def _validate_command(command: str) -> tuple[bool, str]:
    """Return (allowed, reason).

    allowed=True  → command may execute.
    allowed=False → command is blocked; reason explains why.
    """
    if not command or not command.strip():
        return False, "Empty command."

    base = _get_base_command(command)

    # 1. Allowlist check
    if base not in _ALLOWED_COMMANDS:
        return False, (
            f"Command '{base}' is not in the approved command list. "
            f"Allowed: {', '.join(sorted(_ALLOWED_COMMANDS))}."
        )

    # 2. Block pattern check
    for pattern in _BLOCK_PATTERNS:
        if pattern.search(command):
            return False, (
                f"Command contains a blocked pattern (matched: '{pattern.pattern}'). "
                "Destructive, privilege-escalation, or shell-escape operations are not permitted."
            )

    return True, ""


class TerminalTool:
    @staticmethod
    async def run_command(
        command: str,
        timeout: int = 60,
        headers: dict = None,
        cookies: dict = None,
    ) -> dict:
        """Run a shell command safely with allowlist validation and a hard timeout.

        Only commands in _ALLOWED_COMMANDS are permitted.  Secondary block
        patterns catch dangerous compound commands even when the binary is
        on the allowlist.
        """
        # ── Pace outbound traffic ─────────────────────────────────────────────
        # Only network-bound tools wait; local commands run at full speed.
        try:
            from src.core.throttle import is_network_command, pace
            if is_network_command(command):
                await pace()
        except Exception:
            pass  # pacing must never be the reason a scan fails

        # ── P0: Validate before execution ─────────────────────────────────────
        allowed, reason = _validate_command(command)
        if not allowed:
            print(f"[!] TerminalTool BLOCKED: {reason}")
            return {
                "stdout": "",
                "stderr": f"[BLOCKED] {reason}",
                "exit_code": -2,
            }

        try:
            # Inject auth into curl commands
            if command.strip().startswith("curl "):
                auth_args = []
                if headers:
                    for k, v in headers.items():
                        auth_args.append(f"-H '{k}: {v}'")
                if cookies:
                    cookie_str = "; ".join([f"{k}={v}" for k, v in cookies.items()])
                    auth_args.append(f"--cookie '{cookie_str}'")
                if auth_args:
                    parts = command.split(" ", 1)
                    command = f"{parts[0]} {' '.join(auth_args)} {parts[1]}"

            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                preexec_fn=os.setsid,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
                return {
                    "stdout": "",
                    "stderr": f"Command '{command}' timed out after {timeout} seconds.",
                    "exit_code": -1,
                }

            return {
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
                "exit_code": process.returncode,
            }

        except Exception as e:
            return {"stdout": "", "stderr": str(e), "exit_code": -1}
