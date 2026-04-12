import asyncio
import argparse
from dotenv import load_dotenv

from src.core.llm import ClaudeEngine, OpenAIEngine, OllamaEngine
from src.core.orchestrator import PentestOrchestrator
from src.agents.recon import ReconAgent
from src.agents.static_analysis import StaticAnalysisAgent
from src.agents.vuln import VulnAnalyzerAgent
from src.agents.exploit import ExploitAgent
from src.agents.report import ReportingAgent
import src.core.cli_ui as ui

load_dotenv()


class MockClaudeEngine:
    def __init__(self):
        print("[MockLLM] Initialized")

    async def generate_response(self, messages, system_prompt="", **_):
        print(f"[MockLLM] generate_response called (messages: {len(messages)})")

        class MockResponse:
            def __init__(self, text):
                class MockBlock:
                    def __init__(self, t):
                        self.type = "text"
                        self.text = t

                self.content = [MockBlock(text)]
                self.stop_reason = "end_turn"

        # If the system prompt represents the vuln analysis agent, return dynamic JSON hypotheses
        if "Penetration Tester AI" in system_prompt:
            import json as _json

            hypotheses = [
                {
                    "type": "SQLi",
                    "details": "Possible SQL injection on query parameters",
                    "location": "/",
                    "cvss_score": 9.8,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "severity": "Critical"
                },
                {
                    "type": "XSS",
                    "details": "Possible reflected XSS on search/input forms",
                    "location": "/search",
                    "cvss_score": 6.1,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    "severity": "Medium"
                },
                {
                    "type": "Informational",
                    "details": "Server version disclosure in headers (nginx/1.18.0)",
                    "location": "/",
                    "cvss_score": 0.0,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                    "severity": "Informational"
                },
            ]
            return MockResponse(_json.dumps(hypotheses))

        # If the system prompt represents the reporting agent
        if "penetration test report writer" in system_prompt:
            content = messages[0].get("content", "")
            if "CONFIRMED FINDINGS (JSON):" in content:
                import json

                try:
                    findings_part = (
                        content.split("CONFIRMED FINDINGS (JSON):\n")[1].split("RECONNAISSANCE")[0].strip()
                    )
                    findings_list = json.loads(findings_part)
                    mapped_findings = []

                    for i, f in enumerate(findings_list):
                        h = f['hypothesis']
                        mapped_findings.append({
                            "id": f"WVAPT-{i+1}",
                            "title": h['type'],
                            "severity": h.get('severity', 'Unknown'),
                            "cvss_score": h.get('cvss_score', 0.0),
                            "cvss_vector": h.get('cvss_vector', ''),
                            "status": "Open",
                            "location": h['location'],
                            "description": h['details'],
                            "proof_of_concept": f['proof'],
                            "screenshot_path": f.get("screenshot_path", ""),
                            "implications": "Significant business impact.",
                            "recommendations": "Apply security patches."
                        })
                    
                    report_data = {
                        "executive_summary": "This report was generated during a mock testing session.",
                        "attack_surface_overview": "Mock surface overview.",
                        "findings": mapped_findings,
                        "remediation_roadmap": "1. Fix SQLi\n2. Fix XSS",
                        "conclusion": "The application contains validated vulnerabilities."
                    }
                except Exception as e:
                    report_data = {"executive_summary": str(e), "findings": []}

                return MockResponse(json.dumps(report_data))

        # If it's an exploit prompt
        if "Exploitation AI Pentester" in system_prompt:
            return MockResponse("Success: Mock verification successful.")

        return MockResponse(
            "This is a mock LLM response outlining potential issues and findings."
        )

    def extract_text(self, response):
        return response.content[0].text

    def extract_tool_calls(self, *_):
        return []


async def main():
    parser = argparse.ArgumentParser(
        description="Agentic Web Pentest — Enterprise AI-driven penetration testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --url https://target.com --provider anthropic\n"
            "  python main.py --url https://target.com --source ./src --provider openai\n"
            "  python main.py --source ./repo --static-only\n"
            "  python main.py --url https://target.com --provider ollama --ollama-model llama3\n"
        ),
    )
    parser.add_argument("--url", default="", help="Target URL (required unless --static-only)")
    parser.add_argument(
        "--repo", default=".", help="Project root / working directory (default: current directory)"
    )
    parser.add_argument(
        "--source",
        default="",
        metavar="PATH",
        help="Source code directory for static analysis (default: same as --repo)",
    )
    parser.add_argument(
        "--static-only",
        action="store_true",
        help="Run Phase 1.5 (static analysis) + Phase 4 (report) only — no crawl or active exploitation",
    )
    parser.add_argument(
        "--mock-llm",
        action="store_true",
        help="Run in mock mode without actual API calls",
    )
    parser.add_argument(
        "--provider",
        default="anthropic",
        choices=["anthropic", "openai", "ollama"],
        help="LLM provider to use (default: anthropic)",
    )
    parser.add_argument(
        "--ollama-url",
        default=None,
        help="Ollama server base URL (default: http://172.30.48.1:11434, overrides OLLAMA_BASE_URL env var)",
    )
    parser.add_argument(
        "--ollama-model",
        default=None,
        help="Ollama model name (default: qwen2.5-coder:7b-infosec, overrides OLLAMA_MODEL env var)",
    )
    parser.add_argument(
        "--headers",
        help="JSON string of HTTP headers to inject into requests",
        default="{}",
    )
    parser.add_argument(
        "--cookies", help="JSON string of cookies to inject into requests", default="{}"
    )
    parser.add_argument(
        "--scope-include", nargs="*", metavar="PATTERN", default=[],
        help="Regex allow-list: only crawl/test URLs matching at least one pattern (repeatable)",
    )
    parser.add_argument(
        "--scope-exclude", nargs="*", metavar="PATTERN", default=[],
        help="Regex deny-list: skip URLs matching any of these patterns (repeatable)",
    )
    parser.add_argument(
        "--max-hypotheses",
        type=int,
        default=8,
        help="Maximum number of vulnerability hypotheses to generate (default: 8)",
    )
    parser.add_argument(
        "--max-parallel",
        type=int,
        default=3,
        metavar="N",
        help="Max exploit categories to run in parallel (default: 3)",
    )
    parser.add_argument(
        "--feedback-iterations",
        type=int,
        default=2,
        metavar="N",
        help="Max adaptive feedback loop iterations after Phase 3 (default: 2, 0 to disable)",
    )
    args = parser.parse_args()

    # --url is required unless --static-only
    if not args.static_only and not args.url:
        parser.error("--url is required unless --static-only is set.")

    import json

    try:
        headers_dict = json.loads(args.headers)
        cookies_dict = json.loads(args.cookies)
    except json.JSONDecodeError as e:
        ui.error(f"Invalid JSON for --headers or --cookies: {e}")
        return

    # ── Determine provider label for banner ───────────────────────────────────
    _provider_key = "mock" if args.mock_llm else args.provider
    _mode         = "static_only" if args.static_only else "full"

    # ── Print startup banner ──────────────────────────────────────────────────
    ui.print_banner(
        target_url=args.url,
        provider=_provider_key,
        mode=_mode,
        max_parallel=args.max_parallel,
        scope_include=args.scope_include or [],
        scope_exclude=args.scope_exclude or [],
    )

    # ── Initialize LLM engine ─────────────────────────────────────────────────
    if args.mock_llm:
        engine = MockClaudeEngine()
        ui.info("Mock LLM mode — no API calls will be made")
        print()
    else:
        try:
            if args.provider == "openai":
                engine = OpenAIEngine()
            elif args.provider == "ollama":
                engine = OllamaEngine(
                    base_url=args.ollama_url,
                    model=args.ollama_model,
                )
            else:
                engine = ClaudeEngine()
        except Exception as e:
            ui.error(f"Failed to initialize {args.provider.capitalize()} engine: {e}")
            if args.provider == "openai":
                ui.warn("Check your OPENAI_API_KEY in the .env file.")
            elif args.provider == "ollama":
                ollama_url = args.ollama_url or "http://172.30.48.1:11434"
                ui.warn(f"Verify the Ollama server is running at {ollama_url}")
            else:
                ui.warn("Check your ANTHROPIC_API_KEY in the .env file.")
            ui.warn("Use --mock-llm to run without API access.")
            return

    orchestrator = PentestOrchestrator(
        target_url=args.url,
        repo_path=args.repo,
        source_path=args.source,
        headers=headers_dict,
        cookies=cookies_dict,
        scope_include=args.scope_include or [],
        scope_exclude=args.scope_exclude or [],
        static_only=args.static_only,
        max_parallel_exploits=args.max_parallel,
        max_feedback_iterations=args.feedback_iterations,
    )

    # Register Agents — static-only mode skips recon, vuln, and exploit phases
    if args.static_only:
        orchestrator.register_agent("static_analysis", StaticAnalysisAgent(engine))
        orchestrator.register_agent("report", ReportingAgent(engine))
    else:
        orchestrator.register_agent("recon", ReconAgent(engine))
        orchestrator.register_agent("static_analysis", StaticAnalysisAgent(engine))
        orchestrator.register_agent("vuln", VulnAnalyzerAgent(engine, max_llm_hypotheses=args.max_hypotheses))
        orchestrator.register_agent("exploit", ExploitAgent(engine))
        orchestrator.register_agent("report", ReportingAgent(engine))

    try:
        await orchestrator.run_pipeline()
    except Exception as e:
        import traceback
        ui.print_abort(f"Pipeline error: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        ui.print_cancelled()
