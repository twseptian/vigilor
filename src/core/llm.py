import os
import re
import asyncio
from typing import Any, Dict, List, Optional
from anthropic import AsyncAnthropic, APIError
from openai import AsyncOpenAI
import httpx
from dotenv import load_dotenv


# Global semaphore that caps the number of in-flight LLM API calls across
# ALL engine instances.  Prevents concurrent exploit agents from exhausting
# the TPM budget simultaneously (e.g. 3 categories × 3-5k tokens = instant
# 30k TPM hit on OpenAI's free/tier-1 plans).
#
# With a 30k TPM limit, burst rate limit errors are unavoidable when multiple
# agents run concurrently — the semaphore serialises calls so TPM usage spreads
# evenly over the 60-second window instead of being consumed all at once.
# Set to 1 to fully serialise; increase only if your TPM tier is ≥ 90k.
_LLM_MAX_CONCURRENT = 1
_llm_semaphore: Optional[asyncio.Semaphore] = None

# Minimum seconds to hold the semaphore slot after a successful API call.
# With 30k TPM and ~4k tokens/call you can make ≤7 calls/min safely.
# 8s cooldown → ~7.5 calls/min → ~30k TPM — exactly at the limit.
# Adjust upward if you have a higher TPM tier and want faster scans.
_LLM_CALL_COOLDOWN = 8.0


def _get_llm_semaphore() -> asyncio.Semaphore:
    """Return (lazily creating) the global LLM concurrency semaphore."""
    global _llm_semaphore
    if _llm_semaphore is None:
        _llm_semaphore = asyncio.Semaphore(_LLM_MAX_CONCURRENT)
    return _llm_semaphore


def _parse_retry_after(error_message: str) -> Optional[float]:
    """Extract suggested wait time (seconds) from an API rate-limit error message.

    Handles patterns like:
      'Please try again in 1.5s'
      'Please try again in 500ms'
      'Retry-After: 2'
    Returns None if no hint is found.
    """
    m = re.search(r'try again in (\d+(?:\.\d+)?)s', str(error_message), re.IGNORECASE)
    if m:
        return float(m.group(1))
    m = re.search(r'try again in (\d+)ms', str(error_message), re.IGNORECASE)
    if m:
        return float(m.group(1)) / 1000.0
    m = re.search(r'retry.?after[:\s]+(\d+(?:\.\d+)?)', str(error_message), re.IGNORECASE)
    if m:
        return float(m.group(1))
    return None

# Load .env so all OLLAMA_* vars are available regardless of how the process was started.
# find_dotenv walks up from this file's location to locate the .env in the project root.
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "..", "..", ".env"))

# Absolute last-resort fallbacks — only used when .env is missing entirely.
_OLLAMA_FALLBACK_BASE_URL   = "http://127.0.0.1:11434"
_OLLAMA_FALLBACK_MODEL      = "qwen2.5-coder:7b-infosec"
_OLLAMA_FALLBACK_NUM_CTX    = 8192
_OLLAMA_FALLBACK_TEMPERATURE = 0.1


class ClaudeEngine:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")

        anthropic_base_url = os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com")

        # Force IPv4 to prevent hanging on networks with broken IPv6
        transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
        http_client = httpx.AsyncClient(transport=transport)

        self.client = AsyncAnthropic(
            api_key=self.api_key,
            http_client=http_client,
            base_url=anthropic_base_url,
        )
        self.default_model = "claude-sonnet-4-6"
        # Max output tokens — configurable via ANTHROPIC_MAX_TOKENS env var (set from Settings)
        try:
            self.default_max_tokens = int(os.environ.get("ANTHROPIC_MAX_TOKENS", 4096))
        except (ValueError, TypeError):
            self.default_max_tokens = 4096

    async def generate_response(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str = "",
        model: str = None,
        tools: List[Dict[str, Any]] = None,
        max_tokens: int = None,
        temperature: float = 0.7,
    ) -> Any:
        from anthropic import RateLimitError as _AnthropicRateLimitError

        max_retries = 8  # rate limits always resolve; allow more attempts
        base_delay = 2

        for attempt in range(max_retries):
            try:
                kwargs = {
                    "model": model or self.default_model,
                    "system": system_prompt,
                    "messages": messages,
                    "max_tokens": max_tokens if max_tokens is not None else self.default_max_tokens,
                    "temperature": temperature,
                }
                if tools:
                    kwargs["tools"] = tools

                async with _get_llm_semaphore():
                    response = await self.client.messages.create(**kwargs)
                    # Post-call cooldown: hold the semaphore slot for a moment so
                    # the next queued call is staggered in time, distributing TPM
                    # usage evenly across the 60-second window.
                    await asyncio.sleep(_LLM_CALL_COOLDOWN)
                return response

            except _AnthropicRateLimitError as e:
                suggested = _parse_retry_after(str(e))
                sleep_time = (suggested + 0.5) if suggested else 10.0
                print(f"[!] Anthropic Rate Limit (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print(f"    Waiting {sleep_time:.1f}s before retrying...")
                    await asyncio.sleep(sleep_time)
                else:
                    print("[!] Max retries reached. Pipeline execution cannot continue.")
                    raise

            except Exception as e:
                print(
                    f"[!] Anthropic API Error (Attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt < max_retries - 1:
                    sleep_time = base_delay * (2 ** attempt)
                    print(f"    Waiting {sleep_time} seconds before retrying...")
                    await asyncio.sleep(sleep_time)
                else:
                    print(
                        "[!] Max retries reached. Pipeline execution cannot continue."
                    )
                    raise

    @staticmethod
    def extract_text(response: Any) -> str:
        """Extract text blocks from the API response."""
        text_blocks = [blk.text for blk in response.content if blk.type == "text"]
        return "\n".join(text_blocks)

    @staticmethod
    def extract_tool_calls(response: Any) -> List[Any]:
        """Extract tool calls from the API response."""
        return [blk for blk in response.content if blk.type == "tool_use"]


class OpenAIEngine:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set.")

        openai_base_url = os.environ.get("OPENAI_BASE_URL") or None

        transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
        http_client = httpx.AsyncClient(transport=transport)

        client_kwargs: dict = {"api_key": self.api_key, "http_client": http_client}
        if openai_base_url:
            client_kwargs["base_url"] = openai_base_url

        self.client = AsyncOpenAI(**client_kwargs)
        # Model — read from OPENAI_MODEL env var (set by scan_runner for OpenAI/OpenRouter/OpenCode)
        self.default_model = os.environ.get("OPENAI_MODEL") or "gpt-4o"
        # Max output tokens — configurable via OPENAI_MAX_TOKENS env var (set from Settings)
        try:
            self.default_max_tokens = int(os.environ.get("OPENAI_MAX_TOKENS", 4096))
        except (ValueError, TypeError):
            self.default_max_tokens = 4096

    async def generate_response(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str = "",
        model: str = None,
        tools: List[Dict[str, Any]] = None,
        max_tokens: int = None,
        temperature: float = 0.7,
    ) -> Any:
        max_retries = 8  # rate limits always resolve; allow more attempts
        base_delay = 2

        # Build message list: prepend system prompt as a system message.
        # We do this fresh each call to avoid duplication in multi-turn sessions.
        openai_messages = []
        if system_prompt:
            openai_messages.append({"role": "system", "content": system_prompt})
        openai_messages.extend(messages)

        from openai import RateLimitError as _OpenAIRateLimitError

        for attempt in range(max_retries):
            try:
                kwargs = {
                    "model": model or self.default_model,
                    "messages": openai_messages,
                    "max_tokens": max_tokens if max_tokens is not None else self.default_max_tokens,
                    "temperature": temperature,
                }
                if tools:
                    # Convert Anthropic-style tool defs (input_schema) -> OpenAI function format (parameters)
                    openai_tools = []
                    for tool in tools:
                        openai_tools.append({
                            "type": "function",
                            "function": {
                                "name": tool["name"],
                                "description": tool.get("description", ""),
                                "parameters": tool.get("input_schema", {
                                    "type": "object", "properties": {}
                                }),
                            }
                        })
                    kwargs["tools"] = openai_tools

                async with _get_llm_semaphore():
                    response = await self.client.chat.completions.create(**kwargs)
                    await asyncio.sleep(_LLM_CALL_COOLDOWN)
                return response

            except _OpenAIRateLimitError as e:
                # TPM/RPM windows reset on a fixed schedule — use the API's own hint.
                # Do NOT apply exponential backoff here; a 128s wait for a 6s TPM window
                # is wasteful and makes the pipeline appear stuck.
                suggested = _parse_retry_after(str(e))
                sleep_time = (suggested + 0.5) if suggested else 10.0
                print(f"[!] OpenAI Rate Limit (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print(f"    Waiting {sleep_time:.1f}s before retrying...")
                    await asyncio.sleep(sleep_time)
                else:
                    print("[!] Max retries reached. Pipeline execution cannot continue.")
                    raise

            except Exception as e:
                print(
                    f"[!] OpenAI API Error (Attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt < max_retries - 1:
                    sleep_time = base_delay * (2 ** attempt)
                    print(f"    Waiting {sleep_time} seconds before retrying...")
                    await asyncio.sleep(sleep_time)
                else:
                    print(
                        "[!] Max retries reached. Pipeline execution cannot continue."
                    )
                    raise

    @staticmethod
    def extract_text(response: Any) -> str:
        """Extract text from the API response."""
        return response.choices[0].message.content or ""

    @staticmethod
    def extract_tool_calls(response: Any) -> List[Any]:
        """Extract tool calls from the API response."""
        return response.choices[0].message.tool_calls or []

    @staticmethod
    def extract_tool_call_name(tool_call: Any) -> str:
        """Extract tool name from OpenAI tool call."""
        return tool_call.function.name

    @staticmethod
    def extract_tool_call_input(tool_call: Any) -> dict:
        """Extract tool input from OpenAI tool call."""
        import json

        try:
            return json.loads(tool_call.function.arguments)
        except:
            return {}


class OllamaEngine:
    """LLM engine backed by a local Ollama server via its OpenAI-compatible API."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        num_ctx: Optional[int] = None,
    ):
        self.base_url = (
            base_url
            or os.environ.get("OLLAMA_BASE_URL", _OLLAMA_FALLBACK_BASE_URL)
        ).rstrip("/")
        self.default_model = (
            model
            or os.environ.get("OLLAMA_MODEL", _OLLAMA_FALLBACK_MODEL)
        )
        # Context window: CLI arg → OLLAMA_NUM_CTX env var (.env) → fallback
        try:
            self.num_ctx = (
                int(num_ctx)
                if num_ctx is not None
                else int(os.environ.get("OLLAMA_NUM_CTX", _OLLAMA_FALLBACK_NUM_CTX))
            )
        except (ValueError, TypeError):
            self.num_ctx = _OLLAMA_FALLBACK_NUM_CTX

        # Temperature: OLLAMA_TEMPERATURE env var (.env) → fallback
        try:
            self.default_temperature = float(
                os.environ.get("OLLAMA_TEMPERATURE", _OLLAMA_FALLBACK_TEMPERATURE)
            )
        except (ValueError, TypeError):
            self.default_temperature = _OLLAMA_FALLBACK_TEMPERATURE

        # Use a plain httpx client with generous timeouts — no IPv4-forcing transport
        # needed for a local server, and the forced local_address can cause issues.
        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=10.0)
        )

        self.client = AsyncOpenAI(
            api_key="ollama",  # Ollama ignores the key; a non-empty value is required
            base_url=f"{self.base_url}/v1",
            http_client=http_client,
        )

        # Pre-flight: verify server is reachable and model is available (sync check)
        self._check_connection()

    def _check_connection(self) -> None:
        """Synchronous pre-flight check against /api/tags before the pipeline starts."""
        import json as _json

        tags_url = f"{self.base_url}/api/tags"
        print(f"[OllamaEngine] Testing connection → {tags_url}")
        try:
            resp = httpx.get(tags_url, timeout=8.0)
            resp.raise_for_status()
            data = resp.json()
            available = [m["name"] for m in data.get("models", [])]
            print(f"[OllamaEngine] Server OK — {len(available)} model(s) available")
            print(f"[OllamaEngine] Config  — model={self.default_model}  num_ctx={self.num_ctx}  temperature={self.default_temperature}")
            if self.default_model in available:
                print(f"[OllamaEngine] Model '{self.default_model}' found — ready.")
            else:
                # Warn but don't abort; the model name may still be valid (alias, etc.)
                print(
                    f"[OllamaEngine] WARNING: model '{self.default_model}' not in tag list. "
                    f"Available: {', '.join(available)}"
                )
        except httpx.ConnectError as e:
            raise RuntimeError(
                f"[OllamaEngine] Cannot reach Ollama server at {self.base_url}\n"
                f"  → Make sure Ollama is running and accessible.\n"
                f"  → Detail: {e}"
            ) from e
        except httpx.TimeoutException as e:
            raise RuntimeError(
                f"[OllamaEngine] Connection timed out reaching {self.base_url}\n"
                f"  → Detail: {e}"
            ) from e
        except Exception as e:
            raise RuntimeError(
                f"[OllamaEngine] Unexpected error during connectivity check: {e}"
            ) from e

    async def generate_response(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str = "",
        model: str = None,
        tools: List[Dict[str, Any]] = None,
        max_tokens: int = 4096,
        temperature: float = None,
        num_ctx: int = None,
    ) -> Any:
        max_retries = 3
        base_delay = 2

        # Fall back to instance defaults (read from .env at startup)
        _temperature = temperature if temperature is not None else self.default_temperature
        _num_ctx     = num_ctx     if num_ctx     is not None else self.num_ctx

        ollama_messages = []
        if system_prompt:
            ollama_messages.append({"role": "system", "content": system_prompt})
        ollama_messages.extend(messages)

        # Truncate message history to prevent context window overflow.
        # Keep the first user message (the task) and trim old middle turns.
        # Budget: num_ctx tokens total; reserve max_tokens for output + ~800 for
        # system prompt and tool schemas.  Rough char→token ratio = 4.
        _char_budget = max((_num_ctx - max_tokens - 800) * 4, 2000)
        _total_chars = sum(len(str(m.get("content", ""))) for m in ollama_messages)
        if _total_chars > _char_budget:
            # Always keep system message (index 0 if present) and the LAST N messages.
            _sys = [m for m in ollama_messages if m.get("role") == "system"]
            _rest = [m for m in ollama_messages if m.get("role") != "system"]
            # Always preserve the first user message (the original task)
            _preserved_head = _rest[:1]
            _tail = _rest[1:]
            # Drop oldest tail messages until we fit
            while _tail and sum(len(str(m.get("content", ""))) for m in _sys + _preserved_head + _tail) > _char_budget:
                _tail.pop(0)
            ollama_messages = _sys + _preserved_head + _tail
            print(f"[OllamaEngine] Context trimmed: {_total_chars} → {sum(len(str(m.get('content', ''))) for m in ollama_messages)} chars to fit num_ctx={_num_ctx}")

        for attempt in range(max_retries):
            try:
                kwargs = {
                    "model": model or self.default_model,
                    "messages": ollama_messages,
                    "max_tokens": max_tokens,
                    "temperature": _temperature,
                    # num_ctx sets the KV-cache context window in Ollama.
                    # Configurable via OLLAMA_NUM_CTX in .env.
                    "extra_body": {"num_ctx": _num_ctx},
                }
                if tools:
                    openai_tools = []
                    for tool in tools:
                        openai_tools.append({
                            "type": "function",
                            "function": {
                                "name": tool["name"],
                                "description": tool.get("description", ""),
                                "parameters": tool.get("input_schema", {
                                    "type": "object", "properties": {}
                                }),
                            }
                        })
                    kwargs["tools"] = openai_tools

                response = await self.client.chat.completions.create(**kwargs)
                return response

            except Exception as e:
                suggested = _parse_retry_after(str(e))
                sleep_time = max(suggested + 0.5, base_delay * (2 ** attempt)) if suggested else base_delay * (2 ** attempt)
                print(f"[!] Ollama API Error (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print(f"    Waiting {sleep_time:.1f}s before retrying...")
                    await asyncio.sleep(sleep_time)
                else:
                    print("[!] Max retries reached. Pipeline execution cannot continue.")
                    raise

    @staticmethod
    def extract_text(response: Any) -> str:
        """Extract text from the API response."""
        return response.choices[0].message.content or ""

    @staticmethod
    def extract_tool_calls(response: Any) -> List[Any]:
        """Extract tool calls from the API response."""
        return response.choices[0].message.tool_calls or []

    @staticmethod
    def extract_tool_call_name(tool_call: Any) -> str:
        return tool_call.function.name

    @staticmethod
    def extract_tool_call_input(tool_call: Any) -> dict:
        import json
        try:
            return json.loads(tool_call.function.arguments)
        except:
            return {}
