import os
import re
import asyncio
from typing import Any, Dict, List, Optional
from anthropic import AsyncAnthropic, APIError
from openai import AsyncOpenAI
import httpx
from dotenv import load_dotenv


# Sentinel: distinguishes "argument not passed" (fall back to env) from an
# explicit None (e.g. top_p=None means "do not send top_p").
_UNSET = object()


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


def _ensure_valid_completion(response: Any, provider_label: str = "provider") -> Any:
    """Reject a chat completion that carries no choices.

    OpenAI-compatible gateways — OpenRouter in particular — signal several errors
    with HTTP 200 and an ``error`` object in the body instead of a 4xx. The SDK
    happily parses that into a ChatCompletion whose ``choices`` is None, and every
    caller then trips over ``response.choices[0]`` with the useless message
    "'NoneType' object is not subscriptable", losing the provider's actual
    explanation. Surface that explanation as a real error instead.
    """
    if response is not None and getattr(response, "choices", None):
        return response

    detail = ""
    err = getattr(response, "error", None)
    if err is None and hasattr(response, "model_extra"):
        err = (response.model_extra or {}).get("error")
    if isinstance(err, dict):
        detail = str(err.get("message") or err)
        code = err.get("code")
        if code:
            detail = f"{detail} (code {code})"
    elif err:
        detail = str(err)

    low = detail.lower()
    if any(k in low for k in ("per-day", "per_day", "free-models-per-day", "daily limit")):
        raise RuntimeError(
            f"[!] {provider_label} daily free quota exhausted. "
            f"Add credits to your account or use a paid model. {detail}".strip()
        )
    if any(k in low for k in ("credit", "insufficient", "payment", "402")):
        raise RuntimeError(
            f"[!] {provider_label} rejected the request for billing reasons: {detail}"
        )

    raise RuntimeError(
        f"[!] {provider_label} returned no completion"
        + (f": {detail}" if detail else " and no error detail — the model may be "
                                         "unavailable or the request was filtered.")
    )


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
        # Honour a per-scan model via ANTHROPIC_MODEL (set by the web backend);
        # previously this was hardcoded so the UI model choice was ignored.
        self.default_model = os.environ.get("ANTHROPIC_MODEL") or "claude-sonnet-5"
        # Max output tokens — configurable via ANTHROPIC_MAX_TOKENS env var (set from Settings)
        try:
            self.default_max_tokens = int(os.environ.get("ANTHROPIC_MAX_TOKENS", 4096))
        except (ValueError, TypeError):
            self.default_max_tokens = 4096
        try:
            self.default_temperature = float(os.environ.get("ANTHROPIC_TEMPERATURE", 0.7))
        except (ValueError, TypeError):
            self.default_temperature = 0.7
        _tp = os.environ.get("ANTHROPIC_TOP_P")
        self.default_top_p: Optional[float] = float(_tp) if _tp else None

    async def generate_response(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str = "",
        model: str = None,
        tools: List[Dict[str, Any]] = None,
        max_tokens: int = None,
        temperature: float = None,
        enable_cache: bool = True,
    ) -> Any:
        from anthropic import RateLimitError as _AnthropicRateLimitError

        max_retries = 8  # rate limits always resolve; allow more attempts
        base_delay = 2

        # Prompt caching: system prompts >1024 tokens are cached by Anthropic for
        # 5 minutes at 10% of the normal input token cost.  The exploit agent's
        # system prompt is ~9 500 tokens — without caching every turn of every
        # hypothesis pays full price for those tokens.  With caching, only the
        # first call per 5-minute window is billed at full rate.
        # Use structured system param when caching; plain string otherwise.
        if enable_cache and system_prompt and len(system_prompt) > 1024:
            system_param: Any = [
                {
                    "type": "text",
                    "text": system_prompt,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        else:
            system_param = system_prompt

        _temperature = temperature if temperature is not None else self.default_temperature

        for attempt in range(max_retries):
            try:
                kwargs = {
                    "model": model or self.default_model,
                    "system": system_param,
                    "messages": messages,
                    "max_tokens": max_tokens if max_tokens is not None else self.default_max_tokens,
                    "temperature": _temperature,
                    "betas": ["prompt-caching-2024-07-31"],
                }
                if self.default_top_p is not None:
                    kwargs["top_p"] = self.default_top_p
                if tools:
                    kwargs["tools"] = tools

                async with _get_llm_semaphore():
                    response = await self.client.beta.messages.create(**kwargs)
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

    @staticmethod
    def log_cache_stats(response: Any) -> None:
        """Print prompt cache hit/miss stats if available (beta response)."""
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        cache_read   = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_create = getattr(usage, "cache_creation_input_tokens", 0) or 0
        if cache_read or cache_create:
            print(
                f"     [Cache] read={cache_read:,} tokens (saved), "
                f"created={cache_create:,} tokens, "
                f"input={getattr(usage, 'input_tokens', '?'):,} tokens"
            )


class OpenAIEngine:
    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Any = _UNSET,
        frequency_penalty: Optional[float] = None,
        presence_penalty: Optional[float] = None,
    ):
        """All config can be passed explicitly (each falls back to its OPENAI_* env
        var when omitted). The web backend passes per-scan config explicitly so
        concurrent scans on different providers never read each other's values out
        of the shared process environment; the CLI relies on the env fallback."""
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OPENAI_API_KEY is not set.")

        openai_base_url = base_url if base_url is not None else (os.environ.get("OPENAI_BASE_URL") or None)
        # Ensure base URL includes a versioned API path — the SDK default is
        # https://api.openai.com/v1/ and omitting it causes 404 on every request.
        # Providers like Z.AI already ship /paas/v4 — do not rewrite those to /v1.
        if openai_base_url:
            import re as _re
            _u = openai_base_url.rstrip("/")
            if not _re.search(r"/v\d+$", _u):
                openai_base_url = _u + "/v1"
            else:
                openai_base_url = _u

        # Capture the provider label ONCE at construction (from this instance's base
        # URL) instead of re-reading the shared env per request — a concurrent scan
        # must never be able to relabel this one's log/error messages.
        _b = (openai_base_url or "").lower()
        self._provider_label = (
            "OpenRouter" if "openrouter" in _b
            else "Z.AI" if "api.z.ai" in _b or "bigmodel.cn" in _b
            else "DeepSeek" if "deepseek" in _b
            else "xAI" if "api.x.ai" in _b
            else "Mistral" if "mistral" in _b
            else "Groq" if "groq" in _b
            else "Kimi" if "moonshot" in _b
            else "Ollama" if ("11434" in _b or "ollama" in _b)
            else "OpenAI"
        )

        transport = httpx.AsyncHTTPTransport(local_address="0.0.0.0")
        http_client = httpx.AsyncClient(transport=transport)

        client_kwargs: dict = {"api_key": self.api_key, "http_client": http_client}
        if openai_base_url:
            client_kwargs["base_url"] = openai_base_url

        self.client = AsyncOpenAI(**client_kwargs)
        # Model — explicit arg wins, else OPENAI_MODEL env (set by scan_runner), else default.
        self.default_model = model or os.environ.get("OPENAI_MODEL") or "gpt-5.1"
        try:
            self.default_max_tokens = int(max_tokens if max_tokens is not None else os.environ.get("OPENAI_MAX_TOKENS", 4096))
        except (ValueError, TypeError):
            self.default_max_tokens = 4096
        try:
            self.default_temperature = float(temperature if temperature is not None else os.environ.get("OPENAI_TEMPERATURE", 0.7))
        except (ValueError, TypeError):
            self.default_temperature = 0.7
        if top_p is _UNSET:
            _tp = os.environ.get("OPENAI_TOP_P")
            self.default_top_p: Optional[float] = float(_tp) if _tp else None
        else:
            self.default_top_p = float(top_p) if top_p is not None else None
        try:
            self.default_frequency_penalty = float(frequency_penalty if frequency_penalty is not None else os.environ.get("OPENAI_FREQUENCY_PENALTY", 0.0))
        except (ValueError, TypeError):
            self.default_frequency_penalty = 0.0
        try:
            self.default_presence_penalty = float(presence_penalty if presence_penalty is not None else os.environ.get("OPENAI_PRESENCE_PENALTY", 0.0))
        except (ValueError, TypeError):
            self.default_presence_penalty = 0.0

    async def generate_response(
        self,
        messages: List[Dict[str, Any]],
        system_prompt: str = "",
        model: str = None,
        tools: List[Dict[str, Any]] = None,
        max_tokens: int = None,
        temperature: float = None,
    ) -> Any:
        max_retries = 8  # rate limits always resolve; allow more attempts
        base_delay = 2

        _temperature = temperature if temperature is not None else self.default_temperature

        # Build message list: prepend system prompt as a system message.
        # We do this fresh each call to avoid duplication in multi-turn sessions.
        openai_messages = []
        if system_prompt:
            openai_messages.append({"role": "system", "content": system_prompt})
        openai_messages.extend(messages)

        from openai import RateLimitError as _OpenAIRateLimitError

        _skip_temperature = False  # set True for reasoning models that reject temperature

        for attempt in range(max_retries):
            try:
                kwargs = {
                    "model": model or self.default_model,
                    "messages": openai_messages,
                    "max_tokens": max_tokens if max_tokens is not None else self.default_max_tokens,
                }
                if not _skip_temperature:
                    kwargs["temperature"] = _temperature
                if self.default_top_p is not None:
                    kwargs["top_p"] = self.default_top_p
                if self.default_frequency_penalty != 0.0:
                    kwargs["frequency_penalty"] = self.default_frequency_penalty
                if self.default_presence_penalty != 0.0:
                    kwargs["presence_penalty"] = self.default_presence_penalty
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
                return _ensure_valid_completion(response, self._provider_label)

            except _OpenAIRateLimitError as e:
                exc_str = str(e)
                exc_low = exc_str.lower()
                provider_label = self._provider_label

                # Z.AI / DeepSeek / etc. often return HTTP 429 for billing, not RPM.
                # Retrying burns time; fail with an actionable message.
                if any(k in exc_low for k in (
                    "insufficient balance",
                    "no resource pack",
                    "resource package",
                    "out of credit",
                    "not enough credit",
                    "billing",
                    "'code': '1113'",
                    '"code": "1113"',
                    "code': 1113",
                    "code\": 1113",
                )) or ("1113" in exc_str and "insufficient" in exc_low):
                    msg = (
                        f"[!] {provider_label} account has no usable balance / resource pack. "
                        f"Top up credits or enable a resource package at the provider console, "
                        f"then retry. ({exc_str[:240]})"
                    )
                    print(msg)
                    raise RuntimeError(msg) from e

                # Daily quota exhausted (OpenRouter free tier) — retrying is pointless,
                # the quota won't reset until midnight UTC.
                if "per-day" in exc_low or "per_day" in exc_low or "free-models-per-day" in exc_low:
                    # Try to extract reset timestamp (milliseconds epoch) from error metadata
                    reset_hint = ""
                    import re as _re
                    _ts_match = _re.search(r"X-RateLimit-Reset['\"]:\s*['\"]?(\d+)", exc_str)
                    if _ts_match:
                        try:
                            _reset_ts = int(_ts_match.group(1)) / 1000
                            from datetime import datetime, timezone
                            _reset_dt = datetime.fromtimestamp(_reset_ts, tz=timezone.utc)
                            reset_hint = f" Quota resets at {_reset_dt.strftime('%Y-%m-%d %H:%M UTC')}."
                        except Exception:
                            pass
                    msg = (
                        f"[!] {provider_label} daily free quota exhausted. "
                        f"Add credits to your account or use a paid model.{reset_hint}"
                    )
                    print(msg)
                    raise RuntimeError(msg) from e

                # TPM/RPM rate limit — use the API's own retry-after hint.
                suggested = _parse_retry_after(exc_str)
                sleep_time = (suggested + 0.5) if suggested else 10.0
                print(f"[!] OpenAI Rate Limit (Attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    print(f"    Waiting {sleep_time:.1f}s before retrying...")
                    await asyncio.sleep(sleep_time)
                else:
                    print("[!] Max retries reached. Pipeline execution cannot continue.")
                    raise

            except Exception as e:
                exc_str = str(e)
                exc_low = exc_str.lower()

                # Permanent — fail immediately, no retry
                if "404" in exc_str:
                    msg = "[!] OpenAI Error 404: Model not found — check the model name in Settings."
                    print(msg)
                    raise RuntimeError(msg) from e
                if "401" in exc_str:
                    msg = "[!] OpenAI Error 401: Authentication failed — check your API key in Settings."
                    print(msg)
                    raise RuntimeError(msg) from e
                if "403" in exc_str:
                    msg = "[!] OpenAI Error 403: Permission denied — check your API key / account permissions."
                    print(msg)
                    raise RuntimeError(msg) from e

                # 400 — some are fixable (reasoning models reject temperature), others are fatal
                if "400" in exc_str:
                    if ("temperature" in exc_low or "unsupported parameter" in exc_low or "unsupported value" in exc_low) and not _skip_temperature:
                        print("[!] OpenAI 400: model doesn't support temperature — retrying without it.")
                        _skip_temperature = True
                        continue  # retry this attempt without temperature
                    # Any other 400 is a bad request we can't recover from
                    msg = f"[!] OpenAI Error 400: {exc_str}"
                    print(msg)
                    raise RuntimeError(msg) from e

                # 503 "no healthy upstream" (OpenRouter provider down) —
                # short flat delay, max 3 retries, then fail with clear message.
                if "503" in exc_str:
                    _503_max = 3
                    print(f"[!] OpenAI/OpenRouter 503: upstream provider unavailable "
                          f"(Attempt {attempt + 1}/{_503_max}): {exc_str[:200]}")
                    if attempt < _503_max - 1:
                        print("    Waiting 6 seconds before retrying...")
                        await asyncio.sleep(6)
                    else:
                        if self._provider_label == "OpenRouter":
                            msg = (
                                "[!] OpenRouter Error 503: upstream provider is unavailable "
                                "(\"no healthy upstream\"). Try a different model or provider in Settings."
                            )
                        else:
                            msg = "[!] OpenAI Error 503: Service unavailable — try again later."
                        print(msg)
                        raise RuntimeError(msg) from e
                    continue

                # Transient (5xx, network, etc.) — retry with backoff, capped at 20s
                print(
                    f"[!] OpenAI API Error (Attempt {attempt + 1}/{max_retries}): {e}"
                )
                if attempt < max_retries - 1:
                    sleep_time = min(base_delay * (2 ** attempt), 20)
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

        try:
            self.default_temperature = float(
                os.environ.get("OLLAMA_TEMPERATURE", _OLLAMA_FALLBACK_TEMPERATURE)
            )
        except (ValueError, TypeError):
            self.default_temperature = _OLLAMA_FALLBACK_TEMPERATURE

        _top_p = os.environ.get("OLLAMA_TOP_P")
        self.default_top_p: Optional[float] = float(_top_p) if _top_p else None
        _top_k = os.environ.get("OLLAMA_TOP_K")
        self.default_top_k: Optional[int] = int(_top_k) if _top_k else None
        _rp = os.environ.get("OLLAMA_REPEAT_PENALTY")
        self.default_repeat_penalty: Optional[float] = float(_rp) if _rp else None

        # Use a plain httpx client with generous timeouts — no IPv4-forcing transport
        # needed for a local server, and the forced local_address can cause issues.
        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=300.0, write=30.0, pool=10.0)
        )

        # Ollama Cloud (ollama.com) authenticates with a bearer token; a local
        # server ignores the key entirely but the SDK requires a non-empty value.
        self.api_key = os.environ.get("OLLAMA_API_KEY", "").strip()
        self.mode = os.environ.get("OLLAMA_MODE", "local").strip().lower()

        self.client = AsyncOpenAI(
            api_key=self.api_key or "ollama",
            base_url=f"{self.base_url}/v1",
            http_client=http_client,
        )

        # Pre-flight: verify server is reachable and model is available (sync check)
        self._check_connection()

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}

    def _check_connection(self) -> None:
        """Synchronous pre-flight check against /api/tags before the pipeline starts."""
        import json as _json

        tags_url = f"{self.base_url}/api/tags"
        print(f"[OllamaEngine] Testing connection → {tags_url} (mode={self.mode})")
        try:
            resp = httpx.get(tags_url, timeout=8.0, headers=self._auth_headers())
            # A hosted endpoint may not expose /api/tags at all. That is not a
            # reason to abort a cloud run — only an unreachable host is.
            if self.mode == "cloud" and resp.status_code in (401, 403, 404, 405):
                print(
                    f"[OllamaEngine] Cloud endpoint returned {resp.status_code} for /api/tags — "
                    f"skipping model listing, continuing with model='{self.default_model}'"
                )
                return
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
                _extra: dict = {"num_ctx": _num_ctx}
                if self.default_top_k is not None:
                    _extra["top_k"] = self.default_top_k
                if self.default_repeat_penalty is not None:
                    _extra["repeat_penalty"] = self.default_repeat_penalty
                kwargs = {
                    "model": model or self.default_model,
                    "messages": ollama_messages,
                    "max_tokens": max_tokens,
                    "temperature": _temperature,
                    "extra_body": _extra,
                }
                if self.default_top_p is not None:
                    kwargs["top_p"] = self.default_top_p
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
