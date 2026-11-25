import { useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Loader2, RefreshCw, Eye, EyeOff, Info, Trash2, AlertTriangle, X, ShieldOff, Download, Upload, Database, ChevronDown, ChevronRight, Link2, Server, Cloud } from "lucide-react";
import api from "@/api/client";
import { useAuthStore } from "@/store/authStore";

interface Settings {
  anthropic_key_set: boolean;
  anthropic_base_url: string | null;
  anthropic_max_tokens: number;
  anthropic_temperature: number | null;
  anthropic_top_p: number | null;
  openai_key_set: boolean;
  openai_base_url: string | null;
  openai_max_tokens: number;
  openai_default_model: string | null;
  openai_temperature: number | null;
  openai_top_p: number | null;
  openai_frequency_penalty: number | null;
  openai_presence_penalty: number | null;
  openrouter_key_set: boolean;
  openrouter_auth_method: string;
  openrouter_base_url: string | null;
  openrouter_max_tokens: number;
  openrouter_default_model: string | null;
  openrouter_temperature: number | null;
  openrouter_top_p: number | null;
  mistral_key_set: boolean;
  mistral_base_url: string | null;
  mistral_max_tokens: number;
  mistral_default_model: string | null;
  mistral_temperature: number | null;
  mistral_top_p: number | null;
  groq_key_set: boolean;
  groq_base_url: string | null;
  groq_max_tokens: number;
  groq_default_model: string | null;
  groq_temperature: number | null;
  groq_top_p: number | null;
  xai_key_set: boolean;
  xai_base_url: string | null;
  xai_max_tokens: number;
  xai_default_model: string | null;
  xai_temperature: number | null;
  xai_top_p: number | null;
  deepseek_key_set: boolean;
  deepseek_base_url: string | null;
  deepseek_max_tokens: number;
  deepseek_default_model: string | null;
  deepseek_temperature: number | null;
  deepseek_top_p: number | null;
  kimi_key_set: boolean;
  kimi_base_url: string | null;
  kimi_max_tokens: number;
  kimi_default_model: string | null;
  kimi_temperature: number | null;
  kimi_top_p: number | null;
  zai_key_set: boolean;
  zai_base_url: string | null;
  zai_max_tokens: number;
  zai_default_model: string | null;
  zai_temperature: number | null;
  zai_top_p: number | null;
  ollama_mode: string;
  ollama_key_set: boolean;
  ollama_base_url: string | null;
  ollama_default_model: string | null;
  ollama_temperature: number | null;
  ollama_num_ctx: number | null;
  ollama_max_tokens: number | null;
  ollama_top_p: number | null;
  ollama_top_k: number | null;
  ollama_repeat_penalty: number | null;
  max_concurrent_scans: number;
  smtp_host: string | null;
  smtp_port: number | null;
  smtp_user: string | null;
  smtp_from: string | null;
  slack_configured: boolean;
}

// ── Shared field components ────────────────────────────────────────────────────

function FieldLabel({ label, hint, tooltip }: { label: string; hint?: string; tooltip?: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="mb-1">
      <label className="text-xs font-medium text-slate-700 dark:text-zinc-300 inline-flex items-center gap-1.5">
        {label}
        {tooltip && (
          <span className="relative inline-flex items-center">
            <button
              type="button"
              onMouseEnter={() => setOpen(true)}
              onMouseLeave={() => setOpen(false)}
              onClick={() => setOpen((v) => !v)}
              className="h-3.5 w-3.5 rounded-full bg-slate-200 hover:bg-slate-300 text-slate-500 dark:text-zinc-400 text-[9px] font-bold leading-none flex items-center justify-center shrink-0 transition-colors"
              aria-label="More info"
            >
              !
            </button>
            {open && (
              <div className="absolute left-5 top-0 z-50 w-72 bg-white dark:bg-zinc-900 border border-slate-200 dark:border-zinc-800 text-slate-700 dark:text-zinc-300 text-xs rounded-lg shadow-lg p-3 leading-relaxed whitespace-pre-line pointer-events-none">
                <div className="font-semibold text-slate-800 dark:text-zinc-200 mb-1.5 border-b border-slate-200 dark:border-zinc-800 pb-1">{label}</div>
                {tooltip}
                <div className="absolute left-[-5px] top-2 w-0 h-0 border-y-4 border-y-transparent border-r-4 border-r-white" />
                <div className="absolute left-[-6px] top-2 w-0 h-0 border-y-4 border-y-transparent border-r-4 border-r-slate-200" />
              </div>
            )}
          </span>
        )}
      </label>
      {hint && <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">{hint}</p>}
    </div>
  );
}

function SectionCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-white dark:bg-zinc-900 border border-border rounded-xl p-5 space-y-4">
      {children}
    </div>
  );
}

function SectionHeader({
  title, badge, description,
}: {
  title: string; badge?: React.ReactNode; description: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3">
      <div>
        <h3 className="font-semibold text-sm text-slate-800 dark:text-zinc-100">{title}</h3>
        <p className="text-xs text-muted-foreground mt-0.5 leading-snug">{description}</p>
      </div>
      {badge}
    </div>
  );
}

/** Segmented control — used for provider connection modes. */
function ModeSwitch<T extends string>({ value, onChange, options }: {
  value: T;
  onChange: (v: T) => void;
  options: { value: T; label: string; icon?: React.ElementType; hint?: string }[];
}) {
  return (
    <div className="inline-flex items-center gap-0.5 bg-slate-100 dark:bg-zinc-800 rounded-lg p-0.5">
      {options.map(o => {
        const active = value === o.value;
        const Icon = o.icon;
        return (
          <button
            key={o.value}
            type="button"
            onClick={() => onChange(o.value)}
            title={o.hint}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all ${
              active ? "bg-white dark:bg-zinc-900 text-slate-800 dark:text-zinc-200 shadow-sm" : "text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300"
            }`}
          >
            {Icon && <Icon className="h-3.5 w-3.5" />}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/**
 * OAuth PKCE helpers for the OpenRouter connect flow.
 * The verifier stays in sessionStorage and is handed to the backend, which does
 * the code→key exchange so the key never enters frontend state.
 */
const OR_VERIFIER_KEY = "openrouter_pkce_verifier";
const OR_METHOD_KEY   = "openrouter_pkce_method";

const b64url = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/**
 * Start the OpenRouter PKCE flow.
 *
 * crypto.subtle only exists in a secure context, so any deployment reached over
 * plain http on something other than localhost (e.g. http://192.168.1.10:3000)
 * cannot compute an S256 challenge. Rather than throwing — which made the button
 * look dead — fall back to the "plain" method OpenRouter also accepts, and report
 * anything else that goes wrong instead of failing silently.
 */
async function beginOpenRouterConnect(onError?: (msg: string) => void) {
  try {
    const verifier = b64url(crypto.getRandomValues(new Uint8Array(48)));
    sessionStorage.setItem(OR_VERIFIER_KEY, verifier);

    const url = new URL("https://openrouter.ai/auth");
    url.searchParams.set("callback_url", `${window.location.origin}/settings/openrouter/callback`);

    if (window.crypto?.subtle) {
      const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
      url.searchParams.set("code_challenge", b64url(new Uint8Array(digest)));
      url.searchParams.set("code_challenge_method", "S256");
      sessionStorage.setItem(OR_METHOD_KEY, "S256");
    } else {
      url.searchParams.set("code_challenge", verifier);
      url.searchParams.set("code_challenge_method", "plain");
      sessionStorage.setItem(OR_METHOD_KEY, "plain");
    }

    window.location.href = url.toString();
  } catch (e: any) {
    onError?.(e?.message ?? "Could not start the OpenRouter connection.");
  }
}

function ConfiguredBadge({ isSet }: { isSet: boolean }) {
  return isSet ? (
    <span className="text-xs text-teal-700 dark:text-teal-300/90 flex items-center gap-1 shrink-0 mt-0.5">
      <Check className="h-3.5 w-3.5" /> Configured
    </span>
  ) : (
    <span className="text-xs text-amber-700 dark:text-amber-300/90 flex items-center gap-1 shrink-0 mt-0.5">
      Not set
    </span>
  );
}

/** Collapsible "Advanced Settings" disclosure panel */
function AdvancedPanel({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border border-slate-200 dark:border-zinc-800 rounded-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-2 px-3 py-2 text-xs font-medium text-slate-700 dark:text-zinc-300 hover:bg-slate-100 dark:hover:bg-zinc-800/40 transition-colors"
      >
        {open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
        Advanced Settings
      </button>
      {open && (
        <div className="px-3 pb-3 pt-1 border-t border-slate-200 dark:border-zinc-800 space-y-3 bg-slate-50 dark:bg-zinc-900/50">
          {children}
        </div>
      )}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<"llm" | "system" | "backup">("llm");
  // Which provider's config card is shown within the LLM Providers tab.
  const [llmProvider, setLlmProvider] = useState<string>("anthropic");
  const role = useAuthStore((s) => s.role);

  const { data: settings, isLoading } = useQuery<Settings>({
    queryKey: ["settings"],
    queryFn: () => api.get("/settings").then((r) => r.data),
  });

  const mutation = useMutation({
    mutationFn: (data: Record<string, any>) => api.patch("/settings", data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  const disconnectOpenRouter = useMutation({
    mutationFn: () => api.post("/settings/openrouter/disconnect").then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (isLoading) return <div className="text-muted-foreground">Loading settings…</div>;

  return (
    <div className="max-w-5xl mx-auto space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-800 dark:text-zinc-100">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure AI providers, notification channels, and system behavior for the pentest agent.
        </p>
      </div>

      {/* Card: left sub-navigation + content panel */}
      <div className="bg-white dark:bg-zinc-900 rounded-2xl border border-slate-200 dark:border-zinc-800 shadow-sm overflow-hidden flex flex-col sm:flex-row">
        <nav className="sm:w-56 shrink-0 border-b sm:border-b-0 sm:border-r border-slate-200 dark:border-zinc-800 p-3 flex sm:flex-col gap-1 overflow-x-auto">
          {([
            { k: "llm",    label: "LLM Providers", icon: Cloud,    hint: "AI keys & models" },
            { k: "system", label: "System",        icon: Server,   hint: "Scanning & channels" },
            { k: "backup", label: "Backup",         icon: Database, hint: "Export & restore" },
          ] as const).map((t) => (
            <button key={t.k} onClick={() => setTab(t.k)}
              className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-xl text-left transition-colors whitespace-nowrap ${
                tab === t.k
                  ? "vigilor-tab-active"
                  : "text-slate-700 dark:text-zinc-300 hover:bg-slate-50 dark:hover:bg-zinc-800/50"
              }`}>
              <t.icon className="h-4 w-4 shrink-0" />
              <span className="min-w-0">
                <span className="block text-sm font-medium leading-tight">{t.label}</span>
                <span className={`block text-[10px] leading-tight ${tab === t.k ? "opacity-80" : "text-slate-500 dark:text-zinc-400"}`}>{t.hint}</span>
              </span>
            </button>
          ))}
        </nav>

        <div className="flex-1 min-w-0 p-6">

      {tab === "llm" && settings && (
        <div className="space-y-5">
          <div className="flex gap-2.5 bg-slate-50 border border-slate-200 dark:bg-zinc-950/50 dark:border-zinc-800 rounded-lg px-4 py-3">
            <Info className="h-4 w-4 text-slate-500 dark:text-zinc-400 shrink-0 mt-0.5" />
            <p className="text-xs text-slate-600 dark:text-zinc-400 leading-relaxed">
              API keys are encrypted at rest using AES-256 and never returned in plaintext.
              Configure the provider you want to use for each scan. You can override per-scan on the New Scan page.
            </p>
          </div>

          {/* Provider selector — pick one LLM to configure */}
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
            {([
              { k: "anthropic",  label: "Anthropic",       set: !!settings.anthropic_key_set },
              { k: "openai",     label: "OpenAI",          set: !!settings.openai_key_set },
              { k: "openrouter", label: "OpenRouter",      set: !!settings.openrouter_key_set },
              { k: "ollama",     label: "Ollama",          set: settings.ollama_mode === "cloud" ? !!settings.ollama_key_set : true },
              { k: "mistral",    label: "Mistral",         set: !!settings.mistral_key_set },
              { k: "groq",       label: "Groq",            set: !!settings.groq_key_set },
              { k: "xai",        label: "xAI (Grok)",      set: !!settings.xai_key_set },
              { k: "deepseek",   label: "DeepSeek",        set: !!settings.deepseek_key_set },
              { k: "zai",        label: "Z.AI (GLM)",      set: !!settings.zai_key_set },
              { k: "kimi",       label: "Kimi (Moonshot)", set: !!settings.kimi_key_set },
            ] as const).map((p) => (
              <button key={p.k} type="button" onClick={() => setLlmProvider(p.k)}
                className={`flex items-center justify-between gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${
                  llmProvider === p.k
                    ? "border-teal-300 bg-teal-50/80 text-teal-800 font-semibold dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200"
                    : "border-slate-200 dark:border-zinc-800 hover:bg-slate-100 dark:hover:bg-zinc-800/40 text-slate-700 dark:text-zinc-300"
                }`}>
                <span className="truncate">{p.label}</span>
                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${p.set ? "bg-teal-600 dark:bg-teal-500/80" : "bg-slate-300 dark:bg-zinc-600"}`}
                      title={p.set ? "Configured" : "Not configured"} />
              </button>
            ))}
          </div>

          {llmProvider === "anthropic" && (
          <AnthropicSection
            isSet={settings.anthropic_key_set}
            baseUrl={settings.anthropic_base_url || "https://api.anthropic.com"}
            maxTokens={settings.anthropic_max_tokens || 4096}
            temperature={settings.anthropic_temperature ?? 0.7}
            topP={settings.anthropic_top_p ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ anthropic_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "openai" && (
          <OpenAISection
            isSet={settings.openai_key_set}
            baseUrl={settings.openai_base_url || "https://api.openai.com/v1"}
            maxTokens={settings.openai_max_tokens || 4096}
            defaultModel={settings.openai_default_model || ""}
            temperature={settings.openai_temperature ?? 0.7}
            topP={settings.openai_top_p ?? null}
            frequencyPenalty={settings.openai_frequency_penalty ?? 0}
            presencePenalty={settings.openai_presence_penalty ?? 0}
            onSave={(payload: Record<string, any>) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ openai_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "openrouter" && (
          <OpenRouterSection
            isSet={settings.openrouter_key_set}
            authMethod={settings.openrouter_auth_method || "manual"}
            baseUrl={settings.openrouter_base_url || "https://openrouter.ai/api/v1"}
            maxTokens={settings.openrouter_max_tokens || 4096}
            defaultModel={settings.openrouter_default_model || ""}
            temperature={settings.openrouter_temperature ?? 0.7}
            topP={settings.openrouter_top_p ?? null}
            onSave={(payload: Record<string, any>) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ openrouter_api_key: "" })}
            onDisconnect={() => disconnectOpenRouter.mutate()}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "ollama" && (
          <OllamaSection
            mode={settings.ollama_mode || "local"}
            keySet={settings.ollama_key_set}
            baseUrl={settings.ollama_base_url || "http://localhost:11434"}
            defaultModel={settings.ollama_default_model || ""}
            temperature={settings.ollama_temperature ?? 0.1}
            numCtx={settings.ollama_num_ctx ?? 8192}
            maxTokens={settings.ollama_max_tokens ?? 512}
            topP={settings.ollama_top_p ?? null}
            topK={settings.ollama_top_k ?? null}
            repeatPenalty={settings.ollama_repeat_penalty ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "mistral" && (
          <OpenAICompatSection
            provider="mistral" label="Mistral"
            description="Mistral AI models (mistral-large / medium / small, codestral) via the OpenAI-compatible API."
            defaultBase="https://api.mistral.ai/v1" placeholderModel="mistral-large-latest"
            isSet={settings.mistral_key_set}
            baseUrl={settings.mistral_base_url || "https://api.mistral.ai/v1"}
            maxTokens={settings.mistral_max_tokens || 4096}
            defaultModel={settings.mistral_default_model || ""}
            temperature={settings.mistral_temperature ?? 0.7}
            topP={settings.mistral_top_p ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ mistral_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "groq" && (
          <OpenAICompatSection
            provider="groq" label="Groq"
            description="Groq's ultra-fast inference (llama-3.3-70b-versatile, llama-3.1-8b-instant)."
            defaultBase="https://api.groq.com/openai/v1" placeholderModel="llama-3.3-70b-versatile"
            isSet={settings.groq_key_set}
            baseUrl={settings.groq_base_url || "https://api.groq.com/openai/v1"}
            maxTokens={settings.groq_max_tokens || 4096}
            defaultModel={settings.groq_default_model || ""}
            temperature={settings.groq_temperature ?? 0.7}
            topP={settings.groq_top_p ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ groq_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "xai" && (
          <OpenAICompatSection
            provider="xai" label="xAI (Grok)"
            description="xAI Grok models (grok-4.6, grok-4.5, grok-4.3)."
            defaultBase="https://api.x.ai/v1" placeholderModel="grok-4.6"
            isSet={settings.xai_key_set}
            baseUrl={settings.xai_base_url || "https://api.x.ai/v1"}
            maxTokens={settings.xai_max_tokens || 4096}
            defaultModel={settings.xai_default_model || ""}
            temperature={settings.xai_temperature ?? 0.7}
            topP={settings.xai_top_p ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ xai_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "deepseek" && (
          <OpenAICompatSection
            provider="deepseek" label="DeepSeek"
            description="Prefer deepseek-chat or deepseek-reasoner at temperature 0.2 for fewer false positives. Get a key at platform.deepseek.com."
            defaultBase="https://api.deepseek.com" placeholderModel="deepseek-chat"
            isSet={settings.deepseek_key_set}
            baseUrl={settings.deepseek_base_url || "https://api.deepseek.com"}
            maxTokens={settings.deepseek_max_tokens || 4096}
            defaultModel={settings.deepseek_default_model || ""}
            temperature={settings.deepseek_temperature ?? 0.2}
            topP={settings.deepseek_top_p ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ deepseek_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "zai" && (
          <OpenAICompatSection
            provider="zai" label="Z.AI (GLM)"
            description="Prefer glm-4.7 or glm-5 at temperature 0.2 for fewer false positives. OpenAI-compatible API at api.z.ai."
            defaultBase="https://api.z.ai/api/paas/v4" placeholderModel="glm-4.7"
            isSet={settings.zai_key_set}
            baseUrl={settings.zai_base_url || "https://api.z.ai/api/paas/v4"}
            maxTokens={settings.zai_max_tokens || 4096}
            defaultModel={settings.zai_default_model || ""}
            temperature={settings.zai_temperature ?? 0.2}
            topP={settings.zai_top_p ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ zai_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
          {llmProvider === "kimi" && (
          <OpenAICompatSection
            provider="kimi" label="Kimi (Moonshot)"
            description="Moonshot / Kimi models (kimi-latest, kimi-k2-0905-preview, moonshot-v1-*)."
            defaultBase="https://api.moonshot.ai/v1" placeholderModel="kimi-latest"
            isSet={settings.kimi_key_set}
            baseUrl={settings.kimi_base_url || "https://api.moonshot.ai/v1"}
            maxTokens={settings.kimi_max_tokens || 4096}
            defaultModel={settings.kimi_default_model || ""}
            temperature={settings.kimi_temperature ?? 0.7}
            topP={settings.kimi_top_p ?? null}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ kimi_api_key: "" })}
            saving={mutation.isPending}
          />
          )}
        </div>
      )}

      {tab === "system" && settings && (
        <div className="space-y-5">
          <SystemSection
            maxConcurrent={settings.max_concurrent_scans}
            onSave={(v) => mutation.mutate({ max_concurrent_scans: v })}
            saving={mutation.isPending}
          />
          {role === "superadmin" && <ClearDataSection />}
        </div>
      )}

      {tab === "backup" && (
        <BackupSection />
      )}

        </div>
      </div>
    </div>
  );
}

// ── Anthropic Section ─────────────────────────────────────────────────────────

function AnthropicSection({
  isSet, baseUrl, maxTokens, temperature, topP, onSave, onClearKey, saving,
}: {
  isSet: boolean; baseUrl: string; maxTokens: number;
  temperature: number; topP: number | null;
  onSave: (payload: Record<string, any>) => void;
  onClearKey: () => void; saving: boolean;
}) {
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState("");
  const [detectedModels, setDetectedModels] = useState<string[]>([]);
  const [tokensVal, setTokensVal] = useState(maxTokens);
  const [temp, setTemp] = useState(temperature);
  const [topPVal, setTopPVal] = useState<string>(topP !== null ? String(topP) : "");
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; models: string[]; error?: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const PRIORITY = ["claude-sonnet-5", "claude-opus-5", "claude-haiku-4-5-20251001", "claude-fable-5-1"];

  const testKey = async () => {
    setTesting(true); setTestResult(null);
    try {
      const res = await api.post("/settings/test-llm", { provider: "anthropic", api_key: key, base_url: url });
      setTestResult(res.data);
      if (res.data?.valid && res.data.models?.length > 0) {
        setDetectedModels(res.data.models);
        if (!model) {
          const pick = PRIORITY.find(p => res.data.models.includes(p)) ?? res.data.models[0];
          setModel(pick);
        }
      }
    } catch { setTestResult({ valid: false, models: [], error: "Request failed" }); }
    finally { setTesting(false); }
  };

  const handleSave = () => {
    const payload: Record<string, any> = {
      anthropic_base_url: url,
      anthropic_max_tokens: tokensVal,
      anthropic_temperature: temp,
      anthropic_top_p: topPVal !== "" ? parseFloat(topPVal) : null,
    };
    if (key) payload.anthropic_api_key = key;
    if (model.trim()) payload.anthropic_default_model = model.trim();
    onSave(payload);
  };

  return (
    <SectionCard>
      <SectionHeader
        title="Anthropic"
        badge={<ConfiguredBadge isSet={isSet} />}
        description="Powers Claude models (claude-sonnet-5, claude-opus-5). Best for complex reasoning and long-context analysis."
      />

      <div>
        <FieldLabel label="API Key" hint="Your Anthropic API key from console.anthropic.com"
          tooltip={"Your secret Anthropic API key - used to authenticate all scan requests to Claude.\n\nHow to get one:\n1. Go to console.anthropic.com\n2. Navigate to API Keys\n3. Create a new key and copy it\n\nKey format: sk-ant-api03-...\n\nSecurity: Keys are encrypted at rest with AES-256 and never returned in plaintext after saving. Use 'Remove Key' to revoke access."}
        />
        <div className="relative">
          <input
            type={show ? "text" : "password"}
            value={key}
            onChange={(e) => setKey(e.target.value)}
            placeholder={isSet ? "Enter new key to replace…" : "sk-ant-..."}
            className="input w-full pr-10"
          />
          <button type="button" onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
            {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
        <div className="flex gap-2 mt-2 flex-wrap items-center">
          <button onClick={testKey} disabled={!key || testing}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent disabled:opacity-50">
            {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            {testing ? "Detecting…" : "Test & Detect Models"}
          </button>
          {isSet && !confirmClear && (
            <button onClick={() => setConfirmClear(true)}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-red-300 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40">
              <ShieldOff className="h-3 w-3" /> Remove Key
            </button>
          )}
          {isSet && confirmClear && (
            <div className="flex items-center gap-2 bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-800/50 rounded-lg px-3 py-1.5">
              <span className="text-xs text-red-700 dark:text-red-300">Remove saved key?</span>
              <button onClick={() => { onClearKey(); setConfirmClear(false); }} disabled={saving}
                className="text-xs font-medium text-red-700 dark:text-red-300 hover:text-red-900 disabled:opacity-50">Yes, remove</button>
              <button onClick={() => setConfirmClear(false)}
                className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
            </div>
          )}
        </div>
        {testResult && (
          <div className={`text-xs rounded-lg px-3 py-2 mt-2 ${testResult.valid ? "bg-teal-50/80 text-teal-800 border border-teal-200/80 dark:bg-teal-950/40 dark:text-teal-200/90 dark:border-teal-800/40" : "bg-red-50 text-red-800 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/50"}`}>
            {testResult.valid
              ? `Valid: ${testResult.models.length} model(s) detected`
              : `Invalid: ${testResult.error}`}
          </div>
        )}
      </div>

      <div>
        <FieldLabel label="API Server URL" hint="Override to use a proxy or Anthropic-compatible endpoint."
          tooltip={"Leave as default unless you need to route through a proxy or use an Anthropic-compatible endpoint.\n\nCommon use cases:\n• Corporate proxy: https://your-proxy.company.com/anthropic\n• LiteLLM gateway: http://localhost:4000\n\nDefault: https://api.anthropic.com"}
        />
        <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="https://api.anthropic.com" className="input w-full" />
      </div>

      <div>
        <FieldLabel label="Default Model" hint="Model used for scans. Run Test & Detect Models to populate the dropdown."
          tooltip={"The Claude model used for all scan phases.\n\nRecommended (best → fastest):\n• claude-opus-5 - Most capable, best for complex apps\n• claude-sonnet-5 - Best balance of speed + quality (recommended)\n• claude-haiku-4-5 - Fastest, lowest cost\n\nClick 'Test & Detect Models' to auto-populate."}
        />
        {detectedModels.length > 0 ? (
          <select value={model} onChange={(e) => setModel(e.target.value)} className="input w-full">
            <option value="">Select model…</option>
            {detectedModels.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        ) : (
          <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
            placeholder="e.g. claude-sonnet-5" className="input w-full" />
        )}
      </div>

      <div>
        <FieldLabel label="Max Output Tokens" hint="Default: 4096. Claude Sonnet/Opus supports up to 8192."
          tooltip={"Maximum tokens the model can generate per response.\n\n• Too low (< 2048) - may truncate exploit steps mid-output\n• 4096 - Sufficient for most scans\n• 8192 - Recommended for large apps\n\nHigher values = more API cost per scan."}
        />
        <div className="flex gap-2 items-center">
          <input type="number" value={tokensVal} min={256} max={32768} step={256}
            onChange={(e) => setTokensVal(Math.max(256, Math.min(32768, +e.target.value)))}
            className="input w-36" />
          <span className="text-xs text-muted-foreground">tokens</span>
          <div className="flex gap-1 ml-2">
            {[2048, 4096, 8192, 16384].map((preset) => (
              <button key={preset} type="button" onClick={() => setTokensVal(preset)}
                className={`text-xs px-2 py-1 rounded border transition-colors ${tokensVal === preset ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                {preset / 1024}k
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Advanced */}
      <AdvancedPanel>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <FieldLabel label="Temperature"
              tooltip={"Controls output randomness.\n\n0.0 - Fully deterministic\n0.3 - Conservative, fewer creative exploits\n0.7 - Default, good balance (recommended)\n1.0 - Max allowed by Anthropic\n\nBest practice for pentesting: 0.5-0.8\nLower = more consistent, reproducible results\nHigher = more creative hypothesis generation\n\nNote: Anthropic caps temperature at 1.0."}
            />
            <div className="flex items-center gap-2">
              <input type="range" min={0} max={1} step={0.05} value={temp}
                onChange={(e) => setTemp(parseFloat(e.target.value))}
                className="flex-1 h-1.5 accent-primary" />
              <span className="text-xs font-mono w-8 text-right">{temp.toFixed(2)}</span>
            </div>
            <div className="flex gap-1 mt-1">
              {[0.0, 0.3, 0.7, 1.0].map((v) => (
                <button key={v} type="button" onClick={() => setTemp(v)}
                  className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${temp === v ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>

          <div>
            <FieldLabel label="Top P (nucleus sampling)"
              tooltip={"Alternative to temperature for controlling output diversity.\n\nHow it works: the model only considers tokens whose cumulative probability exceeds P.\n\n1.0 - Consider all tokens (default, recommended)\n0.95 - Ignore the bottom 5% of unlikely tokens\n0.8 - More focused, less diverse output\n\nBest practice: use either temperature OR top_p, not both.\nLeave blank to use only temperature control.\n\nFor pentesting: leave blank or set to 0.95."}
            />
            <input type="number" value={topPVal} min={0} max={1} step={0.05}
              placeholder="e.g. 0.95 (blank = off)"
              onChange={(e) => setTopPVal(e.target.value)}
              className="input w-full text-xs" />
            <p className="text-[10px] text-muted-foreground mt-0.5">Leave blank to disable</p>
          </div>
        </div>
      </AdvancedPanel>

      <div className="pt-1 border-t border-border">
        <button onClick={handleSave} disabled={saving}
          className="vigilor-btn-primary disabled:opacity-50">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          Save Anthropic / Claude Settings
        </button>
      </div>
    </SectionCard>
  );
}

// ── OpenAI Section ────────────────────────────────────────────────────────────

function OpenAISection({
  isSet, baseUrl, maxTokens, defaultModel, temperature, topP, frequencyPenalty, presencePenalty,
  onSave, onClearKey, saving,
}: {
  isSet: boolean; baseUrl: string; maxTokens: number; defaultModel: string;
  temperature: number; topP: number | null; frequencyPenalty: number; presencePenalty: number;
  onSave: (payload: Record<string, any>) => void; onClearKey: () => void; saving: boolean;
}) {
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState(defaultModel);
  const [detectedModels, setDetectedModels] = useState<string[]>([]);
  const [tokensVal, setTokensVal] = useState(maxTokens);
  const [temp, setTemp] = useState(temperature);
  const [topPVal, setTopPVal] = useState<string>(topP !== null ? String(topP) : "");
  const [freqPen, setFreqPen] = useState(frequencyPenalty);
  const [presPen, setPresPen] = useState(presencePenalty);
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; models: string[]; error?: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const PRIORITY = ["gpt-5.1", "gpt-5", "gpt-5-mini", "gpt-4.1", "gpt-4o"];

  const testKey = async () => {
    setTesting(true); setTestResult(null);
    try {
      const res = await api.post("/settings/test-llm", { provider: "openai", api_key: key, base_url: url || null });
      setTestResult(res.data);
      if (res.data?.valid && res.data.models?.length > 0) {
        setDetectedModels(res.data.models);
        if (!model) {
          const pick = PRIORITY.find(p => res.data.models.includes(p)) ?? res.data.models[0];
          setModel(pick);
        }
      }
    } catch { setTestResult({ valid: false, models: [], error: "Request failed" }); }
    finally { setTesting(false); }
  };

  const handleSave = () => {
    const payload: Record<string, any> = {
      openai_base_url: url || "https://api.openai.com/v1",
      openai_max_tokens: tokensVal,
      openai_temperature: temp,
      openai_top_p: topPVal !== "" ? parseFloat(topPVal) : null,
      openai_frequency_penalty: freqPen,
      openai_presence_penalty: presPen,
    };
    if (key) payload.openai_api_key = key;
    if (model.trim()) payload.openai_default_model = model.trim();
    onSave(payload);
  };

  return (
    <SectionCard>
      <SectionHeader title="OpenAI" badge={<ConfiguredBadge isSet={isSet} />}
        description="Powers GPT models (gpt-5.x, gpt-4.1, gpt-4o). Use a custom base URL for Azure OpenAI or any OpenAI-compatible endpoint."
      />

      <div>
        <FieldLabel label="API Key" hint="API key from platform.openai.com"
          tooltip={"Your secret OpenAI API key.\n\nKey format: sk-...\n\nSecurity: Encrypted at rest with AES-256, never returned in plaintext.\n\nNote: Reasoning models (o1, o3, o4-mini) don't support temperature - the agent handles this automatically."}
        />
        <div className="relative">
          <input type={show ? "text" : "password"} value={key} onChange={(e) => setKey(e.target.value)}
            placeholder={isSet ? "Enter new key to replace…" : "sk-..."}
            className="input w-full pr-10" />
          <button type="button" onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
            {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
        <div className="flex gap-2 mt-2 flex-wrap items-center">
          <button onClick={testKey} disabled={!key || testing}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent disabled:opacity-50">
            {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            {testing ? "Detecting…" : "Test & Detect Models"}
          </button>
          {isSet && !confirmClear && (
            <button onClick={() => setConfirmClear(true)}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-red-300 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40">
              <ShieldOff className="h-3 w-3" /> Remove Key
            </button>
          )}
          {isSet && confirmClear && (
            <div className="flex items-center gap-2 bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-800/50 rounded-lg px-3 py-1.5">
              <span className="text-xs text-red-700 dark:text-red-300">Remove saved key?</span>
              <button onClick={() => { onClearKey(); setConfirmClear(false); }} disabled={saving}
                className="text-xs font-medium text-red-700 dark:text-red-300 hover:text-red-900 disabled:opacity-50">Yes, remove</button>
              <button onClick={() => setConfirmClear(false)}
                className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
            </div>
          )}
        </div>
        {testResult && (
          <div className={`text-xs rounded-lg px-3 py-2 mt-2 ${testResult.valid ? "bg-teal-50/80 text-teal-800 border border-teal-200/80 dark:bg-teal-950/40 dark:text-teal-200/90 dark:border-teal-800/40" : "bg-red-50 text-red-800 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/50"}`}>
            {testResult.valid
              ? detectedModels.length > 0 ? `Valid: ${detectedModels.length} model(s) detected` : "Valid - key authenticated"
              : `Invalid: ${testResult.error}`}
          </div>
        )}
      </div>

      <div>
        <FieldLabel label="API Server URL" hint="Default: https://api.openai.com/v1. Change for Azure OpenAI or LiteLLM."
          tooltip={"The base endpoint for API requests. Must include /v1.\n\nExamples:\n• https://api.openai.com/v1 - Official OpenAI (default)\n• https://YOUR_RESOURCE.openai.azure.com/openai/deployments/YOUR_DEPLOYMENT - Azure OpenAI\n• http://localhost:4000 - LiteLLM proxy\n\nIMPORTANT: Always include /v1 in the URL - omitting it causes 404 errors on every request."}
        />
        <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="https://api.openai.com/v1" className="input w-full" />
      </div>

      <div>
        <FieldLabel label="Default Model" hint="Recommended: gpt-5.1 (supports tools)"
          tooltip={"Model used for scans unless overridden per-scan.\n\nRecommended for pentesting:\n• gpt-5.1 - Latest general model, strong reasoning ✓\n• gpt-5-mini - Cheaper, faster, good for simple targets\n• gpt-4.1 - Large-context general model\n• gpt-4o - Previous gen, cost-effective\n\nReasoning models (o3, o4-mini) work but may ignore temperature.\n\nClick 'Test & Detect Models' to populate dropdown."}
        />
        {detectedModels.length > 0 ? (
          <select value={model} onChange={(e) => setModel(e.target.value)} className="input w-full">
            <option value="">Select model…</option>
            {detectedModels.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        ) : (
          <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
            placeholder="gpt-5.1" className="input w-full" />
        )}
      </div>

      <div>
        <FieldLabel label="Max Output Tokens" hint="Default: 4096."
          tooltip={"Maximum tokens per LLM response.\n\n• 2048 - Fast, cheap (simple targets)\n• 4096 - Default, works for most scans\n• 8192 - Complex apps with many endpoints\n\nHigher values = more API cost."}
        />
        <div className="flex gap-2 items-center">
          <input type="number" value={tokensVal} min={256} max={100000} step={256}
            onChange={(e) => setTokensVal(Math.max(256, Math.min(100000, +e.target.value)))}
            className="input w-36" />
          <span className="text-xs text-muted-foreground">tokens</span>
          <div className="flex gap-1 ml-2">
            {[2048, 4096, 8192, 16384].map((p) => (
              <button key={p} type="button" onClick={() => setTokensVal(p)}
                className={`text-xs px-2 py-1 rounded border transition-colors ${tokensVal === p ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                {p / 1024}k
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Advanced */}
      <AdvancedPanel>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <FieldLabel label="Temperature"
              tooltip={"Controls output randomness (0.0-2.0 for OpenAI).\n\n0.0 - Fully deterministic\n0.3 - Conservative, fewer creative paths\n0.7 - Default, good balance (recommended)\n1.0 - High creativity\n2.0 - Very random, likely to hallucinate\n\nBest practice for pentesting: 0.5-0.8\n\nNote: Automatically disabled for reasoning models (o1, o3, o4-mini) that don't support it."}
            />
            <div className="flex items-center gap-2">
              <input type="range" min={0} max={2} step={0.05} value={temp}
                onChange={(e) => setTemp(parseFloat(e.target.value))}
                className="flex-1 h-1.5 accent-primary" />
              <span className="text-xs font-mono w-8 text-right">{temp.toFixed(2)}</span>
            </div>
            <div className="flex gap-1 mt-1">
              {[0.0, 0.3, 0.7, 1.0].map((v) => (
                <button key={v} type="button" onClick={() => setTemp(v)}
                  className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${temp === v ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>

          <div>
            <FieldLabel label="Top P (nucleus sampling)"
              tooltip={"Alternative to temperature - limits token selection to top-P cumulative probability.\n\n1.0 - All tokens considered (default)\n0.95 - Trim bottom 5% unlikely tokens\n0.8 - More focused output\n\nBest practice: use EITHER temperature OR top_p, not both simultaneously.\nLeave blank to rely solely on temperature.\n\nFor pentesting: leave blank or 0.95."}
            />
            <input type="number" value={topPVal} min={0} max={1} step={0.05}
              placeholder="e.g. 0.95 (blank = off)"
              onChange={(e) => setTopPVal(e.target.value)}
              className="input w-full text-xs" />
            <p className="text-[10px] text-muted-foreground mt-0.5">Leave blank to disable</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <FieldLabel label="Frequency Penalty"
              tooltip={"Reduces repetition of tokens already used in the output.\n\n0.0 - No penalty (default)\n0.3 - Mild reduction of repeated phrases\n1.0 - Strong penalty against repeating tokens\n2.0 - Maximum (may hurt coherence)\n\nBest practice for pentesting: 0.0-0.3\nHigher values can prevent repetitive exploit steps but may reduce coherence of multi-step attack chains.\n\nRange: -2.0 to 2.0"}
            />
            <div className="flex items-center gap-2">
              <input type="range" min={-2} max={2} step={0.1} value={freqPen}
                onChange={(e) => setFreqPen(parseFloat(e.target.value))}
                className="flex-1 h-1.5 accent-primary" />
              <span className="text-xs font-mono w-8 text-right">{freqPen.toFixed(1)}</span>
            </div>
          </div>

          <div>
            <FieldLabel label="Presence Penalty"
              tooltip={"Encourages the model to introduce new topics / tools not yet used.\n\n0.0 - No penalty (default)\n0.3 - Mild encouragement of novelty\n1.0 - Strongly encourages new attack vectors\n2.0 - Maximum novelty (may reduce coherence)\n\nBest practice for pentesting: 0.0-0.5\nSlight positive value can encourage exploring more diverse attack vectors.\n\nRange: -2.0 to 2.0"}
            />
            <div className="flex items-center gap-2">
              <input type="range" min={-2} max={2} step={0.1} value={presPen}
                onChange={(e) => setPresPen(parseFloat(e.target.value))}
                className="flex-1 h-1.5 accent-primary" />
              <span className="text-xs font-mono w-8 text-right">{presPen.toFixed(1)}</span>
            </div>
          </div>
        </div>
      </AdvancedPanel>

      <div className="pt-1 border-t border-border">
        <button onClick={handleSave} disabled={saving}
          className="vigilor-btn-primary disabled:opacity-50">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          Save OpenAI Settings
        </button>
      </div>
    </SectionCard>
  );
}

// ── Generic OpenAI-compatible provider section ────────────────────────────────
// Reused for Mistral, Groq, xAI (Grok), DeepSeek and Kimi — all speak the OpenAI
// chat-completions API, so one parameterised card covers them. Payload keys are
// built from `provider` (e.g. mistral_api_key, mistral_base_url, ...).

function OpenAICompatSection({
  provider, label, description, defaultBase, placeholderModel,
  isSet, baseUrl, maxTokens, defaultModel, temperature, topP,
  onSave, onClearKey, saving,
}: {
  provider: string; label: string; description: string; defaultBase: string; placeholderModel: string;
  isSet: boolean; baseUrl: string; maxTokens: number; defaultModel: string;
  temperature: number; topP: number | null;
  onSave: (payload: Record<string, any>) => void; onClearKey: () => void; saving: boolean;
}) {
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState(defaultModel);
  const [detectedModels, setDetectedModels] = useState<string[]>([]);
  const [tokensVal, setTokensVal] = useState(maxTokens);
  const [temp, setTemp] = useState(temperature);
  const [topPVal, setTopPVal] = useState<string>(topP !== null ? String(topP) : "");
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; models: string[]; error?: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const testKey = async () => {
    setTesting(true); setTestResult(null);
    try {
      const res = await api.post("/settings/test-llm", { provider, api_key: key, base_url: url || null });
      setTestResult(res.data);
      if (res.data?.valid && res.data.models?.length > 0) {
        setDetectedModels(res.data.models);
        if (!model) setModel(res.data.models[0]);
      }
    } catch { setTestResult({ valid: false, models: [], error: "Request failed" }); }
    finally { setTesting(false); }
  };

  const handleSave = () => {
    const payload: Record<string, any> = {
      [`${provider}_base_url`]: url || defaultBase,
      [`${provider}_max_tokens`]: tokensVal,
      [`${provider}_temperature`]: temp,
      [`${provider}_top_p`]: topPVal !== "" ? parseFloat(topPVal) : null,
    };
    if (key) payload[`${provider}_api_key`] = key;
    if (model.trim()) payload[`${provider}_default_model`] = model.trim();
    onSave(payload);
  };

  return (
    <SectionCard>
      <SectionHeader title={label} badge={<ConfiguredBadge isSet={isSet} />} description={description} />

      <div>
        <FieldLabel label="API Key" hint={`API key for ${label}`}
          tooltip={"Your secret API key for this provider.\n\nSecurity: Encrypted at rest with AES-256, never returned in plaintext."}
        />
        <div className="relative">
          <input type={show ? "text" : "password"} value={key} onChange={(e) => setKey(e.target.value)}
            placeholder={isSet ? "Enter new key to replace…" : "Paste API key…"}
            className="input w-full pr-10" />
          <button type="button" onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
            {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
        <div className="flex gap-2 mt-2 flex-wrap items-center">
          <button onClick={testKey} disabled={!key || testing}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent disabled:opacity-50">
            {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            {testing ? "Detecting…" : "Test & Detect Models"}
          </button>
          {isSet && !confirmClear && (
            <button onClick={() => setConfirmClear(true)}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-red-300 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40">
              <ShieldOff className="h-3 w-3" /> Remove Key
            </button>
          )}
          {isSet && confirmClear && (
            <div className="flex items-center gap-2 bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-800/50 rounded-lg px-3 py-1.5">
              <span className="text-xs text-red-700 dark:text-red-300">Remove saved key?</span>
              <button onClick={() => { onClearKey(); setConfirmClear(false); }} disabled={saving}
                className="text-xs font-medium text-red-700 dark:text-red-300 hover:text-red-900 disabled:opacity-50">Yes, remove</button>
              <button onClick={() => setConfirmClear(false)}
                className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
            </div>
          )}
        </div>
        {testResult && (
          <div className={`text-xs rounded-lg px-3 py-2 mt-2 ${testResult.valid ? "bg-teal-50/80 text-teal-800 border border-teal-200/80 dark:bg-teal-950/40 dark:text-teal-200/90 dark:border-teal-800/40" : "bg-red-50 text-red-800 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/50"}`}>
            {testResult.valid
              ? detectedModels.length > 0 ? `Valid: ${detectedModels.length} model(s) detected` : "Valid - key authenticated"
              : `Invalid: ${testResult.error}`}
          </div>
        )}
      </div>

      <div>
        <FieldLabel label="API Server URL" hint={`Default: ${defaultBase}`}
          tooltip={"The OpenAI-compatible base endpoint. The engine appends /v1 automatically if omitted."}
        />
        <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder={defaultBase} className="input w-full" />
      </div>

      <div>
        <FieldLabel label="Default Model" hint={`Recommended: ${placeholderModel}`}
          tooltip={"Model used for scans unless overridden per-scan.\n\nClick 'Test & Detect Models' to populate the dropdown, or type a model id."}
        />
        {detectedModels.length > 0 ? (
          <select value={model} onChange={(e) => setModel(e.target.value)} className="input w-full">
            <option value="">Select model…</option>
            {detectedModels.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        ) : (
          <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
            placeholder={placeholderModel} className="input w-full" />
        )}
      </div>

      <div>
        <FieldLabel label="Max Output Tokens" hint="Default: 4096." />
        <div className="flex gap-2 items-center">
          <input type="number" value={tokensVal} min={256} max={100000} step={256}
            onChange={(e) => setTokensVal(Math.max(256, Math.min(100000, +e.target.value)))}
            className="input w-36" />
          <span className="text-xs text-muted-foreground">tokens</span>
          <div className="flex gap-1 ml-2">
            {[2048, 4096, 8192, 16384].map((p) => (
              <button key={p} type="button" onClick={() => setTokensVal(p)}
                className={`text-xs px-2 py-1 rounded border transition-colors ${tokensVal === p ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                {p / 1024}k
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Advanced */}
      <AdvancedPanel>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <FieldLabel label="Temperature"
              tooltip={"Controls output randomness (0.0-2.0).\n\n0.0 - Deterministic\n0.7 - Default balance\n1.0+ - More creative.\n\nBest for pentesting: 0.5-0.8"}
            />
            <div className="flex items-center gap-2">
              <input type="range" min={0} max={2} step={0.05} value={temp}
                onChange={(e) => setTemp(parseFloat(e.target.value))}
                className="flex-1 h-1.5 accent-primary" />
              <span className="text-xs font-mono w-8 text-right">{temp.toFixed(2)}</span>
            </div>
            <div className="flex gap-1 mt-1">
              {[0.0, 0.3, 0.7, 1.0].map((v) => (
                <button key={v} type="button" onClick={() => setTemp(v)}
                  className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${temp === v ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>

          <div>
            <FieldLabel label="Top P (nucleus sampling)"
              tooltip={"Alternative to temperature. Leave blank to rely on temperature.\n\n0.95 - Trim unlikely tokens.\n\nUse EITHER temperature OR top_p."}
            />
            <input type="number" value={topPVal} min={0} max={1} step={0.05}
              placeholder="e.g. 0.95 (blank = off)"
              onChange={(e) => setTopPVal(e.target.value)}
              className="input w-full text-xs" />
            <p className="text-[10px] text-muted-foreground mt-0.5">Leave blank to disable</p>
          </div>
        </div>
      </AdvancedPanel>

      <div className="pt-1 border-t border-border">
        <button onClick={handleSave} disabled={saving}
          className="vigilor-btn-primary disabled:opacity-50">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          Save {label} Settings
        </button>
      </div>
    </SectionCard>
  );
}

// ── OpenRouter Section ────────────────────────────────────────────────────────

function OpenRouterSection({
  isSet, authMethod, baseUrl, maxTokens, defaultModel, temperature, topP,
  onSave, onClearKey, onDisconnect, saving,
}: {
  isSet: boolean; authMethod: string; baseUrl: string; maxTokens: number; defaultModel: string;
  temperature: number; topP: number | null;
  onSave: (payload: Record<string, any>) => void; onClearKey: () => void;
  onDisconnect: () => void; saving: boolean;
}) {
  const [key, setKey] = useState("");
  const [connectError, setConnectError] = useState<string | null>(null);
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState(defaultModel);
  const [detectedModels, setDetectedModels] = useState<string[]>([]);
  const [tokensVal, setTokensVal] = useState(maxTokens);
  const [temp, setTemp] = useState(temperature);
  const [topPVal, setTopPVal] = useState<string>(topP !== null ? String(topP) : "");
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; models: string[]; error?: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const PRIORITY = ["anthropic/claude-sonnet-5", "openai/gpt-5.1", "google/gemini-2.5-pro", "meta-llama/llama-3.3-70b-instruct"];

  const testKey = async () => {
    setTesting(true); setTestResult(null);
    try {
      const res = await api.post("/settings/test-llm", { provider: "openrouter", api_key: key, base_url: url || null });
      setTestResult(res.data);
      if (res.data?.valid && res.data.models?.length > 0) {
        setDetectedModels(res.data.models);
        if (!model) {
          const pick = PRIORITY.find(p => res.data.models.includes(p)) ?? res.data.models[0];
          setModel(pick);
        }
      }
    } catch { setTestResult({ valid: false, models: [], error: "Request failed" }); }
    finally { setTesting(false); }
  };

  const handleSave = () => {
    const payload: Record<string, any> = {
      openrouter_base_url: url || "https://openrouter.ai/api/v1",
      openrouter_max_tokens: tokensVal,
      openrouter_temperature: temp,
      openrouter_top_p: topPVal !== "" ? parseFloat(topPVal) : null,
    };
    if (key) payload.openrouter_api_key = key;
    if (model.trim()) payload.openrouter_default_model = model.trim();
    onSave(payload);
  };

  return (
    <SectionCard>
      <SectionHeader
        title="OpenRouter"
        badge={
          authMethod === "oauth" && isSet ? (
            <span className="text-xs text-teal-700 dark:text-teal-300/90 flex items-center gap-1 shrink-0 mt-0.5 font-medium">
              <Link2 className="h-3.5 w-3.5" /> Connected
            </span>
          ) : <ConfiguredBadge isSet={isSet} />
        }
        description="Routes requests to 200+ models (GPT-4o, Claude, Llama, Mistral, etc.) via a single API key. Best for model flexibility and cost comparison."
      />

      {/* Connect flow — the only provider here that offers a real sign-in path.
          OpenRouter mints a user-scoped key via OAuth PKCE, so no key is typed. */}
      <div className={`rounded-xl border p-3.5 ${
        authMethod === "oauth" && isSet
          ? "border-teal-200/80 bg-teal-50/80 dark:border-teal-800/40 dark:bg-teal-950/40"
          : "border-slate-200 dark:border-zinc-800 bg-slate-100 dark:bg-zinc-800/50"
      }`}>
        {authMethod === "oauth" && isSet ? (
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div className="flex items-start gap-2.5">
              <span className="h-8 w-8 rounded-lg bg-teal-100/80 text-teal-700 dark:bg-teal-950/60 dark:text-teal-300 flex items-center justify-center shrink-0">
                <Link2 className="h-4 w-4" />
              </span>
              <div>
                <p className="text-xs font-semibold text-slate-800 dark:text-zinc-200">Connected via OpenRouter sign-in</p>
                <p className="text-[11px] text-slate-500 dark:text-zinc-400 mt-0.5 leading-snug">
                  A user-scoped key was issued to this app. Revoke it any time from
                  your OpenRouter dashboard.
                </p>
              </div>
            </div>
            <button
              onClick={onDisconnect}
              className="text-xs px-3 py-1.5 rounded-lg border border-slate-300 dark:border-zinc-600 text-slate-700 dark:text-zinc-300 hover:bg-white dark:bg-zinc-900 transition-colors shrink-0"
            >
              Disconnect
            </button>
          </div>
        ) : (
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <div className="flex items-start gap-2.5">
              <span className="h-8 w-8 rounded-lg bg-slate-200 text-slate-500 dark:text-zinc-400 flex items-center justify-center shrink-0">
                <Link2 className="h-4 w-4" />
              </span>
              <div>
                <p className="text-xs font-semibold text-slate-800 dark:text-zinc-200">Connect without an API key</p>
                <p className="text-[11px] text-slate-500 dark:text-zinc-400 mt-0.5 leading-snug">
                  Sign in at OpenRouter and it issues a key to this app automatically.
                </p>
              </div>
            </div>
            <button
              onClick={() => { setConnectError(null); beginOpenRouterConnect(setConnectError); }}
              className="vigilor-btn-primary shrink-0 text-xs"
            >
              <Link2 className="h-3.5 w-3.5" /> Connect with OpenRouter
            </button>
          </div>
        )}
      </div>

      {connectError && (
        <p className="text-[11px] text-red-600 dark:text-red-400 flex items-start gap-1.5">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-px" />
          {connectError}
        </p>
      )}

      <div className="flex items-center gap-3">
        <span className="h-px flex-1 bg-slate-100 dark:bg-zinc-800" />
        <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-700 dark:text-zinc-300">or paste a key</span>
        <span className="h-px flex-1 bg-slate-100 dark:bg-zinc-800" />
      </div>

      <div>
        <FieldLabel label="API Key" hint="API key from openrouter.ai/keys"
          tooltip={"Your OpenRouter API key.\n\nKey format: sk-or-...\n\nOpenRouter requires models that support tool/function calling for agent operation.\n\nRecommended models with tool support:\n• anthropic/claude-sonnet-5\n• openai/gpt-5.1\n• google/gemini-2.5-pro\n• meta-llama/llama-3.3-70b-instruct\n\nModels WITHOUT tool support will cause errors."}
        />
        <div className="relative">
          <input type={show ? "text" : "password"} value={key} onChange={(e) => setKey(e.target.value)}
            placeholder={isSet ? "Enter new key to replace…" : "sk-or-..."}
            className="input w-full pr-10" />
          <button type="button" onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
            {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </button>
        </div>
        <div className="flex gap-2 mt-2 flex-wrap items-center">
          <button onClick={testKey} disabled={!key || testing}
            className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-border hover:bg-accent disabled:opacity-50">
            {testing ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
            {testing ? "Detecting…" : "Test & Detect Models"}
          </button>
          {isSet && !confirmClear && (
            <button onClick={() => setConfirmClear(true)}
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-red-300 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/40">
              <ShieldOff className="h-3 w-3" /> Remove Key
            </button>
          )}
          {isSet && confirmClear && (
            <div className="flex items-center gap-2 bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-800/50 rounded-lg px-3 py-1.5">
              <span className="text-xs text-red-700 dark:text-red-300">Remove saved key?</span>
              <button onClick={() => { onClearKey(); setConfirmClear(false); }} disabled={saving}
                className="text-xs font-medium text-red-700 dark:text-red-300 hover:text-red-900 disabled:opacity-50">Yes, remove</button>
              <button onClick={() => setConfirmClear(false)}
                className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
            </div>
          )}
        </div>
        {testResult && (
          <div className={`text-xs rounded-lg px-3 py-2 mt-2 ${testResult.valid ? "bg-teal-50/80 text-teal-800 border border-teal-200/80 dark:bg-teal-950/40 dark:text-teal-200/90 dark:border-teal-800/40" : "bg-red-50 text-red-800 border border-red-200 dark:bg-red-950/40 dark:text-red-300 dark:border-red-800/50"}`}>
            {testResult.valid
              ? detectedModels.length > 0 ? `Valid: ${detectedModels.length} model(s) detected` : "Valid - key authenticated"
              : `Invalid: ${testResult.error}`}
          </div>
        )}
      </div>

      <div>
        <FieldLabel label="API Server URL" hint="Default: https://openrouter.ai/api/v1"
          tooltip={"The OpenRouter API endpoint. Change only if using a self-hosted or proxied OpenRouter-compatible server.\n\nDefault: https://openrouter.ai/api/v1\n\nIMPORTANT: Always include /v1 in the URL."}
        />
        <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="https://openrouter.ai/api/v1" className="input w-full" />
      </div>

      <div>
        <FieldLabel label="Default Model" hint="e.g. anthropic/claude-sonnet-5, openai/gpt-5.1"
          tooltip={"The model used for scans via OpenRouter.\n\nFormat: provider/model-name\n\nRecommended (tool use + good pentest quality):\n• anthropic/claude-sonnet-5 - Best reasoning\n• openai/gpt-5.1 - Strong all-round\n• google/gemini-2.5-pro - Large context\n• meta-llama/llama-3.3-70b-instruct - Open source\n\nAvoid models without function/tool calling support."}
        />
        {detectedModels.length > 0 ? (
          <select value={model} onChange={(e) => setModel(e.target.value)} className="input w-full">
            <option value="">Select model…</option>
            {detectedModels.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        ) : (
          <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
            placeholder="anthropic/claude-sonnet-5" className="input w-full" />
        )}
      </div>

      <div>
        <FieldLabel label="Max Output Tokens" hint="Default: 4096."
          tooltip={"Maximum tokens per LLM response.\n\n• 2048 - Fast and cheap\n• 4096 - Default, good for most scans\n• 8192 - Large apps\n\nCost varies by model - check OpenRouter pricing."}
        />
        <div className="flex gap-2 items-center">
          <input type="number" value={tokensVal} min={256} max={100000} step={256}
            onChange={(e) => setTokensVal(Math.max(256, Math.min(100000, +e.target.value)))}
            className="input w-36" />
          <span className="text-xs text-muted-foreground">tokens</span>
          <div className="flex gap-1 ml-2">
            {[2048, 4096, 8192, 16384].map((p) => (
              <button key={p} type="button" onClick={() => setTokensVal(p)}
                className={`text-xs px-2 py-1 rounded border transition-colors ${tokensVal === p ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                {p / 1024}k
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Advanced */}
      <AdvancedPanel>
        <div className="grid grid-cols-2 gap-3">
          <div>
            <FieldLabel label="Temperature"
              tooltip={"Controls output randomness.\n\n0.0 - Fully deterministic\n0.7 - Default, recommended for pentesting\n1.0 - High creativity\n\nNote: Some models via OpenRouter may have their own temperature caps. If a model returns errors, try lowering this value.\n\nBest practice: 0.5-0.8 for pentest tasks."}
            />
            <div className="flex items-center gap-2">
              <input type="range" min={0} max={2} step={0.05} value={temp}
                onChange={(e) => setTemp(parseFloat(e.target.value))}
                className="flex-1 h-1.5 accent-primary" />
              <span className="text-xs font-mono w-8 text-right">{temp.toFixed(2)}</span>
            </div>
            <div className="flex gap-1 mt-1">
              {[0.0, 0.3, 0.7, 1.0].map((v) => (
                <button key={v} type="button" onClick={() => setTemp(v)}
                  className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${temp === v ? "border-teal-300 bg-teal-50/80 text-teal-800 dark:border-teal-800/50 dark:bg-teal-950/40 dark:text-teal-200" : "border-border hover:bg-accent"}`}>
                  {v}
                </button>
              ))}
            </div>
          </div>

          <div>
            <FieldLabel label="Top P (nucleus sampling)"
              tooltip={"Limits token selection to top-P cumulative probability.\n\n1.0 - All tokens (default)\n0.95 - Trim bottom 5% of unlikely tokens\n0.8 - More focused\n\nBest practice: use EITHER temperature OR top_p.\nLeave blank to rely solely on temperature."}
            />
            <input type="number" value={topPVal} min={0} max={1} step={0.05}
              placeholder="e.g. 0.95 (blank = off)"
              onChange={(e) => setTopPVal(e.target.value)}
              className="input w-full text-xs" />
            <p className="text-[10px] text-muted-foreground mt-0.5">Leave blank to disable</p>
          </div>
        </div>
      </AdvancedPanel>

      <div className="pt-1 border-t border-border">
        <button onClick={handleSave} disabled={saving}
          className="vigilor-btn-primary disabled:opacity-50">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          Save OpenRouter Settings
        </button>
      </div>
    </SectionCard>
  );
}

// ── Ollama Section ────────────────────────────────────────────────────────────

function OllamaSection({
  mode: initialMode, keySet, baseUrl, defaultModel, temperature, numCtx, maxTokens,
  topP, topK, repeatPenalty, onSave, saving,
}: {
  mode: string; keySet: boolean;
  baseUrl: string; defaultModel: string; temperature: number; numCtx: number; maxTokens: number;
  topP: number | null; topK: number | null; repeatPenalty: number | null;
  onSave: (payload: Record<string, any>) => void; saving: boolean;
}) {
  const [mode, setMode] = useState<"local" | "cloud">(initialMode === "cloud" ? "cloud" : "local");
  const [apiKey, setApiKey] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState(defaultModel);
  const [temp, setTemp] = useState(temperature);
  const [ctx, setCtx] = useState(numCtx);
  const [maxTok, setMaxTok] = useState(maxTokens);
  const [topPVal, setTopPVal] = useState<string>(topP !== null ? String(topP) : "");
  const [topKVal, setTopKVal] = useState<string>(topK !== null ? String(topK) : "");
  const [repeatPenVal, setRepeatPenVal] = useState<string>(repeatPenalty !== null ? String(repeatPenalty) : "");
  const [models, setModels] = useState<string[]>([]);
  const [detecting, setDetecting] = useState(false);
  const [detectMsg, setDetectMsg] = useState<string | null>(null);

  // Switching mode swaps in that mode's conventional endpoint, unless the user
  // has already typed something non-default.
  const switchMode = (m: "local" | "cloud") => {
    setMode(m);
    if (m === "cloud" && (!url || url.includes("localhost") || url.includes("127.0.0.1") || url.includes("host.docker.internal")))
      setUrl("https://ollama.com");
    if (m === "local" && url.includes("ollama.com"))
      setUrl("http://localhost:11434");
  };

  const detect = async () => {
    setDetecting(true);
    setDetectMsg(null);
    try {
      const res = await api.post("/settings/detect-ollama-models", { base_url: url });
      setModels(res.data);
      if (res.data.length === 0) setDetectMsg(`No models found at ${url}`);
    } catch { setModels([]); setDetectMsg(`Cannot reach Ollama at ${url}. Check the URL and that the server is running.`); }
    finally { setDetecting(false); }
  };

  const handleSave = () => {
    onSave({
      ollama_mode: mode,
      ...(apiKey ? { ollama_api_key: apiKey } : {}),
      ollama_base_url: url,
      ollama_default_model: model,
      ollama_temperature: temp,
      ollama_num_ctx: ctx,
      ollama_max_tokens: maxTok,
      ollama_top_p: topPVal !== "" ? parseFloat(topPVal) : null,
      ollama_top_k: topKVal !== "" ? parseInt(topKVal) : null,
      ollama_repeat_penalty: repeatPenVal !== "" ? parseFloat(repeatPenVal) : null,
    });
  };

  return (
    <SectionCard>
      <SectionHeader
        title="Ollama"
        badge={mode === "cloud" ? <ConfiguredBadge isSet={keySet} /> : (
          <span className="text-xs text-slate-500 dark:text-zinc-400 flex items-center gap-1 shrink-0 mt-0.5">
            <Server className="h-3.5 w-3.5" /> No auth needed
          </span>
        )}
        description="Open-weight models, either on your own hardware or on Ollama's hosted service."
      />

      {/* Local vs cloud: a self-hosted server needs no credentials, the hosted
          service needs an API key. Everything below adapts to the choice. */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <ModeSwitch
          value={mode}
          onChange={switchMode}
          options={[
            { value: "local", label: "Local server", icon: Server, hint: "Self-hosted Ollama - no credentials" },
            { value: "cloud", label: "Ollama Cloud", icon: Cloud, hint: "ollama.com hosted models - API key required" },
          ]}
        />
        <p className="text-[11px] text-slate-500 dark:text-zinc-400 leading-snug flex-1 min-w-[200px]">
          {mode === "local"
            ? "Runs fully offline. Nothing leaves your network."
            : "Requests go to ollama.com and are billed to that account."}
        </p>
      </div>

      {mode === "cloud" && (
        <div>
          <FieldLabel label="API Key" hint="Create one at ollama.com → Settings → Keys"
            tooltip={"API key for Ollama's hosted service.\n\nOnly needed in Cloud mode - a local Ollama server accepts requests without authentication.\n\nThe key is encrypted at rest and never returned to the browser."}
          />
          <div className="relative">
            <input type={showKey ? "text" : "password"} value={apiKey} onChange={(e) => setApiKey(e.target.value)}
              placeholder={keySet ? "Enter new key to replace…" : "Paste your Ollama Cloud key"}
              className="input w-full pr-10" />
            <button type="button" onClick={() => setShowKey(!showKey)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground">
              {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
        </div>
      )}

      <div>
        <FieldLabel
          label={mode === "local" ? "Server URL" : "API Endpoint"}
          hint={mode === "local"
            ? "Must be reachable from the backend container."
            : "Ollama's hosted endpoint. Leave as-is unless you were given another."}
          tooltip={mode === "local"
            ? "The address where your Ollama instance is running.\n\nCommon values:\n• http://localhost:11434 - Ollama on the same machine\n• http://host.docker.internal:11434 - Host machine from inside Docker\n• http://192.168.1.100:11434 - Remote machine on LAN\n\nIMPORTANT: The URL must be reachable from the BACKEND CONTAINER, not your browser. Use http://host.docker.internal:11434 if Ollama is on the host and backend is in Docker."
            : "Base URL of the hosted service - normally https://ollama.com.\n\nThe engine appends /v1 for chat calls and sends your API key as a bearer token."}
        />
        <div className="flex gap-2">
          <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
            className="input flex-1"
            placeholder={mode === "local" ? "http://localhost:11434" : "https://ollama.com"} />
          <button onClick={detect} disabled={detecting}
            title={mode === "cloud" ? "The hosted service may not expose a model list" : undefined}
            className="flex items-center gap-1.5 text-xs px-3 py-2 border border-border rounded-lg hover:bg-accent disabled:opacity-50 shrink-0">
            {detecting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Detect Models
          </button>
        </div>
        {detectMsg && <p className="text-xs text-red-600 dark:text-red-400 mt-1.5">{detectMsg}</p>}
      </div>

      <div>
        <FieldLabel label="Default Model" hint="Click Detect Models to populate the dropdown."
          tooltip={"The local model to use for scans.\n\nRecommended for pentesting:\n• llama3.2:latest - Good balance, fast (3B/8B)\n• llama3.1:70b - High quality, needs 48GB+ VRAM\n• deepseek-coder-v2 - Strong at code analysis\n• qwen2.5:14b - Good multilingual reasoning\n• mistral:latest - Fast, lightweight\n\nInstall: ollama pull llama3.2\n\nNote: Local models are significantly less capable than GPT-4o/Claude for complex reasoning tasks."}
        />
        {models.length > 0 ? (
          <select value={model} onChange={(e) => setModel(e.target.value)} className="input w-full">
            <option value="">Select model…</option>
            {models.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        ) : (
          <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
            placeholder="e.g. llama3.2:latest" className="input w-full" />
        )}
        {models.length > 0 && <p className="text-xs text-teal-700 dark:text-teal-300/90 mt-1">{models.length} model(s) detected</p>}
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div>
          <FieldLabel label="Temperature" hint="0=deterministic, 1=creative"
            tooltip={"Controls how 'creative' or 'random' the model's responses are.\n\n0.0 - Fully deterministic\n0.1 - Recommended for pentesting (consistent, focused)\n0.5 - Moderate creativity\n1.0 - Highly random, may hallucinate\n\nFor security analysis: keep LOW (0.0-0.2) for consistent, accurate results."}
          />
          <input type="number" value={temp} min={0} max={1} step={0.05}
            onChange={(e) => setTemp(parseFloat(e.target.value))} className="input w-full" />
        </div>
        <div>
          <FieldLabel label="Context Window (num_ctx)" hint="Min 8192 recommended"
            tooltip={"Maximum tokens (input + output) the model processes per request.\n\nGuidelines:\n• 8192 - Minimum, may truncate large pages\n• 16384 - Recommended for most targets\n• 32768 - Large apps with many endpoints\n• 65536+ - Needs significant VRAM\n\nMemory: ~1 GB per 8K tokens for 7B models."}
          />
          <input type="number" value={ctx} min={2048} max={131072} step={1024}
            onChange={(e) => setCtx(parseInt(e.target.value))} className="input w-full" />
        </div>
        <div>
          <FieldLabel label="Max Output Tokens" hint="Keep 512-1024 for local models"
            tooltip={"Maximum tokens generated per LLM call.\n\nKeep lower for Ollama:\n• Local models are slower per token\n• High values eat context window budget\n\nRecommended:\n• 512 - Fast, may truncate complex exploits\n• 1024 - Good balance\n• 2048 - Thorough, slower"}
          />
          <input type="number" value={maxTok} min={64} max={8192} step={64}
            onChange={(e) => setMaxTok(parseInt(e.target.value))} className="input w-full" />
        </div>
      </div>

      {/* Advanced */}
      <AdvancedPanel>
        <div className="grid grid-cols-3 gap-3">
          <div>
            <FieldLabel label="Top P"
              tooltip={"Nucleus sampling - limits token selection to top-P cumulative probability.\n\n1.0 - All tokens (default)\n0.9 - Good balance for local models\n0.7 - More focused and deterministic\n\nBest practice for local models: 0.9\nLocal models benefit more from top_p tuning than cloud models because they're more prone to token probability distribution issues.\n\nLeave blank to disable (temperature-only control)."}
            />
            <input type="number" value={topPVal} min={0} max={1} step={0.05}
              placeholder="blank = off"
              onChange={(e) => setTopPVal(e.target.value)}
              className="input w-full text-xs" />
          </div>

          <div>
            <FieldLabel label="Top K"
              tooltip={"Limits token selection to the K most probable next tokens.\n\n0 - Disabled (default)\n40 - Common default for Llama models\n100 - Wider vocabulary, more creative\n\nBest practice for pentesting:\n• 40-50 - Good for most local models\n• Lower values = more predictable, focused output\n\nSetting both top_p and top_k applies both filters simultaneously - Ollama picks whichever is more restrictive."}
            />
            <input type="number" value={topKVal} min={0} max={500} step={1}
              placeholder="blank = off"
              onChange={(e) => setTopKVal(e.target.value)}
              className="input w-full text-xs" />
          </div>

          <div>
            <FieldLabel label="Repeat Penalty"
              tooltip={"Penalizes tokens that have already appeared in the output to reduce repetition.\n\n1.0 - No penalty (default)\n1.1 - Slight penalty (recommended for most models)\n1.3 - Moderate, good for reducing looping\n1.5 - Strong penalty, may hurt coherence\n\nBest practice for local pentesting models:\n• 1.1 - Reduces repetitive exploit steps\n• 1.15-1.2 - For models that tend to loop\n\nLeave blank to use Ollama's default (1.1 for most models)."}
            />
            <input type="number" value={repeatPenVal} min={0.5} max={2} step={0.05}
              placeholder="blank = default"
              onChange={(e) => setRepeatPenVal(e.target.value)}
              className="input w-full text-xs" />
          </div>
        </div>
      </AdvancedPanel>

      <button onClick={handleSave} disabled={saving}
        className="vigilor-btn-primary disabled:opacity-50">
        {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
        Save Ollama Settings
      </button>
    </SectionCard>
  );
}

// ── System Section ────────────────────────────────────────────────────────────

function SystemSection({
  maxConcurrent, onSave, saving,
}: {
  maxConcurrent: number; onSave: (v: number) => void; saving: boolean;
}) {
  const [val, setVal] = useState(maxConcurrent);
  return (
    <SectionCard>
      <SectionHeader
        title="Scan Limits"
        description="Control how many scans can run in parallel. Higher values increase throughput but may exhaust LLM API rate limits and system resources."
      />
      <div>
        <FieldLabel
          label="Max Concurrent Scans"
          hint="Number of active scans allowed to run simultaneously on this server. Recommended: 1-3."
          tooltip={"How many scans can run at the same time on this server.\n\nEach active scan:\n• Opens 1 Chromium browser instance\n• Makes parallel LLM API calls\n• Uses ~200-500MB RAM\n\nGuidelines:\n• 1 - Safe default, sequential scans\n• 2-3 - Good for teams with multiple users\n• 4+ - Requires high RAM and API rate limits\n\nWARNING: Each scan makes many parallel LLM calls. Running 3 concurrent scans = 9+ simultaneous API calls. Ensure your API tier supports the rate limit."}
        />
        <input type="number" value={val} min={1} max={10} onChange={(e) => setVal(+e.target.value)}
          className="input w-32" />
      </div>
      <button onClick={() => onSave(val)} disabled={saving}
        className="vigilor-btn-primary disabled:opacity-50">
        {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
        Save
      </button>
    </SectionCard>
  );
}

// ── Clear Data Modal ───────────────────────────────────────────────────────────

function ClearDataModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient();
  const [phase, setPhase] = useState<"warn" | "confirm" | "done">("warn");
  const [result, setResult] = useState<{ scans_deleted: number; findings_deleted: number; logs_deleted: number } | null>(null);

  const mutation = useMutation({
    mutationFn: () =>
      api.post("/settings/clear-data", { confirm: "DELETE ALL DATA" }).then((r) => r.data),
    onSuccess: (data) => {
      setResult(data);
      setPhase("done");
      qc.invalidateQueries();
    },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
      <div className="bg-white dark:bg-zinc-900 rounded-2xl shadow-2xl w-full max-w-md overflow-hidden">
        <div className={`flex items-center justify-between px-6 py-4 ${phase === "done" ? "bg-teal-50/80 border-b border-teal-200/80 dark:bg-teal-950/40 dark:border-teal-800/40" : "bg-red-50 border-b border-red-200 dark:bg-red-950/40 dark:border-red-800/50"}`}>
          <div className="flex items-center gap-2">
            {phase === "done" ? <Check className="h-5 w-5 text-teal-700 dark:text-teal-300" /> : <AlertTriangle className="h-5 w-5 text-red-600 dark:text-red-400" />}
            <h2 className="text-base font-semibold text-slate-800 dark:text-zinc-100">
              {phase === "done" ? "Database Cleared" : "Clear All Data"}
            </h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="px-6 py-5 space-y-4">
          {phase === "warn" && (
            <>
              <div className="bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-800/50 rounded-lg p-4 space-y-2">
                <p className="text-sm font-semibold text-red-800">⚠️ This action is permanent and cannot be undone.</p>
                <ul className="text-xs text-red-700 dark:text-red-300 space-y-1 list-disc list-inside">
                  <li>All scan records and logs</li>
                  <li>All findings, comments, and evidence screenshots</li>
                  <li>All generated reports</li>
                </ul>
                <p className="text-xs text-red-700 dark:text-red-300 font-medium mt-2">
                  User accounts and settings (API keys, system config) will NOT be deleted.
                </p>
              </div>
              <div className="flex gap-2 justify-end">
                <button onClick={onClose} className="px-4 py-2 text-sm border border-border rounded-lg hover:bg-accent">Cancel</button>
                <button onClick={() => setPhase("confirm")} className="px-4 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-500 font-medium">I understand, continue</button>
              </div>
            </>
          )}
          {phase === "confirm" && (
            <>
              <p className="text-sm text-slate-700 dark:text-zinc-300 leading-relaxed">
                To confirm, type <span className="font-mono font-bold text-red-700 dark:text-red-300">DELETE ALL DATA</span> and click delete.
              </p>
              <ConfirmInput onConfirmed={() => mutation.mutate()} onCancel={onClose} isLoading={mutation.isPending} />
            </>
          )}
          {phase === "done" && result && (
            <>
              <p className="text-sm text-slate-700 dark:text-zinc-300">The following records have been permanently deleted:</p>
              <div className="bg-slate-100 dark:bg-zinc-800/40 border border-border rounded-lg divide-y divide-border text-sm">
                <div className="flex justify-between px-4 py-2"><span className="text-muted-foreground">Scans</span><span className="font-semibold">{result.scans_deleted}</span></div>
                <div className="flex justify-between px-4 py-2"><span className="text-muted-foreground">Findings</span><span className="font-semibold">{result.findings_deleted}</span></div>
                <div className="flex justify-between px-4 py-2"><span className="text-muted-foreground">Scan Logs</span><span className="font-semibold">{result.logs_deleted}</span></div>
              </div>
              <div className="flex justify-end">
                <button onClick={onClose} className="vigilor-btn-primary text-sm px-4 py-2">Close</button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ConfirmInput({ onConfirmed, onCancel, isLoading }: { onConfirmed: () => void; onCancel: () => void; isLoading: boolean; }) {
  const [value, setValue] = useState("");
  const phrase = "DELETE ALL DATA";
  const match = value === phrase;
  return (
    <div className="space-y-3">
      <input type="text" value={value} onChange={(e) => setValue(e.target.value)} placeholder={phrase}
        className={`w-full text-sm border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 font-mono ${match ? "border-red-500 ring-red-200" : "border-border focus:ring-ring"}`} />
      <div className="flex gap-2 justify-end">
        <button onClick={onCancel} disabled={isLoading} className="px-4 py-2 text-sm border border-border rounded-lg hover:bg-accent disabled:opacity-50">Cancel</button>
        <button onClick={onConfirmed} disabled={!match || isLoading}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-500 disabled:opacity-40 font-medium">
          {isLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Trash2 className="h-3.5 w-3.5" />}
          Delete All Data
        </button>
      </div>
    </div>
  );
}

// ── Backup Section ────────────────────────────────────────────────────────────

function BackupSection() {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [importing, setImporting] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [importResult, setImportResult] = useState<{ message: string; inserted: Record<string, number>; evidence_restored?: number } | null>(null);
  const [importError, setImportError] = useState<string | null>(null);

  const handleExport = async () => {
    setExporting(true);
    try {
      const res = await api.get("/admin/backup/export", { responseType: "blob" });
      const cd = res.headers["content-disposition"] ?? "";
      const match = cd.match(/filename="?([^"]+)"?/);
      const filename = match ? match[1] : `pentest_backup_${new Date().toISOString().slice(0, 10)}.zip`;
      const url = window.URL.createObjectURL(res.data as Blob);
      const a = document.createElement("a");
      a.href = url; a.download = filename; a.click();
      window.URL.revokeObjectURL(url);
    } catch { alert("Export failed. Check your permissions."); }
    finally { setExporting(false); }
  };

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImporting(true); setImportResult(null); setImportError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await api.post("/admin/backup/import", formData, { headers: { "Content-Type": "multipart/form-data" } });
      setImportResult(res.data);
    } catch (err: any) {
      setImportError(err?.response?.data?.detail ?? "Import failed");
    } finally {
      setImporting(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex gap-2.5 bg-slate-50 border border-slate-200 dark:bg-zinc-950/50 dark:border-zinc-800 rounded-lg px-4 py-3">
        <Database className="h-4 w-4 text-slate-500 dark:text-zinc-400 shrink-0 mt-0.5" />
        <p className="text-xs text-slate-600 dark:text-zinc-400 leading-relaxed">
          Backup exports all <strong>scans, findings, projects, comments, and evidence screenshots</strong> as a single <strong>.zip</strong> file.
          User accounts and API keys are excluded for security. On import, existing records (by ID) are skipped.
        </p>
      </div>
      <div className="bg-white dark:bg-zinc-900 border border-border rounded-xl p-5 space-y-3">
        <div>
          <h3 className="font-semibold text-sm text-slate-800 dark:text-zinc-100 flex items-center gap-2"><Download className="h-4 w-4" />Export Database</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Download a full snapshot of all scan data.</p>
        </div>
        <button onClick={handleExport} disabled={exporting}
          className="vigilor-btn-primary disabled:opacity-50 font-medium">
          {exporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
          {exporting ? "Exporting…" : "Download Backup"}
        </button>
      </div>
      <div className="bg-white dark:bg-zinc-900 border border-border rounded-xl p-5 space-y-3">
        <div>
          <h3 className="font-semibold text-sm text-slate-800 dark:text-zinc-100 flex items-center gap-2"><Upload className="h-4 w-4" />Import Backup</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Restore from a <strong>.zip</strong> backup. Legacy <strong>.json</strong> also supported. Existing records are skipped.</p>
        </div>
        <div className="flex items-center gap-3">
          <input ref={fileInputRef} type="file" accept=".zip,.json" className="hidden" onChange={handleImport} />
          <button onClick={() => fileInputRef.current?.click()} disabled={importing}
            className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg border border-border hover:bg-accent disabled:opacity-50 font-medium">
            {importing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
            {importing ? "Importing…" : "Select Backup File"}
          </button>
          {importing && <span className="text-xs text-muted-foreground">Processing, please wait…</span>}
        </div>
        {importResult && (
          <div className="bg-teal-50/80 border border-teal-200/80 dark:bg-teal-950/40 dark:border-teal-800/40 rounded-lg px-4 py-3 space-y-1">
            <p className="text-sm font-medium text-teal-800 dark:text-teal-200 flex items-center gap-1.5"><Check className="h-4 w-4" /> Import successful</p>
            <p className="text-xs text-teal-700 dark:text-teal-300/90">{importResult.message}</p>
            <div className="grid grid-cols-5 gap-2 mt-2">
              {Object.entries(importResult.inserted).map(([k, v]) => (
                <div key={k} className="text-center bg-white dark:bg-zinc-900 border border-teal-200/80 dark:border-teal-800/40 rounded-lg py-2">
                  <p className="text-lg font-bold text-teal-800 dark:text-teal-200">{v}</p>
                  <p className="text-[10px] text-muted-foreground capitalize">{k}</p>
                </div>
              ))}
              {importResult.evidence_restored !== undefined && (
                <div className="text-center bg-white dark:bg-zinc-900 border border-teal-200/80 dark:border-teal-800/40 rounded-lg py-2">
                  <p className="text-lg font-bold text-teal-800 dark:text-teal-200">{importResult.evidence_restored}</p>
                  <p className="text-[10px] text-muted-foreground">evidence files</p>
                </div>
              )}
            </div>
          </div>
        )}
        {importError && (
          <div className="bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-800/50 rounded-lg px-4 py-3">
            <p className="text-sm font-medium text-red-800 flex items-center gap-1.5"><AlertTriangle className="h-4 w-4" /> Import failed</p>
            <p className="text-xs text-red-700 dark:text-red-300 mt-1">{importError}</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Clear Data Section ─────────────────────────────────────────────────────────

function ClearDataSection() {
  const [showModal, setShowModal] = useState(false);
  return (
    <>
      <div className="bg-white dark:bg-zinc-900 border border-red-800/50 rounded-xl p-5 space-y-4">
        <div>
          <h3 className="font-semibold text-sm text-red-700 dark:text-red-300 flex items-center gap-2"><Trash2 className="h-4 w-4" />Danger Zone</h3>
          <p className="text-xs text-muted-foreground mt-0.5">Irreversible actions that affect all scan and finding data.</p>
        </div>
        <div className="flex items-center justify-between gap-4 bg-red-50 border border-red-200 dark:bg-red-950/40 dark:border-red-800/50 rounded-lg px-4 py-3">
          <div>
            <p className="text-sm font-medium text-slate-800 dark:text-zinc-100">Clear All Data</p>
            <p className="text-xs text-muted-foreground mt-0.5">Permanently delete all scans, findings, logs, and evidence. User accounts and settings are preserved.</p>
          </div>
          <button onClick={() => setShowModal(true)}
            className="shrink-0 flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg border border-red-300 dark:border-red-800/60 text-red-700 dark:text-red-300 hover:bg-red-50 dark:hover:bg-red-950/40 font-medium transition-colors">
            <Trash2 className="h-3.5 w-3.5" /> Clear Data
          </button>
        </div>
      </div>
      {showModal && <ClearDataModal onClose={() => setShowModal(false)} />}
    </>
  );
}
