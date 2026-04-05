import { useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, Loader2, RefreshCw, Eye, EyeOff, Info, Trash2, AlertTriangle, X, ShieldOff, Download, Upload, Database } from "lucide-react";
import api from "@/api/client";
import { useAuthStore } from "@/store/authStore";

interface Settings {
  anthropic_key_set: boolean;
  anthropic_base_url: string | null;
  anthropic_max_tokens: number;
  openai_key_set: boolean;
  openai_base_url: string | null;
  openai_max_tokens: number;
  openai_default_model: string | null;
  openrouter_key_set: boolean;
  openrouter_base_url: string | null;
  openrouter_max_tokens: number;
  openrouter_default_model: string | null;
  ollama_base_url: string | null;
  ollama_default_model: string | null;
  ollama_temperature: number | null;
  ollama_num_ctx: number | null;
  ollama_max_tokens: number | null;
  max_concurrent_scans: number;
  smtp_host: string | null;
  smtp_port: number | null;
  smtp_user: string | null;
  smtp_from: string | null;
  slack_configured: boolean;
}

// ── Shared field components ────────────────────────────────────────────────────

function FieldLabel({ label, hint }: { label: string; hint?: string }) {
  return (
    <div className="mb-1">
      <label className="text-xs font-medium text-gray-700">{label}</label>
      {hint && <p className="text-[11px] text-muted-foreground mt-0.5 leading-snug">{hint}</p>}
    </div>
  );
}

function SectionCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="bg-white border border-border rounded-xl p-5 space-y-4">
      {children}
    </div>
  );
}

function SectionHeader({
  title,
  badge,
  description,
}: {
  title: string;
  badge?: React.ReactNode;
  description: string;
}) {
  return (
    <div className="flex items-start justify-between gap-3">
      <div>
        <h3 className="font-semibold text-sm text-gray-900">{title}</h3>
        <p className="text-xs text-muted-foreground mt-0.5 leading-snug">{description}</p>
      </div>
      {badge}
    </div>
  );
}

function ConfiguredBadge({ isSet }: { isSet: boolean }) {
  return isSet ? (
    <span className="text-xs text-green-600 flex items-center gap-1 shrink-0 mt-0.5">
      <Check className="h-3.5 w-3.5" /> Configured
    </span>
  ) : (
    <span className="text-xs text-amber-600 flex items-center gap-1 shrink-0 mt-0.5">
      Not set
    </span>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function SettingsPage() {
  const qc = useQueryClient();
  const [tab, setTab] = useState<"llm" | "system" | "backup">("llm");
  const role = useAuthStore((s) => s.role);

  const { data: settings, isLoading } = useQuery<Settings>({
    queryKey: ["settings"],
    queryFn: () => api.get("/settings").then((r) => r.data),
  });

  const mutation = useMutation({
    mutationFn: (data: Record<string, any>) => api.patch("/settings", data).then((r) => r.data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (isLoading) return <div className="text-muted-foreground">Loading settings…</div>;

  return (
    <div className="max-w-2xl mx-auto space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Configure AI providers, API keys, and system behavior for the pentest agent.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-border">
        {(["llm", "system", "backup"] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition-colors -mb-px ${
              tab === t ? "border-primary text-primary" : "border-transparent text-muted-foreground hover:text-foreground"
            }`}
          >
            {t === "llm" ? "LLM Providers" : t === "system" ? "System" : "Backup"}
          </button>
        ))}
      </div>

      {tab === "llm" && settings && (
        <div className="space-y-5">
          {/* Info banner */}
          <div className="flex gap-2.5 bg-blue-50 border border-blue-200 rounded-lg px-4 py-3">
            <Info className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
            <p className="text-xs text-blue-700 leading-relaxed">
              API keys are encrypted at rest using AES-256 and never returned in plaintext.
              Configure the provider you want to use for each scan — you can override per-scan on the New Scan page.
            </p>
          </div>

          <AnthropicSection
            isSet={settings.anthropic_key_set}
            baseUrl={settings.anthropic_base_url || "https://api.anthropic.com"}
            maxTokens={settings.anthropic_max_tokens || 4096}
            onSave={(payload) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ anthropic_api_key: "" })}
            saving={mutation.isPending}
          />
          <OpenAISection
            isSet={settings.openai_key_set}
            baseUrl={settings.openai_base_url || "https://api.openai.com"}
            maxTokens={settings.openai_max_tokens || 4096}
            defaultModel={settings.openai_default_model || ""}
            onSave={(payload: Record<string, any>) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ openai_api_key: "" })}
            saving={mutation.isPending}
          />
          <OpenRouterSection
            isSet={settings.openrouter_key_set}
            baseUrl={settings.openrouter_base_url || "https://openrouter.ai/api/v1"}
            maxTokens={settings.openrouter_max_tokens || 4096}
            defaultModel={settings.openrouter_default_model || ""}
            onSave={(payload: Record<string, any>) => mutation.mutate(payload)}
            onClearKey={() => mutation.mutate({ openrouter_api_key: "" })}
            saving={mutation.isPending}
          />
          <OllamaSection
            baseUrl={settings.ollama_base_url || "http://localhost:11434"}
            defaultModel={settings.ollama_default_model || ""}
            temperature={settings.ollama_temperature ?? 0.1}
            numCtx={settings.ollama_num_ctx ?? 8192}
            maxTokens={settings.ollama_max_tokens ?? 512}
            onSave={(url, model, temp, ctx, maxTok) => mutation.mutate({
              ollama_base_url: url,
              ollama_default_model: model,
              ollama_temperature: temp,
              ollama_num_ctx: ctx,
              ollama_max_tokens: maxTok,
            })}
            saving={mutation.isPending}
          />
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
  );
}

// ── Anthropic Section ─────────────────────────────────────────────────────────

function AnthropicSection({
  isSet, baseUrl, maxTokens, onSave, onClearKey, saving,
}: {
  isSet: boolean; baseUrl: string; maxTokens: number;
  onSave: (payload: Record<string, any>) => void;
  onClearKey: () => void; saving: boolean;
}) {
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState("");
  const [detectedModels, setDetectedModels] = useState<string[]>([]);
  const [tokensVal, setTokensVal] = useState(maxTokens);
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; models: string[]; error?: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const PRIORITY = ["claude-sonnet-4-6", "claude-opus-4-6", "claude-haiku-4-5", "claude-3-5-sonnet-20241022"];

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
        description="Powers Claude models (claude-sonnet-4-6, claude-opus-4-6). Best for complex reasoning and long-context analysis."
      />

      <div>
        <FieldLabel label="API Key" hint="Your Anthropic API key from console.anthropic.com" />
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
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-red-300 text-red-600 hover:bg-red-50">
              <ShieldOff className="h-3 w-3" /> Remove Key
            </button>
          )}
          {isSet && confirmClear && (
            <div className="flex items-center gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-1.5">
              <span className="text-xs text-red-700">Remove saved key?</span>
              <button onClick={() => { onClearKey(); setConfirmClear(false); }} disabled={saving}
                className="text-xs font-medium text-red-700 hover:text-red-900 disabled:opacity-50">Yes, remove</button>
              <button onClick={() => setConfirmClear(false)}
                className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
            </div>
          )}
        </div>
        {testResult && (
          <div className={`text-xs rounded-lg px-3 py-2 mt-2 ${testResult.valid ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-700 border border-red-200"}`}>
            {testResult.valid
              ? `Valid — ${testResult.models.length} model(s) detected`
              : `Invalid: ${testResult.error}`}
          </div>
        )}
      </div>

      <div>
        <FieldLabel label="API Server URL" hint="Override to use a proxy or Anthropic-compatible endpoint. Default: https://api.anthropic.com" />
        <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder="https://api.anthropic.com" className="input w-full" />
      </div>

      <div>
        <FieldLabel label="Default Model" hint="Model used for scans. Run Test & Detect Models to populate the dropdown." />
        {detectedModels.length > 0 ? (
          <select value={model} onChange={(e) => setModel(e.target.value)} className="input w-full">
            <option value="">Select model…</option>
            {detectedModels.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        ) : (
          <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
            placeholder="e.g. claude-sonnet-4-6" className="input w-full" />
        )}
        {detectedModels.length > 0 && (
          <p className="text-xs text-green-600 mt-1">{detectedModels.length} model(s) available</p>
        )}
      </div>

      <div>
        <FieldLabel label="Max Output Tokens" hint="Default: 4096. Claude Sonnet/Opus supports up to 8192." />
        <div className="flex gap-2 items-center">
          <input type="number" value={tokensVal} min={256} max={32768} step={256}
            onChange={(e) => setTokensVal(Math.max(256, Math.min(32768, +e.target.value)))}
            className="input w-36" />
          <span className="text-xs text-muted-foreground">tokens</span>
          <div className="flex gap-1 ml-2">
            {[1024, 2048, 4096, 8192].map((preset) => (
              <button key={preset} type="button" onClick={() => setTokensVal(preset)}
                className={`text-xs px-2 py-1 rounded border transition-colors ${tokensVal === preset ? "border-primary bg-primary/10 text-primary" : "border-border hover:bg-accent"}`}>
                {preset >= 1024 ? `${preset / 1024}k` : preset}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="pt-1 border-t border-border">
        <button onClick={handleSave} disabled={saving}
          className="flex items-center gap-1.5 text-xs px-4 py-2 rounded-lg bg-primary text-primary-foreground disabled:opacity-50">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          Save Anthropic / Claude Settings
        </button>
      </div>
    </SectionCard>
  );
}

// ── Shared OpenAI-compatible section (used by OpenRouter & OpenCode) ──────────

interface OAICompatProps {
  providerKey: string;
  title: string;
  description: string;
  keyPlaceholder: string;
  keyHint: string;
  defaultUrl: string;
  modelHint: string;
  modelPlaceholder: string;
  priorityModels: string[];
  saveLabel: string;
  isSet: boolean;
  baseUrl: string;
  maxTokens: number;
  defaultModel: string;
  onSave: (payload: Record<string, any>) => void;
  onClearKey: () => void;
  saving: boolean;
}

function OAICompatSection({
  providerKey, title, description,
  keyPlaceholder, keyHint, defaultUrl, modelHint, modelPlaceholder, priorityModels, saveLabel,
  isSet, baseUrl, maxTokens, defaultModel,
  onSave, onClearKey, saving,
}: OAICompatProps) {
  const [key, setKey] = useState("");
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState(defaultModel);
  const [detectedModels, setDetectedModels] = useState<string[]>([]);
  const [tokensVal, setTokensVal] = useState(maxTokens);
  const [show, setShow] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ valid: boolean; models: string[]; error?: string } | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  const pickModel = (models: string[]) => {
    for (const p of priorityModels) {
      if (models.includes(p)) return p;
    }
    return models[0] ?? "";
  };

  const testKey = async () => {
    setTesting(true); setTestResult(null);
    try {
      const res = await api.post("/settings/test-llm", {
        provider: providerKey,
        api_key: key,
        base_url: url || null,
      });
      setTestResult(res.data);
      if (res.data?.valid && res.data.models?.length > 0) {
        setDetectedModels(res.data.models);
        if (!model) setModel(pickModel(res.data.models));
      }
    } catch { setTestResult({ valid: false, models: [], error: "Request failed" }); }
    finally { setTesting(false); }
  };

  const handleSave = () => {
    const payload: Record<string, any> = {
      [`${providerKey}_base_url`]: url || defaultUrl,
      [`${providerKey}_max_tokens`]: tokensVal,
    };
    if (key) payload[`${providerKey}_api_key`] = key;
    if (model.trim()) payload[`${providerKey}_default_model`] = model.trim();
    onSave(payload);
  };

  return (
    <SectionCard>
      <SectionHeader title={title} badge={<ConfiguredBadge isSet={isSet} />} description={description} />

      {/* API Key */}
      <div>
        <FieldLabel label="API Key" hint={keyHint} />
        <div className="relative">
          <input type={show ? "text" : "password"} value={key} onChange={(e) => setKey(e.target.value)}
            placeholder={isSet ? "Enter new key to replace…" : keyPlaceholder}
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
              className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-red-300 text-red-600 hover:bg-red-50">
              <ShieldOff className="h-3 w-3" /> Remove Key
            </button>
          )}
          {isSet && confirmClear && (
            <div className="flex items-center gap-2 bg-red-50 border border-red-200 rounded-lg px-3 py-1.5">
              <span className="text-xs text-red-700">Remove saved key?</span>
              <button onClick={() => { onClearKey(); setConfirmClear(false); }} disabled={saving}
                className="text-xs font-medium text-red-700 hover:text-red-900 disabled:opacity-50">Yes, remove</button>
              <button onClick={() => setConfirmClear(false)}
                className="text-xs text-muted-foreground hover:text-foreground">Cancel</button>
            </div>
          )}
        </div>
        {testResult && (
          <div className={`text-xs rounded-lg px-3 py-2 mt-2 ${testResult.valid ? "bg-green-50 text-green-700 border border-green-200" : "bg-red-50 text-red-700 border border-red-200"}`}>
            {testResult.valid
              ? detectedModels.length > 0
                ? `Valid — ${detectedModels.length} model(s) detected`
                : "Valid — key authenticated (no model list available)"
              : `Invalid: ${testResult.error}`}
          </div>
        )}
      </div>

      {/* API Server URL */}
      <div>
        <FieldLabel label="API Server URL" hint="Base URL of the API endpoint. Change only if using a custom proxy or self-hosted instance." />
        <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
          placeholder={defaultUrl} className="input w-full" />
      </div>

      {/* Default Model — dropdown after detect, text input otherwise */}
      <div>
        <FieldLabel label="Default Model" hint={detectedModels.length > 0 ? `${detectedModels.length} models available — select one below` : modelHint} />
        {detectedModels.length > 0 ? (
          <select value={model} onChange={(e) => setModel(e.target.value)} className="input w-full">
            <option value="">Select model…</option>
            {detectedModels.map((m) => <option key={m} value={m}>{m}</option>)}
          </select>
        ) : (
          <input type="text" value={model} onChange={(e) => setModel(e.target.value)}
            placeholder={modelPlaceholder} className="input w-full" />
        )}
        {detectedModels.length > 0 && (
          <p className="text-xs text-green-600 mt-1">{detectedModels.length} model(s) available</p>
        )}
      </div>

      {/* Max Tokens */}
      <div>
        <FieldLabel label="Max Output Tokens" hint="Maximum tokens per LLM response. Default: 4096." />
        <div className="flex gap-2 items-center">
          <input type="number" value={tokensVal} min={256} max={100000} step={256}
            onChange={(e) => setTokensVal(Math.max(256, Math.min(100000, +e.target.value)))}
            className="input w-36" />
          <span className="text-xs text-muted-foreground">tokens</span>
          <div className="flex gap-1 ml-2">
            {[1024, 2048, 4096, 8192].map((p) => (
              <button key={p} type="button" onClick={() => setTokensVal(p)}
                className={`text-xs px-2 py-1 rounded border transition-colors ${tokensVal === p ? "border-primary bg-primary/10 text-primary" : "border-border hover:bg-accent"}`}>
                {p >= 1024 ? `${p / 1024}k` : p}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="pt-1 border-t border-border">
        <button onClick={handleSave} disabled={saving}
          className="flex items-center gap-1.5 text-xs px-4 py-2 rounded-lg bg-primary text-primary-foreground disabled:opacity-50">
          {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          {saveLabel}
        </button>
      </div>
    </SectionCard>
  );
}

// ── OpenAI Section ────────────────────────────────────────────────────────────

function OpenAISection({ isSet, baseUrl, maxTokens, defaultModel, onSave, onClearKey, saving }: {
  isSet: boolean; baseUrl: string; maxTokens: number; defaultModel: string;
  onSave: (payload: Record<string, any>) => void; onClearKey: () => void; saving: boolean;
}) {
  return (
    <OAICompatSection
      providerKey="openai"
      title="OpenAI"
      description="Powers GPT models (gpt-4o, gpt-4-turbo, o1, o3). Use a custom base URL for Azure OpenAI, LiteLLM proxy, or any OpenAI-compatible endpoint."
      keyPlaceholder="sk-..."
      keyHint="API key from platform.openai.com"
      defaultUrl="https://api.openai.com"
      modelHint="e.g. gpt-4o, gpt-4o-mini, gpt-4-turbo, o1, o3-mini"
      modelPlaceholder="gpt-4o"
      priorityModels={["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "o1", "o3-mini"]}
      saveLabel="Save OpenAI Settings"
      isSet={isSet} baseUrl={baseUrl} maxTokens={maxTokens} defaultModel={defaultModel}
      onSave={onSave} onClearKey={onClearKey} saving={saving}
    />
  );
}

// ── OpenRouter Section ────────────────────────────────────────────────────────

function OpenRouterSection({ isSet, baseUrl, maxTokens, defaultModel, onSave, onClearKey, saving }: {
  isSet: boolean; baseUrl: string; maxTokens: number; defaultModel: string;
  onSave: (payload: Record<string, any>) => void; onClearKey: () => void; saving: boolean;
}) {
  return (
    <OAICompatSection
      providerKey="openrouter"
      title="OpenRouter"
      description="Routes requests to 200+ models (GPT-4o, Claude, Llama, Mistral, etc.) via a single API key. Best for model flexibility and cost comparison."
      keyPlaceholder="sk-or-..."
      keyHint="API key from openrouter.ai/keys"
      defaultUrl="https://openrouter.ai/api/v1"
      modelHint="e.g. openai/gpt-4o, anthropic/claude-3-5-sonnet, meta-llama/llama-3.3-70b-instruct"
      modelPlaceholder="openai/gpt-4o"
      priorityModels={["openai/gpt-4o", "openai/gpt-4-turbo", "anthropic/claude-3-5-sonnet", "meta-llama/llama-3.3-70b-instruct"]}
      saveLabel="Save OpenRouter Settings"
      isSet={isSet} baseUrl={baseUrl} maxTokens={maxTokens} defaultModel={defaultModel}
      onSave={onSave} onClearKey={onClearKey} saving={saving}
    />
  );
}

// ── Ollama Section ────────────────────────────────────────────────────────────

function OllamaSection({
  baseUrl, defaultModel, temperature, numCtx, maxTokens, onSave, saving,
}: {
  baseUrl: string; defaultModel: string; temperature: number; numCtx: number; maxTokens: number;
  onSave: (url: string, model: string, temp: number, ctx: number, maxTok: number) => void; saving: boolean;
}) {
  const [url, setUrl] = useState(baseUrl);
  const [model, setModel] = useState(defaultModel);
  const [temp, setTemp] = useState(temperature);
  const [ctx, setCtx] = useState(numCtx);
  const [maxTok, setMaxTok] = useState(maxTokens);
  const [models, setModels] = useState<string[]>([]);
  const [detecting, setDetecting] = useState(false);

  const detect = async () => {
    setDetecting(true);
    try {
      const res = await api.post("/settings/detect-ollama-models", { base_url: url });
      setModels(res.data);
      if (res.data.length === 0) alert("No models found at " + url);
    } catch { alert("Cannot reach Ollama at " + url); }
    finally { setDetecting(false); }
  };

  return (
    <SectionCard>
      <SectionHeader
        title="Ollama (Local LLM)"
        description="Run scans entirely offline using locally hosted models. Requires Ollama to be running and accessible from this server. Suitable for air-gapped or privacy-sensitive engagements."
      />

      <div>
        <FieldLabel
          label="Server URL"
          hint="The base URL where Ollama is listening. Must be reachable from the backend container."
        />
        <div className="flex gap-2">
          <input type="url" value={url} onChange={(e) => setUrl(e.target.value)}
            className="input flex-1" placeholder="http://localhost:11434" />
          <button onClick={detect} disabled={detecting}
            className="flex items-center gap-1.5 text-xs px-3 py-2 border border-border rounded-lg hover:bg-accent disabled:opacity-50 shrink-0">
            {detecting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Detect Models
          </button>
        </div>
      </div>

      <div>
        <FieldLabel
          label="Default Model"
          hint="Model used when no override is selected per-scan. Click Detect Models to populate the dropdown."
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
        {models.length > 0 && (
          <p className="text-xs text-green-600 mt-1">{models.length} model(s) detected</p>
        )}
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div>
          <FieldLabel
            label="Temperature"
            hint="Controls randomness (0 = deterministic, 1 = creative). Lower values give more consistent pentest results."
          />
          <input type="number" value={temp} min={0} max={1} step={0.05}
            onChange={(e) => setTemp(parseFloat(e.target.value))} className="input w-full" />
        </div>
        <div>
          <FieldLabel
            label="Context Window (num_ctx)"
            hint="Max tokens the model can process per request. Larger values allow longer conversations but use more memory. Minimum 8192 recommended."
          />
          <input type="number" value={ctx} min={2048} max={131072} step={1024}
            onChange={(e) => setCtx(parseInt(e.target.value))} className="input w-full" />
        </div>
        <div>
          <FieldLabel
            label="Max Output Tokens"
            hint="Maximum tokens the model generates per response. Keep low (512–1024) for local models to avoid context overflow."
          />
          <input type="number" value={maxTok} min={64} max={8192} step={64}
            onChange={(e) => setMaxTok(parseInt(e.target.value))} className="input w-full" />
        </div>
      </div>

      <button onClick={() => onSave(url, model, temp, ctx, maxTok)} disabled={saving}
        className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-primary text-primary-foreground disabled:opacity-50">
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
          hint="Number of active scans allowed to run simultaneously on this server. Recommended: 1–3."
        />
        <input type="number" value={val} min={1} max={10} onChange={(e) => setVal(+e.target.value)}
          className="input w-32" />
      </div>
      <button onClick={() => onSave(val)} disabled={saving}
        className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-primary text-primary-foreground disabled:opacity-50">
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
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md overflow-hidden">

        {/* Header */}
        <div className={`flex items-center justify-between px-6 py-4 ${phase === "done" ? "bg-green-50 border-b border-green-200" : "bg-red-50 border-b border-red-200"}`}>
          <div className="flex items-center gap-2">
            {phase === "done"
              ? <Check className="h-5 w-5 text-green-600" />
              : <AlertTriangle className="h-5 w-5 text-red-600" />
            }
            <h2 className="text-base font-semibold text-gray-900">
              {phase === "done" ? "Database Cleared" : "Clear All Data"}
            </h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-4">
          {phase === "warn" && (
            <>
              <div className="bg-red-50 border border-red-200 rounded-lg p-4 space-y-2">
                <p className="text-sm font-semibold text-red-800">⚠️ This action is permanent and cannot be undone.</p>
                <p className="text-xs text-red-700 leading-relaxed">
                  All of the following data will be permanently deleted:
                </p>
                <ul className="text-xs text-red-700 space-y-1 list-disc list-inside">
                  <li>All scan records and logs</li>
                  <li>All findings, comments, and evidence screenshots</li>
                  <li>All generated reports</li>
                </ul>
                <p className="text-xs text-red-700 font-medium mt-2">
                  User accounts and settings (API keys, system config) will NOT be deleted.
                </p>
              </div>
              <div className="flex gap-2 justify-end">
                <button onClick={onClose}
                  className="px-4 py-2 text-sm border border-border rounded-lg hover:bg-accent">
                  Cancel
                </button>
                <button onClick={() => setPhase("confirm")}
                  className="px-4 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-500 font-medium">
                  I understand, continue
                </button>
              </div>
            </>
          )}

          {phase === "confirm" && (
            <>
              <p className="text-sm text-gray-700 leading-relaxed">
                To confirm, type <span className="font-mono font-bold text-red-700">DELETE ALL DATA</span> in the box below and click the delete button.
              </p>
              <ConfirmInput
                onConfirmed={() => mutation.mutate()}
                onCancel={onClose}
                isLoading={mutation.isPending}
              />
            </>
          )}

          {phase === "done" && result && (
            <>
              <p className="text-sm text-gray-700">The following records have been permanently deleted:</p>
              <div className="bg-slate-50 border border-border rounded-lg divide-y divide-border text-sm">
                <div className="flex justify-between px-4 py-2">
                  <span className="text-muted-foreground">Scans</span>
                  <span className="font-semibold">{result.scans_deleted}</span>
                </div>
                <div className="flex justify-between px-4 py-2">
                  <span className="text-muted-foreground">Findings</span>
                  <span className="font-semibold">{result.findings_deleted}</span>
                </div>
                <div className="flex justify-between px-4 py-2">
                  <span className="text-muted-foreground">Scan Logs</span>
                  <span className="font-semibold">{result.logs_deleted}</span>
                </div>
              </div>
              <div className="flex justify-end">
                <button onClick={onClose}
                  className="px-4 py-2 text-sm bg-primary text-primary-foreground rounded-lg">
                  Close
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function ConfirmInput({
  onConfirmed, onCancel, isLoading,
}: {
  onConfirmed: () => void;
  onCancel: () => void;
  isLoading: boolean;
}) {
  const [value, setValue] = useState("");
  const phrase = "DELETE ALL DATA";
  const match = value === phrase;
  return (
    <div className="space-y-3">
      <input
        type="text"
        value={value}
        onChange={(e) => setValue(e.target.value)}
        placeholder={phrase}
        className={`w-full text-sm border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 font-mono ${
          match ? "border-red-500 ring-red-200" : "border-border focus:ring-ring"
        }`}
      />
      <div className="flex gap-2 justify-end">
        <button onClick={onCancel} disabled={isLoading}
          className="px-4 py-2 text-sm border border-border rounded-lg hover:bg-accent disabled:opacity-50">
          Cancel
        </button>
        <button
          onClick={onConfirmed}
          disabled={!match || isLoading}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-red-600 text-white rounded-lg hover:bg-red-500 disabled:opacity-40 font-medium"
        >
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
      a.href = url;
      a.download = filename;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch {
      alert("Export failed. Check your permissions.");
    } finally {
      setExporting(false);
    }
  };

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImporting(true);
    setImportResult(null);
    setImportError(null);
    try {
      const formData = new FormData();
      formData.append("file", file);
      const res = await api.post("/admin/backup/import", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
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
      {/* Info */}
      <div className="flex gap-2.5 bg-blue-50 border border-blue-200 rounded-lg px-4 py-3">
        <Database className="h-4 w-4 text-blue-500 shrink-0 mt-0.5" />
        <p className="text-xs text-blue-700 leading-relaxed">
          Backup exports all <strong>scans, findings, projects, comments, and evidence screenshots</strong> as a single <strong>.zip</strong> file.
          User accounts and API keys are excluded for security. On import, existing records (by ID) are skipped — no data is overwritten.
          Legacy <strong>.json</strong> backups are also supported for import.
        </p>
      </div>

      {/* Export */}
      <div className="bg-white border border-border rounded-xl p-5 space-y-3">
        <div>
          <h3 className="font-semibold text-sm text-gray-900 flex items-center gap-2">
            <Download className="h-4 w-4" />
            Export Database
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5 leading-snug">
            Download a full JSON snapshot of all scan data. Use this to back up before clearing data or migrating.
          </p>
        </div>
        <button
          onClick={handleExport}
          disabled={exporting}
          className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg bg-primary text-primary-foreground disabled:opacity-50 font-medium"
        >
          {exporting ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
          {exporting ? "Exporting…" : "Download Backup"}
        </button>
      </div>

      {/* Import */}
      <div className="bg-white border border-border rounded-xl p-5 space-y-3">
        <div>
          <h3 className="font-semibold text-sm text-gray-900 flex items-center gap-2">
            <Upload className="h-4 w-4" />
            Import Backup
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5 leading-snug">
            Restore data from a previously exported <strong>.zip</strong> backup (includes evidence screenshots). Legacy <strong>.json</strong> backups are also supported. Existing records are skipped.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <input
            ref={fileInputRef}
            type="file"
            accept=".zip,.json"
            className="hidden"
            onChange={handleImport}
          />
          <button
            onClick={() => fileInputRef.current?.click()}
            disabled={importing}
            className="flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg border border-border hover:bg-accent disabled:opacity-50 font-medium"
          >
            {importing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />}
            {importing ? "Importing…" : "Select Backup File"}
          </button>
          {importing && <span className="text-xs text-muted-foreground">Processing, please wait…</span>}
        </div>

        {/* Import result */}
        {importResult && (
          <div className="bg-green-50 border border-green-200 rounded-lg px-4 py-3 space-y-1">
            <p className="text-sm font-medium text-green-800 flex items-center gap-1.5">
              <Check className="h-4 w-4" /> Import successful
            </p>
            <p className="text-xs text-green-700">{importResult.message}</p>
            <div className="grid grid-cols-5 gap-2 mt-2">
              {Object.entries(importResult.inserted).map(([k, v]) => (
                <div key={k} className="text-center bg-white border border-green-200 rounded-lg py-2">
                  <p className="text-lg font-bold text-green-700">{v}</p>
                  <p className="text-[10px] text-muted-foreground capitalize">{k}</p>
                </div>
              ))}
              {importResult.evidence_restored !== undefined && (
                <div className="text-center bg-white border border-green-200 rounded-lg py-2">
                  <p className="text-lg font-bold text-green-700">{importResult.evidence_restored}</p>
                  <p className="text-[10px] text-muted-foreground">evidence files</p>
                </div>
              )}
            </div>
          </div>
        )}

        {importError && (
          <div className="bg-red-50 border border-red-200 rounded-lg px-4 py-3">
            <p className="text-sm font-medium text-red-800 flex items-center gap-1.5">
              <AlertTriangle className="h-4 w-4" /> Import failed
            </p>
            <p className="text-xs text-red-700 mt-1">{importError}</p>
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
      <div className="bg-white border border-red-200 rounded-xl p-5 space-y-4">
        <div>
          <h3 className="font-semibold text-sm text-red-700 flex items-center gap-2">
            <Trash2 className="h-4 w-4" />
            Danger Zone
          </h3>
          <p className="text-xs text-muted-foreground mt-0.5 leading-snug">
            Irreversible actions that affect all scan and finding data.
          </p>
        </div>
        <div className="flex items-center justify-between gap-4 bg-red-50 border border-red-200 rounded-lg px-4 py-3">
          <div>
            <p className="text-sm font-medium text-gray-900">Clear All Data</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Permanently delete all scans, findings, logs, and evidence. User accounts and settings are preserved.
            </p>
          </div>
          <button
            onClick={() => setShowModal(true)}
            className="shrink-0 flex items-center gap-1.5 text-sm px-4 py-2 rounded-lg border border-red-300 text-red-700 hover:bg-red-100 font-medium transition-colors"
          >
            <Trash2 className="h-3.5 w-3.5" />
            Clear Data
          </button>
        </div>
      </div>
      {showModal && <ClearDataModal onClose={() => setShowModal(false)} />}
    </>
  );
}
