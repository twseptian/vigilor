/**
 * Landing page for the OpenRouter OAuth PKCE redirect.
 *
 * OpenRouter sends the user back here with ?code=…; we hand that code plus the
 * PKCE verifier to the backend, which performs the exchange and stores the
 * resulting key encrypted. The key itself never touches this page.
 */
import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Loader2, Check, AlertTriangle } from "lucide-react";
import api from "@/api/client";

const OR_VERIFIER_KEY = "openrouter_pkce_verifier";
const OR_METHOD_KEY   = "openrouter_pkce_method";

export default function OpenRouterCallback() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [state, setState] = useState<"working" | "done" | "error">("working");
  const [message, setMessage] = useState("Completing the connection…");
  const ran = useRef(false);   // StrictMode double-invoke guard: the code is single-use

  useEffect(() => {
    if (ran.current) return;
    ran.current = true;

    const code = params.get("code");
    const error = params.get("error");

    if (error) {
      setState("error");
      setMessage(`OpenRouter returned: ${error}`);
      return;
    }
    if (!code) {
      setState("error");
      setMessage("No authorization code was returned. Start the connection again from Settings.");
      return;
    }

    const verifier = sessionStorage.getItem(OR_VERIFIER_KEY);
    // Must match whatever method the connect step actually used — a secure
    // context gets S256, plain http on a non-localhost host falls back to plain.
    const method = sessionStorage.getItem(OR_METHOD_KEY) || "S256";

    api.post("/settings/openrouter/oauth-exchange", {
      code,
      code_verifier: verifier || undefined,
      code_challenge_method: method,
    })
      .then(() => {
        sessionStorage.removeItem(OR_VERIFIER_KEY);
        sessionStorage.removeItem(OR_METHOD_KEY);
        setState("done");
        setMessage("OpenRouter connected. Returning to Settings…");
        setTimeout(() => navigate("/settings", { replace: true }), 1400);
      })
      .catch((e: any) => {
        setState("error");
        setMessage(e?.response?.data?.detail ?? "The exchange failed. Try connecting again.");
      });
  }, [params, navigate]);

  const tone =
    state === "done"  ? { ring: "border-emerald-800/50 bg-emerald-50", text: "text-emerald-700" }
    : state === "error" ? { ring: "border-red-800/50 bg-red-50",       text: "text-red-700 dark:text-red-300" }
    :                     { ring: "border-slate-200 dark:border-zinc-800 bg-white dark:bg-zinc-900",      text: "text-slate-700 dark:text-zinc-300" };

  return (
    <div className="flex items-center justify-center min-h-[60vh] px-4">
      <div className={`w-full max-w-md rounded-2xl border shadow-sm p-6 text-center ${tone.ring}`}>
        <div className="flex justify-center mb-3">
          {state === "working" && <Loader2 className="h-7 w-7 text-slate-500 dark:text-zinc-400 animate-spin" />}
          {state === "done" && <Check className="h-7 w-7 text-emerald-700 dark:text-emerald-400" />}
          {state === "error" && <AlertTriangle className="h-7 w-7 text-red-500" />}
        </div>
        <h1 className="text-sm font-bold text-slate-800 dark:text-zinc-200 mb-1">
          {state === "working" ? "Connecting to OpenRouter"
            : state === "done" ? "Connected"
            : "Connection failed"}
        </h1>
        <p className={`text-xs leading-relaxed ${tone.text}`}>{message}</p>

        {state === "error" && (
          <button
            onClick={() => navigate("/settings", { replace: true })}
            className="mt-4 text-xs font-semibold px-3 py-1.5 rounded-lg border border-slate-300 dark:border-zinc-600 text-slate-700 dark:text-zinc-300 hover:bg-white dark:bg-zinc-900 transition-colors"
          >
            Back to Settings
          </button>
        )}
      </div>
    </div>
  );
}
