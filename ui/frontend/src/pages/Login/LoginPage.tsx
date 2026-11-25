import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Eye as EyeIcon, EyeOff, Sun, Moon } from "lucide-react";
import { authApi } from "@/api/auth";
import { useAuthStore } from "@/store/authStore";
import { useThemeStore } from "@/store/themeStore";
import { BRAND } from "@/brand";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const setTokens = useAuthStore((s) => s.setTokens);
  const { theme, toggle } = useThemeStore();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      const data = await authApi.login(username, password);
      setTokens(data.access_token, data.refresh_token, data.username, data.role);
      navigate("/");
    } catch (err: any) {
      setError(err?.response?.data?.detail || "Invalid username or password");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col relative overflow-hidden bg-background">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute -top-32 -left-20 w-[420px] h-[420px] rounded-full bg-slate-400/10 dark:bg-zinc-600/15 blur-3xl" />
        <div className="absolute top-1/3 -right-24 w-[380px] h-[380px] rounded-full bg-teal-700/8 dark:bg-teal-900/20 blur-3xl" />
      </div>

      <div className="absolute top-4 right-4 z-20">
        <button
          type="button"
          onClick={toggle}
          className="flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1.5 rounded-lg border border-border bg-card text-foreground hover:bg-muted transition-colors"
        >
          {theme === "dark"
            ? <><Sun className="h-3.5 w-3.5 text-amber-700 dark:text-amber-400" /> White</>
            : <><Moon className="h-3.5 w-3.5 text-teal-700" /> Dark</>}
        </button>
      </div>

      <div className="flex-1 flex items-center justify-center p-4 relative z-10">
        <div className="w-full max-w-sm">
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4
              bg-teal-700 dark:bg-teal-800 border border-teal-800/30 shadow-lg shadow-black/10">
              <EyeIcon className="h-8 w-8 text-teal-50" />
            </div>
            <h1 className="text-3xl font-bold text-foreground tracking-[0.28em]">{BRAND.name}</h1>
            <p className="text-muted-foreground text-sm mt-2">{BRAND.tagline}</p>
          </div>

          <div className="vigilor-card px-8 py-8 shadow-sm">
            <h2 className="text-xl font-bold text-foreground mb-1">Operator login</h2>
            <p className="text-sm text-muted-foreground mb-6">
              Authorized engagements only. Sign in with your assigned credentials.
            </p>

            <form onSubmit={handleSubmit} className="space-y-5">
              <div>
                <label className="block text-sm font-medium text-foreground mb-1.5">Username</label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoFocus
                  placeholder="admin"
                  className="input"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-foreground mb-1.5">Password</label>
                <div className="relative">
                  <input
                    type={showPw ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••••••"
                    className="input pr-10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(!showPw)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    {showPw ? <EyeOff className="h-4 w-4" /> : <EyeIcon className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {error && (
                <div className="bg-red-50 border border-red-200 text-red-700 dark:bg-red-950/50 dark:border-red-800 dark:text-red-400 text-sm rounded-lg px-3 py-2">
                  {error}
                </div>
              )}

              <button type="submit" disabled={loading} className="vigilor-btn-primary w-full py-3 mt-2">
                {loading ? "Authenticating…" : "Enter console"}
              </button>
            </form>
          </div>
        </div>
      </div>

      <footer className="py-4 px-6 relative z-10">
        <div className="flex items-center justify-center gap-6 text-xs text-muted-foreground">
          <span>© 2026 {BRAND.name}</span>
          <span>·</span>
          <span>{BRAND.shortTagline}</span>
        </div>
      </footer>
    </div>
  );
}
