import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ShieldAlert, Eye, EyeOff } from "lucide-react";
import { authApi } from "@/api/auth";
import { useAuthStore } from "@/store/authStore";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const setTokens = useAuthStore((s) => s.setTokens);
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
    <div className="min-h-screen bg-slate-950 flex flex-col">
      {/* Main content */}
      <div className="flex-1 flex items-center justify-center p-4">
        <div className="w-full max-w-sm">
          {/* Logo / Brand */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-600 rounded-2xl mb-4">
              <ShieldAlert className="h-8 w-8 text-white" />
            </div>
            <h1 className="text-2xl font-bold text-white">Agentic Web Pentest</h1>
            <p className="text-slate-400 text-sm mt-1">by Ensign InfoSecurity</p>
          </div>

          {/* Card */}
          <div className="bg-slate-900 border border-slate-700 rounded-xl px-8 py-8 shadow-2xl">
            <h2 className="text-xl font-bold text-white mb-1">Log in</h2>
            <p className="text-sm text-slate-400 mb-6">
              Authorized access only. Sign in with your assigned credentials.
            </p>

            <form onSubmit={handleSubmit} className="space-y-5">
              {/* Username */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  required
                  autoFocus
                  placeholder="admin"
                  className="w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-3 py-2.5 text-sm
                             placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>

              {/* Password */}
              <div>
                <label className="block text-sm font-medium text-slate-300 mb-1.5">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPw ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    placeholder="••••••••••••"
                    className="w-full bg-slate-800 border border-slate-600 text-white rounded-lg px-3 py-2.5 pr-10 text-sm
                               placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(!showPw)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200"
                  >
                    {showPw ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </button>
                </div>
              </div>

              {/* Remember me + Forgot */}
              <div className="flex items-center justify-between pt-1">
                <label className="flex items-center gap-2 text-sm text-slate-400 cursor-pointer select-none">
                  <input type="checkbox" className="rounded border-slate-600 bg-slate-800 text-blue-600" />
                  Remember me
                </label>
                <button type="button" className="text-sm text-blue-400 hover:text-blue-300 hover:underline">
                  Forgot password
                </button>
              </div>

              {/* Error */}
              {error && (
                <div className="bg-red-950/50 border border-red-800 text-red-400 text-sm rounded-lg px-3 py-2">
                  {error}
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-60 disabled:cursor-not-allowed
                           text-white font-semibold rounded-lg py-3 text-sm transition-colors mt-2"
              >
                {loading ? "Logging in..." : "Log in"}
              </button>
            </form>
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="py-4 px-6">
        <div className="flex items-center justify-center gap-8 text-xs text-slate-500">
          <span>Copyright © 2026 Ensign InfoSecurity</span>
          <a href="#" className="text-blue-400 hover:underline">Privacy Policy</a>
          <a href="#" className="text-blue-400 hover:underline">Data Protection Policy</a>
        </div>
      </footer>
    </div>
  );
}
