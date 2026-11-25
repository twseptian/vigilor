import { useState, useRef, useEffect } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, ScanSearch, Bug, Settings, Users,
  Info, Plus, LogOut, Search, Network, Radio, Sun, Moon,
  Cable, ShieldAlert,
} from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import Sidebar from "./Sidebar";
import { useAuthStore } from "@/store/authStore";
import { useThemeStore } from "@/store/themeStore";
import { authApi } from "@/api/auth";
import NotificationBell from "@/components/notifications/NotificationBell";
import { BRAND } from "@/brand";
import api from "@/api/client";

const ROUTES: {
  pattern: RegExp;
  title: string;
  sub: string;
  icon: React.ElementType;
}[] = [
  { pattern: /^\/$/, title: "Dashboard", sub: "Scans, findings, coverage", icon: LayoutDashboard },
  { pattern: /^\/scans\/new/, title: "New Engagement", sub: "Scope and launch", icon: Plus },
  { pattern: /^\/scans\/[^/]+/, title: "Engagement", sub: "Progress, graph, findings", icon: ScanSearch },
  { pattern: /^\/scans/, title: "Engagements", sub: "All scan runs", icon: ScanSearch },
  { pattern: /^\/findings\/[^/]+/, title: "Finding", sub: "Evidence and retest", icon: Bug },
  { pattern: /^\/findings/, title: "Findings", sub: "Triage queue", icon: Bug },
  { pattern: /^\/assets/, title: "Assets", sub: "Hosts and coverage", icon: Network },
  { pattern: /^\/traffic/, title: "Traffic", sub: "HTTP evidence", icon: Cable },
  { pattern: /^\/approvals/, title: "Approvals", sub: "Pending intercepts", icon: ShieldAlert },
  { pattern: /^\/activity/, title: "Activity", sub: "Agent event timeline", icon: Radio },
  { pattern: /^\/settings/, title: "Settings", sub: "Providers and defaults", icon: Settings },
  { pattern: /^\/users/, title: "Users", sub: "Accounts and roles", icon: Users },
  { pattern: /^\/about/, title: "About", sub: BRAND.name, icon: Info },
];

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(
    () => localStorage.getItem("sidebar-collapsed") === "true"
  );
  const { pathname } = useLocation();
  const navigate = useNavigate();
  const { username, role, clearAuth } = useAuthStore();
  const { theme, toggle } = useThemeStore();
  const [query, setQuery] = useState("");
  const searchRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchRef.current?.focus();
        searchRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const page = ROUTES.find(r => r.pattern.test(pathname)) ?? {
    title: BRAND.name, sub: "", icon: LayoutDashboard,
  };
  const PageIcon = page.icon;

  const toggleSidebar = () => {
    setCollapsed(v => {
      const next = !v;
      localStorage.setItem("sidebar-collapsed", String(next));
      return next;
    });
  };

  const handleLogout = async () => {
    try { await authApi.logout(); } catch { /* ignore */ }
    clearAuth();
    navigate("/login");
  };

  const runSearch = () => {
    const q = query.trim();
    if (q) navigate(`/scans?target=${encodeURIComponent(q)}`);
  };

  const { data: approvalSummary } = useQuery({
    queryKey: ["approvals-summary"],
    queryFn: () => api.get("/approvals/summary").then(r => r.data as { pending: number }),
    refetchInterval: 10_000,
  });
  const pendingApprovals = approvalSummary?.pending ?? 0;

  return (
    <div className="flex h-screen overflow-hidden bg-transparent">
      <Sidebar collapsed={collapsed} onToggle={toggleSidebar} />

      <div className="flex flex-col flex-1 overflow-hidden min-w-0">
        <header className="shrink-0 h-14 vigilor-shell border-b border-border flex items-center px-5 gap-4 backdrop-blur-md">
          <div className="flex items-center gap-2.5 min-w-0 shrink-0">
            <div className="vigilor-icon-box h-7 w-7 shrink-0">
              <PageIcon className="h-3.5 w-3.5" />
            </div>
            <span className="text-[14px] font-semibold text-foreground leading-none truncate">{page.title}</span>
            {page.sub && (
              <>
                <span className="text-muted-foreground text-[11px] hidden lg:block">/</span>
                <span className="text-[11px] text-muted-foreground truncate hidden lg:block">{page.sub}</span>
              </>
            )}
          </div>

          <div className="flex-1 flex justify-center min-w-0">
            <div className="flex items-center gap-2 w-full max-w-md bg-muted/70 border border-border rounded-xl px-3 py-2 focus-within:border-teal-600/50 dark:focus-within:border-teal-700/50 focus-within:ring-1 focus-within:ring-teal-600/20 dark:focus-within:ring-teal-700/25 transition-colors">
              <Search className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
              <input
                ref={searchRef}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") runSearch(); }}
                placeholder="Search engagements by target..."
                className="flex-1 bg-transparent text-[13px] text-foreground placeholder:text-muted-foreground outline-none min-w-0"
              />
              <kbd className="hidden sm:flex items-center gap-0.5 text-[9px] font-medium text-muted-foreground bg-background border border-border rounded px-1 py-0.5 shrink-0">⌘K</kbd>
            </div>
          </div>

          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={toggle}
              title={theme === "dark" ? "Switch to white theme" : "Switch to dark theme"}
              className="flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1.5 rounded-lg border border-border text-foreground hover:bg-muted transition-colors"
            >
              {theme === "dark"
                ? <><Sun className="h-3.5 w-3.5 text-amber-700 dark:text-amber-400" /> White</>
                : <><Moon className="h-3.5 w-3.5 text-teal-700" /> Dark</>}
            </button>
            <button
              onClick={() => navigate("/approvals")}
              title="Intercept approvals"
              className="relative flex items-center justify-center h-8 w-8 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
            >
              <ShieldAlert className="h-3.5 w-3.5" />
              {pendingApprovals > 0 && (
                <span className="absolute -top-1 -right-1 min-w-[16px] h-4 px-1 rounded-full bg-amber-500 text-[9px] font-bold text-amber-950 flex items-center justify-center">
                  {pendingApprovals > 9 ? "9+" : pendingApprovals}
                </span>
              )}
            </button>
            <NotificationBell />
            <div className="w-px h-4 bg-border" />
            <div className="flex items-center gap-1.5">
              <div className="h-7 w-7 rounded-full bg-teal-700 dark:bg-teal-800 flex items-center justify-center text-[11px] font-bold text-white uppercase shrink-0">
                {username?.[0] ?? "U"}
              </div>
              <span className="text-[12px] font-medium text-foreground hidden sm:block">{username}</span>
              <span className="vigilor-chip capitalize hidden sm:inline-flex">{role}</span>
            </div>
            <div className="w-px h-4 bg-border" />
            <button
              onClick={handleLogout}
              title="Sign out"
              className="flex items-center gap-1 text-[11px] text-muted-foreground hover:text-red-500 transition-colors px-1.5 py-1 rounded hover:bg-red-50 dark:hover:bg-red-950/40"
            >
              <LogOut className="h-3.5 w-3.5" />
              <span className="hidden sm:block">Logout</span>
            </button>
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-5">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
