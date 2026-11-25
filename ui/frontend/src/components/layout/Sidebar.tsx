import { NavLink } from "react-router-dom";
import {
  LayoutDashboard, ScanSearch, Bug, Settings, Users,
  Plus, LogOut, Info, ChevronLeft, ChevronRight,
  Network, Radio, Eye, Cable, ShieldAlert,
} from "lucide-react";
import { useAuthStore } from "@/store/authStore";
import { cn } from "@/lib/utils";
import { BRAND } from "@/brand";

const mainNav = [
  { to: "/",          icon: LayoutDashboard, label: "Dashboard", exact: true },
  { to: "/scans",     icon: ScanSearch,      label: "Engagements"            },
  { to: "/findings",  icon: Bug,             label: "Findings"               },
  { to: "/assets",    icon: Network,         label: "Assets"                 },
  { to: "/traffic",   icon: Cable,           label: "Traffic"                },
  { to: "/approvals", icon: ShieldAlert,     label: "Approvals"              },
  { to: "/activity",  icon: Radio,           label: "Activity"               },
  { to: "/about",     icon: Info,            label: "About"                  },
];

const adminNav = [
  { to: "/settings", icon: Settings, label: "Settings" },
  { to: "/users",    icon: Users,    label: "Users"    },
];

function Tip({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="relative group/tip flex">
      {children}
      <div className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-2.5 z-50
        opacity-0 group-hover/tip:opacity-100 transition-opacity duration-150 whitespace-nowrap">
        <div className="bg-popover text-popover-foreground text-[11px] font-medium px-2.5 py-1 rounded-lg shadow-xl border border-border">
          {label}
        </div>
      </div>
    </div>
  );
}

const navClass = (isActive: boolean) => cn(
  "flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] transition-all duration-100 border",
  isActive
    ? "bg-teal-50/80 text-teal-800 font-semibold border-teal-200/80 dark:bg-teal-950/40 dark:text-teal-200 dark:border-teal-800/40"
    : "text-muted-foreground hover:bg-muted hover:text-foreground border-transparent"
);
const navIconClass = (isActive: boolean) =>
  cn("h-4 w-4 shrink-0", isActive ? "text-teal-700 dark:text-teal-300/90" : "");
const navActiveCollapsed =
  "bg-teal-50/80 text-teal-800 border-teal-200/80 dark:bg-teal-950/40 dark:text-teal-200 dark:border-teal-800/40";
const navDot = "ml-auto h-1.5 w-1.5 rounded-full bg-teal-600 dark:bg-teal-500/70";

export default function Sidebar({ collapsed, onToggle }: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const role     = useAuthStore(s => s.role);
  const logout   = useAuthStore(s => s.clearAuth);
  const username = useAuthStore(s => s.username);
  const isAdmin  = role === "admin" || role === "superadmin";

  return (
    <aside
      className={cn(
        "vigilor-shell text-foreground flex flex-col shrink-0 border-r border-border transition-all duration-200 ease-in-out overflow-hidden",
        collapsed ? "w-14" : "w-56"
      )}
    >
      <div className={cn("flex items-center gap-2.5 pt-5 pb-4", collapsed ? "px-3 justify-center" : "px-4")}>
        <div className="h-8 w-8 rounded-xl bg-gradient-to-br from-teal-700 to-teal-900 dark:from-teal-700 dark:to-teal-950 flex items-center justify-center shrink-0 border border-teal-800/30">
          <Eye style={{ width: "1.05rem", height: "1.05rem" }} className="text-teal-50" />
        </div>
        {!collapsed && (
          <div className="leading-tight min-w-0">
            <p className="text-[14px] font-bold text-foreground tracking-[0.18em] truncate">{BRAND.name}</p>
            <p className="text-[10px] text-muted-foreground truncate">{BRAND.shortTagline}</p>
          </div>
        )}
      </div>

      <div className={cn("pb-3", collapsed ? "px-2" : "px-3")}>
        {collapsed ? (
          <Tip label="New Engagement">
            <NavLink to="/scans/new" className="vigilor-btn-primary w-full h-9 px-0">
              <Plus className="h-4 w-4" />
            </NavLink>
          </Tip>
        ) : (
          <NavLink to="/scans/new" className="vigilor-btn-primary w-full">
            <span className="flex items-center justify-center h-5 w-5 rounded-md bg-black/10 shrink-0">
              <Plus className="h-3 w-3" />
            </span>
            New Engagement
          </NavLink>
        )}
      </div>

      {!collapsed && (
        <p className="px-4 pb-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Ops</p>
      )}

      <nav className="flex-1 px-2 space-y-0.5 overflow-y-auto overflow-x-hidden">
        {mainNav.map(({ to, icon: Icon, label, exact }) => (
          collapsed ? (
            <Tip key={to} label={label}>
              <NavLink to={to} end={exact}
                className={({ isActive }) => cn(
                  "flex items-center justify-center w-full h-9 rounded-lg transition-all duration-100 border",
                  isActive ? navActiveCollapsed : "text-muted-foreground hover:bg-muted border-transparent"
                )}>
                {({ isActive }) => <Icon className={navIconClass(isActive)} />}
              </NavLink>
            </Tip>
          ) : (
            <NavLink key={to} to={to} end={exact} className={({ isActive }) => navClass(isActive)}>
              {({ isActive }) => (
                <>
                  <Icon className={navIconClass(isActive)} />
                  {label}
                  {isActive && <span className={navDot} />}
                </>
              )}
            </NavLink>
          )
        ))}

        {isAdmin && (
          <>
            <div className={cn("pt-3 pb-1", collapsed ? "px-1" : "px-3")}>
              {collapsed
                ? <div className="h-px bg-border" />
                : <p className="text-[10px] font-semibold uppercase tracking-widest text-muted-foreground">Admin</p>
              }
            </div>
            {adminNav.map(({ to, icon: Icon, label }) => (
              collapsed ? (
                <Tip key={to} label={label}>
                  <NavLink to={to}
                    className={({ isActive }) => cn(
                      "flex items-center justify-center w-full h-9 rounded-lg transition-all border",
                      isActive ? navActiveCollapsed : "text-muted-foreground hover:bg-muted border-transparent"
                    )}>
                    {({ isActive }) => <Icon className={navIconClass(isActive)} />}
                  </NavLink>
                </Tip>
              ) : (
                <NavLink key={to} to={to} className={({ isActive }) => navClass(isActive)}>
                  {({ isActive }) => (
                    <>
                      <Icon className={navIconClass(isActive)} />
                      {label}
                      {isActive && <span className={navDot} />}
                    </>
                  )}
                </NavLink>
              )
            ))}
          </>
        )}
      </nav>

      <div className="mx-3 border-t border-border mt-2" />
      <div className={cn("py-2", collapsed ? "px-2 flex justify-center" : "px-3 flex justify-end")}>
        <button
          onClick={onToggle}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="flex items-center justify-center h-7 w-7 rounded-lg text-muted-foreground hover:text-foreground hover:bg-muted transition-colors"
        >
          {collapsed ? <ChevronRight className="h-3.5 w-3.5" /> : <ChevronLeft className="h-3.5 w-3.5" />}
        </button>
      </div>

      <div className="mx-3 border-t border-border" />
      {collapsed ? (
        <div className="px-2 py-3 flex justify-center">
          <Tip label={`${username ?? "User"} · ${role ?? "analyst"}`}>
            <button
              onClick={logout}
              className="h-7 w-7 rounded-full bg-slate-100 border border-slate-200 dark:bg-zinc-800 dark:border-zinc-700 flex items-center justify-center text-[11px] font-bold text-slate-700 dark:text-zinc-200 uppercase hover:bg-red-50 hover:text-red-600 dark:hover:bg-red-950/50 dark:hover:text-red-300 transition-colors"
            >
              {username?.[0] ?? "U"}
            </button>
          </Tip>
        </div>
      ) : (
        <div className="px-3 py-3 flex items-center gap-2.5">
          <div className="h-7 w-7 rounded-full bg-slate-100 border border-slate-200 dark:bg-zinc-800 dark:border-zinc-700 flex items-center justify-center shrink-0 text-[11px] font-bold text-slate-700 dark:text-zinc-200 uppercase">
            {username?.[0] ?? "U"}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-[12px] font-medium text-foreground truncate">{username ?? "User"}</p>
            <p className="text-[10px] text-muted-foreground capitalize">{role ?? "analyst"}</p>
          </div>
          <button onClick={logout} title="Sign out" className="text-muted-foreground hover:text-red-500 transition-colors p-1 rounded">
            <LogOut className="h-3.5 w-3.5" />
          </button>
        </div>
      )}
    </aside>
  );
}
