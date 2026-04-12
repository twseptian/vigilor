import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  ScanSearch,
  Bug,
  Settings,
  Users,
  ShieldAlert,
  Plus,
  LogOut,
} from "lucide-react";
import { useAuthStore } from "@/store/authStore";
import { cn } from "@/lib/utils";

const mainNav = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard", exact: true },
  { to: "/scans", icon: ScanSearch, label: "Scans" },
  { to: "/findings", icon: Bug, label: "Findings" },
];

const adminNav = [
  { to: "/settings", icon: Settings, label: "Settings" },
  { to: "/users", icon: Users, label: "Users" },
];

export default function Sidebar() {
  const role = useAuthStore((s) => s.role);
  const logout = useAuthStore((s) => s.clearAuth);
  const username = useAuthStore((s) => s.username);
  const isAdmin = role === "admin" || role === "superadmin";

  return (
    <aside className="w-56 bg-[#0f1117] text-slate-100 flex flex-col shrink-0 border-r border-white/[0.06]">

      {/* Logo */}
      <div className="px-4 pt-5 pb-4">
        <div className="flex items-center gap-2.5">
          <div className="h-8 w-8 rounded-lg bg-blue-600 flex items-center justify-center shrink-0">
            <ShieldAlert className="h-4.5 w-4.5 text-white" style={{ width: "1.1rem", height: "1.1rem" }} />
          </div>
          <div className="leading-tight">
            <p className="text-[13px] font-bold text-white tracking-tight">Agentic Web Pentest</p>
            <p className="text-[10px] text-slate-500">by Ensign InfoSecurity</p>
          </div>
        </div>
      </div>

      {/* New Scan button */}
      <div className="px-3 pb-3">
        <NavLink
          to="/scans/new"
          className={({ isActive }) =>
            cn(
              "group flex items-center gap-2.5 w-full px-3 py-2.5 rounded-lg text-[13px] font-semibold transition-all duration-150",
              isActive
                ? "bg-blue-600 text-white shadow-lg shadow-blue-900/40"
                : "bg-blue-600/15 text-blue-400 hover:bg-blue-600 hover:text-white hover:shadow-lg hover:shadow-blue-900/30 border border-blue-500/20 hover:border-transparent"
            )
          }
        >
          {({ isActive }) => (
            <>
              <span className={cn(
                "flex items-center justify-center h-5 w-5 rounded-md transition-colors shrink-0",
                isActive ? "bg-white/20" : "bg-blue-500/30 group-hover:bg-white/20"
              )}>
                <Plus className="h-3 w-3" />
              </span>
              Start New Scan
            </>
          )}
        </NavLink>
      </div>

      {/* Divider */}
      <div className="mx-3 border-t border-white/[0.06] mb-2" />

      {/* Main nav */}
      <nav className="flex-1 px-2 space-y-0.5 overflow-y-auto">
        {mainNav.map(({ to, icon: Icon, label, exact }) => (
          <NavLink
            key={to}
            to={to}
            end={exact}
            className={({ isActive }) =>
              cn(
                "flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] transition-all duration-100",
                isActive
                  ? "bg-white/10 text-white font-medium"
                  : "text-slate-400 hover:bg-white/[0.06] hover:text-slate-100"
              )
            }
          >
            {({ isActive }) => (
              <>
                <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-blue-400" : "")} />
                {label}
                {isActive && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-400" />}
              </>
            )}
          </NavLink>
        ))}

        {/* Admin section */}
        {isAdmin && (
          <>
            <div className="pt-3 pb-1 px-3">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-600">Admin</p>
            </div>
            {adminNav.map(({ to, icon: Icon, label }) => (
              <NavLink
                key={to}
                to={to}
                className={({ isActive }) =>
                  cn(
                    "flex items-center gap-3 px-3 py-2 rounded-lg text-[13px] transition-all duration-100",
                    isActive
                      ? "bg-white/10 text-white font-medium"
                      : "text-slate-400 hover:bg-white/[0.06] hover:text-slate-100"
                  )
                }
              >
                {({ isActive }) => (
                  <>
                    <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-blue-400" : "")} />
                    {label}
                    {isActive && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-blue-400" />}
                  </>
                )}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      {/* User + logout */}
      <div className="mx-3 border-t border-white/[0.06] mt-2" />
      <div className="px-3 py-3 flex items-center gap-2.5">
        <div className="h-7 w-7 rounded-full bg-slate-700 flex items-center justify-center shrink-0 text-[11px] font-bold text-slate-300 uppercase">
          {username?.[0] ?? "U"}
        </div>
        <div className="flex-1 min-w-0">
          <p className="text-[12px] font-medium text-slate-200 truncate">{username ?? "User"}</p>
          <p className="text-[10px] text-slate-500 capitalize">{role ?? "analyst"}</p>
        </div>
        <button
          onClick={logout}
          title="Sign out"
          className="text-slate-500 hover:text-slate-300 transition-colors p-1 rounded"
        >
          <LogOut className="h-3.5 w-3.5" />
        </button>
      </div>
    </aside>
  );
}
