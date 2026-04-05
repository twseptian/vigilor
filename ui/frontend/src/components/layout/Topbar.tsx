import { useNavigate } from "react-router-dom";
import { LogOut, User } from "lucide-react";
import { useAuthStore } from "@/store/authStore";
import { authApi } from "@/api/auth";

export default function Topbar() {
  const { username, role, clearAuth } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = async () => {
    try { await authApi.logout(); } catch { /* ignore */ }
    clearAuth();
    navigate("/login");
  };

  return (
    <header className="h-14 bg-white border-b border-border flex items-center justify-between px-6 shrink-0">
      <div />
      <div className="flex items-center gap-3 text-sm text-muted-foreground">
        <User className="h-4 w-4" />
        <span className="font-medium text-foreground">{username}</span>
        <span className="text-xs bg-secondary px-2 py-0.5 rounded capitalize">{role}</span>
        <button
          onClick={handleLogout}
          className="flex items-center gap-1 text-xs hover:text-destructive transition-colors ml-2"
        >
          <LogOut className="h-3.5 w-3.5" />
          Logout
        </button>
      </div>
    </header>
  );
}
