import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Bell, CheckCheck, Trash2, X } from "lucide-react";
import { useNotificationStore, type Notification } from "@/store/notificationStore";
import { cn } from "@/lib/utils";
import { useScanNotifications } from "@/hooks/useScanNotifications";

const TYPE_STYLES: Record<string, string> = {
  info:    "bg-blue-50 border-blue-200 text-blue-800 dark:bg-blue-950/40 dark:border-blue-800/50 dark:text-blue-300",
  success: "bg-emerald-50 border-emerald-200 text-emerald-800 dark:bg-emerald-950/40 dark:border-emerald-800/50 dark:text-emerald-300",
  warning: "bg-amber-50 border-amber-200 text-amber-900 dark:bg-amber-950/40 dark:border-amber-800/50 dark:text-amber-300",
  error:   "bg-red-50 border-red-200 text-red-800 dark:bg-red-950/40 dark:border-red-800/50 dark:text-red-300",
};

const DOT_STYLES: Record<string, string> = {
  info:    "bg-blue-500",
  success: "bg-green-500",
  warning: "bg-amber-500",
  error:   "bg-red-500",
};

function NotifItem({ n, onClose }: { n: Notification; onClose: () => void }) {
  const { markRead } = useNotificationStore();
  const navigate = useNavigate();

  function handleClick() {
    markRead(n.id);
    if (n.scanId) {
      navigate(`/scans/${n.scanId}`);
      onClose();
    }
  }

  const elapsed = (() => {
    const diffMs = Date.now() - n.ts;
    const s = Math.floor(diffMs / 1000);
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    return `${Math.floor(m / 60)}h ago`;
  })();

  return (
    <div
      className={cn(
        "flex items-start gap-2.5 px-3 py-2.5 border-b border-border last:border-0",
        n.scanId ? "cursor-pointer hover:bg-slate-50 dark:hover:bg-zinc-900/60" : "",
        !n.read ? "bg-teal-50 dark:bg-teal-950/25" : ""
      )}
      onClick={n.scanId ? handleClick : () => markRead(n.id)}
    >
      <span className={cn("mt-1.5 h-2 w-2 rounded-full shrink-0", DOT_STYLES[n.type])} />
      <div className="flex-1 min-w-0">
        <p className="text-xs font-semibold text-gray-800 leading-tight">{n.title}</p>
        <p className="text-xs text-slate-500 dark:text-zinc-400 mt-0.5 leading-snug break-words">{n.message}</p>
        <p className="text-[10px] text-slate-500 dark:text-zinc-400 mt-1">{elapsed}</p>
      </div>
      {!n.read && (
        <span className="mt-1 h-1.5 w-1.5 rounded-full bg-teal-500 shrink-0" />
      )}
    </div>
  );
}

export default function NotificationBell() {
  useScanNotifications();

  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const notifications = useNotificationStore((s) => s.notifications);
  const unreadCount = useNotificationStore((s) => s.unreadCount());
  const markAllRead = useNotificationStore((s) => s.markAllRead);
  const clear = useNotificationStore((s) => s.clear);

  useEffect(() => {
    function handleOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handleOutside);
    return () => document.removeEventListener("mousedown", handleOutside);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className={cn(
          "relative flex items-center justify-center h-8 w-8 rounded-lg transition-colors",
          open ? "bg-slate-100 dark:bg-zinc-800 text-slate-700 dark:text-zinc-300" : "text-slate-500 dark:text-zinc-400 hover:bg-slate-100 dark:hover:bg-zinc-800 hover:text-slate-700 dark:text-zinc-300"
        )}
        title="Notifications"
      >
        <Bell className="h-4.5 w-4.5" style={{ width: "1.1rem", height: "1.1rem" }} />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 flex h-4 min-w-4 items-center justify-center rounded-full bg-red-500 px-1 text-[10px] font-bold text-white leading-none">
            {unreadCount > 99 ? "99+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full mt-2 w-80 bg-white dark:bg-zinc-900 border border-border rounded-xl shadow-xl z-50 overflow-hidden">
          {/* Header */}
          <div className="flex items-center justify-between px-3 py-2.5 border-b border-border">
            <span className="text-xs font-semibold text-gray-800">
              Notifications {unreadCount > 0 && <span className="ml-1 text-teal-700 dark:text-teal-400">({unreadCount} new)</span>}
            </span>
            <div className="flex items-center gap-1">
              {notifications.length > 0 && (
                <>
                  <button
                    onClick={markAllRead}
                    title="Mark all read"
                    className="p-1 rounded hover:bg-slate-100 dark:hover:bg-zinc-800 text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300 transition-colors"
                  >
                    <CheckCheck className="h-3.5 w-3.5" />
                  </button>
                  <button
                    onClick={clear}
                    title="Clear all"
                    className="p-1 rounded hover:bg-slate-100 dark:hover:bg-zinc-800 text-slate-500 dark:text-zinc-400 hover:text-red-500 transition-colors"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </>
              )}
              <button
                onClick={() => setOpen(false)}
                className="p-1 rounded hover:bg-slate-100 dark:hover:bg-zinc-800 text-slate-500 dark:text-zinc-400 hover:text-slate-700 dark:text-zinc-300 transition-colors"
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* List */}
          <div className="max-h-96 overflow-y-auto">
            {notifications.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-10 text-slate-500 dark:text-zinc-400">
                <Bell className="h-8 w-8 mb-2 opacity-30" />
                <p className="text-xs">No notifications</p>
              </div>
            ) : (
              notifications.map((n) => (
                <NotifItem key={n.id} n={n} onClose={() => setOpen(false)} />
              ))
            )}
          </div>
        </div>
      )}
    </div>
  );
}
