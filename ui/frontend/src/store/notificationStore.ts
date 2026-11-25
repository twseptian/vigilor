import { create } from "zustand";

export type NotifType = "info" | "success" | "warning" | "error";

export interface Notification {
  id: string;
  type: NotifType;
  title: string;
  message: string;
  ts: number;
  read: boolean;
  scanId?: string;
}

interface NotificationState {
  notifications: Notification[];
  push: (n: Omit<Notification, "id" | "ts" | "read">) => void;
  markRead: (id: string) => void;
  markAllRead: () => void;
  clear: () => void;
  unreadCount: () => number;
}

export const useNotificationStore = create<NotificationState>((set, get) => ({
  notifications: [],

  push: (n) =>
    set((s) => ({
      notifications: [
        { ...n, id: crypto.randomUUID(), ts: Date.now(), read: false },
        ...s.notifications,
      ].slice(0, 100),
    })),

  markRead: (id) =>
    set((s) => ({
      notifications: s.notifications.map((n) =>
        n.id === id ? { ...n, read: true } : n
      ),
    })),

  markAllRead: () =>
    set((s) => ({
      notifications: s.notifications.map((n) => ({ ...n, read: true })),
    })),

  clear: () => set({ notifications: [] }),

  unreadCount: () => get().notifications.filter((n) => !n.read).length,
}));
