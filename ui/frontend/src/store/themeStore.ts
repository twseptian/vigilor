import { create } from "zustand";

export type AppTheme = "dark" | "light";

const KEY = "vigilor-theme";

function applyDom(theme: AppTheme) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.classList.toggle("light", theme === "light");
  root.style.colorScheme = theme;
}

function readInitial(): AppTheme {
  const saved = localStorage.getItem(KEY);
  if (saved === "light" || saved === "dark") return saved;
  return "dark";
}

interface ThemeState {
  theme: AppTheme;
  setTheme: (theme: AppTheme) => void;
  toggle: () => void;
}

const initial = typeof document !== "undefined" ? readInitial() : "dark";
if (typeof document !== "undefined") applyDom(initial);

export const useThemeStore = create<ThemeState>((set, get) => ({
  theme: initial,
  setTheme: (theme) => {
    localStorage.setItem(KEY, theme);
    applyDom(theme);
    set({ theme });
  },
  toggle: () => {
    const next: AppTheme = get().theme === "dark" ? "light" : "dark";
    get().setTheme(next);
  },
}));
