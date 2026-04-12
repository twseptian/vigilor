import { create } from "zustand";

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  username: string | null;
  role: string | null;
  isAuthenticated: boolean;

  setTokens: (access: string, refresh: string, username: string, role: string) => void;
  clearAuth: () => void;
}

export const useAuthStore = create<AuthState>((set) => ({
  accessToken: localStorage.getItem("access_token"),
  refreshToken: localStorage.getItem("refresh_token"),
  username: localStorage.getItem("username"),
  role: localStorage.getItem("role"),
  isAuthenticated: !!localStorage.getItem("access_token"),

  setTokens: (access, refresh, username, role) => {
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
    localStorage.setItem("username", username);
    localStorage.setItem("role", role);
    set({ accessToken: access, refreshToken: refresh, username, role, isAuthenticated: true });
  },

  clearAuth: () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    localStorage.removeItem("username");
    localStorage.removeItem("role");
    set({ accessToken: null, refreshToken: null, username: null, role: null, isAuthenticated: false });
  },
}));
