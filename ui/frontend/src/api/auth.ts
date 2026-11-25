import api from "./client";

export interface LoginResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  role: string;
  username: string;
}

export interface UserProfile {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  last_login_at: string | null;
}

export const authApi = {
  login: async (username: string, password: string): Promise<LoginResponse> => {
    const form = new FormData();
    form.append("username", username);
    form.append("password", password);
    const res = await api.post<LoginResponse>("/auth/login", form, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return res.data;
  },

  logout: async () => {
    await api.post("/auth/logout");
  },

  me: async (): Promise<UserProfile> => {
    const res = await api.get<UserProfile>("/auth/me");
    return res.data;
  },
};
