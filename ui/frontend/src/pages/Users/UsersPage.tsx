import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Loader2, Pencil, Trash2, KeyRound, X, Check, Users } from "lucide-react";
import api from "@/api/client";
import { useAuthStore } from "@/store/authStore";

interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

const ROLES = ["viewer", "analyst", "admin", "superadmin"];

const ROLE_DESCRIPTIONS: Record<string, string> = {
  viewer:     "Read-only access to findings and scans",
  analyst:    "Can view and triage findings, add comments",
  admin:      "Full access — manage scans, findings, and users",
  superadmin: "All permissions including user deletion and system config",
};

const ROLE_COLORS: Record<string, string> = {
  viewer:     "bg-gray-100 text-gray-600",
  analyst:    "bg-blue-50 text-blue-700",
  admin:      "bg-purple-50 text-purple-700",
  superadmin: "bg-amber-50 text-amber-700",
};

// ── Edit User Modal ────────────────────────────────────────────────────────────

function EditUserModal({
  user,
  onClose,
  isSuperadmin,
}: {
  user: User;
  onClose: () => void;
  isSuperadmin: boolean;
}) {
  const qc = useQueryClient();
  const [email, setEmail] = useState(user.email);
  const [role, setRole] = useState(user.role);
  const [isActive, setIsActive] = useState(user.is_active);
  const [newPassword, setNewPassword] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [pwdSuccess, setPwdSuccess] = useState(false);

  const updateMutation = useMutation({
    mutationFn: () => api.patch(`/users/${user.id}`, { email, role, is_active: isActive }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ["users"] }); onClose(); },
  });

  const resetPwdMutation = useMutation({
    mutationFn: () => api.post(`/users/${user.id}/reset-password`, { new_password: newPassword }),
    onSuccess: () => { setNewPassword(""); setPwdSuccess(true); setTimeout(() => setPwdSuccess(false), 3000); },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-md mx-4 overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-border">
          <div>
            <h2 className="text-base font-semibold">Edit User</h2>
            <p className="text-xs text-muted-foreground mt-0.5">@{user.username}</p>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="h-5 w-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          {/* Email */}
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Email</label>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)}
              className="input w-full" />
          </div>

          {/* Role */}
          <div>
            <label className="text-xs font-medium text-gray-700 block mb-1">Role</label>
            <select value={role} onChange={(e) => setRole(e.target.value)} className="input w-full">
              {ROLES.map((r) => (
                <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>
              ))}
            </select>
            <p className="text-[11px] text-muted-foreground mt-1">{ROLE_DESCRIPTIONS[role]}</p>
          </div>

          {/* Active toggle */}
          <div className="flex items-center justify-between bg-muted/30 rounded-lg px-4 py-3">
            <div>
              <p className="text-xs font-medium text-gray-700">Account Status</p>
              <p className="text-[11px] text-muted-foreground mt-0.5">
                {isActive ? "User can log in and access the platform" : "User is blocked from logging in"}
              </p>
            </div>
            <button
              type="button"
              onClick={() => setIsActive(!isActive)}
              className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors ${isActive ? "bg-green-500" : "bg-gray-300"}`}
            >
              <span className={`inline-block h-4 w-4 rounded-full bg-white shadow transition-transform ${isActive ? "translate-x-4" : "translate-x-0.5"}`} />
            </button>
          </div>

          {/* Reset password */}
          <div className="border-t border-border pt-4">
            <label className="text-xs font-medium text-gray-700 flex items-center gap-1.5 mb-1">
              <KeyRound className="h-3.5 w-3.5" /> Reset Password
            </label>
            <div className="flex gap-2">
              <input
                type={showPwd ? "text" : "password"}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="New password…"
                className="input flex-1"
              />
              <button
                type="button"
                onClick={() => setShowPwd(!showPwd)}
                className="text-xs px-2 py-1.5 border border-border rounded-lg text-muted-foreground hover:bg-accent"
              >
                {showPwd ? "Hide" : "Show"}
              </button>
              <button
                onClick={() => newPassword && resetPwdMutation.mutate()}
                disabled={!newPassword || resetPwdMutation.isPending}
                className="text-xs px-3 py-1.5 bg-gray-800 text-white rounded-lg disabled:opacity-50 hover:bg-gray-700 shrink-0"
              >
                {resetPwdMutation.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : "Reset"}
              </button>
            </div>
            {pwdSuccess && (
              <p className="text-xs text-green-600 mt-1 flex items-center gap-1">
                <Check className="h-3 w-3" /> Password updated successfully
              </p>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-2 px-6 py-4 border-t border-border bg-slate-50">
          <button onClick={onClose} className="px-4 py-2 text-sm border border-border rounded-lg hover:bg-accent">
            Cancel
          </button>
          <button
            onClick={() => updateMutation.mutate()}
            disabled={updateMutation.isPending}
            className="flex items-center gap-1.5 px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-500 disabled:opacity-50"
          >
            {updateMutation.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
            Save Changes
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function UsersPage() {
  const qc = useQueryClient();
  const { role: currentRole, username: currentUsername } = useAuthStore();
  const isAdmin      = currentRole === "admin" || currentRole === "superadmin";
  const isSuperadmin = currentRole === "superadmin";

  const [showCreate, setShowCreate] = useState(false);
  const [editingUser, setEditingUser] = useState<User | null>(null);
  const [newUser, setNewUser] = useState({ username: "", email: "", password: "", role: "analyst" });

  const { data: users = [], isLoading } = useQuery<User[]>({
    queryKey: ["users"],
    queryFn: () => api.get("/users").then((r) => r.data),
  });

  const createMutation = useMutation({
    mutationFn: (data: typeof newUser) => api.post("/users", data).then((r) => r.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["users"] });
      setShowCreate(false);
      setNewUser({ username: "", email: "", password: "", role: "analyst" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => api.delete(`/users/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["users"] }),
  });

  const handleDelete = (u: User) => {
    if (window.confirm(`Delete user "${u.username}"? This action cannot be undone.`)) {
      deleteMutation.mutate(u.id);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Users</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Manage platform accounts and access levels. Each user is assigned a role that controls
            what they can view and modify within the system.
          </p>
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium px-4 py-2 rounded-lg shrink-0"
          >
            <Plus className="h-4 w-4" /> Add User
          </button>
        )}
      </div>

      {/* Role legend */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {ROLES.map((r) => (
          <div key={r} className="bg-white border border-border rounded-lg px-3 py-2.5">
            <span className={`text-xs font-semibold px-2 py-0.5 rounded capitalize ${ROLE_COLORS[r]}`}>{r}</span>
            <p className="text-[11px] text-muted-foreground mt-1.5 leading-snug">{ROLE_DESCRIPTIONS[r]}</p>
          </div>
        ))}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="bg-white border border-border rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="font-semibold text-sm">New User</h3>
              <p className="text-xs text-muted-foreground mt-0.5">Create a new account and assign a role.</p>
            </div>
            <button onClick={() => setShowCreate(false)} className="text-muted-foreground hover:text-foreground">
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="text-xs font-medium text-gray-700 block mb-1">Username</label>
              <input placeholder="e.g. john.doe" value={newUser.username}
                onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
                className="input w-full" />
            </div>
            <div>
              <label className="text-xs font-medium text-gray-700 block mb-1">Email</label>
              <input placeholder="john@example.com" type="email" value={newUser.email}
                onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
                className="input w-full" />
            </div>
            <div>
              <label className="text-xs font-medium text-gray-700 block mb-1">Password</label>
              <input placeholder="Minimum 8 characters" type="password" value={newUser.password}
                onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
                className="input w-full" />
            </div>
            <div>
              <label className="text-xs font-medium text-gray-700 block mb-1">Role</label>
              <select value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value })}
                className="input w-full">
                {ROLES.map((r) => <option key={r} value={r}>{r.charAt(0).toUpperCase() + r.slice(1)}</option>)}
              </select>
              <p className="text-[11px] text-muted-foreground mt-1">{ROLE_DESCRIPTIONS[newUser.role]}</p>
            </div>
          </div>
          <div className="flex gap-2 pt-1">
            <button onClick={() => setShowCreate(false)}
              className="px-3 py-1.5 text-sm border border-border rounded-lg hover:bg-accent">Cancel</button>
            <button onClick={() => createMutation.mutate(newUser)}
              disabled={createMutation.isPending || !newUser.username || !newUser.email || !newUser.password}
              className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-lg disabled:opacity-50 hover:bg-blue-500">
              {createMutation.isPending && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              Create User
            </button>
          </div>
        </div>
      )}

      {/* Table */}
      <div className="bg-white border border-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border bg-muted/20">
              <th className="text-left py-3 px-4 text-muted-foreground font-medium">Username</th>
              <th className="text-left py-3 px-4 text-muted-foreground font-medium">Email</th>
              <th className="text-left py-3 px-4 text-muted-foreground font-medium">Role</th>
              <th className="text-left py-3 px-4 text-muted-foreground font-medium">Status</th>
              <th className="text-left py-3 px-4 text-muted-foreground font-medium">Last Login</th>
              {isAdmin && (
                <th className="text-right py-3 px-4 text-muted-foreground font-medium">Actions</th>
              )}
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={isAdmin ? 6 : 5} className="py-8 text-center text-muted-foreground">Loading…</td></tr>
            )}
            {!isLoading && users.length === 0 && (
              <tr><td colSpan={isAdmin ? 6 : 5} className="py-8 text-center text-muted-foreground">No users found</td></tr>
            )}
            {users.map((u) => (
              <tr key={u.id} className="border-b border-border/50 last:border-0 hover:bg-muted/10">
                <td className="py-3 px-4">
                  <div className="flex items-center gap-2">
                    <div className="h-7 w-7 rounded-full bg-muted flex items-center justify-center text-xs font-semibold text-muted-foreground shrink-0">
                      {u.username.charAt(0).toUpperCase()}
                    </div>
                    <span className="font-medium">
                      {u.username}
                      {u.username === currentUsername && (
                        <span className="ml-1.5 text-[10px] bg-blue-50 text-blue-600 px-1.5 py-0.5 rounded">You</span>
                      )}
                    </span>
                  </div>
                </td>
                <td className="py-3 px-4 text-muted-foreground">{u.email}</td>
                <td className="py-3 px-4">
                  <span className={`text-xs px-2 py-0.5 rounded capitalize font-medium ${ROLE_COLORS[u.role] || "bg-gray-100 text-gray-600"}`}>
                    {u.role}
                  </span>
                </td>
                <td className="py-3 px-4">
                  <span className={`text-xs px-2 py-0.5 rounded font-medium ${u.is_active ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}`}>
                    {u.is_active ? "Active" : "Disabled"}
                  </span>
                </td>
                <td className="py-3 px-4 text-muted-foreground text-xs">
                  {u.last_login_at ? new Date(u.last_login_at).toLocaleDateString() : "Never"}
                </td>
                {isAdmin && (
                  <td className="py-3 px-4">
                    <div className="flex items-center justify-end gap-1">
                      {/* Edit — admin & superadmin */}
                      <button
                        onClick={() => setEditingUser(u)}
                        title="Edit user"
                        className="p-1.5 rounded-lg text-muted-foreground hover:text-blue-600 hover:bg-blue-50 transition-colors"
                      >
                        <Pencil className="h-3.5 w-3.5" />
                      </button>
                      {/* Delete — superadmin only, cannot delete self */}
                      {isSuperadmin && u.username !== currentUsername && (
                        <button
                          onClick={() => handleDelete(u)}
                          title="Delete user"
                          disabled={deleteMutation.isPending}
                          className="p-1.5 rounded-lg text-muted-foreground hover:text-red-600 hover:bg-red-50 transition-colors disabled:opacity-50"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Footer note for non-admins */}
      {!isAdmin && (
        <p className="text-xs text-muted-foreground text-center">
          Contact an administrator to modify user accounts or add new users.
        </p>
      )}

      {/* Edit modal */}
      {editingUser && (
        <EditUserModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
          isSuperadmin={isSuperadmin}
        />
      )}
    </div>
  );
}
