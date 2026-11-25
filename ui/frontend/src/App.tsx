import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "@/store/authStore";
import AppShell from "@/components/layout/AppShell";
import LoginPage from "@/pages/Login/LoginPage";
import DashboardPage from "@/pages/Dashboard/DashboardPage";
import ScanListPage from "@/pages/Scans/ScanListPage";
import NewScanPage from "@/pages/Scans/NewScanPage";
import ScanDetailPage from "@/pages/Scans/ScanDetailPage";
import FindingListPage from "@/pages/Findings/FindingListPage";
import FindingDetailPage from "@/pages/Findings/FindingDetailPage";
import SettingsPage from "@/pages/Settings/SettingsPage";
import OpenRouterCallback from "@/pages/Settings/OpenRouterCallback";
import UsersPage from "@/pages/Users/UsersPage";
import AboutPage from "@/pages/About/AboutPage";
import AssetsPage from "@/pages/Assets/AssetsPage";
import ActivityPage from "@/pages/Activity/ActivityPage";
import TrafficPage from "@/pages/Traffic/TrafficPage";
import ApprovalsPage from "@/pages/Approvals/ApprovalsPage";

function RequireAuth({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  if (!isAuthenticated) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route
          path="/"
          element={
            <RequireAuth>
              <AppShell />
            </RequireAuth>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="scans" element={<ScanListPage />} />
          <Route path="scans/new" element={<NewScanPage />} />
          <Route path="scans/:id" element={<ScanDetailPage />} />
          <Route path="findings" element={<FindingListPage />} />
          <Route path="findings/:id" element={<FindingDetailPage />} />
          <Route path="assets" element={<AssetsPage />} />
          <Route path="traffic" element={<TrafficPage />} />
          <Route path="approvals" element={<ApprovalsPage />} />
          <Route path="activity" element={<ActivityPage />} />
          <Route path="settings" element={<SettingsPage />} />
          <Route path="settings/openrouter/callback" element={<OpenRouterCallback />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="about" element={<AboutPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
