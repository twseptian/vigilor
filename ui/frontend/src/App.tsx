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
import UsersPage from "@/pages/Users/UsersPage";

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
          <Route path="settings" element={<SettingsPage />} />
          <Route path="users" element={<UsersPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
