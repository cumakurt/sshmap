import { lazy, Suspense, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { api, type ApiSummary } from "./api";
import { DashboardPage } from "./pages/DashboardPage";
import { HostDetailPage } from "./pages/HostDetailPage";
import { HostsPage } from "./pages/HostsPage";
import { KeyDetailPage } from "./pages/KeyDetailPage";
import { KeysPage } from "./pages/KeysPage";
import { RiskDetailPage } from "./pages/RiskDetailPage";
import { RisksPage } from "./pages/RisksPage";
import { ToolsPage } from "./pages/ToolsPage";
import { UserDetailPage } from "./pages/UserDetailPage";
import { UsersPage } from "./pages/UsersPage";
import "./styles.css";

const GraphPage = lazy(() =>
  import("./pages/GraphPage").then((module) => ({ default: module.GraphPage })),
);

function AppShell() {
  const [summaryLine, setSummaryLine] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<ApiSummary>("/api/summary")
      .then((summary) => {
        setSummaryLine(
          `${summary.stats.hosts} hosts · ${summary.stats.risks} risks · ${summary.reused_keys} reused keys`,
        );
        setError(null);
      })
      .catch((fetchError) => {
        setError(fetchError instanceof Error ? fetchError.message : "Failed to load summary");
      });
  }, []);

  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout summaryLine={summaryLine} error={error} />}>
          <Route index element={<DashboardPage />} />
          <Route path="hosts" element={<HostsPage />} />
          <Route path="hosts/:id" element={<HostDetailPage />} />
          <Route path="users" element={<UsersPage />} />
          <Route path="users/:username" element={<UserDetailPage />} />
          <Route path="keys" element={<KeysPage />} />
          <Route path="keys/:id" element={<KeyDetailPage />} />
          <Route path="risks" element={<RisksPage />} />
          <Route path="risks/:id" element={<RiskDetailPage />} />
          <Route
            path="graph"
            element={
              <Suspense fallback={<p className="muted">Loading graph view...</p>}>
                <GraphPage />
              </Suspense>
            }
          />
          <Route path="tools" element={<ToolsPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}

createRoot(document.getElementById("root")!).render(<AppShell />);
