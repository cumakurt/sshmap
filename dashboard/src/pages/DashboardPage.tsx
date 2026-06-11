import { useEffect, useState } from "react";
import { api, type ApiSummary } from "../api";

function metricCard(label: string, value: number) {
  return (
    <div className="card" key={label}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function DashboardPage() {
  const [summary, setSummary] = useState<ApiSummary | null>(null);

  useEffect(() => {
    api<ApiSummary>("/api/summary").then(setSummary).catch(() => setSummary(null));
  }, []);

  if (!summary) {
    return <p className="muted">Loading summary...</p>;
  }

  return (
    <div className="grid">
      {metricCard("Hosts", summary.stats.hosts)}
      {metricCard("SSH Open", summary.ssh_open_hosts)}
      {metricCard("Users", summary.stats.users)}
      {metricCard("Public Keys", summary.stats.keys)}
      {metricCard("Critical Risks", summary.critical_risks)}
      {metricCard("High Risks", summary.high_risks)}
      {metricCard("Reused Keys", summary.reused_keys)}
    </div>
  );
}
