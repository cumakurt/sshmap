import { useEffect, useState } from "react";
import { api, type ApiSummary, type OperationsMetricsRecord } from "../api";

function metricCard(label: string, value: number | string) {
  return (
    <div className="card" key={label}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function DashboardPage() {
  const [summary, setSummary] = useState<ApiSummary | null>(null);
  const [metrics, setMetrics] = useState<OperationsMetricsRecord | null>(null);

  useEffect(() => {
    Promise.all([
      api<ApiSummary>("/api/summary"),
      api<OperationsMetricsRecord>("/api/operations-metrics"),
    ])
      .then(([summaryData, metricsData]) => {
        setSummary(summaryData);
        setMetrics(metricsData);
      })
      .catch(() => {
        setSummary(null);
        setMetrics(null);
      });
  }, []);

  if (!summary) {
    return <p className="muted">Loading summary...</p>;
  }

  const severityEntries = Object.entries(metrics?.severity_distribution ?? summary.severity_distribution);

  return (
    <>
      <div className="grid">
        {metricCard("Hosts", summary.stats.hosts)}
        {metricCard("SSH Open", summary.ssh_open_hosts)}
        {metricCard("Users", summary.stats.users)}
        {metricCard("Public Keys", summary.stats.keys)}
        {metricCard("Critical Risks", summary.critical_risks)}
        {metricCard("High Risks", summary.high_risks)}
        {metricCard("Reused Keys", summary.reused_keys)}
        {metricCard("Coverage %", Math.round(summary.scan_coverage_percent))}
        {metricCard("Hosts w/ Users", summary.hosts_with_users)}
      </div>

      {metrics ? (
        <section className="panel">
          <h2>Risk Severity Distribution</h2>
          <div className="metrics-grid">
            {severityEntries.map(([severity, count]) => (
              <div className="metric" key={severity}>
                <span>{severity}</span>
                <strong>{count}</strong>
              </div>
            ))}
          </div>
        </section>
      ) : null}

      {metrics && metrics.baseline_trend.length > 0 ? (
        <section className="panel">
          <h2>Baseline Risk Trend</h2>
          <table>
            <thead>
              <tr>
                <th>Baseline</th>
                <th>Created</th>
                <th>Critical</th>
                <th>High</th>
                <th>Total</th>
              </tr>
            </thead>
            <tbody>
              {metrics.baseline_trend.map((point) => (
                <tr key={point.name}>
                  <td>{point.name}</td>
                  <td>{point.created_at}</td>
                  <td>{point.critical_risks}</td>
                  <td>{point.high_risks}</td>
                  <td>{point.total_risks}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      ) : null}
    </>
  );
}
