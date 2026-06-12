import { useEffect, useMemo, useState } from "react";
import {
  api,
  apiPost,
  type BaselineDiffRecord,
  type BaselineRecord,
  type ScanRunRecord,
} from "../api";

export function OperationsPage() {
  const [runs, setRuns] = useState<ScanRunRecord[]>([]);
  const [baselines, setBaselines] = useState<BaselineRecord[]>([]);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("latest");
  const [newBaseline, setNewBaseline] = useState("");
  const [diff, setDiff] = useState<BaselineDiffRecord | null>(null);
  const [message, setMessage] = useState("");

  async function load() {
    const [runData, baselineData] = await Promise.all([
      api<ScanRunRecord[]>("/api/scan-runs?limit=20"),
      api<BaselineRecord[]>("/api/baselines"),
    ]);
    setRuns(runData);
    setBaselines(baselineData);
    if (!from && baselineData.length > 0) {
      setFrom(baselineData[0].name);
    }
  }

  useEffect(() => {
    load().catch((error) => setMessage(String(error)));
  }, []);

  const trendRows = useMemo(
    () =>
      [...baselines]
        .sort((left, right) => left.created_at.localeCompare(right.created_at))
        .map((baseline) => ({
          name: baseline.name,
          critical: baseline.summary.critical_risks,
          high: baseline.summary.high_risks,
          total: baseline.summary.risks,
        })),
    [baselines],
  );

  async function createBaseline() {
    if (!newBaseline.trim()) {
      setMessage("Baseline name is required.");
      return;
    }
    await apiPost<BaselineRecord>("/api/baselines", { name: newBaseline.trim() });
    setNewBaseline("");
    setMessage("Baseline created.");
    await load();
  }

  async function loadDiff() {
    if (!from.trim()) {
      setMessage("Source baseline is required.");
      return;
    }
    const result = await api<BaselineDiffRecord>(
      `/api/diff?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to || "latest")}`,
    );
    setDiff(result);
    setMessage("Diff loaded.");
  }

  return (
    <>
      <section className="panel">
        <h2>Scan Runs</h2>
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Mode</th>
              <th>Status</th>
              <th>Started</th>
              <th>Finished</th>
              <th>Operator</th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.id}>
                <td>{run.id}</td>
                <td>{run.mode}</td>
                <td>{run.status}</td>
                <td>{run.started_at}</td>
                <td>{run.finished_at ?? "-"}</td>
                <td>{run.operator ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>Baselines</h2>
        <div className="toolbar">
          <input
            value={newBaseline}
            onChange={(event) => setNewBaseline(event.target.value)}
            placeholder="baseline name"
          />
          <button type="button" onClick={() => createBaseline().catch((error) => setMessage(String(error)))}>
            Create
          </button>
        </div>
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Created</th>
              <th>Critical</th>
              <th>High</th>
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            {trendRows.map((row) => (
              <tr key={row.name}>
                <td>{row.name}</td>
                <td>{baselines.find((baseline) => baseline.name === row.name)?.created_at}</td>
                <td>{row.critical}</td>
                <td>{row.high}</td>
                <td>{row.total}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>Baseline Diff</h2>
        <div className="toolbar">
          <input value={from} onChange={(event) => setFrom(event.target.value)} placeholder="from" />
          <input value={to} onChange={(event) => setTo(event.target.value)} placeholder="latest" />
          <button type="button" onClick={() => loadDiff().catch((error) => setMessage(String(error)))}>
            Compare
          </button>
        </div>
        {diff ? (
          <div className="metrics-grid">
            <div className="metric"><span>New</span><strong>{diff.new_risks.length}</strong></div>
            <div className="metric"><span>Resolved</span><strong>{diff.resolved_risks.length}</strong></div>
            <div className="metric"><span>Unchanged</span><strong>{diff.unchanged_risks}</strong></div>
          </div>
        ) : null}
        {message ? <p className="muted">{message}</p> : null}
      </section>
    </>
  );
}
