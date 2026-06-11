import { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, riskTarget, type RiskRecord } from "../api";

const LIMIT_OPTIONS = [100, 500, 1000] as const;

function parseLimit(value: string | null): number {
  const parsed = Number(value ?? "500");
  return LIMIT_OPTIONS.includes(parsed as (typeof LIMIT_OPTIONS)[number]) ? parsed : 500;
}

export function RisksPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const [risks, setRisks] = useState<RiskRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const severity = searchParams.get("severity") ?? "";
  const code = searchParams.get("code") ?? "";
  const limit = parseLimit(searchParams.get("limit"));
  const [codeDraft, setCodeDraft] = useState(code);

  useEffect(() => {
    setCodeDraft(code);
  }, [code]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (codeDraft === code) {
        return;
      }

      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current);
          if (codeDraft.trim()) {
            next.set("code", codeDraft.trim());
          } else {
            next.delete("code");
          }
          return next;
        },
        { replace: true },
      );
    }, 350);

    return () => window.clearTimeout(timer);
  }, [codeDraft, code, setSearchParams]);

  useEffect(() => {
    setLoading(true);
    const query = new URLSearchParams();
    query.set("limit", String(limit));
    if (severity) {
      query.set("severity", severity);
    }
    if (code.trim()) {
      query.set("code", code.trim());
    }

    api<RiskRecord[]>(`/api/risks?${query.toString()}`)
      .then(setRisks)
      .catch(() => setRisks([]))
      .finally(() => setLoading(false));
  }, [severity, code, limit]);

  function updateFilter(key: "severity" | "code" | "limit", value: string) {
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (value) {
          next.set(key, value);
        } else {
          next.delete(key);
        }
        return next;
      },
      { replace: true },
    );
  }

  return (
    <>
      <div className="toolbar">
        <select
          value={severity}
          onChange={(event) => updateFilter("severity", event.target.value)}
        >
          <option value="">All severities</option>
          <option value="CRITICAL">CRITICAL</option>
          <option value="HIGH">HIGH</option>
          <option value="MEDIUM">MEDIUM</option>
          <option value="LOW">LOW</option>
        </select>
        <input
          type="search"
          placeholder="Risk code filter"
          value={codeDraft}
          onChange={(event) => setCodeDraft(event.target.value)}
        />
        <select
          value={String(limit)}
          onChange={(event) => updateFilter("limit", event.target.value)}
        >
          {LIMIT_OPTIONS.map((option) => (
            <option key={option} value={option}>
              Limit {option}
            </option>
          ))}
        </select>
        <span className="muted">
          {loading ? "Loading risks..." : `${risks.length} risks loaded`}
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Code</th>
            <th>Target</th>
            <th>Title</th>
          </tr>
        </thead>
        <tbody>
          {risks.map((risk) => (
            <tr
              key={risk.id}
              className="clickable-row"
              onClick={() => navigate(`/risks/${risk.id}`)}
            >
              <td>
                <Link to={`/risks/${risk.id}`} onClick={(event) => event.stopPropagation()}>
                  {risk.id}
                </Link>
              </td>
              <td className={`severity-${risk.severity}`}>{risk.severity}</td>
              <td>{risk.risk_code}</td>
              <td>{riskTarget(risk)}</td>
              <td>{risk.title}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
