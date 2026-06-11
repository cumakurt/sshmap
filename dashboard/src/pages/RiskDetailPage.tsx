import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { api, riskTarget, type RiskRecord } from "../api";

function DetailField({ label, value }: { label: string; value: string | null | undefined }) {
  if (!value) {
    return null;
  }

  return (
    <div className="detail-field">
      <h4>{label}</h4>
      <pre className="inline-pre">{value}</pre>
    </div>
  );
}

export function RiskDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [risk, setRisk] = useState<RiskRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const breadcrumbLabel = risk?.risk_code ?? (id ? `Risk ${id}` : "Risk");
  const breadcrumbs = [{ label: "Risks", to: "/risks" }, { label: breadcrumbLabel }];

  useEffect(() => {
    if (!id) {
      return;
    }

    api<RiskRecord>(`/api/risks/${encodeURIComponent(id)}`)
      .then((record) => {
        setRisk(record);
        setError(null);
      })
      .catch((fetchError) => {
        setRisk(null);
        setError(fetchError instanceof Error ? fetchError.message : "Failed to load risk");
      });
  }, [id]);

  if (error) {
    return (
      <>
        <Breadcrumbs items={breadcrumbs} />
        <div className="error">{error}</div>
      </>
    );
  }

  if (!risk) {
    return (
      <>
        <Breadcrumbs items={breadcrumbs} />
        <p className="muted">Loading risk details...</p>
      </>
    );
  }

  return (
    <>
      <Breadcrumbs items={breadcrumbs} />
      <div className="detail-header">
        <h2>{risk.title}</h2>
        <p className="muted">
          <span className={`severity-${risk.severity}`}>{risk.severity}</span>
          {" · "}
          {risk.risk_code} · {riskTarget(risk)}
        </p>
      </div>
      <div className="grid">
        <div className="card">
          <span>Score</span>
          <strong>{risk.score}</strong>
        </div>
        <div className="card">
          <span>Confidence</span>
          <strong className="detail-metric">{risk.confidence}</strong>
        </div>
        <div className="card">
          <span>Status</span>
          <strong className="detail-metric">{risk.status}</strong>
        </div>
        <div className="card">
          <span>Last seen</span>
          <strong className="detail-metric">{risk.last_seen}</strong>
        </div>
      </div>
      <div className="detail-meta">
        {risk.host_id ? (
          <span>
            Host:{" "}
            <Link to={`/hosts/${risk.host_id}`}>
              {risk.hostname ?? risk.ip_address ?? risk.host_id}
            </Link>
          </span>
        ) : null}
        {risk.username ? (
          <span>
            User: <Link to={`/users/${encodeURIComponent(risk.username)}`}>{risk.username}</Link>
          </span>
        ) : null}
        {risk.public_key_fingerprint ? (
          <span>Fingerprint: {risk.public_key_fingerprint}</span>
        ) : null}
      </div>
      <DetailField label="Description" value={risk.description} />
      <DetailField label="Impact" value={risk.impact} />
      <DetailField label="Evidence" value={risk.evidence} />
      <DetailField label="Recommendation" value={risk.recommendation} />
    </>
  );
}
