import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Breadcrumbs } from "../components/Breadcrumbs";
import { api, riskTarget, type KeyDetailRecord } from "../api";

function keyBreadcrumbLabel(detail: KeyDetailRecord | null, id: string | undefined): string {
  if (detail) {
    return detail.key.fingerprint_sha256.slice(0, 24);
  }
  return id ? `Key ${id}` : "Key";
}

export function KeyDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [detail, setDetail] = useState<KeyDetailRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const breadcrumbs = [
    { label: "Keys", to: "/keys" },
    { label: keyBreadcrumbLabel(detail, id) },
  ];

  useEffect(() => {
    if (!id) {
      return;
    }

    api<KeyDetailRecord>(`/api/keys/${encodeURIComponent(id)}`)
      .then((record) => {
        setDetail(record);
        setError(null);
      })
      .catch((fetchError) => {
        setDetail(null);
        setError(fetchError instanceof Error ? fetchError.message : "Failed to load key");
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

  if (!detail) {
    return (
      <>
        <Breadcrumbs items={breadcrumbs} />
        <p className="muted">Loading key details...</p>
      </>
    );
  }

  const { key, locations, risks } = detail;

  return (
    <>
      <Breadcrumbs items={breadcrumbs} />
      <div className="detail-header">
        <h2>{key.key_type}</h2>
        <p className="muted">{key.fingerprint_sha256}</p>
        {key.key_comment ? <p className="muted">Comment: {key.key_comment}</p> : null}
      </div>
      <div className="grid">
        <div className="card">
          <span>Hosts</span>
          <strong>{key.host_count}</strong>
        </div>
        <div className="card">
          <span>Users</span>
          <strong>{key.user_count}</strong>
        </div>
        <div className="card">
          <span>Root usages</span>
          <strong>{key.root_usage_count}</strong>
        </div>
        <div className="card">
          <span>Risks</span>
          <strong>{risks.length}</strong>
        </div>
      </div>
      <div className="detail-section">
        <h3>Locations ({locations.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>User</th>
              <th>Source</th>
              <th>Options</th>
            </tr>
          </thead>
          <tbody>
            {locations.map((location) => (
              <tr
                key={`${location.host_id}-${location.username}-${location.source_file ?? ""}-${location.line_number ?? ""}`}
              >
                <td>
                  <Link to={`/hosts/${location.host_id}`}>
                    {location.hostname ?? location.ip_address}
                  </Link>
                </td>
                <td>
                  <Link to={`/users/${encodeURIComponent(location.username)}`}>
                    {location.username}
                  </Link>
                </td>
                <td>
                  {location.source_file ?? "-"}
                  {location.line_number ? `:${location.line_number}` : ""}
                </td>
                <td>{location.options ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="detail-section">
        <h3>Risks ({risks.length})</h3>
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
              <tr key={risk.id} className="clickable-row">
                <td>
                  <Link to={`/risks/${risk.id}`}>{risk.id}</Link>
                </td>
                <td className={`severity-${risk.severity}`}>{risk.severity}</td>
                <td>{risk.risk_code}</td>
                <td>{riskTarget(risk)}</td>
                <td>{risk.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
