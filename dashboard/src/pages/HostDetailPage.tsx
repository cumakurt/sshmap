import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Breadcrumbs } from "../components/Breadcrumbs";
import {
  api,
  hostLabel,
  riskTarget,
  type HostDetailRecord,
} from "../api";

export function HostDetailPage() {
  const { id } = useParams<{ id: string }>();
  const [detail, setDetail] = useState<HostDetailRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const breadcrumbLabel = detail ? hostLabel(detail.host) : id ?? "Host";
  const breadcrumbs = [{ label: "Hosts", to: "/hosts" }, { label: breadcrumbLabel }];

  useEffect(() => {
    if (!id) {
      return;
    }

    api<HostDetailRecord>(`/api/hosts/${encodeURIComponent(id)}`)
      .then((record) => {
        setDetail(record);
        setError(null);
      })
      .catch((fetchError) => {
        setDetail(null);
        setError(fetchError instanceof Error ? fetchError.message : "Failed to load host");
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
        <p className="muted">Loading host details...</p>
      </>
    );
  }

  const { host, users, risks } = detail;

  return (
    <>
      <Breadcrumbs items={breadcrumbs} />
      <div className="detail-header">
        <h2>{hostLabel(host)}</h2>
        <p className="muted">
          {host.ip_address}:{host.port} · SSH {host.ssh_open ? "open" : "closed"} · {host.source}
        </p>
      </div>
      <div className="grid">
        <div className="card">
          <span>Users</span>
          <strong>{users.length}</strong>
        </div>
        <div className="card">
          <span>Risks</span>
          <strong>{risks.length}</strong>
        </div>
        <div className="card">
          <span>First seen</span>
          <strong className="detail-metric">{host.first_seen}</strong>
        </div>
        <div className="card">
          <span>Last seen</span>
          <strong className="detail-metric">{host.last_seen}</strong>
        </div>
      </div>
      {host.ssh_banner ? (
        <div className="detail-section">
          <h3>SSH banner</h3>
          <pre className="inline-pre">{host.ssh_banner}</pre>
        </div>
      ) : null}
      <div className="detail-section">
        <h3>Users ({users.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Username</th>
              <th>UID</th>
              <th>Shell</th>
              <th>Home</th>
              <th>Flags</th>
            </tr>
          </thead>
          <tbody>
            {users.map((user) => (
              <tr key={user.id}>
                <td>
                  <Link to={`/users/${encodeURIComponent(user.username)}`}>{user.username}</Link>
                </td>
                <td>{user.uid ?? "-"}</td>
                <td>{user.shell ?? "-"}</td>
                <td>{user.home_dir ?? "-"}</td>
                <td>
                  {user.is_root ? "root " : ""}
                  {user.is_system_account ? "system " : ""}
                  {user.is_service_account ? "service" : ""}
                  {!user.is_root && !user.is_system_account && !user.is_service_account ? "-" : ""}
                </td>
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
