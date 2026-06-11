import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { Breadcrumbs } from "../components/Breadcrumbs";
import {
  accountHostLabel,
  api,
  riskTarget,
  type UserDetailRecord,
} from "../api";

export function UserDetailPage() {
  const { username } = useParams<{ username: string }>();
  const [detail, setDetail] = useState<UserDetailRecord | null>(null);
  const [error, setError] = useState<string | null>(null);
  const breadcrumbLabel = detail?.username ?? username ?? "User";
  const breadcrumbs = [{ label: "Users", to: "/users" }, { label: breadcrumbLabel }];

  useEffect(() => {
    if (!username) {
      return;
    }

    api<UserDetailRecord>(`/api/users/${encodeURIComponent(username)}`)
      .then((record) => {
        setDetail(record);
        setError(null);
      })
      .catch((fetchError) => {
        setDetail(null);
        setError(fetchError instanceof Error ? fetchError.message : "Failed to load user");
      });
  }, [username]);

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
        <p className="muted">Loading user details...</p>
      </>
    );
  }

  const { accounts, authorized_keys, sudo_rules, risks } = detail;

  return (
    <>
      <Breadcrumbs items={breadcrumbs} />
      <div className="detail-header">
        <h2>{detail.username}</h2>
        <p className="muted">
          {accounts.length} accounts · {authorized_keys.length} keys · {sudo_rules.length} sudo
          rules · {risks.length} risks
        </p>
      </div>
      <div className="detail-section">
        <h3>Accounts ({accounts.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>UID</th>
              <th>Shell</th>
              <th>Home</th>
              <th>Flags</th>
            </tr>
          </thead>
          <tbody>
            {accounts.map((account) => (
              <tr key={account.id}>
                <td>
                  <Link to={`/hosts/${account.host_id}`}>{accountHostLabel(account)}</Link>
                </td>
                <td>{account.uid ?? "-"}</td>
                <td>{account.shell ?? "-"}</td>
                <td>{account.home_dir ?? "-"}</td>
                <td>
                  {account.is_root ? "root " : ""}
                  {account.is_system_account ? "system " : ""}
                  {account.is_service_account ? "service" : ""}
                  {!account.is_root && !account.is_system_account && !account.is_service_account
                    ? "-"
                    : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="detail-section">
        <h3>Authorized keys ({authorized_keys.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Type</th>
              <th>Fingerprint</th>
              <th>Source</th>
            </tr>
          </thead>
          <tbody>
            {authorized_keys.map((key) => (
              <tr key={`${key.public_key_id}-${key.host_id}-${key.source_file ?? ""}-${key.line_number ?? ""}`}>
                <td>
                  <Link to={`/hosts/${key.host_id}`}>{key.hostname ?? key.ip_address}</Link>
                </td>
                <td>{key.key_type}</td>
                <td>
                  <Link to={`/keys/${key.public_key_id}`}>{key.fingerprint_sha256}</Link>
                </td>
                <td>
                  {key.source_file ?? "-"}
                  {key.line_number ? `:${key.line_number}` : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="detail-section">
        <h3>Sudo rules ({sudo_rules.length})</h3>
        <table>
          <thead>
            <tr>
              <th>Host</th>
              <th>Run as</th>
              <th>Command</th>
              <th>No passwd</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {sudo_rules.map((rule) => (
              <tr
                key={`${rule.host_id}-${rule.subject}-${rule.command ?? ""}-${rule.line_number ?? ""}`}
              >
                <td>
                  <Link to={`/hosts/${rule.host_id}`}>{rule.hostname ?? rule.ip_address}</Link>
                </td>
                <td>{rule.run_as ?? "-"}</td>
                <td>{rule.command ?? "-"}</td>
                <td>{rule.nopasswd ? "yes" : "no"}</td>
                <td>{rule.risk_level ?? "-"}</td>
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
