import { useEffect, useState } from "react";
import {
  api,
  type DataQualityFindingRecord,
  type HostAliasRecord,
} from "../api";

export function DataQualityPage() {
  const [findings, setFindings] = useState<DataQualityFindingRecord[]>([]);
  const [aliases, setAliases] = useState<HostAliasRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api<DataQualityFindingRecord[]>("/api/data-quality"),
      api<HostAliasRecord[]>("/api/host-aliases"),
    ])
      .then(([qualityRows, aliasRows]) => {
        setFindings(qualityRows);
        setAliases(aliasRows);
      })
      .catch(() => {
        setFindings([]);
        setAliases([]);
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <div className="toolbar">
        <span className="muted">
          {loading
            ? "Loading data quality..."
            : `${findings.length} findings · ${aliases.length} aliases`}
        </span>
      </div>

      <section className="panel">
        <h2>Data Quality</h2>
        <table>
          <thead>
            <tr>
              <th>Severity</th>
              <th>Code</th>
              <th>Host</th>
              <th>Message</th>
              <th>Evidence</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => (
              <tr key={finding.id}>
                <td>{finding.severity}</td>
                <td>{finding.code}</td>
                <td>{finding.hostname ?? finding.ip_address ?? "-"}</td>
                <td>{finding.message}</td>
                <td>{finding.evidence ?? "-"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel">
        <h2>Host Aliases</h2>
        <table>
          <thead>
            <tr>
              <th>Alias</th>
              <th>IP</th>
              <th>Host</th>
              <th>Kind</th>
              <th>Source</th>
              <th>Confidence</th>
            </tr>
          </thead>
          <tbody>
            {aliases.map((alias) => (
              <tr key={alias.id}>
                <td>{alias.alias}</td>
                <td>{alias.ip_address}</td>
                <td>{alias.hostname ?? alias.host_ip_address}</td>
                <td>{alias.alias_kind}</td>
                <td>{alias.source_file ?? alias.source}</td>
                <td>{alias.confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </>
  );
}
