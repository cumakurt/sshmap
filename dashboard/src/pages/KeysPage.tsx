import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { useEffect, useState } from "react";
import { api, type KeySummaryRecord } from "../api";

type KeyFilter = "reused" | "all";

function parseKeyFilter(value: string | null): KeyFilter {
  return value === "all" ? "all" : "reused";
}

export function KeysPage() {
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const filter = parseKeyFilter(searchParams.get("filter"));
  const [keys, setKeys] = useState<KeySummaryRecord[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const path = filter === "reused" ? "/api/keys/reuse" : "/api/keys";
    api<KeySummaryRecord[]>(path)
      .then(setKeys)
      .catch(() => setKeys([]))
      .finally(() => setLoading(false));
  }, [filter]);

  function setFilter(nextFilter: KeyFilter) {
    setSearchParams(
      (current) => {
        const next = new URLSearchParams(current);
        if (nextFilter === "reused") {
          next.delete("filter");
        } else {
          next.set("filter", nextFilter);
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
          value={filter}
          onChange={(event) => setFilter(event.target.value as KeyFilter)}
        >
          <option value="reused">Reused keys only</option>
          <option value="all">All keys</option>
        </select>
        <span className="muted">{loading ? "Loading keys..." : `${keys.length} keys loaded`}</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Type</th>
            <th>Fingerprint</th>
            <th>Hosts</th>
            <th>Users</th>
            <th>Root</th>
            <th>Risks</th>
          </tr>
        </thead>
        <tbody>
          {keys.map((key) => (
            <tr
              key={key.id}
              className="clickable-row"
              onClick={() => navigate(`/keys/${key.id}`)}
            >
              <td>
                <Link to={`/keys/${key.id}`} onClick={(event) => event.stopPropagation()}>
                  {key.id}
                </Link>
              </td>
              <td>{key.key_type}</td>
              <td>
                <Link to={`/keys/${key.id}`} onClick={(event) => event.stopPropagation()}>
                  {key.fingerprint_sha256}
                </Link>
              </td>
              <td>{key.host_count}</td>
              <td>{key.user_count}</td>
              <td>{key.root_usage_count}</td>
              <td>{key.risk_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
