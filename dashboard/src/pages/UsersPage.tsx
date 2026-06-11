import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type UserSummaryRecord } from "../api";

const LIMIT_OPTIONS = [100, 500, 1000] as const;

function parseLimit(value: string | null): number {
  const parsed = Number(value ?? "500");
  return LIMIT_OPTIONS.includes(parsed as (typeof LIMIT_OPTIONS)[number]) ? parsed : 500;
}

function parseMinCount(value: string | null): number | undefined {
  if (!value) {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

export function UsersPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [users, setUsers] = useState<UserSummaryRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const q = searchParams.get("q") ?? "";
  const minHosts = searchParams.get("min_hosts") ?? "";
  const minRisks = searchParams.get("min_risks") ?? "";
  const limit = parseLimit(searchParams.get("limit"));
  const [searchDraft, setSearchDraft] = useState(q);

  useEffect(() => {
    setSearchDraft(q);
  }, [q]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (searchDraft === q) {
        return;
      }

      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current);
          if (searchDraft.trim()) {
            next.set("q", searchDraft.trim());
          } else {
            next.delete("q");
          }
          return next;
        },
        { replace: true },
      );
    }, 350);

    return () => window.clearTimeout(timer);
  }, [searchDraft, q, setSearchParams]);

  useEffect(() => {
    setLoading(true);
    const query = new URLSearchParams();
    query.set("limit", String(limit));
    if (q.trim()) {
      query.set("q", q.trim());
    }
    const minHostsValue = parseMinCount(minHosts);
    if (minHostsValue !== undefined) {
      query.set("min_hosts", String(minHostsValue));
    }
    const minRisksValue = parseMinCount(minRisks);
    if (minRisksValue !== undefined) {
      query.set("min_risks", String(minRisksValue));
    }

    api<UserSummaryRecord[]>(`/api/users?${query.toString()}`)
      .then(setUsers)
      .catch(() => setUsers([]))
      .finally(() => setLoading(false));
  }, [q, minHosts, minRisks, limit]);

  function updateFilter(key: "min_hosts" | "min_risks" | "limit", value: string) {
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
        <input
          type="search"
          placeholder="Search username"
          value={searchDraft}
          onChange={(event) => setSearchDraft(event.target.value)}
        />
        <select
          value={minHosts}
          onChange={(event) => updateFilter("min_hosts", event.target.value)}
        >
          <option value="">Any host count</option>
          <option value="2">2+ hosts</option>
          <option value="5">5+ hosts</option>
          <option value="10">10+ hosts</option>
        </select>
        <select
          value={minRisks}
          onChange={(event) => updateFilter("min_risks", event.target.value)}
        >
          <option value="">Any risk count</option>
          <option value="1">1+ risks</option>
          <option value="5">5+ risks</option>
        </select>
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
          {loading ? "Loading users..." : `${users.length} users loaded`}
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Username</th>
            <th>Hosts</th>
            <th>Keys</th>
            <th>Sudo</th>
            <th>Risks</th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => (
            <tr key={user.username} className="clickable-row">
              <td>
                <Link to={`/users/${encodeURIComponent(user.username)}`}>{user.username}</Link>
              </td>
              <td>{user.host_count}</td>
              <td>{user.key_count}</td>
              <td>{user.sudo_rule_count}</td>
              <td>{user.risk_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
