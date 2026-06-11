import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, hostLabel, type HostRecord } from "../api";

const LIMIT_OPTIONS = [100, 500, 1000] as const;
type SshFilter = "" | "open" | "closed";

function parseLimit(value: string | null): number {
  const parsed = Number(value ?? "500");
  return LIMIT_OPTIONS.includes(parsed as (typeof LIMIT_OPTIONS)[number]) ? parsed : 500;
}

function parseSshFilter(value: string | null): SshFilter {
  if (value === "open" || value === "closed") {
    return value;
  }
  return "";
}

function sshFilterToParam(filter: SshFilter): boolean | undefined {
  if (filter === "open") {
    return true;
  }
  if (filter === "closed") {
    return false;
  }
  return undefined;
}

export function HostsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [hosts, setHosts] = useState<HostRecord[]>([]);
  const [loading, setLoading] = useState(true);

  const ssh = parseSshFilter(searchParams.get("ssh"));
  const source = searchParams.get("source") ?? "";
  const q = searchParams.get("q") ?? "";
  const limit = parseLimit(searchParams.get("limit"));
  const [sourceDraft, setSourceDraft] = useState(source);
  const [searchDraft, setSearchDraft] = useState(q);

  useEffect(() => {
    setSourceDraft(source);
  }, [source]);

  useEffect(() => {
    setSearchDraft(q);
  }, [q]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      if (sourceDraft === source) {
        return;
      }

      setSearchParams(
        (current) => {
          const next = new URLSearchParams(current);
          if (sourceDraft.trim()) {
            next.set("source", sourceDraft.trim());
          } else {
            next.delete("source");
          }
          return next;
        },
        { replace: true },
      );
    }, 350);

    return () => window.clearTimeout(timer);
  }, [sourceDraft, source, setSearchParams]);

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
    const sshOpen = sshFilterToParam(ssh);
    if (sshOpen !== undefined) {
      query.set("ssh_open", String(sshOpen));
    }
    if (source.trim()) {
      query.set("source", source.trim());
    }
    if (q.trim()) {
      query.set("q", q.trim());
    }

    api<HostRecord[]>(`/api/hosts?${query.toString()}`)
      .then(setHosts)
      .catch(() => setHosts([]))
      .finally(() => setLoading(false));
  }, [ssh, source, q, limit]);

  function updateFilter(key: "ssh" | "limit", value: string) {
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
        <select value={ssh} onChange={(event) => updateFilter("ssh", event.target.value)}>
          <option value="">All SSH states</option>
          <option value="open">SSH open</option>
          <option value="closed">SSH closed</option>
        </select>
        <input
          type="search"
          placeholder="Source filter"
          value={sourceDraft}
          onChange={(event) => setSourceDraft(event.target.value)}
        />
        <input
          type="search"
          placeholder="Search hostname or IP"
          value={searchDraft}
          onChange={(event) => setSearchDraft(event.target.value)}
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
          {loading ? "Loading hosts..." : `${hosts.length} hosts loaded`}
        </span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Host</th>
            <th>Address</th>
            <th>SSH</th>
            <th>Users</th>
            <th>Risks</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {hosts.map((host) => (
            <tr key={host.id} className="clickable-row">
              <td>
                <Link to={`/hosts/${host.id}`}>{hostLabel(host)}</Link>
              </td>
              <td>
                {host.ip_address}:{host.port}
              </td>
              <td>{host.ssh_open ? "open" : "closed"}</td>
              <td>{host.user_count}</td>
              <td>{host.risk_count}</td>
              <td>{host.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
