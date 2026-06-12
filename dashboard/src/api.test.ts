import { beforeEach, describe, expect, it } from "vitest";
import {
  accountHostLabel,
  getToken,
  hostLabel,
  parseGraphListResponse,
  riskTarget,
  setToken,
  type GraphEdgeRecord,
  type HostRecord,
  type RiskRecord,
  type UserAccountRecord,
} from "./api";

describe("api helpers", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("stores and reads API tokens", () => {
    setToken(" secret-token ");
    expect(getToken()).toBe("secret-token");
    setToken("   ");
    expect(getToken()).toBe("");
  });

  it("formats host labels with hostname preference", () => {
    const host: HostRecord = {
      id: 1,
      hostname: "web01",
      fqdn: "web01.example.com",
      ip_address: "10.0.0.10",
      port: 22,
      os_family: null,
      os_version: null,
      environment: null,
      criticality: null,
      ssh_open: true,
      ssh_banner: null,
      source: "scan",
      first_seen: "2026-01-01",
      last_seen: "2026-01-02",
      user_count: 1,
      risk_count: 0,
    };

    expect(hostLabel(host)).toBe("web01");
  });

  it("formats account host labels", () => {
    const account: UserAccountRecord = {
      id: 1,
      username: "deploy",
      host_id: 1,
      hostname: "web01",
      ip_address: "10.0.0.10",
      uid: 1000,
      gid: 1000,
      home_dir: "/home/deploy",
      shell: "/bin/bash",
      is_root: false,
      is_system_account: false,
      is_service_account: false,
    };

    expect(accountHostLabel(account)).toBe("web01");
  });

  it("parses graph list API responses", () => {
    const edge: GraphEdgeRecord = {
      id: 1,
      from_type: "HOST",
      from_id: 1,
      from_label: "web01",
      to_type: "USER",
      to_id: 2,
      to_label: "deploy@web01",
      edge_type: "HOST_HAS_USER",
      weight: 1,
      confidence: "HIGH",
      evidence: "test",
    };

    expect(parseGraphListResponse([edge])).toEqual({
      edges: [edge],
      truncated: false,
      total_edges: 1,
      edge_limit: 1,
    });

    expect(
      parseGraphListResponse({
        edges: [edge],
        truncated: true,
        total_edges: 72,
        edge_limit: 5000,
      }),
    ).toEqual({
      edges: [edge],
      truncated: true,
      total_edges: 72,
      edge_limit: 5000,
    });
  });

  it("formats risk targets for user and host scoped findings", () => {
    const userRisk: RiskRecord = {
      id: 1,
      host_id: 1,
      hostname: "web01",
      ip_address: "10.0.0.10",
      username: "deploy",
      public_key_fingerprint: null,
      risk_code: "SSH_PASSWORD_AUTH_ENABLED",
      severity: "HIGH",
      score: 80,
      confidence: "HIGH",
      title: "Password auth enabled",
      description: null,
      impact: null,
      evidence: null,
      recommendation: null,
      status: "OPEN",
      first_seen: "2026-01-01",
      last_seen: "2026-01-01",
    };

    expect(riskTarget(userRisk)).toBe("deploy@web01");
  });
});
