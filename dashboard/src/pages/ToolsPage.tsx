import { useState } from "react";
import {
  api,
  apiPost,
  getToken,
  setToken,
  type BlastRadiusRecord,
  type GraphPathRecord,
  type RemediationRecord,
  type RiskExceptionRecord,
} from "../api";

export function ToolsPage() {
  const [token, setTokenValue] = useState(getToken());
  const [pathFrom, setPathFrom] = useState("");
  const [pathTo, setPathTo] = useState("");
  const [blastUser, setBlastUser] = useState("");
  const [riskCode, setRiskCode] = useState("");
  const [exceptionCode, setExceptionCode] = useState("");
  const [exceptionReason, setExceptionReason] = useState("");
  const [output, setOutput] = useState("Use the controls below to query path and blast radius analysis.");

  async function runQuery(label: string, request: Promise<unknown>) {
    try {
      const result = await request;
      setOutput(JSON.stringify(result, null, 2));
    } catch (error) {
      setOutput(`${label} failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  return (
    <>
      <div className="tools-section panel">
        <h2>API token</h2>
        <label htmlFor="api-token">X-SSHMap-Token</label>
        <input
          id="api-token"
          type="password"
          value={token}
          onChange={(event) => setTokenValue(event.target.value)}
          placeholder="Optional when server has no token"
        />
        <button
          type="button"
          onClick={() => {
            setToken(token);
            setOutput("Token saved.");
          }}
        >
          Save token
        </button>
      </div>

      <div className="tools-section panel">
        <h2>Path analysis</h2>
        <label htmlFor="path-from">From</label>
        <input
          id="path-from"
          value={pathFrom}
          onChange={(event) => setPathFrom(event.target.value)}
          placeholder="key:SHA256:..."
        />
        <label htmlFor="path-to">To</label>
        <input
          id="path-to"
          value={pathTo}
          onChange={(event) => setPathTo(event.target.value)}
          placeholder="host:web01"
        />
        <button
          type="button"
          onClick={() =>
            runQuery(
              "Path query",
              api<GraphPathRecord>(
                `/api/path?from=${encodeURIComponent(pathFrom)}&to=${encodeURIComponent(pathTo)}`,
              ),
            )
          }
        >
          Find path
        </button>
      </div>

      <div className="tools-section panel">
        <h2>Blast radius</h2>
        <label htmlFor="blast-user">Username</label>
        <input
          id="blast-user"
          value={blastUser}
          onChange={(event) => setBlastUser(event.target.value)}
          placeholder="deploy"
        />
        <button
          type="button"
          onClick={() =>
            runQuery(
              "Blast radius",
              api<BlastRadiusRecord>(`/api/blast-radius?user=${encodeURIComponent(blastUser)}`),
            )
          }
        >
          Analyze
        </button>
        <button
          type="button"
          onClick={() =>
            runQuery("Exceptions", api<RiskExceptionRecord[]>("/api/exceptions"))
          }
        >
          Load exceptions
        </button>
      </div>

      <div className="tools-section panel">
        <h2>Exception</h2>
        <label htmlFor="exception-code">Risk code</label>
        <input
          id="exception-code"
          value={exceptionCode}
          onChange={(event) => setExceptionCode(event.target.value)}
          placeholder="SSH_PASSWORD_AUTH_ENABLED"
        />
        <label htmlFor="exception-reason">Reason</label>
        <input
          id="exception-reason"
          value={exceptionReason}
          onChange={(event) => setExceptionReason(event.target.value)}
          placeholder="accepted until remediation window"
        />
        <button
          type="button"
          onClick={() =>
            runQuery(
              "Add exception",
              apiPost<RiskExceptionRecord>("/api/exceptions", {
                code: exceptionCode,
                reason: exceptionReason,
              }),
            )
          }
        >
          Add
        </button>
      </div>

      <div className="tools-section panel">
        <h2>Remediation</h2>
        <label htmlFor="risk-code">Risk code</label>
        <input
          id="risk-code"
          value={riskCode}
          onChange={(event) => setRiskCode(event.target.value)}
          placeholder="SSH_PASSWORD_AUTH_ENABLED"
        />
        <button
          type="button"
          onClick={() =>
            runQuery(
              "Remediation",
              api<RemediationRecord>(`/api/remediation/${encodeURIComponent(riskCode)}`),
            )
          }
        >
          Load
        </button>
      </div>

      <pre className="tools-output">{output}</pre>
    </>
  );
}
