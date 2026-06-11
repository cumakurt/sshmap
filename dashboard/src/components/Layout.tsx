import { NavLink, Outlet } from "react-router-dom";

export function Layout({ summaryLine, error }: { summaryLine: string; error: string | null }) {
  const linkClass = ({ isActive }: { isActive: boolean }) => (isActive ? "active" : undefined);

  return (
    <>
      <header>
        <div>
          <h1>SSHMap Dashboard</h1>
          <p>Read-only SSH exposure and access graph analysis</p>
        </div>
        <div className="muted" style={{ fontSize: "0.9rem" }}>
          {summaryLine || "Loading inventory..."}
        </div>
      </header>
      <nav>
        <NavLink to="/" end className={linkClass}>
          Dashboard
        </NavLink>
        <NavLink to="/hosts" className={linkClass}>
          Hosts
        </NavLink>
        <NavLink to="/users" className={linkClass}>
          Users
        </NavLink>
        <NavLink to="/keys" className={linkClass}>
          Keys
        </NavLink>
        <NavLink to="/risks" className={linkClass}>
          Risks
        </NavLink>
        <NavLink to="/graph" className={linkClass}>
          Graph
        </NavLink>
        <NavLink to="/tools" className={linkClass}>
          Tools
        </NavLink>
      </nav>
      <main>
        {error ? <div className="error">{error}</div> : null}
        <Outlet />
      </main>
    </>
  );
}
