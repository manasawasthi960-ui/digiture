import { useState } from "react";
import "./App.css";

function App() {
  const [scanning, setScanning] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);

  function startDemoScan() {
    if (scanning) return;

    setScanning(true);
    setScanComplete(false);

    window.setTimeout(() => {
      setScanning(false);
      setScanComplete(true);
    }, 1200);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">D</div>
          <div>
            <h1>Digiture</h1>
            <span>Digital Security</span>
          </div>
        </div>

        <p className="nav-label">WORKSPACE</p>

        <nav className="navigation">
          <button className="nav-item active">▦ <span>Overview</span></button>
          <button className="nav-item">⌕ <span>Security Scan</span></button>
          <button className="nav-item">◇ <span>Findings</span></button>
          <button className="nav-item">✓ <span>Verification</span></button>
          <button className="nav-item">◷ <span>Activity History</span></button>
        </nav>

        <div className="sidebar-bottom">
          <div className="privacy-card">
            <strong>Your device, your control.</strong>
            <p>Review findings before taking action. No automatic fixes.</p>
          </div>
          <div className="version">DIGITURE PREVIEW · 0.1.0</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">Workspace <span>/</span> Overview</div>
          <div className="local-badge">
            <span className="status-dot" />
            LOCAL DESKTOP APP
          </div>
        </header>

        <section className="welcome-section">
          <div>
            <div className="eyebrow">YOUR DIGITAL SAFETY WORKSPACE</div>
            <h2>Security, made <span>clear.</span></h2>
            <p>
              Understand your device's security status, review potential
              issues, and verify improvements.
            </p>
          </div>
          <div className="shield-art" aria-hidden="true">
            <div className="shield">✓</div>
          </div>
        </section>

        <section className="notice">
          <span className="notice-icon">i</span>
          <div>
            <strong>Preview mode</strong>
            <p>
              This scan is a demonstration only. It does not inspect your
              computer or change any settings.
            </p>
          </div>
        </section>

        <section className="section-heading">
          <div>
            <h3>Security overview</h3>
            <p>Your device status at a glance</p>
          </div>
          <button
            className="primary-button"
            onClick={startDemoScan}
            disabled={scanning}
          >
            {scanning ? "Running demo..." : "↻ Run demo scan"}
          </button>
        </section>

        <section className="stats-grid">
          <article className="stat-card">
            <div className="stat-top">
              <span>Security checks</span>
              <span className="stat-icon purple">⌕</span>
            </div>
            <div className="stat-number">{scanComplete ? "4" : "—"}</div>
            <div className="stat-caption">
              {scanComplete ? "Demo checks displayed" : "Awaiting first scan"}
            </div>
          </article>

          <article className="stat-card">
            <div className="stat-top">
              <span>Passed checks</span>
              <span className="stat-icon green">✓</span>
            </div>
            <div className="stat-number">0</div>
            <div className="stat-caption">No checks verified yet</div>
          </article>

          <article className="stat-card">
            <div className="stat-top">
              <span>Needs review</span>
              <span className="stat-icon amber">!</span>
            </div>
            <div className="stat-number">{scanComplete ? "4" : "—"}</div>
            <div className="stat-caption">
              {scanComplete ? "Demo items, not real findings" : "No real scan performed"}
            </div>
          </article>
        </section>

        <section className="checks-panel">
          <div className="panel-heading">
            <div>
              <h3>Security checkup</h3>
              <p>Areas planned for real, read-only inspection</p>
            </div>
            <span className="check-count">04 CHECKS</span>
          </div>

          {[
            ["◈", "Windows Security", "Antivirus and device protection status"],
            ["⬡", "Firewall", "Windows firewall protection status"],
            ["↻", "System Updates", "Review Windows update status"],
            ["▤", "Startup Applications", "Review applications that launch at startup"],
          ].map(([icon, title, description]) => (
            <article className="check-row" key={title}>
              <div className="check-symbol">{icon}</div>
              <div className="check-info">
                <strong>{title}</strong>
                <p>{description}</p>
              </div>
              <span className="check-status">
                <span className="small-dot" />
                {scanComplete ? "Demo only" : "Not checked"}
              </span>
              <span className="row-arrow">›</span>
            </article>
          ))}

          <div className="panel-footer">
            <span className="footer-dot" />
            No system settings have been changed.
          </div>
        </section>

        <footer className="app-footer">
          <span>Digiture · Transparency and user control</span>
          <span>PREVIEW BUILD</span>
        </footer>
      </main>
    </div>
  );
}

export default App;