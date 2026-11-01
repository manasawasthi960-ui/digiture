import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type FirewallProfile = {
  Name?: string;
  Enabled?: boolean | string;
};

type FirewallStatus = {
  success: boolean;
  profiles: string;
  details: string;
};

function App() {
  const [checking, setChecking] = useState(false);
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null);
  const [error, setError] = useState("");

  async function checkFirewall() {
    if (checking) return;

    setChecking(true);
    setError("");

    try {
      const result = await invoke<FirewallStatus>(
        "check_firewall_status"
      );

      setFirewall(result);

      if (!result.success) {
        setError(result.details);
      }
    } catch (err) {
      setFirewall(null);
      setError(String(err));
    } finally {
      setChecking(false);
    }
  }

  function getProfiles(): FirewallProfile[] {
    if (!firewall?.success) return [];

    try {
      const parsed: unknown = JSON.parse(firewall.profiles);
      const profiles = Array.isArray(parsed) ? parsed : [parsed];

      return profiles as FirewallProfile[];
    } catch {
      return [];
    }
  }

  const profiles = getProfiles();
  const disabledCount = profiles.filter(
    (profile) => String(profile.Enabled).toLowerCase() === "false"
  ).length;

  function getFirewallSummary() {
    if (!firewall?.success) return "Not checked";
    if (profiles.length === 0) return "No profiles returned";

    return disabledCount > 0
      ? `${disabledCount} profile(s) disabled`
      : "All returned profiles enabled";
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
          <button className="nav-item active">
            ▦ <span>Overview</span>
          </button>
          <button className="nav-item" onClick={checkFirewall}>
            ⌕ <span>Security Scan</span>
          </button>
          <button className="nav-item">
            ◇ <span>Findings</span>
          </button>
          <button className="nav-item">
            ✓ <span>Verification</span>
          </button>
          <button className="nav-item">
            ◷ <span>Activity History</span>
          </button>
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
          <div className="breadcrumb">
            Workspace <span>/</span> Overview
          </div>
          <div className="local-badge">
            <span className="status-dot" />
            LOCAL DESKTOP APP
          </div>
        </header>

        <section className="welcome-section">
          <div>
            <div className="eyebrow">YOUR DIGITAL SAFETY WORKSPACE</div>
            <h2>
              Security, made <span>clear.</span>
            </h2>
            <p>
              Understand your device&apos;s security status, review potential
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
            <strong>Read-only security check</strong>
            <p>
              Digiture checks Windows Firewall profile status. It does not
              change firewall settings or perform a complete security
              assessment.
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
            onClick={checkFirewall}
            disabled={checking}
          >
            {checking ? "Checking firewall..." : "↻ Check firewall"}
          </button>
        </section>

        <section className="stats-grid">
          <article className="stat-card">
            <div className="stat-top">
              <span>Security checks</span>
              <span className="stat-icon purple">⌕</span>
            </div>
            <div className="stat-number">
              {firewall?.success ? "1" : "—"}
            </div>
            <div className="stat-caption">
              {firewall?.success ? "Firewall check completed" : "Awaiting check"}
            </div>
          </article>

          <article className="stat-card">
            <div className="stat-top">
              <span>Firewall profiles</span>
              <span className="stat-icon green">✓</span>
            </div>
            <div className="stat-number">
              {firewall?.success ? profiles.length : "—"}
            </div>
            <div className="stat-caption">Profiles returned by Windows</div>
          </article>

          <article className="stat-card">
            <div className="stat-top">
              <span>Firewall status</span>
              <span className="stat-icon amber">!</span>
            </div>
            <div className="stat-number">
              {firewall?.success ? (disabledCount > 0 ? "!" : "✓") : "—"}
            </div>
            <div className="stat-caption">{getFirewallSummary()}</div>
          </article>
        </section>

        <section className="checks-panel">
          <div className="panel-heading">
            <div>
              <h3>Security checkup</h3>
              <p>Results from the available read-only check</p>
            </div>
            <span className="check-count">01 CHECK</span>
          </div>

          <article className="check-row">
            <div className="check-symbol">⬡</div>
            <div className="check-info">
              <strong>Windows Firewall</strong>
              <p>Reads the status of Windows Firewall profiles.</p>
            </div>
            <span className="check-status">
              <span className="small-dot" />
              {checking
                ? "Checking"
                : firewall?.success
                  ? "Retrieved"
                  : "Not checked"}
            </span>
            <span className="row-arrow">›</span>
          </article>

          {firewall?.success && profiles.length > 0 && (
            <div className="firewall-results">
              <h4>Firewall profile results</h4>

              {profiles.map((profile, index) => {
                const enabled =
                  String(profile.Enabled).toLowerCase() === "true";

                return (
                  <article
                    className="check-row"
                    key={`${profile.Name ?? "profile"}-${index}`}
                  >
                    <div className="check-info">
                      <strong>{profile.Name ?? `Profile ${index + 1}`}</strong>
                      <p>
                        {enabled
                          ? "Windows reports this profile is enabled."
                          : "Windows reports this profile is disabled. Review this setting."}
                      </p>
                    </div>
                    <span className="check-status">
                      <span className="small-dot" />
                      {enabled ? "Enabled" : "Disabled"}
                    </span>
                  </article>
                );
              })}
            </div>
          )}

          {error && (
            <div className="notice error-notice" role="alert">
              <span className="notice-icon">!</span>
              <div>
                <strong>Firewall check failed</strong>
                <p>{error}</p>
              </div>
            </div>
          )}

          {firewall?.success && (
            <div className="panel-footer">
              <span className="footer-dot" />
              {firewall.details} No settings were changed.
            </div>
          )}

          {!firewall && !error && (
            <div className="panel-footer">
              <span className="footer-dot" />
              Select &quot;Check firewall&quot; to retrieve the current status.
            </div>
          )}
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