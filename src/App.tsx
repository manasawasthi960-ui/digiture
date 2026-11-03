import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type FirewallProfile = {
  Name?: string;
  Enabled?: boolean | string;
};

type AntivirusProduct = {
  displayName?: string;
  productState?: number;
};

type AntivirusStatus = {
  success: boolean;
  products: string;
  details: string;
};

type FirewallStatus = {
  success: boolean;
  profiles: string;
  details: string;
};

type RealTimeProtectionStatus = {
  success: boolean;
  antivirus_enabled: boolean | null;
  real_time_protection_enabled: boolean | null;
  service_enabled: boolean | null;
  details: string;
};

function App() {
  const [checking, setChecking] = useState(false);
  const [firewall, setFirewall] = useState<FirewallStatus | null>(null);
  const [error, setError] = useState("");

  const [checkingAntivirus, setCheckingAntivirus] = useState(false);
  const [antivirus, setAntivirus] = useState<AntivirusStatus | null>(null);
  const [antivirusError, setAntivirusError] = useState("");

  const [checkingProtection, setCheckingProtection] = useState(false);
  const [protection, setProtection] = useState<RealTimeProtectionStatus | null>(null);
  const [protectionError, setProtectionError] = useState("");

  const [checkingAll, setCheckingAll] = useState(false);

  async function checkFirewall() {
    if (checking) return;
    setChecking(true);
    setError("");

    try {
      const result = await invoke<FirewallStatus>("check_firewall_status");
      setFirewall(result);
      if (!result.success) setError(result.details || "Firewall check failed.");
    } catch (err) {
      setFirewall(null);
      setError(String(err));
    } finally {
      setChecking(false);
    }
  }

  async function checkAntivirus() {
    if (checkingAntivirus) return;
    setCheckingAntivirus(true);
    setAntivirusError("");

    try {
      const result = await invoke<AntivirusStatus>("check_antivirus_status");
      setAntivirus(result);
      if (!result.success) setAntivirusError(result.details || "Antivirus check failed.");
    } catch (err) {
      setAntivirus(null);
      setAntivirusError(String(err));
    } finally {
      setCheckingAntivirus(false);
    }
  }

  async function checkRealTimeProtection() {
    if (checkingProtection) return;
    setCheckingProtection(true);
    setProtectionError("");

    try {
      const result = await invoke<RealTimeProtectionStatus>("check_real_time_protection");
      setProtection(result);
      if (!result.success) {
        setProtectionError(result.details || "Real-time protection check failed.");
      }
    } catch (err) {
      setProtection(null);
      setProtectionError(String(err));
    } finally {
      setCheckingProtection(false);
    }
  }

  async function refreshAllChecks() {
    if (checkingAll) return;
    setCheckingAll(true);
    try {
      await Promise.all([
        checkFirewall(),
        checkAntivirus(),
        checkRealTimeProtection(),
      ]);
    } finally {
      setCheckingAll(false);
    }
  }

  function getAntivirusProducts(): AntivirusProduct[] {
    if (!antivirus?.success || !antivirus.products) return [];

    try {
      const parsed: unknown = JSON.parse(antivirus.products);
      if (Array.isArray(parsed)) return parsed as AntivirusProduct[];
      if (parsed && typeof parsed === "object") return [parsed as AntivirusProduct];
      return [];
    } catch {
      return [];
    }
  }

  function getProfiles(): FirewallProfile[] {
    if (!firewall?.success || !firewall.profiles) return [];

    try {
      const parsed: unknown = JSON.parse(firewall.profiles);
      return Array.isArray(parsed)
        ? (parsed as FirewallProfile[])
        : [parsed as FirewallProfile];
    } catch {
      return [];
    }
  }

  const profiles = getProfiles();
  const antivirusProducts = getAntivirusProducts();

  const disabledCount = profiles.filter(
    (profile) => String(profile.Enabled).toLowerCase() === "false"
  ).length;

  const allChecksSuccessful =
    firewall?.success === true &&
    antivirus?.success === true &&
    protection?.success === true;

  const securityScore = allChecksSuccessful
    ? (profiles.length > 0 && profiles.every(
        (profile) => String(profile.Enabled).toLowerCase() === "true"
      ) ? 40 : 0) +
      (antivirusProducts.length > 0 ? 30 : 0) +
      (protection?.real_time_protection_enabled === true ? 30 : 0)
    : null;

  const completedChecks =
    (firewall !== null ? 1 : 0) +
    (antivirus !== null ? 1 : 0) +
    (protection !== null ? 1 : 0);

  function getFirewallSummary(): string {
    if (!firewall?.success) return "Not checked";
    if (profiles.length === 0) return "No profiles returned";
    return disabledCount > 0
      ? `${disabledCount} profile(s) disabled`
      : "All returned profiles enabled";
  }

  const isAnyChecking =
    checkingAll || checking || checkingAntivirus || checkingProtection;

  const statusText = isAnyChecking
    ? "Running diagnostics..."
    : allChecksSuccessful
    ? "All checks completed"
    : completedChecks > 0
    ? `${completedChecks} of 3 checks completed`
    : "Ready to inspect";

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </div>
          <div className="brand-text">
            <span className="brand-name">Digiture</span>
            <span className="brand-badge">Digital Security</span>
          </div>
        </div>

        <p className="nav-label">Workspace</p>

        <nav className="navigation" aria-label="Main navigation">
          <button className="nav-item active" type="button">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="3" y="3" width="7" height="7" rx="1.5" />
              <rect x="14" y="3" width="7" height="7" rx="1.5" />
              <rect x="14" y="14" width="7" height="7" rx="1.5" />
              <rect x="3" y="14" width="7" height="7" rx="1.5" />
            </svg>
            <span>Overview</span>
          </button>

          <button className="nav-item" type="button" onClick={checkAntivirus} disabled={checkingAntivirus}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="11" cy="11" r="8" />
              <line x1="21" y1="21" x2="16.65" y2="16.65" />
            </svg>
            <span>Security Scan</span>
          </button>

          <button className="nav-item" type="button" onClick={() => document.getElementById("security-results")?.scrollIntoView({ behavior: "smooth" })}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" />
              <line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
            <span>Findings</span>
          </button>

          <button className="nav-item" type="button" onClick={() => document.getElementById("security-results")?.scrollIntoView({ behavior: "smooth" })}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              <polyline points="9 12 11 14 15 10" />
            </svg>
            <span>Verification</span>
          </button>

          <button className="nav-item" type="button" onClick={() => document.getElementById("security-results")?.scrollIntoView({ behavior: "smooth" })}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <polyline points="12 6 12 12 16 14" />
            </svg>
            <span>Activity History</span>
          </button>
        </nav>

        <div className="sidebar-footer">
          <div className="privacy-card">
            <div className="privacy-card-header">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                <path d="M7 11V7a5 5 0 0 1 10 0v4" />
              </svg>
              <span>Read-only inspection</span>
            </div>
            <p>Checks your system without changing its security settings.</p>
          </div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <span>/</span> <strong>Overview</strong>
          </div>
          <div className={`live-status-pill ${isAnyChecking ? "is-checking" : ""}`}>
            <span className={`status-dot ${allChecksSuccessful ? "is-success" : isAnyChecking ? "is-checking" : ""}`} />
            <span>{statusText}</span>
          </div>
        </header>

        <section className="welcome-section">
          <div className="welcome-content">
            <div className="eyebrow">Your Digital Safety Workspace</div>
            <h1>Security, made <span>clear.</span></h1>
            <p>
              Understand your device&apos;s security status, review potential
              issues, and verify improvements with zero disruption.
            </p>
          </div>
          <div className="welcome-visual" aria-hidden="true">
            <div className="shield-graphic">
              <div className="shield-ring" />
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                <path d="m9 12 2 2 4-4" />
              </svg>
            </div>
          </div>
        </section>

        <section className="notice">
          <div className="notice-icon-box" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="16" x2="12" y2="12" />
              <line x1="12" y1="8" x2="12.01" y2="8" />
            </svg>
          </div>
          <div className="notice-body">
            <strong>Read-only security checks</strong>
            <p>
              Digiture reads Windows Firewall profiles, registered antivirus
              products, and Microsoft Defender real-time protection status.
              It does not change security settings. The score is an informational
              indicator based only on these checks, not a complete security assessment.
            </p>
          </div>
        </section>

        <section className="section-heading">
          <div className="section-title-row">
            <div>
              <h2>Security overview</h2>
              <p>Your device status at a glance</p>
            </div>
          </div>

          <div className="action-buttons">
            <button className="primary-button" type="button" onClick={refreshAllChecks} disabled={checkingAll}>
              <svg className={checkingAll ? "spin-icon" : ""} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
              </svg>
              <span>{checkingAll ? "Refreshing all..." : "Refresh all checks"}</span>
            </button>

            <button className="secondary-button" type="button" onClick={checkFirewall} disabled={checking}>
              <svg className={checking ? "spin-icon" : ""} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="18" height="18" rx="2" />
                <path d="M3 9h18M3 15h18M9 3v6M15 9v6M9 15v6" />
              </svg>
              <span>{checking ? "Checking firewall..." : "Check firewall"}</span>
            </button>

            <button className="secondary-button" type="button" onClick={checkAntivirus} disabled={checkingAntivirus}>
              <svg className={checkingAntivirus ? "spin-icon" : ""} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
              <span>{checkingAntivirus ? "Checking antivirus..." : "Check antivirus"}</span>
            </button>

            <button className="secondary-button" type="button" onClick={checkRealTimeProtection} disabled={checkingProtection}>
              <svg className={checkingProtection ? "spin-icon" : ""} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
              </svg>
              <span>{checkingProtection ? "Checking protection..." : "Check real-time protection"}</span>
            </button>
          </div>
        </section>

        <section className="stats-grid">
          <article className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Security score</span>
              <span className="stat-icon">
                <svg viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2" /></svg>
              </span>
            </div>
            <div className={`stat-value ${securityScore !== null ? "accent" : ""}`}>
              {securityScore === null ? "—" : `${securityScore}%`}
            </div>
            <div className="stat-caption">
              {securityScore === null ? `${completedChecks}/3 checks returned results` : "Based on these three checks only"}
            </div>
          </article>

          <article className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Security checks</span>
              <span className="stat-icon">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
                </svg>
              </span>
            </div>
            <div className="stat-value">
              {(firewall?.success ? 1 : 0) + (antivirus?.success ? 1 : 0) + (protection?.success ? 1 : 0)}
              <span className="stat-suffix"> / 3</span>
            </div>
            <div className="stat-caption">Successful checks completed</div>
          </article>

          <article className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Firewall profiles</span>
              <span className="stat-icon green">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
              </span>
            </div>
            <div className="stat-value">{firewall?.success ? profiles.length : "—"}</div>
            <div className="stat-caption">Profiles reported by Windows</div>
          </article>

          <article className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Firewall status</span>
              <span className={`stat-icon ${disabledCount > 0 ? "amber" : "green"}`}>
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  {disabledCount > 0 ? <><circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" /></> : <polyline points="20 6 9 17 4 12" />}
                </svg>
              </span>
            </div>
            <div className="stat-value stat-value-compact">
              {firewall?.success ? disabledCount > 0 ? `${disabledCount} disabled` : "Active" : "—"}
            </div>
            <div className="stat-caption">{getFirewallSummary()}</div>
          </article>

          <article className="stat-card">
            <div className="stat-header">
              <span className="stat-label">Antivirus products</span>
              <span className="stat-icon green">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
              </span>
            </div>
            <div className="stat-value">{antivirus?.success ? antivirusProducts.length : "—"}</div>
            <div className="stat-caption">
              {checkingAntivirus ? "Checking antivirus..." : antivirus?.success ? "Registered with Windows" : "Not checked"}
            </div>
          </article>
        </section>

        <section className="checks-panel" id="security-results">
          <div className="panel-heading">
            <div>
              <h2>Security checkup</h2>
              <p>Results from available read-only checks</p>
            </div>
            <span className="check-count">
              {(firewall?.success ? 1 : 0) + (antivirus?.success ? 1 : 0) + (protection?.success ? 1 : 0)} / 3 verified
            </span>
          </div>

          <article className="check-row">
            <div className="check-symbol" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="3" y="3" width="18" height="18" rx="2" /><path d="M3 9h18M3 15h18M9 3v6M15 9v6M9 15v6" />
              </svg>
            </div>
            <div className="check-info">
              <strong>Windows Firewall</strong>
              <p>Reads the status of Windows Firewall profiles.</p>
            </div>
            <span className={`check-status ${firewall?.success ? "success" : error ? "error" : ""}`}>
              <span className="small-dot" />
              {checking ? "Checking" : firewall?.success ? "Retrieved" : error ? "Failed" : "Not checked"}
            </span>
          </article>

          {firewall?.success && profiles.length > 0 && (
            <div className="firewall-results">
              <h3>Firewall profile results</h3>
              {profiles.map((profile, index) => {
                const enabled = String(profile.Enabled).toLowerCase() === "true";
                return (
                  <article className="detail-row" key={`${profile.Name ?? "profile"}-${index}`}>
                    <div className="check-info">
                      <strong>{profile.Name ?? `Profile ${index + 1}`}</strong>
                      <p>{enabled ? "Windows reports this profile is enabled." : "Windows reports this profile is disabled. Review this setting."}</p>
                    </div>
                    <span className={`check-status ${enabled ? "success" : "warning"}`}>
                      <span className="small-dot" />{enabled ? "Enabled" : "Disabled"}
                    </span>
                  </article>
                );
              })}
            </div>
          )}

          <article className="check-row">
            <div className="check-symbol" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /></svg>
            </div>
            <div className="check-info">
              <strong>Registered antivirus</strong>
              <p>Lists antivirus products reported by Windows Security Center. Registration alone does not confirm active real-time protection.</p>
            </div>
            <span className={`check-status ${antivirus?.success ? "success" : antivirusError ? "error" : ""}`}>
              <span className="small-dot" />
              {checkingAntivirus ? "Checking" : antivirus?.success ? "Retrieved" : antivirusError ? "Failed" : "Not checked"}
            </span>
          </article>

          {antivirus?.success && (
            <div className="firewall-results">
              <h3>Registered antivirus products</h3>
              {antivirusProducts.length > 0 ? antivirusProducts.map((product, index) => (
                <article className="detail-row" key={`${product.displayName ?? "antivirus"}-${index}`}>
                  <div className="check-info">
                    <strong>{product.displayName ?? "Unnamed antivirus product"}</strong>
                    <p>
                      Registered with Windows Security Center. Product state:{" "}
                      {typeof product.productState === "number" ? product.productState : "not provided"}.
                      This value alone does not confirm active real-time protection.
                    </p>
                  </div>
                  <span className="check-status success"><span className="small-dot" />Registered</span>
                </article>
              )) : <p>Windows returned no registered antivirus products.</p>}
              {antivirus.details && <p className="result-detail-note">{antivirus.details}</p>}
            </div>
          )}

          <article className="check-row">
            <div className="check-symbol" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 12h-4l-3 9L9 3l-3 9H2" /></svg>
            </div>
            <div className="check-info">
              <strong>Windows Defender Real-Time Protection</strong>
              <p>Checks whether Microsoft Defender reports that real-time threat monitoring is active.</p>
            </div>
            <span className={`check-status ${protection?.success ? protection.real_time_protection_enabled === true ? "success" : "warning" : protectionError ? "error" : ""}`}>
              <span className="small-dot" />
              {checkingProtection ? "Checking" : protection?.success ? protection.real_time_protection_enabled === true ? "Enabled" : protection.real_time_protection_enabled === false ? "Disabled" : "Unknown" : protectionError ? "Failed" : "Not checked"}
            </span>
          </article>

          {protection?.success && (
            <div className="firewall-results">
              <h3>Real-time protection details</h3>
              <div className="detail-row">
                <div className="check-info">
                  <strong>Antivirus engine service</strong>
                  <p>Whether Windows reports the Defender antivirus service as enabled.</p>
                </div>
                <span className={`check-status ${protection.antivirus_enabled === true ? "success" : protection.antivirus_enabled === false ? "warning" : ""}`}>
                  <span className="small-dot" />
                  {protection.antivirus_enabled === true ? "Enabled" : protection.antivirus_enabled === false ? "Disabled" : "Unknown"}
                </span>
              </div>
              <div className="detail-row">
                <div className="check-info">
                  <strong>Real-time threat monitoring</strong>
                  <p>Whether Windows reports Defender real-time protection as actively scanning.</p>
                </div>
                <span className={`check-status ${protection.real_time_protection_enabled === true ? "success" : protection.real_time_protection_enabled === false ? "warning" : ""}`}>
                  <span className="small-dot" />
                  {protection.real_time_protection_enabled === true ? "Enabled" : protection.real_time_protection_enabled === false ? "Disabled" : "Unknown"}
                </span>
              </div>
              {protection.details && <p className="result-detail-note">{protection.details}</p>}
            </div>
          )}

          {error && <div className="notice error-notice" role="alert"><strong>Firewall check failed</strong><p>{error}</p></div>}
          {antivirusError && <div className="notice error-notice" role="alert"><strong>Antivirus check failed</strong><p>{antivirusError}</p></div>}
          {protectionError && <div className="notice error-notice" role="alert"><strong>Real-time protection check failed</strong><p>{protectionError}</p></div>}

          {(firewall?.success || antivirus?.success || protection?.success) && (
            <div className="panel-footer">
              <span className="footer-dot" />
              Read-only results retrieved. No security settings were changed.
            </div>
          )}
          {!firewall && !antivirus && !protection && !error && !antivirusError && !protectionError && (
            <div className="panel-footer">
              <span className="footer-dot" />
              Select a diagnostic check above to inspect your current security status.
            </div>
          )}
        </section>

        <footer className="app-footer">
          <span>Digiture</span>
          <span>Transparency · User control · Read-only diagnostics</span>
        </footer>
      </main>
    </div>
  );
}

export default App;
