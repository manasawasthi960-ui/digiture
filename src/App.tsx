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

  async function checkFirewall() {
    if (checking) return;

    setChecking(true);
    setError("");

    try {
      const result = await invoke<FirewallStatus>("check_firewall_status");
      setFirewall(result);

      if (!result.success) {
        setError(result.details || "Firewall check failed.");
      }
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
      const result = await invoke<AntivirusStatus>(
        "check_antivirus_status"
      );

      setAntivirus(result);

      if (!result.success) {
        setAntivirusError(result.details || "Antivirus check failed.");
      }
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
    const result = await invoke<RealTimeProtectionStatus>(
      "check_real_time_protection"
    );

    setProtection(result);

    if (!result.success) {
      setProtectionError(
        result.details || "Real-time protection check failed."
      );
    }
  } catch (err) {
    setProtection(null);
    setProtectionError(String(err));
  } finally {
    setCheckingProtection(false);
  }
}

  function getAntivirusProducts(): AntivirusProduct[] {
    if (!antivirus?.success || !antivirus.products) {
      return [];
    }

    try {
      const parsed: unknown = JSON.parse(antivirus.products);

      if (Array.isArray(parsed)) {
        return parsed as AntivirusProduct[];
      }

      if (parsed && typeof parsed === "object") {
        return [parsed as AntivirusProduct];
      }

      return [];
    } catch {
      return [];
    }
  }

  function getProfiles(): FirewallProfile[] {
    if (!firewall?.success || !firewall.profiles) {
      return [];
    }

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

  function getFirewallSummary(): string {
    if (!firewall?.success) {
      return "Not checked";
    }

    if (profiles.length === 0) {
      return "No profiles returned";
    }

    return disabledCount > 0
      ? `${disabledCount} profile(s) disabled`
      : "All returned profiles enabled";
  }

  return (
    <div className="app-shell">
      {/* SIDEBAR */}
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
          <button className="nav-item active" type="button">
            ▦ <span>Overview</span>
          </button>

          <button
            className="nav-item"
            type="button"
            onClick={checkAntivirus}
            disabled={checkingAntivirus}
          >
            ⌕ <span>Security Scan</span>
          </button>

          <button
            className="nav-item"
            type="button"
            onClick={() =>
              document
                .getElementById("security-results")
                ?.scrollIntoView({ behavior: "smooth" })
            }
          >
            ◇ <span>Findings</span>
          </button>

          <button
            className="nav-item"
            type="button"
            onClick={() =>
              document
                .getElementById("security-results")
                ?.scrollIntoView({ behavior: "smooth" })
            }
          >
            ✓ <span>Verification</span>
          </button>

          <button
            className="nav-item"
            type="button"
            onClick={() =>
              document
                .getElementById("security-results")
                ?.scrollIntoView({ behavior: "smooth" })
            }
          >
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

      {/* MAIN CONTENT */}
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

        {/* WELCOME */}
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

        {/* INFORMATION NOTICE */}
        <section className="notice">
          <span className="notice-icon">i</span>

          <div>
            <strong>Read-only security checks</strong>

            <p>
              Digiture reads Windows Firewall profile status and registered
              antivirus products. It does not change security settings.
              These checks do not constitute a complete security assessment.
            </p>
          </div>
        </section>

        {/* ACTION BUTTONS */}
        <section className="section-heading">
          <div>
            <h3>Security overview</h3>
            <p>Your device status at a glance</p>
          </div>

          <div className="action-buttons">
            <button
              className="primary-button"
              type="button"
              onClick={checkFirewall}
              disabled={checking}
            >
              {checking ? "Checking firewall..." : "Check firewall"}
            </button>

            <button
              className="primary-button"
              type="button"
              onClick={checkAntivirus}
              disabled={checkingAntivirus}
            >
              {checkingAntivirus
                ? "Checking antivirus..."
                : "Check antivirus"}
            </button>

            <button
              className="primary-button"
              type="button"
              onClick={checkRealTimeProtection}
              disabled={checkingProtection}
            >
              {checkingProtection
                 ? "Checking protection..."
                 : "Check real-time protection"}
            </button>




          </div>
        </section>

        {/* STATISTICS */}
        <section className="stats-grid">
          <article className="stat-card">
            <div className="stat-top">
              <span>Security checks</span>
              <span className="stat-icon purple">⌕</span>
            </div>

            <div className="stat-number">
              {(firewall?.success ? 1 : 0) +
                (antivirus?.success ? 1 : 0) +
                (protection?.success ? 1 : 0)}
            </div>

            <div className="stat-caption">
              Successful checks
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

            <div className="stat-caption">
              Profiles returned by Windows
            </div>
          </article>

          <article className="stat-card">
            <div className="stat-top">
              <span>Firewall status</span>
              <span className="stat-icon amber">!</span>
            </div>

            <div className="stat-number">
              {firewall?.success
                ? disabledCount > 0
                  ? "!"
                  : "✓"
                : "—"}
            </div>

            <div className="stat-caption">
              {getFirewallSummary()}
            </div>
          </article>

          <article className="stat-card">
            <div className="stat-top">
              <span>Antivirus products</span>
              <span className="stat-icon green">🛡</span>
            </div>

            <div className="stat-number">
              {antivirus?.success ? antivirusProducts.length : "—"}
            </div>

            <div className="stat-caption">
              {checkingAntivirus
                ? "Checking antivirus..."
                : antivirus?.success
                  ? "Registered with Windows"
                  : "Not checked"}
            </div>
          </article>
        </section>

        {/* SECURITY RESULTS */}
        <section className="checks-panel" id="security-results">
          <div className="panel-heading">
            <div>
              <h3>Security checkup</h3>
              <p>Results from available read-only checks</p>
            </div>

            <span className="check-count">
              {(firewall?.success ? 1 : 0) +
                (antivirus?.success ? 1 : 0) +
                (protection?.success ? 1 : 0)}{" "}
              CHECK(S)
            </span>
          </div>

          {/* FIREWALL STATUS */}
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
                  : error
                    ? "Failed"
                    : "Not checked"}
            </span>

            <span className="row-arrow">›</span>
          </article>

          {/* FIREWALL PROFILE DETAILS */}
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
                      <strong>
                        {profile.Name ?? `Profile ${index + 1}`}
                      </strong>

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

          {/* ANTIVIRUS STATUS */}
          <article className="check-row">
            <div className="check-symbol">🛡</div>

            <div className="check-info">
              <strong>Registered antivirus</strong>

              <p>
                Lists antivirus products reported by Windows Security Center.
                Registration alone does not confirm that real-time protection
                is enabled.
              </p>
            </div>

            <span className="check-status">
              <span className="small-dot" />

              {checkingAntivirus
                ? "Checking"
                : antivirus?.success
                  ? "Retrieved"
                  : antivirusError
                    ? "Failed"
                    : "Not checked"}
            </span>

            <span className="row-arrow">›</span>
          </article>

          {/* ANTIVIRUS PRODUCT DETAILS */}
          {antivirus?.success && (
            <div className="firewall-results">
              <h4>Registered antivirus products</h4>

              {antivirusProducts.length > 0 ? (
                antivirusProducts.map((item, index) => {
                  const product = item as AntivirusProduct;

                  return (
                    <article
                      className="check-row"
                      key={`${product.displayName ?? "antivirus"}-${index}`}
                    >
                      <div className="check-info">
                        <strong>
                          {product.displayName ??
                            "Unnamed antivirus product"}
                        </strong>

                        <p>
                          Registered with Windows Security Center. The raw
                          product-state value is{" "}
                          {typeof product.productState === "number"
                            ? product.productState
                            : "not provided"}
                          . This value alone does not confirm that protection
                          is active.
                        </p>
                      </div>

                      <span className="check-status">
                        <span className="small-dot" />
                        Registered
                      </span>
                    </article>
                  );
                })
              ) : (
                <p>
                  Windows returned no registered antivirus products.
                </p>
              )}

              <p>{antivirus.details}</p>
            </div>
          )}
          
          {/* REAL-TIME PROTECTION STATUS */}

<article className="check-row">
  <div className="check-symbol">🛡</div>

  <div className="check-info">
    <strong>Windows Defender Real-Time Protection</strong>

```
<p>
  Checks whether Microsoft Defender reports that real-time threat
  monitoring is enabled.
</p>
```

  </div>

  <span className="check-status">
    <span className="small-dot" />

```
{checkingProtection
  ? "Checking"
  : protection?.success
    ? protection.real_time_protection_enabled === true
      ? "Enabled"
      : protection.real_time_protection_enabled === false
        ? "Disabled"
        : "Unknown"
    : protectionError
      ? "Failed"
      : "Not checked"}
```

  </span>
</article>

{protection?.success && (

  <div className="firewall-results">
    <h4>Real-time protection details</h4>

```
<article className="check-row">
  <div className="check-info">
    <strong>Antivirus engine</strong>
    <p>
      Whether Windows reports the Defender antivirus service as enabled.
    </p>
  </div>

  <span className="check-status">
    {protection.antivirus_enabled === true
      ? "Enabled"
      : protection.antivirus_enabled === false
        ? "Disabled"
        : "Unknown"}
  </span>
</article>

<article className="check-row">
  <div className="check-info">
    <strong>Real-time monitoring</strong>
    <p>
      Whether Windows reports Defender real-time protection as enabled.
    </p>
  </div>

  <span className="check-status">
    {protection.real_time_protection_enabled === true
      ? "Enabled"
      : protection.real_time_protection_enabled === false
        ? "Disabled"
        : "Unknown"}
  </span>
</article>

<p>{protection.details}</p>
```

  </div>
)}


          {/* ERROR MESSAGES */}
          {error && (
            <div className="notice error-notice" role="alert">
              <span className="notice-icon">!</span>

              <div>
                <strong>Firewall check failed</strong>
                <p>{error}</p>
              </div>
            </div>
          )}

          {antivirusError && (
            <div className="notice error-notice" role="alert">
              <span className="notice-icon">!</span>

              <div>
                <strong>Antivirus check failed</strong>
                <p>{antivirusError}</p>
              </div>
            </div>
          )}

          {protectionError && (
  <div className="notice error-notice" role="alert">
    <span className="notice-icon">!</span>

    <div>
      <strong>Real-time protection check failed</strong>
      <p>{protectionError}</p>
    </div>
  </div>
)}

          {/* FOOTER MESSAGE */}
          {(firewall?.success || antivirus?.success) && (
            <div className="panel-footer">
              <span className="footer-dot" />
              Read-only results retrieved. No security settings were changed.
            </div>
          )}

          {!firewall && !antivirus && !error && !antivirusError && (
            <div className="panel-footer">
              <span className="footer-dot" />
              Select a check above to retrieve the current status.
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