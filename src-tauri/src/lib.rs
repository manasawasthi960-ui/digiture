use serde::Serialize;
use std::process::Command;

#[derive(Serialize)]
struct FirewallStatus {
    success: bool,
    profiles: String,
    details: String,
}

#[derive(Serialize)]
struct AntivirusStatus {
    success: bool,
    products: String,
    details: String,
}

#[derive(Serialize)]
struct RealTimeProtectionStatus {
    success: bool,
    antivirus_enabled: Option<bool>,
    real_time_protection_enabled: Option<bool>,
    service_enabled: Option<bool>,
    details: String,
}

#[tauri::command]
fn check_firewall_status() -> FirewallStatus {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress",
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => FirewallStatus {
            success: true,
            profiles: String::from_utf8_lossy(&result.stdout)
                .trim()
                .to_string(),
            details: "Windows Firewall profile status was retrieved.".to_string(),
        },
        Ok(result) => FirewallStatus {
            success: false,
            profiles: String::new(),
            details: format!(
                "Could not retrieve firewall status. Exit code: {:?}. {}",
                result.status.code(),
                String::from_utf8_lossy(&result.stderr).trim()
            ),
        },
        Err(error) => FirewallStatus {
            success: false,
            profiles: String::new(),
            details: format!("Could not run the firewall check: {error}"),
        },
    }
}

#[tauri::command]
fn check_antivirus_status() -> AntivirusStatus {
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName, productState | ConvertTo-Json -Compress",
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let products = String::from_utf8_lossy(&result.stdout)
                .trim()
                .to_string();

            if products.is_empty() || products == "null" {
                AntivirusStatus {
                    success: true,
                    products: "[]".to_string(),
                    details: "Windows returned no registered antivirus products.".to_string(),
                }
            } else {
                AntivirusStatus {
                    success: true,
                    products,
                    details: "Registered antivirus information was retrieved from Windows Security Center.".to_string(),
                }
            }
        }
        Ok(result) => AntivirusStatus {
            success: false,
            products: String::new(),
            details: format!(
                "Could not retrieve antivirus status. Exit code: {:?}. {}",
                result.status.code(),
                String::from_utf8_lossy(&result.stderr).trim()
            ),
        },
        Err(error) => AntivirusStatus {
            success: false,
            products: String::new(),
            details: format!("Could not run the antivirus check: {error}"),
        },
    }
}

#[tauri::command]
fn check_real_time_protection() -> RealTimeProtectionStatus {
    let script = r#"
        $ErrorActionPreference = 'Stop'
        $status = Get-MpComputerStatus -ErrorAction Stop

        [PSCustomObject]@{
            AntivirusEnabled = $status.AMServiceEnabled
            RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
            ServiceEnabled = $status.AMServiceEnabled
        } | ConvertTo-Json -Compress
    "#;

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ])
        .output();

    match output {
        Ok(result) if result.status.success() => {
            let json = String::from_utf8_lossy(&result.stdout)
                .trim()
                .to_string();

            match serde_json::from_str::<serde_json::Value>(&json) {
                Ok(data) => {
                    let antivirus_enabled = data["AntivirusEnabled"].as_bool();
                    let real_time_protection_enabled =
                        data["RealTimeProtectionEnabled"].as_bool();
                    let service_enabled = data["ServiceEnabled"].as_bool();

                    if antivirus_enabled.is_none()
                        || real_time_protection_enabled.is_none()
                        || service_enabled.is_none()
                    {
                        RealTimeProtectionStatus {
                            success: false,
                            antivirus_enabled,
                            real_time_protection_enabled,
                            service_enabled,
                            details: "Windows did not return all expected Defender status values.".to_string(),
                        }
                    } else {
                        RealTimeProtectionStatus {
                            success: true,
                            antivirus_enabled,
                            real_time_protection_enabled,
                            service_enabled,
                            details: "Windows Defender protection status was retrieved. This check does not assess third-party antivirus products.".to_string(),
                        }
                    }
                }
                Err(error) => RealTimeProtectionStatus {
                    success: false,
                    antivirus_enabled: None,
                    real_time_protection_enabled: None,
                    service_enabled: None,
                    details: format!("Could not parse protection status: {error}"),
                },
            }
        }
        Ok(result) => RealTimeProtectionStatus {
            success: false,
            antivirus_enabled: None,
            real_time_protection_enabled: None,
            service_enabled: None,
            details: format!(
                "Could not retrieve Windows Defender protection status. {}",
                String::from_utf8_lossy(&result.stderr).trim()
            ),
        },
        Err(error) => RealTimeProtectionStatus {
            success: false,
            antivirus_enabled: None,
            real_time_protection_enabled: None,
            service_enabled: None,
            details: format!("Could not run the protection check: {error}"),
        },
    }
}

#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            check_firewall_status,
            check_antivirus_status,
            check_real_time_protection
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}