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
struct AntivirusProduct {
    displayName: Option<String>,
    productState: Option<i32>,
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
            profiles: String::from_utf8_lossy(&result.stdout).to_string(),
            details: "Windows Firewall profile status was retrieved.".to_string(),
        },
        Ok(result) => FirewallStatus {
            success: false,
            profiles: String::new(),
            details: format!(
                "Could not retrieve firewall status. Exit code: {:?}. {}",
                result.status.code(),
                String::from_utf8_lossy(&result.stderr)
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
            let products = String::from_utf8_lossy(&result.stdout).trim().to_string();

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
                String::from_utf8_lossy(&result.stderr)
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
            check_antivirus_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}