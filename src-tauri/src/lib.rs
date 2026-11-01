use serde::Serialize;
use std::process::Command;

#[derive(Serialize)]
struct FirewallStatus {
    success: bool,
    profiles: String,
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
        Ok(result) if result.status.success() => {
            let profiles = String::from_utf8_lossy(&result.stdout).to_string();

            FirewallStatus {
                success: true,
                profiles,
                details: "Windows Firewall profile status was retrieved.".to_string(),
            }
        }
        Ok(result) => FirewallStatus {
            success: false,
            profiles: String::new(),
            details: format!(
                "PowerShell could not retrieve the firewall status. Exit code: {:?}",
                result.status.code()
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
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            check_firewall_status
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}