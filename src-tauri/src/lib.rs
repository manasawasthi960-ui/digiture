use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, BufReader};
use std::path::{Path, PathBuf};
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

#[derive(Serialize)]
struct FileScanResult {
    name: String,
    path: String,
    extension: String,
    size: u64,
    sha256: Option<String>,
    status: String,
    findings: Vec<String>,
}

#[derive(Serialize)]
struct ScanReport {
    success: bool,
    scanned: usize,
    skipped: usize,
    results: Vec<FileScanResult>,
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


const MAX_FILES: usize = 500;
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
const MAX_DEPTH: usize = 8;

fn inspect_file(path: &Path) -> FileScanResult {
    let name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let extension = path
        .extension()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            return FileScanResult {
                name,
                path: path.to_string_lossy().to_string(),
                extension,
                size: 0,
                sha256: None,
                status: "Could not scan".to_string(),
                findings: vec!["File metadata could not be read.".to_string()],
            };
        }
    };

    let size = metadata.len();
    let mut findings = Vec::new();

    let suspicious_extensions = [
        "exe", "dll", "scr", "bat", "cmd",
        "ps1", "vbs", "js", "hta", "msi",
    ];

    if suspicious_extensions.contains(&extension.as_str()) {
        findings.push(
            "Executable or script file. Review its source before opening."
                .to_string(),
        );
    }

    if name.starts_with('.') {
        findings.push("Hidden filename characteristic detected.".to_string());
    }

    let double_extension = name.matches('.').count() > 1;

    if double_extension {
        findings.push(
            "Multiple filename extensions detected. Verify the actual file type."
                .to_string(),
        );
    }

    if size > MAX_FILE_SIZE {
        findings.push(
            "File exceeds the current 100 MB hashing limit.".to_string(),
        );

        return FileScanResult {
            name,
            path: path.to_string_lossy().to_string(),
            extension,
            size,
            sha256: None,
            status: "Could not scan".to_string(),
            findings,
        };
    }

    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            findings.push("File could not be opened for reading.".to_string());

            return FileScanResult {
                name,
                path: path.to_string_lossy().to_string(),
                extension,
                size,
                sha256: None,
                status: "Could not scan".to_string(),
                findings,
            };
        }
    };

    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(bytes_read) => {
                hasher.update(&buffer[..bytes_read]);
            }
            Err(_) => {
                findings.push("An error occurred while reading the file.".to_string());

                return FileScanResult {
                    name,
                    path: path.to_string_lossy().to_string(),
                    extension,
                    size,
                    sha256: None,
                    status: "Could not scan".to_string(),
                    findings,
                };
            }
        }
    }

let hash = hasher
    .finalize()
    .iter()
    .map(|byte| format!("{:02x}", byte))
    .collect::<String>();
    let status = if findings.is_empty() {
        "No indicators found".to_string()
    } else {
        "Review recommended".to_string()
    };

    FileScanResult {
        name,
        path: path.to_string_lossy().to_string(),
        extension,
        size,
        sha256: Some(hash),
        status,
        findings,
    }
}

fn collect_files(
    path: &Path,
    depth: usize,
    results: &mut Vec<FileScanResult>,
    skipped: &mut usize,
) {
    if results.len() >= MAX_FILES || depth > MAX_DEPTH {
        *skipped += 1;
        return;
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            *skipped += 1;
            return;
        }
    };

    // Do not follow symbolic links.
    if metadata.file_type().is_symlink() {
        *skipped += 1;
        return;
    }

    if metadata.is_file() {
        results.push(inspect_file(path));
        return;
    }

    if metadata.is_dir() {
        let entries = match fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => {
                *skipped += 1;
                return;
            }
        };

        for entry in entries {
            if results.len() >= MAX_FILES {
                *skipped += 1;
                break;
            }

            match entry {
                Ok(entry) => {
                    collect_files(
                        &entry.path(),
                        depth + 1,
                        results,
                        skipped,
                    );
                }
                Err(_) => *skipped += 1,
            }
        }
    }
}

#[tauri::command]
fn scan_selected_path(path: String) -> ScanReport {
    let selected_path = PathBuf::from(&path);

    if !selected_path.exists() {
        return ScanReport {
            success: false,
            scanned: 0,
            skipped: 0,
            results: Vec::new(),
            details: "The selected path does not exist.".to_string(),
        };
    }

    let mut results = Vec::new();
    let mut skipped = 0;

    collect_files(
        &selected_path,
        0,
        &mut results,
        &mut skipped,
    );

    let scanned = results.len();

    ScanReport {
        success: true,
        scanned,
        skipped,
        results,
        details: format!(
            "Inspection completed. {} file(s) processed and {} item(s) skipped.",
            scanned,
            skipped
        ),
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            greet,
            check_firewall_status,
            check_antivirus_status,
            check_real_time_protection
        ])
        .invoke_handler(tauri::generate_handler![
    greet,
    check_firewall_status,
    check_antivirus_status,
    check_real_time_protection,
    scan_selected_path
])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}