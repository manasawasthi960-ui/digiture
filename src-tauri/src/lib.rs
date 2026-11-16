use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, BufReader};
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Serialize, Deserialize)]
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
struct PrivacyPermission {
    category: String,
    application: String,
    access: String,
}

#[derive(Serialize)]
struct PrivacyAuditStatus {
    success: bool,
    permissions: Vec<PrivacyPermission>,
    details: String,
}

#[derive(Serialize, Deserialize)]
struct JunkFileCandidate {
    name: String,
    path: String,
    size_bytes: u64,
    modified_days: u64,
    modified_unix_secs: u64,
     sha256: String,
}

#[derive(Serialize)]
struct JunkScanReport {
    success: bool,
    scanned_files: usize,
    candidate_files: usize,
    skipped_files: usize,
    total_candidate_bytes: u64,
    candidates: Vec<JunkFileCandidate>,
    details: String,
}

#[derive(Serialize)]
struct JunkFileVerification {
    name: String,
    path: String,
    verified: bool,
    details: String,
}

#[derive(Serialize)]
struct JunkVerificationReport {
    success: bool,
    verified_files: usize,
    rejected_files: usize,
    results: Vec<JunkFileVerification>,
    details: String,
}

#[derive(Serialize)]
struct JunkCleanupFileResult {
    name: String,
    path: String,
    moved_to_recycle_bin: bool,
    details: String,
}

#[derive(Serialize)]
struct JunkCleanupReport {
    success: bool,
    moved_files: usize,
    failed_files: usize,
    results: Vec<JunkCleanupFileResult>,
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
    severity: String,
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
fn audit_privacy_permissions() -> PrivacyAuditStatus {
    let script = r#"
        $ErrorActionPreference = 'Stop'

        $categories = @(
            @{
                Name = 'Camera'
                Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'
            },
            @{
                Name = 'Microphone'
                Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone'
            },
            @{
                Name = 'Location'
                Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location'
            }
        )

        $items = @()

        foreach ($category in $categories) {
            if (Test-Path $category.Path) {

                $root = Get-ItemProperty -Path $category.Path `
                    -Name Value -ErrorAction SilentlyContinue

                if ($null -ne $root.Value) {
                    $items += [PSCustomObject]@{
                        Category = $category.Name
                        Application = 'Device-wide setting'
                        Access = [string]$root.Value
                    }
                }

                $keys = Get-ChildItem -Path $category.Path `
                    -Recurse -ErrorAction SilentlyContinue

                foreach ($key in $keys) {
                    $permission = Get-ItemProperty `
                        -Path $key.PSPath `
                        -Name Value -ErrorAction SilentlyContinue

                    if ($null -ne $permission.Value) {
                        $application = $key.Name -replace '^.*\\', ''

                        $items += [PSCustomObject]@{
                            Category = $category.Name
                            Application = $application
                            Access = [string]$permission.Value
                        }
                    }
                }
            }
        }

        ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
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
                    let mut permissions = Vec::new();

                    if let Some(items) = data.as_array() {
                        for item in items {
                            permissions.push(PrivacyPermission {
                                category: item["Category"]
                                    .as_str()
                                    .unwrap_or("Unknown")
                                    .to_string(),

                                application: item["Application"]
                                    .as_str()
                                    .unwrap_or("Unknown")
                                    .to_string(),

                                access: item["Access"]
                                    .as_str()
                                    .unwrap_or("Unknown")
                                    .to_string(),
                            });
                        }
                    }

                    PrivacyAuditStatus {
                        success: true,
                        permissions,
                        details: "Windows privacy permission records were retrieved. These records may not include every installed application.".to_string(),
                    }
                }

                Err(error) => PrivacyAuditStatus {
                    success: false,
                    permissions: Vec::new(),
                    details: format!(
                        "Could not parse privacy permission records: {error}"
                    ),
                },
            }
        }

        Ok(result) => PrivacyAuditStatus {
            success: false,
            permissions: Vec::new(),
            details: format!(
                "Could not retrieve privacy permissions: {}",
                String::from_utf8_lossy(&result.stderr).trim()
            ),
        },

        Err(error) => PrivacyAuditStatus {
            success: false,
            permissions: Vec::new(),
            details: format!(
                "Could not run the privacy audit: {error}"
            ),
        },
    }
}


#[tauri::command]
fn scan_junk_files() -> JunkScanReport {
    const MAX_FILES: usize = 1000;
    const MIN_AGE_DAYS: u64 = 7;

    let temp_path = std::env::temp_dir();

    let entries = match fs::read_dir(&temp_path) {
        Ok(entries) => entries,
        Err(error) => {
            return JunkScanReport {
                success: false,
                scanned_files: 0,
                candidate_files: 0,
                skipped_files: 0,
                total_candidate_bytes: 0,
                candidates: Vec::new(),
                details: format!(
                    "Could not access the temporary folder: {error}"
                ),
            };
        }
    };

    let mut scanned_files = 0;
    let mut skipped_files = 0;
    let mut total_candidate_bytes = 0u64;
    let mut candidates = Vec::new();

    let now = std::time::SystemTime::now();

    for entry_result in entries {
        if scanned_files + skipped_files >= MAX_FILES {
            break;
        }

        let entry = match entry_result {
            Ok(entry) => entry,
            Err(_) => {
                skipped_files += 1;
                continue;
            }
        };

        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(_) => {
                skipped_files += 1;
                continue;
            }
        };

        if !file_type.is_file() {
            skipped_files += 1;
            continue;
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => {
                skipped_files += 1;
                continue;
            }
        };

        let modified = match metadata.modified() {
            Ok(time) => time,
            Err(_) => {
                skipped_files += 1;
                continue;
            }
        };

        let age = match now.duration_since(modified) {
            Ok(age) => age,
            Err(_) => {
                skipped_files += 1;
                continue;
            }
        };

        scanned_files += 1;

        let modified_days = age.as_secs() / 86400;

        if modified_days >= MIN_AGE_DAYS {
            let size = metadata.len();

            let modified_unix_secs = modified
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs();

// Open the candidate file for fingerprinting.
let mut file = match File::open(entry.path()) {
    Ok(file) => file,
    Err(_) => {
        skipped_files += 1;
        continue;
    }
};

// Calculate SHA-256 in chunks.
let mut hasher = Sha256::new();
let mut buffer = [0u8; 8192];
let mut read_failed = false;

loop {
    match file.read(&mut buffer) {
        Ok(0) => break,
        Ok(bytes_read) => {
            hasher.update(&buffer[..bytes_read]);
        }
        Err(_) => {
            read_failed = true;
            break;
        }
    }
}

if read_failed {
    skipped_files += 1;
    continue;
}

let sha256 = hasher
    .finalize()
    .iter()
    .map(|byte| format!("{:02x}", byte))
    .collect::<String>();

total_candidate_bytes =
    total_candidate_bytes.saturating_add(size);

candidates.push(JunkFileCandidate {
    name: entry.file_name().to_string_lossy().to_string(),
    path: entry.path().to_string_lossy().to_string(),
    size_bytes: size,
    sha256,
    modified_days,
    modified_unix_secs,
});
    }
}

    let candidate_files = candidates.len();

    JunkScanReport {
        success: true,
        scanned_files,
        candidate_files,
        skipped_files,
        total_candidate_bytes,
        candidates,
        details: format!(
            "Inspected the current user's temporary folder. \
            Files older than {MIN_AGE_DAYS} days are listed as potential cleanup candidates. \
            No files were deleted or modified."
        ),
    }
}

#[tauri::command]
fn verify_junk_files(
    candidates: Vec<JunkFileCandidate>,
) -> JunkVerificationReport {
    const MIN_AGE_DAYS: u64 = 7;

    let temp_path = match fs::canonicalize(std::env::temp_dir()) {
        Ok(path) => path,
        Err(error) => {
            return JunkVerificationReport {
                success: false,
                verified_files: 0,
                rejected_files: candidates.len(),
                results: Vec::new(),
                details: format!("Could not verify temporary folder: {error}"),
            };
        }
    };

    let mut results = Vec::new();
    let mut verified_files = 0;
    let mut rejected_files = 0;

    for candidate in candidates {
        let reject = |details: String| JunkFileVerification {
            name: candidate.name.clone(),
            path: candidate.path.clone(),
            verified: false,
            details,
        };

        let metadata = match fs::symlink_metadata(&candidate.path) {
            Ok(metadata) => metadata,
            Err(_) => {
                rejected_files += 1;
                results.push(reject("File is missing or inaccessible.".into()));
                continue;
            }
        };

        if !metadata.file_type().is_file() {
            rejected_files += 1;
            results.push(reject("Not a regular file or is a symbolic link.".into()));
            continue;
        }

        let canonical_file = match fs::canonicalize(&candidate.path) {
            Ok(path) => path,
            Err(_) => {
                rejected_files += 1;
                results.push(reject("Could not resolve file path.".into()));
                continue;
            }
        };

        if canonical_file.parent() != Some(temp_path.as_path()) {
            rejected_files += 1;
            results.push(reject("File is outside the permitted temporary folder.".into()));
            continue;
        }

        let modified = match metadata.modified() {
            Ok(time) => time,
            Err(_) => {
                rejected_files += 1;
                results.push(reject("Could not read modification time.".into()));
                continue;
            }
        };

        let modified_unix_secs = modified
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let age = std::time::SystemTime::now()
            .duration_since(modified);

        let old_enough = age
            .map(|duration| duration.as_secs() >= MIN_AGE_DAYS * 86400)
            .unwrap_or(false);

        if metadata.len() != candidate.size_bytes
            || modified_unix_secs != candidate.modified_unix_secs
            || !old_enough
        {
            rejected_files += 1;
            results.push(reject(
                "File changed since scanning or is no longer old enough.".into(),
            ));
            continue;
        }

        let mut file = match File::open(&candidate.path) {
    Ok(file) => file,
    Err(_) => {
        rejected_files += 1;
        results.push(reject("Could not open file for fingerprint verification.".into()));
        continue;
    }
};

let mut hasher = Sha256::new();
let mut buffer = [0u8; 8192];
let mut read_failed = false;

loop {
    match file.read(&mut buffer) {
        Ok(0) => break,
        Ok(bytes_read) => hasher.update(&buffer[..bytes_read]),
        Err(_) => {
            read_failed = true;
            break;
        }
    }
}

if read_failed {
    rejected_files += 1;
    results.push(reject("Could not read file contents.".into()));
    continue;
}

let current_sha256 = hasher
    .finalize()
    .iter()
    .map(|byte| format!("{:02x}", byte))
    .collect::<String>();

if current_sha256 != candidate.sha256 {
    rejected_files += 1;
    results.push(reject("File content changed since the original scan.".into()));
    continue;
}

        verified_files += 1;

        results.push(JunkFileVerification {
            name: candidate.name,
            path: candidate.path,
            verified: true,
            details: "File metadata and SHA-256 fingerprint match the original scan.".into(),
        });
    }

    JunkVerificationReport {
        success: true,
        verified_files,
        rejected_files,
        results,
        details: "Verification completed. No files were deleted or modified.".into(),
    }
}


fn move_file_to_recycle_bin(path: String) -> Result<(), String> {
    let operation = std::thread::spawn(move || {
        trash::delete(path)
    });

    match operation.join() {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!(
            "Could not move file to Recycle Bin: {error}"
        )),
        Err(_) => Err(
            "Recycle Bin operation encountered an internal error.".into()
        ),
    }
}

fn validate_junk_candidate(
    candidate: &JunkFileCandidate,
    temp_path: &Path,
) -> Result<(), String> {
    const MIN_AGE_DAYS: u64 = 7;

    let metadata = fs::symlink_metadata(&candidate.path)
        .map_err(|_| "File is missing or inaccessible.".to_string())?;

    if !metadata.file_type().is_file() {
        return Err("File is not a regular file or is a symbolic link.".into());
    }

    let canonical_file = fs::canonicalize(&candidate.path)
        .map_err(|_| "Could not resolve file path.".to_string())?;

    if canonical_file.parent() != Some(temp_path) {
        return Err("File is outside the permitted temporary folder.".into());
    }

    let modified = metadata.modified()
        .map_err(|_| "Could not read modification time.".to_string())?;

    let modified_unix_secs = modified
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let age = std::time::SystemTime::now()
        .duration_since(modified)
        .map_err(|_| "File modification time is in the future.".to_string())?;

    if metadata.len() != candidate.size_bytes
        || modified_unix_secs != candidate.modified_unix_secs
        || age.as_secs() < MIN_AGE_DAYS * 86400
    {
        return Err("File changed or is no longer at least 7 days old.".into());
    }

    let mut file = File::open(&candidate.path)
        .map_err(|_| "Could not open file for verification.".to_string())?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)
            .map_err(|_| "Could not read file contents.".to_string())?;

        if bytes_read == 0 {
            break;
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let current_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<String>();

    if current_sha256 != candidate.sha256 {
        return Err("File content changed since the original scan.".into());
    }

    Ok(())
}

#[tauri::command]
fn cleanup_junk_files(
    candidates: Vec<JunkFileCandidate>,
    confirmed: bool,
) -> JunkCleanupReport {
    const MAX_CLEANUP_FILES: usize = 1000;

    let mut report = JunkCleanupReport {
        success: false,
        moved_files: 0,
        failed_files: 0,
        results: Vec::new(),
        details: String::new(),
    };

    if !confirmed {
        report.failed_files = candidates.len();
        report.details = "Cleanup cancelled: explicit confirmation was not provided.".into();
        return report;
    }

    if candidates.is_empty() || candidates.len() > MAX_CLEANUP_FILES {
        report.failed_files = candidates.len();
        report.details = "Invalid cleanup selection.".into();
        return report;
    }

    let temp_path = match fs::canonicalize(std::env::temp_dir()) {
        Ok(path) => path,
        Err(error) => {
            report.failed_files = candidates.len();
            report.details = format!("Could not access temporary folder: {error}");
            return report;
        }
    };

    for candidate in candidates {
        let name = candidate.name.clone();
        let path = candidate.path.clone();

        if let Err(error) = validate_junk_candidate(&candidate, &temp_path) {
            report.failed_files += 1;

            report.results.push(JunkCleanupFileResult {
                name,
                path,
                moved_to_recycle_bin: false,
                details: format!("Final verification failed: {error}"),
            });

            continue;
        }

        match move_file_to_recycle_bin(candidate.path.clone()) {
            Ok(()) => {
                if Path::new(&candidate.path).exists() {
                    report.failed_files += 1;

                    report.results.push(JunkCleanupFileResult {
                        name,
                        path,
                        moved_to_recycle_bin: false,
                        details: "Recycle Bin operation returned, but the original file still exists.".into(),
                    });
                } else {
                    report.moved_files += 1;

                    report.results.push(JunkCleanupFileResult {
                        name,
                        path,
                        moved_to_recycle_bin: true,
           details: "Windows Recycle Bin operation completed successfully. The original file no longer exists at its previous location.".into(),         });
                }
            }

            Err(error) => {
                report.failed_files += 1;

                report.results.push(JunkCleanupFileResult {
                    name,
                    path,
                    moved_to_recycle_bin: false,
                    details: error,
                });
            }
        }
    }

    report.success = report.failed_files == 0 && report.moved_files > 0;

    report.details = format!(
        "Cleanup finished: {} file(s) moved to the Recycle Bin; {} file(s) failed.",
        report.moved_files,
        report.failed_files
    );

    report
}


#[tauri::command]
fn greet(name: &str) -> String {
    format!("Hello, {}! You've been greeted from Rust!", name)
}


const MAX_FILES: usize = 500;
const MAX_FILE_SIZE: u64 = 100 * 1024 * 1024;
const MAX_DEPTH: usize = 8;

fn classify_severity(
    findings: &[String],
    is_executable: bool,
    double_extension: bool,
) -> String {
    let mut risk_score = 0;

    // Executable or script file
    if is_executable {
        risk_score += 2;
    }

    // Multiple filename extensions
    if double_extension {
        risk_score += 3;
    }

    // Hidden filename
    if findings.iter().any(|f| f.contains("Hidden filename")) {
        risk_score += 1;
    }

    // Other suspicious indicators
    if findings.len() >= 3 {
        risk_score += 2;
    }

    // Determine severity
    if risk_score >= 5 {
        "High".to_string()
    } else if risk_score >= 2 {
        "Medium".to_string()
    } else {
        "Low".to_string()
    }
}


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
                severity: "Unknown".to_string(),
                findings: vec![
                    "File metadata could not be read.".to_string()
                ],
            };
        }
    };

    let size = metadata.len();
    let mut findings = Vec::new();

    let suspicious_extensions = [
        "exe", "dll", "scr", "bat", "cmd",
        "ps1", "vbs", "js", "hta", "msi",
    ];

    let is_executable = suspicious_extensions.contains(&extension.as_str());

    if is_executable {
        findings.push(
            "Executable or script file. Review its source before opening."
                .to_string(),
        );
    }

    if name.starts_with('.') {
        findings.push(
            "Hidden filename characteristic detected.".to_string(),
        );
    }

    let double_extension = name.matches('.').count() > 1;

if double_extension {
    findings.push(
        "Multiple filename extensions detected. Verify the actual file type."
            .to_string(),
    );
}

// Check whether an executable is disguised with a familiar document or image extension.
let filename_parts: Vec<&str> = name.split('.').collect();

let misleading_extensions = [
    "pdf", "jpg", "jpeg", "png", "gif",
    "doc", "docx", "xls", "xlsx",
    "txt", "mp3", "mp4",
];

let misleading_executable =
    is_executable
    && filename_parts
        .iter()
        .take(filename_parts.len().saturating_sub(1))
        .any(|part| {
            misleading_extensions.contains(&part.to_lowercase().as_str())
        });

if misleading_executable {
    findings.push(
        "Potentially misleading filename: executable uses a familiar document or media extension."
            .to_string(),
    );
}

    // File size limit
    if size > MAX_FILE_SIZE {
        findings.push(
            "File exceeds the current 100 MB hashing limit.".to_string(),
        );

        let severity = classify_severity(
            &findings,
            is_executable,
            double_extension,
        );

        return FileScanResult {
            name,
            path: path.to_string_lossy().to_string(),
            extension,
            size,
            sha256: None,
            status: "Could not scan".to_string(),
            severity,
            findings,
        };
    }

    // Open file
    let file = match File::open(path) {
        Ok(file) => file,
        Err(_) => {
            findings.push(
                "File could not be opened for reading.".to_string(),
            );

            return FileScanResult {
                name,
                path: path.to_string_lossy().to_string(),
                extension,
                size,
                sha256: None,
                status: "Could not scan".to_string(),
                severity: "Unknown".to_string(),
                findings,
            };
        }
    };

    // Calculate SHA-256
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
            findings.push(
                "An error occurred while reading the file.".to_string(),
            );

            return FileScanResult {
                name,
                path: path.to_string_lossy().to_string(),
                extension,
                size,
                sha256: None,
                status: "Could not scan".to_string(),
                severity: "Unknown".to_string(),
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


    // Calculate severity
    let severity = classify_severity(
        &findings,
        is_executable,
        double_extension,
    );

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
        severity,
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
            check_real_time_protection,
            scan_selected_path,
            audit_privacy_permissions,
            scan_junk_files,
            verify_junk_files,
             cleanup_junk_files
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}