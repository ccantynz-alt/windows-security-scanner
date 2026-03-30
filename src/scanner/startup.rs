use crate::signatures::process_names::KNOWN_BAD_PROCESSES;
#[cfg(windows)]
use crate::signatures::process_names::SUSPICIOUS_PATH_FRAGMENTS;
use crate::threat::{Severity, Threat, ThreatAction, ThreatCategory};
use std::path::Path;

/// Registry paths to check for startup entries (Windows)
#[cfg(windows)]
const REGISTRY_RUN_KEYS: &[(&str, &str)] = &[
    (
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
    ),
    (
        "HKLM",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ),
];

/// Scan startup/persistence locations for threats
pub fn scan() -> Vec<Threat> {
    let mut threats = Vec::new();

    // Scan registry Run keys (Windows only)
    #[cfg(windows)]
    {
        scan_registry_keys(&mut threats);
    }

    // Scan startup folders (cross-platform logic, Windows paths)
    scan_startup_folders(&mut threats);

    threats
}

#[cfg(windows)]
fn scan_registry_keys(threats: &mut Vec<Threat>) {
    use winreg::enums::*;
    use winreg::RegKey;

    for (hive_name, subkey_path) in REGISTRY_RUN_KEYS {
        let hive = match *hive_name {
            "HKCU" => RegKey::predef(HKEY_CURRENT_USER),
            "HKLM" => RegKey::predef(HKEY_LOCAL_MACHINE),
            _ => continue,
        };

        let key = match hive.open_subkey(subkey_path) {
            Ok(k) => k,
            Err(_) => continue,
        };

        for value_result in key.enum_values() {
            let (value_name, value_data) = match value_result {
                Ok(v) => v,
                Err(_) => continue,
            };

            let value_str = format!("{:?}", value_data);
            let value_lower = value_str.to_lowercase();
            let full_key = format!("{}\\{}", hive_name, subkey_path);

            // Check against known bad names
            for bad_name in KNOWN_BAD_PROCESSES {
                if value_lower.contains(bad_name) || value_name.to_lowercase().contains(bad_name) {
                    threats.push(Threat {
                        name: format!("Malicious startup entry: {}", value_name),
                        severity: Severity::Critical,
                        category: ThreatCategory::SuspiciousStartup,
                        location: full_key.clone(),
                        description: format!(
                            "Registry startup entry '{}' matches known threat '{}'. Value: {}",
                            value_name, bad_name, value_str
                        ),
                        action: ThreatAction::RemoveStartupEntry {
                            key_path: full_key.clone(),
                            value_name: value_name.clone(),
                        },
                    });
                    break;
                }
            }

            // Check for suspicious paths in startup values
            for fragment in SUSPICIOUS_PATH_FRAGMENTS {
                if value_lower.contains(fragment) {
                    threats.push(Threat {
                        name: format!("Suspicious startup path: {}", value_name),
                        severity: Severity::High,
                        category: ThreatCategory::SuspiciousStartup,
                        location: full_key.clone(),
                        description: format!(
                            "Startup entry '{}' points to suspicious location containing '{}'. Value: {}",
                            value_name, fragment, value_str
                        ),
                        action: ThreatAction::RemoveStartupEntry {
                            key_path: full_key.clone(),
                            value_name: value_name.clone(),
                        },
                    });
                    break;
                }
            }

            // Check if the executable actually exists
            // Extract path from value (handle quoted paths and arguments)
            let exe_path = extract_exe_path(&value_str);
            if !exe_path.is_empty() && !Path::new(&exe_path).exists() {
                threats.push(Threat {
                    name: format!("Orphaned startup entry: {}", value_name),
                    severity: Severity::Low,
                    category: ThreatCategory::SuspiciousStartup,
                    location: full_key.clone(),
                    description: format!(
                        "Startup entry '{}' points to non-existent file: {}",
                        value_name, exe_path
                    ),
                    action: ThreatAction::RemoveStartupEntry {
                        key_path: full_key.clone(),
                        value_name: value_name.clone(),
                    },
                });
            }
        }
    }
}

fn scan_startup_folders(threats: &mut Vec<Threat>) {
    let startup_paths = get_startup_folder_paths();

    for startup_dir in &startup_paths {
        let path = Path::new(startup_dir);
        if !path.exists() {
            continue;
        }

        let entries = match std::fs::read_dir(path) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let file_name = entry.file_name().to_string_lossy().to_lowercase();
            let file_path = entry.path().to_string_lossy().to_string();

            // Check against known bad names
            for bad_name in KNOWN_BAD_PROCESSES {
                if file_name.contains(bad_name) {
                    threats.push(Threat {
                        name: format!("Malicious startup file: {}", entry.file_name().to_string_lossy()),
                        severity: Severity::Critical,
                        category: ThreatCategory::SuspiciousStartup,
                        location: file_path.clone(),
                        description: format!(
                            "Startup folder contains file matching known threat '{}'",
                            bad_name
                        ),
                        action: ThreatAction::QuarantineFile(file_path.clone()),
                    });
                    break;
                }
            }

            // Flag .exe, .bat, .vbs, .ps1 files in startup — these auto-run
            let suspicious_extensions = [".exe", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1", ".scr"];
            if suspicious_extensions.iter().any(|ext| file_name.ends_with(ext)) {
                // Only flag if not already caught by known-bad check
                let already_flagged = threats.iter().any(|t| t.location == file_path);
                if !already_flagged {
                    threats.push(Threat {
                        name: format!("Executable in startup: {}", entry.file_name().to_string_lossy()),
                        severity: Severity::Medium,
                        category: ThreatCategory::SuspiciousStartup,
                        location: file_path.clone(),
                        description: format!(
                            "Executable file in startup folder will run automatically on login. Verify this is intended."
                        ),
                        action: ThreatAction::ManualReview,
                    });
                }
            }
        }
    }
}

fn get_startup_folder_paths() -> Vec<String> {
    let mut paths = Vec::new();

    if cfg!(windows) {
        // User startup folder
        if let Some(appdata) = dirs::config_dir() {
            paths.push(
                appdata
                    .join("Microsoft")
                    .join("Windows")
                    .join("Start Menu")
                    .join("Programs")
                    .join("Startup")
                    .to_string_lossy()
                    .to_string(),
            );
        }
        // All users startup folder
        paths.push(
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup".to_string(),
        );
    }

    paths
}

#[cfg(windows)]
fn extract_exe_path(value: &str) -> String {
    let trimmed = value.trim_matches('"').trim();
    // Handle "path\to\exe.exe" -arguments
    if let Some(idx) = trimmed.find(".exe") {
        return trimmed[..idx + 4].trim_matches('"').to_string();
    }
    trimmed.to_string()
}
