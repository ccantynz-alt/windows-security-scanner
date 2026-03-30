use crate::threat::{Threat, ThreatAction};
use chrono::Local;
use colored::*;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct QuarantineEntry {
    pub id: usize,
    pub original_path: String,
    pub quarantine_path: String,
    pub threat_name: String,
    pub quarantined_at: String,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct QuarantineManifest {
    pub entries: Vec<QuarantineEntry>,
    pub next_id: usize,
}

impl QuarantineManifest {
    pub fn load() -> Self {
        let manifest_path = get_quarantine_dir().join("manifest.json");
        if manifest_path.exists() {
            let content = fs::read_to_string(&manifest_path).unwrap_or_default();
            serde_json::from_str(&content).unwrap_or_default()
        } else {
            QuarantineManifest {
                entries: Vec::new(),
                next_id: 1,
            }
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let quarantine_dir = get_quarantine_dir();
        fs::create_dir_all(&quarantine_dir)
            .map_err(|e| format!("Failed to create quarantine directory: {}", e))?;

        let manifest_path = quarantine_dir.join("manifest.json");
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize manifest: {}", e))?;

        fs::write(&manifest_path, content)
            .map_err(|e| format!("Failed to write manifest: {}", e))?;

        Ok(())
    }
}

/// Execute quarantine actions for all threats
pub fn quarantine_threats(threats: &[Threat]) -> Result<usize, String> {
    let mut manifest = QuarantineManifest::load();
    let quarantine_dir = get_quarantine_dir();
    fs::create_dir_all(&quarantine_dir)
        .map_err(|e| format!("Failed to create quarantine directory: {}", e))?;

    let mut quarantined_count = 0;

    for threat in threats {
        match &threat.action {
            ThreatAction::KillProcess(pid) => {
                // Kill the process
                #[cfg(windows)]
                {
                    let result = std::process::Command::new("taskkill")
                        .args(["/F", "/PID", &pid.to_string()])
                        .output();

                    match result {
                        Ok(output) if output.status.success() => {
                            println!(
                                "  {} Killed process PID {}",
                                "[✓]".green().bold(),
                                pid
                            );
                            quarantined_count += 1;
                        }
                        _ => {
                            println!(
                                "  {} Failed to kill PID {} (may need admin privileges)",
                                "[✗]".red(),
                                pid
                            );
                        }
                    }
                }

                #[cfg(not(windows))]
                {
                    println!(
                        "  {} Would kill PID {} (Windows only)",
                        "[~]".yellow(),
                        pid
                    );
                }
            }

            ThreatAction::QuarantineFile(path) => {
                let source = PathBuf::from(path);
                if !source.exists() {
                    println!(
                        "  {} File not found (already removed?): {}",
                        "[~]".yellow(),
                        path
                    );
                    continue;
                }

                let id = manifest.next_id;
                let dest_name = format!("quarantine_{}", id);
                let dest = quarantine_dir.join(&dest_name);

                match fs::rename(&source, &dest) {
                    Ok(_) => {
                        manifest.entries.push(QuarantineEntry {
                            id,
                            original_path: path.clone(),
                            quarantine_path: dest.to_string_lossy().to_string(),
                            threat_name: threat.name.clone(),
                            quarantined_at: Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
                        });
                        manifest.next_id += 1;
                        quarantined_count += 1;

                        println!(
                            "  {} Quarantined: {} (ID: {})",
                            "[✓]".green().bold(),
                            path,
                            id
                        );
                    }
                    Err(e) => {
                        // Try copy + delete if rename fails (cross-device)
                        if fs::copy(&source, &dest).is_ok() && fs::remove_file(&source).is_ok() {
                            manifest.entries.push(QuarantineEntry {
                                id,
                                original_path: path.clone(),
                                quarantine_path: dest.to_string_lossy().to_string(),
                                threat_name: threat.name.clone(),
                                quarantined_at: Local::now()
                                    .format("%Y-%m-%d %H:%M:%S")
                                    .to_string(),
                            });
                            manifest.next_id += 1;
                            quarantined_count += 1;

                            println!(
                                "  {} Quarantined: {} (ID: {})",
                                "[✓]".green().bold(),
                                path,
                                id
                            );
                        } else {
                            println!(
                                "  {} Failed to quarantine: {} — {}",
                                "[✗]".red(),
                                path,
                                e
                            );
                        }
                    }
                }
            }

            ThreatAction::RemoveStartupEntry {
                key_path: _,
                value_name: _,
            } => {
                #[cfg(windows)]
                {
                    remove_registry_entry(_key_path, _value_name, &mut quarantined_count);
                }

                #[cfg(not(windows))]
                {
                    println!(
                        "  {} Would remove startup entry (Windows only)",
                        "[~]".yellow()
                    );
                }
            }

            ThreatAction::UninstallProgram { name, .. } => {
                println!(
                    "  {} Skipped uninstall '{}' — use --nuke for full removal",
                    "[~]".yellow(),
                    name
                );
            }

            ThreatAction::DeleteScheduledTask { task_name } => {
                println!(
                    "  {} Skipped task '{}' — use --nuke to delete",
                    "[~]".yellow(),
                    task_name
                );
            }

            ThreatAction::DisableBrowserExtension { browser, ext_id } => {
                println!(
                    "  {} Skipped {} extension '{}' — use --nuke or --fix-browser",
                    "[~]".yellow(),
                    browser,
                    ext_id
                );
            }

            ThreatAction::ResetProxy => {
                println!(
                    "  {} Skipped proxy reset — use --nuke to fix",
                    "[~]".yellow()
                );
            }

            ThreatAction::RestoreDefender => {
                println!(
                    "  {} Skipped Defender restore — use --nuke to fix",
                    "[~]".yellow()
                );
            }

            ThreatAction::ManualReview => {
                println!(
                    "  {} Skipped (manual review needed): {}",
                    "[~]".yellow(),
                    threat.name
                );
            }
        }
    }

    manifest.save()?;
    Ok(quarantined_count)
}

#[cfg(windows)]
fn remove_registry_entry(key_path: &str, value_name: &str, count: &mut usize) {
    use winreg::enums::*;
    use winreg::RegKey;

    let (hive, subkey) = if key_path.starts_with("HKCU") {
        (
            RegKey::predef(HKEY_CURRENT_USER),
            key_path.strip_prefix("HKCU\\").unwrap_or(key_path),
        )
    } else if key_path.starts_with("HKLM") {
        (
            RegKey::predef(HKEY_LOCAL_MACHINE),
            key_path.strip_prefix("HKLM\\").unwrap_or(key_path),
        )
    } else {
        println!(
            "  {} Unknown registry hive: {}",
            "[✗]".red(),
            key_path
        );
        return;
    };

    match hive.open_subkey_with_flags(subkey, winreg::enums::KEY_WRITE) {
        Ok(key) => match key.delete_value(value_name) {
            Ok(_) => {
                println!(
                    "  {} Removed startup entry: {} from {}",
                    "[✓]".green().bold(),
                    value_name,
                    key_path
                );
                *count += 1;
            }
            Err(e) => {
                println!(
                    "  {} Failed to remove '{}': {}",
                    "[✗]".red(),
                    value_name,
                    e
                );
            }
        },
        Err(e) => {
            println!(
                "  {} Cannot open registry key '{}': {} (may need admin)",
                "[✗]".red(),
                key_path,
                e
            );
        }
    }
}

/// Restore a quarantined file by ID
pub fn restore_file(id: usize) -> Result<(), String> {
    let mut manifest = QuarantineManifest::load();

    let entry_idx = manifest
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| format!("No quarantined item with ID {}", id))?;

    let entry = &manifest.entries[entry_idx];
    let source = PathBuf::from(&entry.quarantine_path);
    let dest = PathBuf::from(&entry.original_path);

    if !source.exists() {
        return Err(format!(
            "Quarantine file not found: {}",
            entry.quarantine_path
        ));
    }

    // Ensure destination directory exists
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create destination directory: {}", e))?;
    }

    fs::rename(&source, &dest)
        .or_else(|_| {
            fs::copy(&source, &dest)?;
            fs::remove_file(&source)
        })
        .map_err(|e| format!("Failed to restore file: {}", e))?;

    println!(
        "  {} Restored: {} -> {}",
        "[✓]".green().bold(),
        entry.quarantine_path,
        entry.original_path
    );

    manifest.entries.remove(entry_idx);
    manifest.save()?;

    Ok(())
}

/// List all quarantined items
pub fn list_quarantine() {
    let manifest = QuarantineManifest::load();

    if manifest.entries.is_empty() {
        println!(
            "  {} No items in quarantine.",
            "[i]".blue()
        );
        return;
    }

    println!(
        "\n  {} {} items in quarantine:\n",
        "[i]".blue().bold(),
        manifest.entries.len()
    );

    for entry in &manifest.entries {
        println!(
            "  ID: {}  |  {}  |  {}",
            entry.id.to_string().yellow().bold(),
            entry.threat_name.white(),
            entry.quarantined_at.dimmed()
        );
        println!(
            "         Original: {}",
            entry.original_path.dimmed()
        );
    }

    println!(
        "\n  To restore: {}",
        "down --restore <ID>".yellow()
    );
}

fn get_quarantine_dir() -> PathBuf {
    if cfg!(windows) {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("DownScanner")
            .join("quarantine")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".down-scanner")
            .join("quarantine")
    }
}
