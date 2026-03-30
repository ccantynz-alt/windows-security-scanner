use crate::threat::{Threat, ThreatAction};
use colored::*;

/// Execute aggressive removal actions for all threats.
/// This is the --nuke mode: kill processes, uninstall programs,
/// delete scheduled tasks, remove startup entries, quarantine files.
pub fn nuke_threats(threats: &[Threat]) -> Result<usize, String> {
    let mut removed_count = 0;

    for threat in threats {
        match &threat.action {
            ThreatAction::KillProcess(pid) => {
                kill_process(*pid, &threat.name, &mut removed_count);
            }

            ThreatAction::UninstallProgram {
                uninstall_string,
                name,
            } => {
                uninstall_program(uninstall_string, name, &mut removed_count);
            }

            ThreatAction::DeleteScheduledTask { task_name } => {
                delete_scheduled_task(task_name, &mut removed_count);
            }

            ThreatAction::RemoveStartupEntry {
                key_path,
                value_name,
            } => {
                remove_startup_entry(key_path, value_name, &mut removed_count);
            }

            ThreatAction::QuarantineFile(path) => {
                // In nuke mode, just delete instead of quarantine
                delete_file(path, &mut removed_count);
            }

            ThreatAction::DisableBrowserExtension { browser, ext_id } => {
                remove_browser_extension(browser, ext_id, &mut removed_count);
            }

            ThreatAction::ResetProxy => {
                reset_proxy_settings(&mut removed_count);
            }

            ThreatAction::RestoreDefender => {
                restore_defender(&mut removed_count);
            }

            ThreatAction::ManualReview => {
                println!(
                    "  {} Skipped (manual review): {}",
                    "[~]".yellow(),
                    threat.name
                );
            }
        }
    }

    Ok(removed_count)
}

#[allow(unused_variables)]
fn kill_process(pid: u32, name: &str, count: &mut usize) {
    #[cfg(windows)]
    {
        let result = std::process::Command::new("taskkill")
            .args(["/F", "/PID", &pid.to_string()])
            .output();
        match result {
            Ok(output) if output.status.success() => {
                println!("  {} Killed: {} (PID {})", "[✓]".green().bold(), name, pid);
                *count += 1;
            }
            _ => {
                println!(
                    "  {} Failed to kill PID {} (may need admin)",
                    "[✗]".red(),
                    pid
                );
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!(
            "  {} Would kill PID {} — {} (Windows only)",
            "[~]".yellow(),
            pid,
            name
        );
    }
}

#[allow(unused_variables)]
fn uninstall_program(uninstall_string: &str, name: &str, count: &mut usize) {
    if uninstall_string.is_empty() {
        println!(
            "  {} No uninstaller found for '{}' — will delete files instead",
            "[~]".yellow(),
            name
        );
        return;
    }

    println!(
        "  {} Uninstalling: {}...",
        "[>]".blue().bold(),
        name
    );

    #[cfg(windows)]
    {
        // Try various silent uninstall flags
        let silent_flags = ["/S", "/VERYSILENT", "/SILENT", "/quiet", "/qn", "-s", "--silent"];
        let mut success = false;

        // Check if it's an MSI uninstall
        let uninstall_lower = uninstall_string.to_lowercase();
        if uninstall_lower.contains("msiexec") {
            // Extract the GUID and run silent MSI uninstall
            if let Some(guid_start) = uninstall_string.find('{') {
                if let Some(guid_end) = uninstall_string.find('}') {
                    let guid = &uninstall_string[guid_start..=guid_end];
                    let result = std::process::Command::new("msiexec")
                        .args(["/x", guid, "/qn", "/norestart"])
                        .output();
                    match result {
                        Ok(output) if output.status.success() => {
                            println!("  {} Uninstalled (MSI): {}", "[✓]".green().bold(), name);
                            *count += 1;
                            success = true;
                        }
                        _ => {}
                    }
                }
            }
        }

        if !success {
            // Try the uninstall string with various silent flags
            for flag in &silent_flags {
                let result = std::process::Command::new("cmd")
                    .args(["/C", &format!("{} {}", uninstall_string, flag)])
                    .output();
                match result {
                    Ok(output) if output.status.success() => {
                        println!("  {} Uninstalled: {}", "[✓]".green().bold(), name);
                        *count += 1;
                        success = true;
                        break;
                    }
                    _ => continue,
                }
            }
        }

        if !success {
            println!(
                "  {} Uninstaller failed for '{}'. Files may need manual removal.",
                "[✗]".red(),
                name
            );
        }
    }

    #[cfg(not(windows))]
    {
        println!(
            "  {} Would uninstall '{}' using: {} (Windows only)",
            "[~]".yellow(),
            name,
            uninstall_string
        );
    }
}

#[allow(unused_variables)]
fn delete_scheduled_task(task_name: &str, count: &mut usize) {
    #[cfg(windows)]
    {
        let result = std::process::Command::new("schtasks")
            .args(["/delete", "/tn", task_name, "/f"])
            .output();
        match result {
            Ok(output) if output.status.success() => {
                println!(
                    "  {} Deleted scheduled task: {}",
                    "[✓]".green().bold(),
                    task_name
                );
                *count += 1;
            }
            _ => {
                println!(
                    "  {} Failed to delete task '{}' (may need admin)",
                    "[✗]".red(),
                    task_name
                );
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!(
            "  {} Would delete task '{}' (Windows only)",
            "[~]".yellow(),
            task_name
        );
    }
}

#[allow(unused_variables)]
fn remove_startup_entry(key_path: &str, value_name: &str, count: &mut usize) {
    #[cfg(windows)]
    {
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
            return;
        };

        match hive.open_subkey_with_flags(subkey, KEY_WRITE) {
            Ok(key) => match key.delete_value(value_name) {
                Ok(_) => {
                    println!(
                        "  {} Removed startup: {} from {}",
                        "[✓]".green().bold(),
                        value_name,
                        key_path
                    );
                    *count += 1;
                }
                Err(e) => {
                    println!("  {} Failed to remove '{}': {}", "[✗]".red(), value_name, e);
                }
            },
            Err(e) => {
                println!(
                    "  {} Cannot open '{}': {} (need admin?)",
                    "[✗]".red(),
                    key_path,
                    e
                );
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!(
            "  {} Would remove '{}' from '{}' (Windows only)",
            "[~]".yellow(),
            value_name,
            key_path
        );
    }
}

fn delete_file(path: &str, count: &mut usize) {
    let p = std::path::Path::new(path);
    if !p.exists() {
        println!("  {} Already gone: {}", "[~]".yellow(), path);
        return;
    }

    let result = if p.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    };

    match result {
        Ok(_) => {
            println!("  {} Deleted: {}", "[✓]".green().bold(), path);
            *count += 1;
        }
        Err(e) => {
            println!("  {} Failed to delete '{}': {}", "[✗]".red(), path, e);
        }
    }
}

fn remove_browser_extension(browser: &str, ext_id: &str, count: &mut usize) {
    let ext_dirs = match browser {
        "Chrome" => get_chromium_ext_path("Google\\Chrome"),
        "Edge" => get_chromium_ext_path("Microsoft\\Edge"),
        _ => vec![],
    };

    for dir in ext_dirs {
        let ext_path = dir.join(ext_id);
        if ext_path.exists() {
            match std::fs::remove_dir_all(&ext_path) {
                Ok(_) => {
                    println!(
                        "  {} Removed {} extension: {}",
                        "[✓]".green().bold(),
                        browser,
                        ext_id
                    );
                    *count += 1;
                }
                Err(e) => {
                    println!(
                        "  {} Failed to remove extension '{}': {}",
                        "[✗]".red(),
                        ext_id,
                        e
                    );
                }
            }
        }
    }
}

fn get_chromium_ext_path(browser_path: &str) -> Vec<std::path::PathBuf> {
    let mut dirs = Vec::new();
    if let Some(local) = dirs::data_local_dir() {
        let base = local.join(browser_path).join("User Data");
        dirs.push(base.join("Default").join("Extensions"));
        if let Ok(entries) = std::fs::read_dir(&base) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Profile ") {
                    dirs.push(entry.path().join("Extensions"));
                }
            }
        }
    }
    dirs
}

#[allow(unused_variables)]
fn reset_proxy_settings(count: &mut usize) {
    #[cfg(windows)]
    {
        use winreg::enums::*;
        use winreg::RegKey;

        let hkcu = RegKey::predef(HKEY_CURRENT_USER);
        let key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
        match hkcu.open_subkey_with_flags(key_path, KEY_WRITE) {
            Ok(key) => {
                // Disable proxy
                let _ = key.set_value("ProxyEnable", &0u32);
                let _ = key.delete_value("ProxyServer");
                let _ = key.delete_value("AutoConfigURL");
                println!(
                    "  {} Proxy settings reset to direct connection",
                    "[✓]".green().bold()
                );
                *count += 1;
            }
            Err(e) => {
                println!("  {} Failed to reset proxy: {}", "[✗]".red(), e);
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!("  {} Would reset proxy settings (Windows only)", "[~]".yellow());
    }
}

#[allow(unused_variables)]
fn restore_defender(count: &mut usize) {
    #[cfg(windows)]
    {
        // Remove the DisableAntiSpyware policy
        use winreg::enums::*;
        use winreg::RegKey;

        let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
        let policy_path = r"SOFTWARE\Policies\Microsoft\Windows Defender";
        if let Ok(key) = hklm.open_subkey_with_flags(policy_path, KEY_WRITE) {
            let _ = key.delete_value("DisableAntiSpyware");
            let _ = key.delete_value("DisableAntiVirus");
        }

        // Restart the Defender service
        let result = std::process::Command::new("sc")
            .args(["start", "WinDefend"])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                println!(
                    "  {} Windows Defender re-enabled",
                    "[✓]".green().bold()
                );
                *count += 1;
            }
            _ => {
                println!(
                    "  {} Cleared Defender policy. May need restart to take effect.",
                    "[~]".yellow()
                );
                *count += 1;
            }
        }
    }
    #[cfg(not(windows))]
    {
        println!("  {} Would restore Defender (Windows only)", "[~]".yellow());
    }
}
