use colored::*;

/// Check if the current process is running with admin privileges
pub fn is_admin() -> bool {
    #[cfg(windows)]
    {
        // Check if we're in the Administrators group
        use std::process::Command;
        let output = Command::new("net").args(["session"]).output();
        match output {
            Ok(o) => o.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(not(windows))]
    {
        // On Linux/Mac, check if we're root
        libc_geteuid() == 0
    }
}

#[cfg(not(windows))]
fn libc_geteuid() -> u32 {
    // Simple check — if we can write to /etc, we're probably root
    std::fs::metadata("/etc/shadow")
        .map(|_| 0u32)
        .unwrap_or(1000)
}

/// Request elevation and re-run the current process as admin.
/// Returns Ok(true) if elevation was launched (caller should exit).
/// Returns Ok(false) if already admin.
/// Returns Err if elevation failed.
pub fn request_elevation() -> Result<bool, String> {
    if is_admin() {
        return Ok(false);
    }

    println!(
        "\n  {} {}",
        "[!]".yellow().bold(),
        "This action requires administrator privileges.".yellow()
    );

    #[cfg(windows)]
    {
        println!(
            "  {} A Windows elevation prompt will appear...\n",
            "[i]".blue()
        );

        let exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get executable path: {}", e))?;

        let args: Vec<String> = std::env::args().skip(1).collect();
        let args_str = args.join(" ");

        // Use PowerShell Start-Process with -Verb RunAs for UAC elevation
        let status = std::process::Command::new("powershell")
            .args([
                "-Command",
                &format!(
                    "Start-Process -FilePath '{}' -ArgumentList '{}' -Verb RunAs -Wait",
                    exe.display(),
                    args_str
                ),
            ])
            .status()
            .map_err(|e| format!("Failed to request elevation: {}", e))?;

        if status.success() {
            Ok(true) // Elevated process was launched
        } else {
            Err("Elevation was denied or failed. Please right-click and Run as Administrator.".to_string())
        }
    }

    #[cfg(not(windows))]
    {
        println!(
            "  {} Run with: sudo {}\n",
            "[i]".blue(),
            std::env::args().collect::<Vec<_>>().join(" ")
        );
        Err("Please re-run with sudo for full functionality.".to_string())
    }
}

/// Print a warning if not running as admin (non-blocking)
pub fn warn_if_not_admin() {
    if !is_admin() {
        println!(
            "  {} {}",
            "[!]".yellow(),
            "Running without admin privileges. Some checks will be limited.".dimmed()
        );
        println!(
            "  {} {}\n",
            "[i]".blue(),
            "Run as Administrator for full scan + removal capabilities.".dimmed()
        );
    }
}
