use crate::threat::{Severity, Threat};
use chrono::Local;
use colored::*;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

pub fn print_banner() {
    println!(
        "{}",
        r#"
  ____   _____        ___   _
 |  _ \ / _ \ \      / / \ | |
 | | | | | | \ \ /\ / /|  \| |
 | |_| | |_| |\ V  V / | |\  |
 |____/ \___/  \_/\_/  |_| \_|
  Windows Security Scanner v0.2.0
"#
        .cyan()
        .bold()
    );
}

pub fn print_scan_start(scan_type: &str) {
    println!(
        "{} {} {}",
        "[*]".cyan().bold(),
        "Starting".white(),
        scan_type.yellow().bold()
    );
    println!("{}", "─".repeat(60).dimmed());
}

pub fn print_module_start(module: &str) {
    println!(
        "\n{} {}",
        "[>]".blue().bold(),
        module.white().bold()
    );
}

pub fn print_module_clean(module: &str) {
    println!(
        "  {} {} — {}",
        "[✓]".green().bold(),
        module.white(),
        "Clean".green()
    );
}

pub fn print_threat(threat: &Threat) {
    let severity_colored = match threat.severity {
        Severity::Critical => threat.severity.to_string().red().bold(),
        Severity::High => threat.severity.to_string().red(),
        Severity::Medium => threat.severity.to_string().yellow(),
        Severity::Low => threat.severity.to_string().white(),
    };

    println!(
        "  {} [{}] {} — {}",
        "[!]".red().bold(),
        severity_colored,
        threat.name.white().bold(),
        threat.category.to_string().dimmed()
    );
    println!("      Location: {}", threat.location.dimmed());
    println!("      Detail:   {}", threat.description);
    println!("      Action:   {}", threat.action.to_string().yellow());
}

pub fn print_summary(threats: &[Threat]) {
    println!("\n{}", "═".repeat(60).dimmed());
    println!("{}", "  SCAN SUMMARY".white().bold());
    println!("{}", "═".repeat(60).dimmed());

    let critical = threats.iter().filter(|t| t.severity == Severity::Critical).count();
    let high = threats.iter().filter(|t| t.severity == Severity::High).count();
    let medium = threats.iter().filter(|t| t.severity == Severity::Medium).count();
    let low = threats.iter().filter(|t| t.severity == Severity::Low).count();
    let total = threats.len();

    if total == 0 {
        println!(
            "\n  {} {}",
            "✓".green().bold(),
            "No threats detected. Your system looks clean.".green().bold()
        );
    } else {
        println!();
        if critical > 0 {
            println!(
                "  {} Critical: {}",
                "●".red().bold(),
                critical.to_string().red().bold()
            );
        }
        if high > 0 {
            println!(
                "  {} High:     {}",
                "●".red(),
                high.to_string().red()
            );
        }
        if medium > 0 {
            println!(
                "  {} Medium:   {}",
                "●".yellow(),
                medium.to_string().yellow()
            );
        }
        if low > 0 {
            println!(
                "  {} Low:      {}",
                "●".white(),
                low.to_string().white()
            );
        }
        println!(
            "\n  Total threats found: {}",
            total.to_string().red().bold()
        );
        println!(
            "\n  {} Run {} to remove detected threats.",
            "→".cyan(),
            "down --quarantine".yellow().bold()
        );
    }
    println!("{}\n", "═".repeat(60).dimmed());
}

/// Write scan results to a log file
pub fn write_log(threats: &[Threat]) -> Result<PathBuf, String> {
    let log_dir = get_log_dir();
    fs::create_dir_all(&log_dir).map_err(|e| format!("Failed to create log directory: {}", e))?;

    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S");
    let log_path = log_dir.join(format!("scan-{}.log", timestamp));

    let mut file =
        fs::File::create(&log_path).map_err(|e| format!("Failed to create log file: {}", e))?;

    writeln!(file, "DOWN Security Scanner — Scan Report").ok();
    writeln!(file, "Date: {}", Local::now().format("%Y-%m-%d %H:%M:%S")).ok();
    writeln!(file, "Threats found: {}", threats.len()).ok();
    writeln!(file, "{}", "=".repeat(60)).ok();

    for (i, threat) in threats.iter().enumerate() {
        writeln!(file, "\n--- Threat #{} ---", i + 1).ok();
        writeln!(file, "Name:     {}", threat.name).ok();
        writeln!(file, "Severity: {}", threat.severity).ok();
        writeln!(file, "Category: {}", threat.category).ok();
        writeln!(file, "Location: {}", threat.location).ok();
        writeln!(file, "Detail:   {}", threat.description).ok();
        writeln!(file, "Action:   {}", threat.action).ok();
    }

    writeln!(file, "\n{}", "=".repeat(60)).ok();
    writeln!(file, "End of report.").ok();

    println!(
        "  {} Log saved to: {}",
        "[i]".blue(),
        log_path.display().to_string().dimmed()
    );

    Ok(log_path)
}

fn get_log_dir() -> PathBuf {
    if cfg!(windows) {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("DownScanner")
            .join("logs")
    } else {
        // For development/testing on Linux/Mac
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".down-scanner")
            .join("logs")
    }
}
