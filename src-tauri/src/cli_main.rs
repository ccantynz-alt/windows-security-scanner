mod browser_fix;
mod elevation;
mod quarantine;
mod remover;
mod report;
mod scanner;
mod signatures;
mod threat;
mod updater;

use clap::Parser;
use colored::*;
use std::time::Instant;
use sysinfo::System;

#[derive(Parser)]
#[command(
    name = "down",
    about = "DOWN — Personal AI-powered Windows Security Scanner v0.2",
    long_about = "Scans your Windows PC for malware, scareware, and potentially unwanted programs.\nBuilt in Rust for speed and safety. No telemetry, no cloud dependency.\n\nv0.2: Nuke mode, browser fix, Defender protection, signature updates.",
    version
)]
struct Cli {
    /// Run a full scan (all modules) — default if no flags
    #[arg(long, default_value_t = false)]
    scan: bool,

    /// Run a quick scan (processes + startup only)
    #[arg(long, default_value_t = false)]
    quick: bool,

    /// NUKE MODE: Scan + aggressively remove ALL threats (uninstall, delete, kill)
    #[arg(long, default_value_t = false)]
    nuke: bool,

    /// Fix browser hijacking (reset homepage, search engine, remove bad extensions)
    #[arg(long, default_value_t = false)]
    fix_browser: bool,

    /// Quarantine detected threats (move to safe folder)
    #[arg(long, default_value_t = false)]
    quarantine: bool,

    /// Restore a quarantined file by ID
    #[arg(long, value_name = "ID")]
    restore: Option<usize>,

    /// List all quarantined items
    #[arg(long, default_value_t = false)]
    list_quarantine: bool,

    /// Download latest threat signatures
    #[arg(long, default_value_t = false)]
    update_sigs: bool,
}

fn main() {
    let cli = Cli::parse();

    // Handle non-scan commands first
    if let Some(id) = cli.restore {
        report::print_banner();
        println!(
            "{} Restoring quarantined item #{}...\n",
            "[*]".cyan().bold(),
            id
        );
        match quarantine::restore_file(id) {
            Ok(_) => println!("\n  {} Done.", "[✓]".green().bold()),
            Err(e) => println!("\n  {} {}", "[✗]".red().bold(), e),
        }
        return;
    }

    if cli.list_quarantine {
        report::print_banner();
        quarantine::list_quarantine();
        return;
    }

    if cli.update_sigs {
        report::print_banner();
        match updater::update_signatures() {
            Ok(_) => println!("\n  {} Signatures are up to date.", "[✓]".green().bold()),
            Err(e) => println!("\n  {} {}", "[!]".yellow(), e),
        }
        return;
    }

    if cli.fix_browser {
        report::print_banner();
        let fixed = browser_fix::fix_all_browsers();
        println!(
            "\n  {} Fixed {} browser profile(s).",
            "[✓]".green().bold(),
            fixed
        );
        return;
    }

    // For nuke mode, request elevation if needed
    if cli.nuke {
        report::print_banner();
        if !elevation::is_admin() {
            match elevation::request_elevation() {
                Ok(true) => return, // Elevated process was launched
                Ok(false) => {} // Already admin (shouldn't reach here)
                Err(e) => {
                    println!("  {} {}", "[!]".yellow(), e);
                    println!("  {} Continuing without admin — some removals may fail.\n", "[i]".blue());
                }
            }
        }
        let threats = run_full_scan();
        handle_nuke(&threats);
        return;
    }

    // Default scan modes
    let is_full = cli.scan || (!cli.quick && !cli.quarantine);
    let is_quick = cli.quick;

    report::print_banner();
    elevation::warn_if_not_admin();

    if is_full {
        let threats = run_full_scan();
        handle_results(&threats, cli.quarantine);
    } else if is_quick {
        let threats = run_quick_scan();
        handle_results(&threats, cli.quarantine);
    } else if cli.quarantine {
        println!(
            "  {} Running scan before quarantine...\n",
            "[i]".blue()
        );
        let threats = run_full_scan();
        handle_results(&threats, true);
    }
}

fn run_full_scan() -> Vec<threat::Threat> {
    report::print_scan_start("Full System Scan");
    let start = Instant::now();
    let mut all_threats = Vec::new();

    // 1. Process scan
    report::print_module_start("Scanning running processes...");
    let mut system = System::new_all();
    system.refresh_all();
    let proc_threats = scanner::processes::scan(&system);
    report_module_results("Processes", &proc_threats);
    all_threats.extend(proc_threats);

    // 2. Startup scan
    report::print_module_start("Scanning startup entries...");
    let startup_threats = scanner::startup::scan();
    report_module_results("Startup entries", &startup_threats);
    all_threats.extend(startup_threats);

    // 3. File scan
    report::print_module_start("Scanning file system...");
    let file_threats = scanner::files::scan();
    report_module_results("File system", &file_threats);
    all_threats.extend(file_threats);

    // 4. Browser extension scan
    report::print_module_start("Auditing browser extensions...");
    let browser_threats = scanner::browser::scan();
    report_module_results("Browser extensions", &browser_threats);
    all_threats.extend(browser_threats);

    // 5. Network scan
    report::print_module_start("Checking network configuration...");
    let net_threats = scanner::network::scan();
    report_module_results("Network configuration", &net_threats);
    all_threats.extend(net_threats);

    // 6. Scareware scan (now includes Defender tampering + proxy)
    report::print_module_start("Scanning for scareware, PUPs & Defender tampering...");
    let scare_threats = scanner::scareware::scan();
    report_module_results("Scareware / PUPs / Defender", &scare_threats);
    all_threats.extend(scare_threats);

    let elapsed = start.elapsed();
    println!(
        "\n  {} Scan completed in {:.1}s",
        "[i]".blue(),
        elapsed.as_secs_f64()
    );

    all_threats
}

fn run_quick_scan() -> Vec<threat::Threat> {
    report::print_scan_start("Quick Scan (Processes + Startup)");
    let start = Instant::now();
    let mut all_threats = Vec::new();

    report::print_module_start("Scanning running processes...");
    let mut system = System::new_all();
    system.refresh_all();
    let proc_threats = scanner::processes::scan(&system);
    report_module_results("Processes", &proc_threats);
    all_threats.extend(proc_threats);

    report::print_module_start("Scanning startup entries...");
    let startup_threats = scanner::startup::scan();
    report_module_results("Startup entries", &startup_threats);
    all_threats.extend(startup_threats);

    let elapsed = start.elapsed();
    println!(
        "\n  {} Quick scan completed in {:.1}s",
        "[i]".blue(),
        elapsed.as_secs_f64()
    );

    all_threats
}

fn report_module_results(module: &str, threats: &[threat::Threat]) {
    if threats.is_empty() {
        report::print_module_clean(module);
    } else {
        for t in threats {
            report::print_threat(t);
        }
    }
}

fn handle_results(threats: &[threat::Threat], do_quarantine: bool) {
    let mut sorted = threats.to_vec();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    report::print_summary(&sorted);

    if let Err(e) = report::write_log(&sorted) {
        println!("  {} Failed to write log: {}", "[!]".red(), e);
    }

    if do_quarantine && !sorted.is_empty() {
        println!(
            "\n{} {}",
            "[*]".cyan().bold(),
            "Quarantining threats...".yellow().bold()
        );
        match quarantine::quarantine_threats(&sorted) {
            Ok(count) => {
                println!(
                    "\n  {} Quarantined {} items.",
                    "[✓]".green().bold(),
                    count
                );
            }
            Err(e) => {
                println!("\n  {} Quarantine error: {}", "[✗]".red().bold(), e);
            }
        }
    } else if !sorted.is_empty() {
        println!(
            "  {} Use {} to remove threats, or {} for aggressive removal.",
            "[i]".blue(),
            "down --quarantine".yellow(),
            "down --nuke".red().bold()
        );
    }
}

fn handle_nuke(threats: &[threat::Threat]) {
    let mut sorted = threats.to_vec();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    report::print_summary(&sorted);

    if let Err(e) = report::write_log(&sorted) {
        println!("  {} Failed to write log: {}", "[!]".red(), e);
    }

    if sorted.is_empty() {
        return;
    }

    println!(
        "\n{} {}",
        "[*]".red().bold(),
        "NUKE MODE: Removing all threats...".red().bold()
    );
    println!("{}", "─".repeat(60).red());

    match remover::nuke_threats(&sorted) {
        Ok(count) => {
            println!(
                "\n  {} Removed {} threats.",
                "[✓]".green().bold(),
                count
            );
            println!(
                "  {} Run {} again to verify clean.",
                "[i]".blue(),
                "down --scan".yellow()
            );
        }
        Err(e) => {
            println!("\n  {} Removal error: {}", "[✗]".red().bold(), e);
        }
    }
}
