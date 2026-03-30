pub mod browser_fix;
pub mod elevation;
pub mod quarantine;
pub mod remover;
pub mod report;
pub mod scanner;
pub mod signatures;
pub mod threat;
pub mod updater;

use serde::Serialize;
use sysinfo::System;
use threat::{Severity, Threat};

#[derive(Debug, Clone, Serialize)]
pub struct ScanResult {
    pub threats: Vec<Threat>,
    pub summary: ScanSummary,
    pub duration_secs: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub total: usize,
}

/// Run a full system scan and return structured results
pub fn run_full_scan() -> ScanResult {
    let start = std::time::Instant::now();
    let mut all_threats = Vec::new();

    // Process scan
    let mut system = System::new_all();
    system.refresh_all();
    all_threats.extend(scanner::processes::scan(&system));

    // Startup scan
    all_threats.extend(scanner::startup::scan());

    // File scan
    all_threats.extend(scanner::files::scan());

    // Browser extension scan
    all_threats.extend(scanner::browser::scan());

    // Network scan
    all_threats.extend(scanner::network::scan());

    // Scareware scan (includes Defender tampering)
    all_threats.extend(scanner::scareware::scan());

    // Sort by severity
    all_threats.sort_by(|a, b| b.severity.cmp(&a.severity));

    let elapsed = start.elapsed().as_secs_f64();

    let summary = ScanSummary {
        critical: all_threats.iter().filter(|t| t.severity == Severity::Critical).count(),
        high: all_threats.iter().filter(|t| t.severity == Severity::High).count(),
        medium: all_threats.iter().filter(|t| t.severity == Severity::Medium).count(),
        low: all_threats.iter().filter(|t| t.severity == Severity::Low).count(),
        total: all_threats.len(),
    };

    ScanResult {
        threats: all_threats,
        summary,
        duration_secs: elapsed,
    }
}

/// Run a quick scan (processes + startup only)
pub fn run_quick_scan() -> ScanResult {
    let start = std::time::Instant::now();
    let mut all_threats = Vec::new();

    let mut system = System::new_all();
    system.refresh_all();
    all_threats.extend(scanner::processes::scan(&system));
    all_threats.extend(scanner::startup::scan());
    all_threats.sort_by(|a, b| b.severity.cmp(&a.severity));

    let elapsed = start.elapsed().as_secs_f64();
    let summary = ScanSummary {
        critical: all_threats.iter().filter(|t| t.severity == Severity::Critical).count(),
        high: all_threats.iter().filter(|t| t.severity == Severity::High).count(),
        medium: all_threats.iter().filter(|t| t.severity == Severity::Medium).count(),
        low: all_threats.iter().filter(|t| t.severity == Severity::Low).count(),
        total: all_threats.len(),
    };

    ScanResult { threats: all_threats, summary, duration_secs: elapsed }
}
