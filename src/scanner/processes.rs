use crate::signatures::process_names::{
    KNOWN_BAD_PROCESSES, KNOWN_SAFE_PROCESSES, SUSPICIOUS_PATH_FRAGMENTS,
};
use crate::threat::{Severity, Threat, ThreatAction, ThreatCategory};
use sysinfo::System;

/// CPU usage threshold (percentage) — above this for a single process is suspicious
const CRYPTOMINER_CPU_THRESHOLD: f32 = 80.0;

/// Scan all running processes for threats
pub fn scan(system: &System) -> Vec<Threat> {
    let mut threats = Vec::new();

    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        let exe_path = process
            .exe()
            .map(|p| p.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        let pid_u32 = pid.as_u32();

        // Check against known bad process names
        for bad_name in KNOWN_BAD_PROCESSES {
            if name.contains(bad_name) {
                threats.push(Threat {
                    name: format!("Known bad process: {}", process.name().to_string_lossy()),
                    severity: Severity::Critical,
                    category: ThreatCategory::Malware,
                    location: exe_path.clone(),
                    description: format!(
                        "Process '{}' (PID: {}) matches known malware/scareware signature '{}'",
                        process.name().to_string_lossy(),
                        pid_u32,
                        bad_name
                    ),
                    action: ThreatAction::KillProcess(pid_u32),
                });
                break;
            }
        }

        // Skip safe processes for path/CPU checks
        let name_lower = name.clone();
        if KNOWN_SAFE_PROCESSES.iter().any(|s| name_lower.contains(s)) {
            continue;
        }

        // Check for suspicious paths
        if !exe_path.is_empty() {
            for fragment in SUSPICIOUS_PATH_FRAGMENTS {
                if exe_path.contains(fragment) {
                    threats.push(Threat {
                        name: format!(
                            "Suspicious location: {}",
                            process.name().to_string_lossy()
                        ),
                        severity: Severity::High,
                        category: ThreatCategory::SuspiciousProcess,
                        location: exe_path.clone(),
                        description: format!(
                            "Process '{}' (PID: {}) is running from suspicious path containing '{}'",
                            process.name().to_string_lossy(),
                            pid_u32,
                            fragment
                        ),
                        action: ThreatAction::KillProcess(pid_u32),
                    });
                    break;
                }
            }
        }

        // Check for potential cryptominers (high CPU usage)
        let cpu = process.cpu_usage();
        if cpu > CRYPTOMINER_CPU_THRESHOLD {
            threats.push(Threat {
                name: format!("High CPU usage: {}", process.name().to_string_lossy()),
                severity: Severity::Medium,
                category: ThreatCategory::Cryptominer,
                location: exe_path.clone(),
                description: format!(
                    "Process '{}' (PID: {}) using {:.1}% CPU — possible cryptominer. \
                     Check if this is a legitimate program (e.g., video encoding, game).",
                    process.name().to_string_lossy(),
                    pid_u32,
                    cpu
                ),
                action: ThreatAction::ManualReview,
            });
        }
    }

    threats
}
