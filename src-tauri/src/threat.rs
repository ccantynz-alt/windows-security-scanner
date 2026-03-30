use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThreatCategory {
    Malware,
    Scareware,
    PotentiallyUnwanted,
    Adware,
    Cryptominer,
    BrowserHijacker,
    SuspiciousFile,
    SuspiciousProcess,
    SuspiciousStartup,
    SuspiciousNetwork,
    HostsTampering,
    DnsTampering,
    DefenderTampering,
    ProxyHijack,
}

impl fmt::Display for ThreatCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatCategory::Malware => write!(f, "Malware"),
            ThreatCategory::Scareware => write!(f, "Scareware"),
            ThreatCategory::PotentiallyUnwanted => write!(f, "Potentially Unwanted Program"),
            ThreatCategory::Adware => write!(f, "Adware"),
            ThreatCategory::Cryptominer => write!(f, "Cryptominer"),
            ThreatCategory::BrowserHijacker => write!(f, "Browser Hijacker"),
            ThreatCategory::SuspiciousFile => write!(f, "Suspicious File"),
            ThreatCategory::SuspiciousProcess => write!(f, "Suspicious Process"),
            ThreatCategory::SuspiciousStartup => write!(f, "Suspicious Startup Entry"),
            ThreatCategory::SuspiciousNetwork => write!(f, "Suspicious Network Activity"),
            ThreatCategory::HostsTampering => write!(f, "Hosts File Tampering"),
            ThreatCategory::DnsTampering => write!(f, "DNS Tampering"),
            ThreatCategory::DefenderTampering => write!(f, "Windows Defender Tampering"),
            ThreatCategory::ProxyHijack => write!(f, "Proxy Hijacking"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatAction {
    /// Kill process by PID
    KillProcess(u32),
    /// Quarantine file at path
    QuarantineFile(String),
    /// Remove registry startup entry
    RemoveStartupEntry { key_path: String, value_name: String },
    /// Uninstall a program using its uninstall command
    UninstallProgram { uninstall_string: String, name: String },
    /// Delete a scheduled task by name
    DeleteScheduledTask { task_name: String },
    /// Remove a browser extension
    DisableBrowserExtension { browser: String, ext_id: String },
    /// Reset proxy settings to direct connection
    ResetProxy,
    /// Re-enable Windows Defender
    RestoreDefender,
    /// No automated action — manual review needed
    ManualReview,
}

impl fmt::Display for ThreatAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThreatAction::KillProcess(pid) => write!(f, "Kill process (PID: {})", pid),
            ThreatAction::QuarantineFile(path) => write!(f, "Quarantine: {}", path),
            ThreatAction::RemoveStartupEntry { value_name, .. } => {
                write!(f, "Remove startup entry: {}", value_name)
            }
            ThreatAction::UninstallProgram { name, .. } => {
                write!(f, "Uninstall program: {}", name)
            }
            ThreatAction::DeleteScheduledTask { task_name } => {
                write!(f, "Delete scheduled task: {}", task_name)
            }
            ThreatAction::DisableBrowserExtension { browser, ext_id } => {
                write!(f, "Remove {} extension: {}", browser, ext_id)
            }
            ThreatAction::ResetProxy => write!(f, "Reset proxy to direct connection"),
            ThreatAction::RestoreDefender => write!(f, "Re-enable Windows Defender"),
            ThreatAction::ManualReview => write!(f, "Manual review recommended"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Threat {
    pub name: String,
    pub severity: Severity,
    pub category: ThreatCategory,
    pub location: String,
    pub description: String,
    pub action: ThreatAction,
}
