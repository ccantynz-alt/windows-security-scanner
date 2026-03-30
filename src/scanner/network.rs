use crate::signatures::ip_blocklist::{
    KNOWN_BAD_DOMAINS, KNOWN_BAD_DNS, KNOWN_BAD_IP_PREFIXES, LEGITIMATE_HOSTS_ENTRIES,
};
use crate::threat::{Severity, Threat, ThreatAction, ThreatCategory};
use std::fs;
use std::path::Path;

/// Scan network configuration for threats
pub fn scan() -> Vec<Threat> {
    let mut threats = Vec::new();

    // Check hosts file for tampering
    check_hosts_file(&mut threats);

    // Check for suspicious network connections (Windows)
    #[cfg(windows)]
    check_network_connections(&mut threats);

    // Check DNS configuration (Windows)
    #[cfg(windows)]
    check_dns_settings(&mut threats);

    // Check proxy hijacking (Windows)
    #[cfg(windows)]
    check_proxy_hijack(&mut threats);

    // On non-Windows, do basic hosts file check and resolv.conf
    #[cfg(not(windows))]
    check_resolv_conf(&mut threats);

    threats
}

/// Check if system proxy has been hijacked by malware
#[cfg(windows)]
fn check_proxy_hijack(threats: &mut Vec<Threat>) {
    use winreg::enums::*;
    use winreg::RegKey;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let key = match hkcu.open_subkey(key_path) {
        Ok(k) => k,
        Err(_) => return,
    };

    let proxy_enable: u32 = key.get_value("ProxyEnable").unwrap_or(0);
    if proxy_enable == 0 {
        return; // Proxy not enabled — clean
    }

    let proxy_server: String = key.get_value("ProxyServer").unwrap_or_default();
    let auto_config_url: String = key.get_value("AutoConfigURL").unwrap_or_default();

    if !proxy_server.is_empty() {
        threats.push(Threat {
            name: format!("Proxy server configured: {}", proxy_server),
            severity: Severity::High,
            category: ThreatCategory::ProxyHijack,
            location: format!("{}\\ProxyServer", key_path),
            description: format!(
                "Your internet traffic is being routed through proxy server '{}'. \
                 If you didn't set this yourself, malware may be intercepting your traffic.",
                proxy_server
            ),
            action: ThreatAction::ResetProxy,
        });
    }

    if !auto_config_url.is_empty() {
        threats.push(Threat {
            name: format!("Proxy auto-config URL: {}", auto_config_url),
            severity: Severity::High,
            category: ThreatCategory::ProxyHijack,
            location: format!("{}\\AutoConfigURL", key_path),
            description: format!(
                "A proxy auto-config (PAC) file is set to '{}'. \
                 This can redirect your traffic through a malicious proxy.",
                auto_config_url
            ),
            action: ThreatAction::ResetProxy,
        });
    }
}

fn check_hosts_file(threats: &mut Vec<Threat>) {
    let hosts_path = if cfg!(windows) {
        Path::new(r"C:\Windows\System32\drivers\etc\hosts")
    } else {
        Path::new("/etc/hosts")
    };

    let content = match fs::read_to_string(hosts_path) {
        Ok(c) => c,
        Err(_) => return, // Can't read hosts file — might need admin
    };

    let mut suspicious_entries = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();

        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Parse the line: IP hostname [hostname2 ...]
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }

        let ip = parts[0];
        let hostnames: Vec<&str> = parts[1..].to_vec();

        // Check if hostnames are legitimate
        for hostname in &hostnames {
            let is_legitimate = LEGITIMATE_HOSTS_ENTRIES
                .iter()
                .any(|legit| hostname.eq_ignore_ascii_case(legit));

            if !is_legitimate {
                // Check if the entry is redirecting known good sites (hijacking)
                let is_redirect = ip != "127.0.0.1" && ip != "::1" && ip != "0.0.0.0";
                let is_blocking = ip == "127.0.0.1" || ip == "0.0.0.0";

                if is_redirect {
                    // Redirecting to a non-local IP — very suspicious
                    suspicious_entries.push(format!("{} -> {} (REDIRECT)", hostname, ip));
                } else if is_blocking {
                    // Blocking entries could be ad-blockers (legitimate) or malware
                    // Only flag if it's blocking important domains
                    let important_domains = [
                        "windowsupdate", "microsoft.com", "google.com",
                        "chrome.google.com", "update.googleapis.com",
                    ];
                    if important_domains
                        .iter()
                        .any(|d| hostname.to_lowercase().contains(d))
                    {
                        suspicious_entries
                            .push(format!("{} BLOCKED by hosts file (could prevent updates)", hostname));
                    }
                }
            }
        }

        // Check if the IP points to known bad addresses
        for (bad_prefix, description) in KNOWN_BAD_IP_PREFIXES {
            if ip.starts_with(bad_prefix) {
                threats.push(Threat {
                    name: "Hosts file points to malicious IP".to_string(),
                    severity: Severity::Critical,
                    category: ThreatCategory::HostsTampering,
                    location: hosts_path.to_string_lossy().to_string(),
                    description: format!(
                        "Hosts entry '{}' redirects to suspicious IP {} — {}",
                        hostnames.join(", "),
                        ip,
                        description
                    ),
                    action: ThreatAction::ManualReview,
                });
            }
        }

        // Check for known bad domains in hosts file
        for (bad_domain, description) in KNOWN_BAD_DOMAINS {
            for hostname in &hostnames {
                if hostname.to_lowercase().contains(bad_domain) {
                    threats.push(Threat {
                        name: format!("Known bad domain in hosts: {}", hostname),
                        severity: Severity::High,
                        category: ThreatCategory::HostsTampering,
                        location: hosts_path.to_string_lossy().to_string(),
                        description: format!(
                            "Hosts file references known malicious domain pattern '{}' — {}",
                            bad_domain, description
                        ),
                        action: ThreatAction::ManualReview,
                    });
                }
            }
        }
    }

    if !suspicious_entries.is_empty() {
        threats.push(Threat {
            name: "Hosts file modifications detected".to_string(),
            severity: Severity::High,
            category: ThreatCategory::HostsTampering,
            location: hosts_path.to_string_lossy().to_string(),
            description: format!(
                "Found {} suspicious entries in hosts file:\n      {}",
                suspicious_entries.len(),
                suspicious_entries.join("\n      ")
            ),
            action: ThreatAction::ManualReview,
        });
    }
}

#[cfg(windows)]
fn check_network_connections(threats: &mut Vec<Threat>) {
    // Use netstat via command to list connections
    let output = match std::process::Command::new("netstat")
        .args(["-an"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 3 {
            continue;
        }

        // Check for connections to known bad IPs
        let remote = parts.get(2).unwrap_or(&"");
        for (bad_prefix, description) in KNOWN_BAD_IP_PREFIXES {
            if remote.starts_with(bad_prefix) {
                threats.push(Threat {
                    name: format!("Connection to suspicious IP: {}", remote),
                    severity: Severity::Critical,
                    category: ThreatCategory::SuspiciousNetwork,
                    location: format!("Active connection: {} -> {}", parts.get(1).unwrap_or(&"?"), remote),
                    description: format!(
                        "Active network connection to known suspicious IP range — {}",
                        description
                    ),
                    action: ThreatAction::ManualReview,
                });
            }
        }
    }
}

#[cfg(windows)]
fn check_dns_settings(threats: &mut Vec<Threat>) {
    // Check DNS via ipconfig
    let output = match std::process::Command::new("ipconfig")
        .args(["/all"])
        .output()
    {
        Ok(o) => o,
        Err(_) => return,
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.contains("DNS Servers") || trimmed.contains("DNS-Server") {
            // Extract IP from the line
            if let Some(ip_part) = trimmed.split(':').nth(1) {
                let ip = ip_part.trim();
                for (bad_dns, description) in KNOWN_BAD_DNS {
                    if ip.starts_with(bad_dns) {
                        threats.push(Threat {
                            name: format!("Malicious DNS server: {}", ip),
                            severity: Severity::Critical,
                            category: ThreatCategory::DnsTampering,
                            location: "Network adapter DNS settings".to_string(),
                            description: format!(
                                "DNS server {} is known malicious — {}. \
                                 Your DNS queries may be intercepted.",
                                ip, description
                            ),
                            action: ThreatAction::ManualReview,
                        });
                    }
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn check_resolv_conf(threats: &mut Vec<Threat>) {
    let resolv_path = "/etc/resolv.conf";
    let content = match fs::read_to_string(resolv_path) {
        Ok(c) => c,
        Err(_) => return,
    };

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver") {
            if let Some(ip) = trimmed.split_whitespace().nth(1) {
                for (bad_dns, description) in KNOWN_BAD_DNS {
                    if ip.starts_with(bad_dns) {
                        threats.push(Threat {
                            name: format!("Malicious DNS server: {}", ip),
                            severity: Severity::Critical,
                            category: ThreatCategory::DnsTampering,
                            location: resolv_path.to_string(),
                            description: format!(
                                "DNS server {} is known malicious — {}",
                                ip, description
                            ),
                            action: ThreatAction::ManualReview,
                        });
                    }
                }
            }
        }
    }
}
