use colored::*;
use std::fs;
use std::path::PathBuf;

/// Reset browser settings (homepage, search engine, proxy) for all browsers.
/// Requires browsers to be closed.
pub fn fix_all_browsers() -> usize {
    let mut fixed = 0;

    println!(
        "\n{} {}",
        "[*]".cyan().bold(),
        "Fixing browser settings...".yellow().bold()
    );

    // Check if browsers are running
    check_browsers_closed();

    // Fix Chrome
    for profile in get_chromium_profiles("Google\\Chrome") {
        if fix_chromium_profile(&profile, "Chrome") {
            fixed += 1;
        }
    }

    // Fix Edge
    for profile in get_chromium_profiles("Microsoft\\Edge") {
        if fix_chromium_profile(&profile, "Edge") {
            fixed += 1;
        }
    }

    // Fix Firefox
    for profile in get_firefox_profiles() {
        if fix_firefox_profile(&profile) {
            fixed += 1;
        }
    }

    if fixed == 0 {
        println!(
            "  {} No browser profiles found or all already clean.",
            "[i]".blue()
        );
    }

    fixed
}

fn check_browsers_closed() {
    let browsers = ["chrome", "msedge", "firefox"];
    let mut sys = sysinfo::System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    for browser in &browsers {
        for (_pid, process) in sys.processes() {
            if process.name().to_string_lossy().to_lowercase().contains(browser) {
                println!(
                    "  {} {} is running. Close it for best results.",
                    "[!]".yellow().bold(),
                    browser
                );
                break;
            }
        }
    }
}

fn fix_chromium_profile(profile_dir: &PathBuf, browser: &str) -> bool {
    let prefs_path = profile_dir.join("Preferences");
    if !prefs_path.exists() {
        return false;
    }

    let content = match fs::read_to_string(&prefs_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let mut prefs: serde_json::Value = match serde_json::from_str(&content) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let mut changed = false;

    // Reset homepage
    let homepage_hijacked = prefs
        .pointer("/homepage")
        .and_then(|v| v.as_str())
        .map(|hp| (hp.to_string(), is_hijacked_url(&hp.to_lowercase())))
        .filter(|(_, hijacked)| *hijacked);
    if let Some((old_hp, _)) = homepage_hijacked {
        prefs["homepage"] = serde_json::json!("https://www.google.com");
        prefs["homepage_is_newtabpage"] = serde_json::json!(true);
        println!(
            "  {} {} homepage reset (was: {})",
            "[✓]".green().bold(),
            browser,
            old_hp
        );
        changed = true;
    }

    // Reset startup pages
    let hijacked_count = prefs
        .pointer("/session/startup_urls")
        .and_then(|v| v.as_array())
        .map(|urls| {
            urls.iter()
                .filter_map(|u| u.as_str())
                .filter(|u| is_hijacked_url(&u.to_lowercase()))
                .count()
        })
        .unwrap_or(0);
    if hijacked_count > 0 {
        prefs["session"]["startup_urls"] = serde_json::json!([]);
        prefs["session"]["restore_on_startup"] = serde_json::json!(1);
        println!(
            "  {} {} startup pages reset (removed {} hijacked URLs)",
            "[✓]".green().bold(),
            browser,
            hijacked_count
        );
        changed = true;
    }

    // Reset default search engine
    let search_hijacked = prefs
        .pointer("/default_search_provider/search_url")
        .and_then(|v| v.as_str())
        .map(|s| (s.to_string(), is_hijacked_url(&s.to_lowercase())))
        .filter(|(_, hijacked)| *hijacked);
    if let Some((old_search, _)) = search_hijacked {
        if let Some(obj) = prefs.as_object_mut() {
            obj.remove("default_search_provider");
            obj.remove("default_search_provider_data");
        }
        println!(
            "  {} {} search engine reset (was: {})",
            "[✓]".green().bold(),
            browser,
            old_search
        );
        changed = true;
    }

    // Reset proxy settings in browser
    if let Some(proxy) = prefs.pointer("/proxy") {
        if proxy.get("mode").and_then(|m| m.as_str()) == Some("fixed_servers") {
            if let Some(obj) = prefs.as_object_mut() {
                obj.remove("proxy");
            }
            println!(
                "  {} {} proxy settings cleared",
                "[✓]".green().bold(),
                browser
            );
            changed = true;
        }
    }

    if changed {
        // Backup original
        let backup_path = prefs_path.with_extension("bak.down");
        let _ = fs::copy(&prefs_path, &backup_path);

        // Write fixed preferences
        if let Ok(new_content) = serde_json::to_string_pretty(&prefs) {
            let _ = fs::write(&prefs_path, new_content);
        }
    }

    changed
}

fn fix_firefox_profile(profile_dir: &PathBuf) -> bool {
    let prefs_path = profile_dir.join("prefs.js");
    if !prefs_path.exists() {
        return false;
    }

    let content = match fs::read_to_string(&prefs_path) {
        Ok(c) => c,
        Err(_) => return false,
    };

    let mut lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
    let mut changed = false;

    // Check each preference line
    let hijack_prefs = [
        "browser.startup.homepage",
        "browser.search.defaultenginename",
        "browser.newtabpage.url",
        "keyword.URL",
        "browser.search.selectedEngine",
    ];

    let original_len = lines.len();
    lines.retain(|line| {
        for pref in &hijack_prefs {
            if line.contains(pref) {
                // Extract the URL value
                if let Some(start) = line.find('"') {
                    let rest = &line[start + 1..];
                    if let Some(end) = rest.rfind('"') {
                        let value = &rest[..end];
                        if is_hijacked_url(&value.to_lowercase()) {
                            println!(
                                "  {} Firefox pref removed: {} (was: {})",
                                "[✓]".green().bold(),
                                pref,
                                value
                            );
                            return false; // Remove this line
                        }
                    }
                }
            }
        }
        true
    });

    if lines.len() != original_len {
        changed = true;
        // Backup original
        let backup_path = prefs_path.with_extension("bak.down");
        let _ = fs::copy(&prefs_path, &backup_path);
        // Write cleaned prefs
        let _ = fs::write(&prefs_path, lines.join("\n"));
    }

    // Also check for proxy settings in prefs
    let proxy_prefs_path = profile_dir.join("prefs.js");
    if let Ok(prefs_content) = fs::read_to_string(&proxy_prefs_path) {
        if prefs_content.contains("network.proxy.type") {
            // Check if proxy is set to manual (type=1) with suspicious server
            for line in prefs_content.lines() {
                if line.contains("network.proxy.http") && !line.contains("//") {
                    if let Some(start) = line.find('"') {
                        let rest = &line[start + 1..];
                        if let Some(end) = rest.rfind('"') {
                            let proxy_server = &rest[..end];
                            if !proxy_server.is_empty() {
                                println!(
                                    "  {} Firefox proxy detected: {}",
                                    "[!]".yellow(),
                                    proxy_server
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    if changed {
        println!("  {} Firefox profile fixed", "[✓]".green().bold());
    }

    changed
}

fn is_hijacked_url(url: &str) -> bool {
    use crate::signatures::hijacker_domains::HIJACKER_SEARCH_DOMAINS;
    HIJACKER_SEARCH_DOMAINS
        .iter()
        .any(|(domain, _)| url.contains(domain))
}

fn get_chromium_profiles(browser_path: &str) -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    if let Some(local) = dirs::data_local_dir() {
        let base = local.join(browser_path).join("User Data");
        let default = base.join("Default");
        if default.exists() {
            profiles.push(default);
        }
        if let Ok(entries) = fs::read_dir(&base) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("Profile ") {
                    profiles.push(entry.path());
                }
            }
        }
    }
    profiles
}

fn get_firefox_profiles() -> Vec<PathBuf> {
    let mut profiles = Vec::new();
    if let Some(roaming) = dirs::config_dir() {
        let profiles_dir = roaming.join("Mozilla").join("Firefox").join("Profiles");
        if let Ok(entries) = fs::read_dir(&profiles_dir) {
            for entry in entries.flatten() {
                if entry.path().is_dir() {
                    profiles.push(entry.path());
                }
            }
        }
    }
    profiles
}
