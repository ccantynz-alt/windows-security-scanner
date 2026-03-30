use colored::*;
use std::fs;
use std::path::PathBuf;

/// Download latest signatures from a remote URL and save locally.
/// Falls back to embedded signatures if download fails.
pub fn update_signatures() -> Result<(), String> {
    println!(
        "\n{} {}",
        "[*]".cyan().bold(),
        "Checking for signature updates...".yellow().bold()
    );

    let sig_dir = get_signatures_dir();
    fs::create_dir_all(&sig_dir)
        .map_err(|e| format!("Failed to create signatures directory: {}", e))?;

    let sig_file = sig_dir.join("signatures.json");

    // TODO: Replace with actual signature hosting URL once you set up a repo
    // For now, this pulls from the GitHub repo's raw content
    let url = "https://raw.githubusercontent.com/ccantynz-alt/down-scanner/main/signatures.json";

    println!("  {} Fetching from: {}", "[>]".blue(), url.dimmed());

    match ureq::get(url).call() {
        Ok(response) => {
            let body = response
                .into_body()
                .read_to_string()
                .map_err(|e| format!("Failed to read response: {}", e))?;

            // Validate it's valid JSON
            let _: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| format!("Invalid signature file: {}", e))?;

            fs::write(&sig_file, &body)
                .map_err(|e| format!("Failed to save signatures: {}", e))?;

            println!(
                "  {} Signatures updated: {}",
                "[✓]".green().bold(),
                sig_file.display()
            );
            Ok(())
        }
        Err(e) => {
            println!(
                "  {} Download failed: {}. Using embedded signatures.",
                "[!]".yellow(),
                e
            );
            Err(format!("Failed to download signatures: {}", e))
        }
    }
}

/// Load additional signatures from local file (if downloaded).
/// Returns extra process names, hashes, etc. to merge with embedded ones.
pub fn load_extra_signatures() -> Option<ExtraSignatures> {
    let sig_file = get_signatures_dir().join("signatures.json");
    if !sig_file.exists() {
        return None;
    }

    let content = fs::read_to_string(&sig_file).ok()?;
    serde_json::from_str(&content).ok()
}

#[derive(Debug, serde::Deserialize)]
pub struct ExtraSignatures {
    #[serde(default)]
    pub bad_processes: Vec<String>,
    #[serde(default)]
    pub bad_hashes: Vec<(String, String)>,
    #[serde(default)]
    pub bad_extension_ids: Vec<(String, String, String)>,
    #[serde(default)]
    pub bad_ips: Vec<(String, String)>,
    #[serde(default)]
    pub scareware_names: Vec<String>,
}

fn get_signatures_dir() -> PathBuf {
    if cfg!(windows) {
        dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("DownScanner")
            .join("signatures")
    } else {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".down-scanner")
            .join("signatures")
    }
}
