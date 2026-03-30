#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use down::{run_full_scan, run_quick_scan, ScanResult};
use serde::Deserialize;

#[tauri::command]
fn full_scan() -> ScanResult {
    run_full_scan()
}

#[tauri::command]
fn quick_scan() -> ScanResult {
    run_quick_scan()
}

#[tauri::command]
fn nuke_threats(threats: Vec<down::threat::Threat>) -> NukeResult {
    match down::remover::nuke_threats(&threats) {
        Ok(count) => NukeResult {
            success: true,
            removed: count,
            error: None,
        },
        Err(e) => NukeResult {
            success: false,
            removed: 0,
            error: Some(e),
        },
    }
}

#[tauri::command]
fn fix_browsers() -> usize {
    down::browser_fix::fix_all_browsers()
}

#[tauri::command]
fn check_admin() -> bool {
    down::elevation::is_admin()
}

#[tauri::command]
fn get_quarantine_list() -> Vec<down::quarantine::QuarantineEntry> {
    let manifest = down::quarantine::QuarantineManifest::load();
    manifest.entries
}

#[tauri::command]
fn restore_item(id: usize) -> Result<(), String> {
    down::quarantine::restore_file(id)
}

#[tauri::command]
fn ask_claude(api_key: String, threats_summary: String) -> Result<String, String> {
    let body = serde_json::json!({
        "model": "claude-sonnet-4-6",
        "max_tokens": 1024,
        "messages": [{
            "role": "user",
            "content": format!(
                "You are a Windows security expert analyzing scan results from a personal PC. \
                 The user is not technical. Give clear, actionable advice in plain English. \
                 Be specific about what to remove and what's safe.\n\n\
                 SCAN RESULTS:\n{}\n\n\
                 Analyze these threats. For each one, explain:\n\
                 1. What it is (in simple terms)\n\
                 2. How dangerous it is (1-10)\n\
                 3. What to do about it\n\
                 4. Is it safe to auto-remove with --nuke?\n\n\
                 End with an overall system health assessment.",
                threats_summary
            )
        }]
    });

    let body_str = serde_json::to_string(&body)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    let response = ureq::post("https://api.anthropic.com/v1/messages")
        .header("Content-Type", "application/json")
        .header("x-api-key", &api_key)
        .header("anthropic-version", "2025-09-01")
        .send(body_str.as_bytes())
        .map_err(|e| format!("API request failed: {}", e))?;

    let response_str = response
        .into_body()
        .read_to_string()
        .map_err(|e| format!("Failed to read response: {}", e))?;

    let json: serde_json::Value = serde_json::from_str(&response_str)
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    json.pointer("/content/0/text")
        .and_then(|v: &serde_json::Value| v.as_str())
        .map(|s: &str| s.to_string())
        .ok_or_else(|| "No response from Claude".to_string())
}

#[derive(serde::Serialize)]
struct NukeResult {
    success: bool,
    removed: usize,
    error: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct ClaudeRequest {
    api_key: String,
    threats_summary: String,
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            full_scan,
            quick_scan,
            nuke_threats,
            fix_browsers,
            check_admin,
            get_quarantine_list,
            restore_item,
            ask_claude,
        ])
        .run(tauri::generate_context!())
        .expect("error running DOWN Security Scanner");
}
