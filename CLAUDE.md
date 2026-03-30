# DOWN — AI Security Scanner: Project Blueprint

## Mission

Build the most intelligent, lightweight, ethical antivirus scanner on the market. No scareware. No fake threats. No CPU-destroying background scans. No subscriptions to unlock "protection." Just honest, AI-powered security that respects the user and their machine.

**This is a commercial product.** Every decision must serve the end user, not our revenue.

## Core Principles

1. **Lightweight first** — Never spike CPU above 15% during scans. Scan smart, not hard. Use idle-priority threads. Pause if the user is gaming or rendering.
2. **No scareware, ever** — We do NOT inflate threat counts. We do NOT show scary popups to upsell. If something is safe, we say it's safe. Period.
3. **AI-native detection** — Traditional AV relies on hash matching (reactive). We use AI pattern recognition to catch threats that don't exist in any database yet.
4. **Privacy absolute** — Zero telemetry. Zero cloud uploads of user files. All scanning happens locally. The only network call is Claude AI analysis (opt-in, user-initiated).
5. **Transparent** — Open source core. Users can see exactly what we scan and why we flag things.

## Architecture

### Stack

- **Backend**: Rust (performance, safety, small binary ~15MB)
- **Frontend**: React via Tauri 2.0 (native desktop, no Electron bloat, no HTML served over HTTP)
- **AI Engine**: Claude API (threat analysis, plain-English explanations)
- **Target**: Windows primary, Linux/macOS secondary

### Module Map

```
src-tauri/
  src/
    main.rs              — Tauri GUI entry, command handlers, Claude API
    cli_main.rs          — CLI entry with clap args
    lib.rs               — Core scan orchestration (full_scan, quick_scan)
    threat.rs            — Threat data model (severity, category, action)
    scanner/
      mod.rs             — Scanner module registry
      processes.rs       — Running process analysis
      startup.rs         — Registry persistence detection
      files.rs           — File system scanning (hashes, double extensions)
      browser.rs         — Browser extension analysis
      network.rs         — Network config tampering detection
      scareware.rs       — Fake AV / optimizer detection
    signatures/
      mod.rs             — Signature database loader
      process_names.rs   — Known bad process names (200+)
      hashes.rs          — Known malware SHA256 hashes
      extension_ids.rs   — Malicious browser extension IDs
      hijacker_domains.rs — DNS hijack domains
      ip_blocklist.rs    — Malicious IP ranges
      safe_tasks.rs      — Legit Windows tasks (false positive prevention)
    remover.rs           — NUKE mode threat removal
    quarantine.rs        — Quarantine with restore capability
    browser_fix.rs       — Browser settings reset
    elevation.rs         — UAC/admin elevation
    updater.rs           — Signature database updates
    report.rs            — Scan report generation
ui/
  src/
    App.jsx              — React dashboard (dark theme, threat cards)
    App.css              — Styling (severity color coding)
```

### Data Flow

```
User clicks "Scan"
  → lib.rs orchestrates 6 scanner modules (sequential, low-priority threads)
  → Each module returns Vec<Threat>
  → Threats sorted by severity (Critical > High > Medium > Low)
  → Results displayed in GUI with severity badges
  → User optionally sends summary to Claude for AI analysis
  → User can NUKE (auto-remove), quarantine, or manually review
```

## Current State (v0.3.0)

### Working
- 6 scanner modules (processes, startup, files, browser, network, scareware)
- GUI dashboard with dark theme and threat cards
- CLI mode with full feature parity
- Claude AI threat analysis (bring your own API key)
- NUKE mode (aggressive removal)
- Quarantine with restore capability
- Browser fix (Chrome, Edge, Firefox)
- UAC elevation
- Signature update system
- CI/CD pipeline (GitHub Actions builds .exe)

### Critical Gaps to Fix
1. **Signature hosting broken** — updater points to non-existent repo `ccantynz-alt/down-scanner`
2. **Hash database empty** — file scanner can't match known malware hashes
3. **Safe tasks list unused** — `safe_tasks.rs` exists but scanner doesn't filter against it, causing false positives
4. **No scan history** — results lost after each scan
5. **No quarantine UI in GUI** — only available via CLI
6. **No progress feedback** — scans appear frozen on large file systems
7. **No signature verification** — downloaded updates not cryptographically verified
8. **Claude model outdated** — hardcoded to Claude 3.5 Sonnet, should use latest Claude Sonnet 4.6

## Roadmap

### Phase 1: Foundation Fixes (Current Priority)
- [ ] Fix signature hosting (set up real GitHub repo or CDN for signatures.json)
- [ ] Populate hash database with real malware hashes from public threat feeds
- [ ] Wire up safe_tasks.rs to prevent false positives on scheduled tasks
- [ ] Add quarantine list/restore to the GUI dashboard
- [ ] Add scan progress bar with real-time module status
- [ ] Update Claude API call to use latest model (claude-sonnet-4-6)
- [ ] Fix build pipeline — ensure GitHub Release is created with downloadable .exe
- [ ] Add signature verification (SHA256 checksum for downloaded updates)

### Phase 2: AI-Native Detection
- [ ] Behavioral analysis — detect suspicious process behavior patterns, not just names
- [ ] Memory scanning — detect injected code in running processes
- [ ] Startup chain analysis — map which programs launch which, detect hijacked chains
- [ ] AI heuristic engine — use Claude to evaluate unknown executables based on metadata
- [ ] Real-time file monitor — watch Downloads folder for new threats (low-CPU event-driven)
- [ ] Network traffic analysis — detect C&C communication patterns
- [ ] Registry change monitor — alert on suspicious registry modifications

### Phase 3: Threat Intelligence
- [ ] Integrate public threat feeds (VirusTotal, MalwareBazaar, abuse.ch)
- [ ] Community threat reporting — users can submit new threats (anonymized)
- [ ] Auto-update signatures on a schedule (daily, background, low-priority)
- [ ] Threat trend dashboard — show what's currently spreading
- [ ] Regional threat awareness — threats targeting specific regions

### Phase 4: Commercial Release
- [ ] Code signing certificate (eliminate SmartScreen warnings)
- [ ] Auto-updater for the application itself
- [ ] Licensing system (free tier + pro tier)
- [ ] Installer (MSI/MSIX for enterprise deployment)
- [ ] Documentation site
- [ ] User onboarding flow
- [ ] Crash reporting (opt-in, no PII)

## Build Commands

### Linux / macOS
```bash
cd ui && npm install && npm run build && cd ..
cargo build --release
```

### Windows (PowerShell)
```powershell
cd ui; npm install; npm run build; cd ..
cargo build --release
```

### Output
- Binary: `target/release/down.exe` (Windows) or `target/release/down` (Linux/macOS)
- CI builds: GitHub Actions creates release with .exe and installer zip on version tags

## Development Rules

### Before Every Build
1. Read this CLAUDE.md file first
2. Check the roadmap — what phase are we in?
3. Check existing scanner modules before adding new ones
4. Run `cargo check` before `cargo build` to catch errors fast

### Code Standards
- **No HTML files** — all UI goes through React/Tauri components
- **No unnecessary dependencies** — every crate must justify its inclusion
- **CPU discipline** — any scan loop must yield periodically, never block the UI thread
- **False positive prevention** — every detection rule needs a safe-list counterpart
- **Error handling** — use Result<>, never panic in production code
- **No telemetry** — never add network calls that the user didn't explicitly request

### Threat Detection Rules
- Every threat must have: name, description, severity, category, and recommended action
- Severity must be honest — don't inflate to scare users
- Always provide a "Manual Review" option for uncertain detections
- Quarantine before delete — give users a way to recover false positives
- NUKE mode is opt-in only, never automatic

### Scanner Module Template
When adding a new scanner module:
1. Create `src-tauri/src/scanner/{module_name}.rs`
2. Implement `pub fn scan_{module_name}() -> Vec<Threat>`
3. Register in `scanner/mod.rs`
4. Add to `lib.rs` scan orchestration
5. Add corresponding signature file if needed in `signatures/`
6. Update this CLAUDE.md roadmap

## Competitive Positioning

### What We Do Better
- **Honest** — we don't manufacture threats to sell upgrades
- **Lightweight** — <15% CPU, <100MB RAM during scans
- **AI-powered** — Claude provides human-readable threat explanations
- **Transparent** — open source, users can audit every detection rule
- **Respectful** — no popups, no nagging, no "your PC is at risk" nonsense

### What Traditional AV Gets Wrong
- Constant background scanning that destroys system performance
- Inflated threat counts to justify subscription renewals
- Bundled browser toolbars and "safe search" hijackers
- Blocking legitimate software as "potentially unwanted"
- Selling user browsing data to advertisers
- Disabling Windows Defender to force dependency on their product

We exist because the antivirus industry became the very thing it was supposed to protect against.
