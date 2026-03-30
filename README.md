# DOWN — AI Security Scanner

A complete Windows security scanner with a GUI dashboard and Claude AI threat analysis. Built in Rust + React with Tauri 2.0.

**No bloat. No telemetry. No subscriptions. Your data stays on your PC.**

## What It Does

| Module | What It Scans |
|--------|--------------|
| **Processes** | Running processes against 200+ known malware names, suspicious paths, cryptominer CPU usage |
| **Startup** | Registry Run keys, startup folders, scheduled tasks for persistence |
| **Files** | Downloads, Temp, AppData for known malware hashes, double extensions (e.g. `invoice.pdf.exe`) |
| **Browser Extensions** | Chrome, Edge, Firefox for known malicious IDs and excessive permissions |
| **Network** | Hosts file tampering, DNS hijacking, proxy hijacking, suspicious connections |
| **Scareware** | Fake antivirus, fake optimizers, fake cleaners, Windows Defender tampering |

## Features

- **GUI Dashboard** — Dark-themed cockpit with scan controls, threat cards, severity badges
- **Claude AI Cockpit** — Send scan results to Claude for intelligent threat analysis (bring your own API key)
- **NUKE Mode** — One-click aggressive removal: uninstalls programs, kills processes, deletes scheduled tasks, cleans registry
- **Browser Fix** — Reset hijacked homepage, search engine, remove bad extensions across Chrome, Edge, Firefox
- **Auto-Elevation** — Requests admin access via UAC when needed for removals
- **Quarantine** — Safely isolate threats with restore capability for false positives
- **Signature Updates** — Download latest threat databases

## Build From Source

Requires [Rust](https://rustup.rs/) and [Node.js](https://nodejs.org/).

```bash
# Build the frontend
cd ui && npm install && npm run build && cd ..

# Build the app
cargo build --release
```

The binary appears at `target/release/down.exe` (Windows).

### For Windows cross-compilation from Linux:

```bash
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

## Usage

### GUI Mode (default)
Just run `down.exe` — the dashboard window opens.

### CLI Mode
The scanner modules also work from command line:
```
down.exe --scan              # Full scan
down.exe --quick             # Quick scan (processes + startup)
down.exe --nuke              # Scan + remove all threats
down.exe --fix-browser       # Reset hijacked browser settings
down.exe --quarantine        # Scan + quarantine threats
down.exe --list-quarantine   # Show quarantined items
down.exe --restore <ID>      # Restore a false positive
down.exe --update-sigs       # Download latest signatures
```

## Claude AI Integration

1. Get an API key from [console.anthropic.com](https://console.anthropic.com)
2. Open the "Claude AI" tab in the app
3. Paste your API key (stored locally only)
4. Click "Analyze Threats" after a scan

Claude reads the threat summary (never file contents) and gives you plain-English advice about what's dangerous, what's safe, and what to remove.

## License

MIT
