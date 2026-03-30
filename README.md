# DOWN — Windows Security Scanner

A lightweight, fast Windows security scanner built in Rust. Detects and removes malware, scareware, and potentially unwanted programs (PUPs).

**Under 1MB.** No bloat. No telemetry. No subscriptions.

## What It Scans

| Module | What It Checks |
|--------|---------------|
| **Processes** | Running processes against known malware names, suspicious paths, cryptominer CPU usage |
| **Startup** | Registry Run keys, startup folders, scheduled tasks for persistence |
| **Files** | Downloads, Temp, AppData for known malware hashes, double extensions (e.g. `invoice.pdf.exe`) |
| **Browser Extensions** | Chrome, Edge, Firefox extensions for known malicious IDs and excessive permissions |
| **Network** | Hosts file tampering, suspicious DNS servers, connections to known bad IPs |
| **Scareware** | Fake antivirus, fake optimizers, fake cleaners — programs that scare you into paying |

## Usage

```
down.exe --scan              # Full scan (all modules)
down.exe --quick             # Quick scan (processes + startup only)
down.exe --quarantine        # Scan and remove all threats found
down.exe --list-quarantine   # Show quarantined items
down.exe --restore <ID>      # Restore a false positive
```

## Build From Source

Requires [Rust](https://rustup.rs/).

```bash
cargo build --release
```

Binary appears at `target/release/down.exe` (Windows) or `target/release/down` (Linux/Mac for testing).

### Cross-compile for Windows from Linux:

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64
cargo build --release --target x86_64-pc-windows-gnu
```

## How Quarantine Works

Detected threats are moved to a quarantine folder (`%LOCALAPPDATA%\DownScanner\quarantine\` on Windows). A manifest tracks where each file came from so you can restore false positives with `--restore <ID>`.

## Scan Logs

Every scan writes a log to `%LOCALAPPDATA%\DownScanner\logs\` (Windows) or `~/.down-scanner/logs/` (Linux/Mac).

## License

MIT
