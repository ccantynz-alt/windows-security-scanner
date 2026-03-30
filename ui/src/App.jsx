import { useState, useEffect } from 'react'
import { invoke } from '@tauri-apps/api/core'

const SEVERITY_COLORS = {
  Critical: '#ff4444',
  High: '#ff8800',
  Medium: '#ffcc00',
  Low: '#888888',
}

const SEVERITY_BG = {
  Critical: 'rgba(255,68,68,0.1)',
  High: 'rgba(255,136,0,0.1)',
  Medium: 'rgba(255,204,0,0.1)',
  Low: 'rgba(136,136,136,0.1)',
}

export default function App() {
  const [view, setView] = useState('home')
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [nuking, setNuking] = useState(false)
  const [nukeResult, setNukeResult] = useState(null)
  const [isAdmin, setIsAdmin] = useState(false)
  const [apiKey, setApiKey] = useState(localStorage.getItem('claude_api_key') || '')
  const [claudeAnalysis, setClaudeAnalysis] = useState('')
  const [analyzing, setAnalyzing] = useState(false)
  const [fixingBrowser, setFixingBrowser] = useState(false)
  const [browserFixed, setBrowserFixed] = useState(null)

  useEffect(() => {
    invoke('check_admin').then(setIsAdmin).catch(() => {})
  }, [])

  const runFullScan = async () => {
    setScanning(true)
    setScanResult(null)
    setClaudeAnalysis('')
    setNukeResult(null)
    try {
      const result = await invoke('full_scan')
      setScanResult(result)
      setView('results')
    } catch (e) {
      console.error(e)
    }
    setScanning(false)
  }

  const runQuickScan = async () => {
    setScanning(true)
    setScanResult(null)
    setClaudeAnalysis('')
    setNukeResult(null)
    try {
      const result = await invoke('quick_scan')
      setScanResult(result)
      setView('results')
    } catch (e) {
      console.error(e)
    }
    setScanning(false)
  }

  const runNuke = async () => {
    if (!scanResult?.threats?.length) return
    setNuking(true)
    try {
      const result = await invoke('nuke_threats', { threats: scanResult.threats })
      setNukeResult(result)
    } catch (e) {
      setNukeResult({ success: false, removed: 0, error: String(e) })
    }
    setNuking(false)
  }

  const runFixBrowser = async () => {
    setFixingBrowser(true)
    try {
      const count = await invoke('fix_browsers')
      setBrowserFixed(count)
    } catch (e) {
      console.error(e)
    }
    setFixingBrowser(false)
  }

  const askClaude = async () => {
    if (!apiKey || !scanResult) return
    localStorage.setItem('claude_api_key', apiKey)
    setAnalyzing(true)
    setClaudeAnalysis('')
    try {
      const summary = scanResult.threats.map((t, i) =>
        `${i+1}. [${t.severity}] ${t.name} — ${t.category}\n   Location: ${t.location}\n   Detail: ${t.description}`
      ).join('\n\n')
      const analysis = await invoke('ask_claude', {
        apiKey,
        threatsSummary: summary || 'No threats found. System appears clean.'
      })
      setClaudeAnalysis(analysis)
    } catch (e) {
      setClaudeAnalysis(`Error: ${e}`)
    }
    setAnalyzing(false)
  }

  return (
    <div className="app">
      <header>
        <div className="logo">
          <span className="logo-icon">&#x1F6E1;</span>
          <div>
            <h1>DOWN</h1>
            <p className="subtitle">AI Security Scanner v0.3</p>
          </div>
        </div>
        <nav>
          <button className={view === 'home' ? 'active' : ''} onClick={() => setView('home')}>Scan</button>
          <button className={view === 'results' ? 'active' : ''} onClick={() => setView('results')} disabled={!scanResult}>Results</button>
          <button className={view === 'claude' ? 'active' : ''} onClick={() => setView('claude')}>Claude AI</button>
          <button className={view === 'settings' ? 'active' : ''} onClick={() => setView('settings')}>Settings</button>
        </nav>
        <div className="admin-badge">
          {isAdmin ? <span className="badge green">ADMIN</span> : <span className="badge yellow">LIMITED</span>}
        </div>
      </header>

      <main>
        {scanning && (
          <div className="scanning-overlay">
            <div className="scanner-animation">
              <div className="pulse"></div>
              <p>Scanning your system...</p>
              <p className="subtext">Checking processes, startup, files, browser, network, scareware</p>
            </div>
          </div>
        )}

        {view === 'home' && (
          <div className="home">
            <div className="hero">
              <h2>Protect Your PC</h2>
              <p>Scan for malware, scareware, and unwanted programs. Powered by AI.</p>
            </div>
            <div className="scan-buttons">
              <button className="btn-primary btn-large" onClick={runFullScan} disabled={scanning}>
                <span className="btn-icon">&#x1F50D;</span>
                Full Scan
                <span className="btn-desc">All 6 modules — processes, startup, files, browser, network, scareware</span>
              </button>
              <button className="btn-secondary btn-large" onClick={runQuickScan} disabled={scanning}>
                <span className="btn-icon">&#x26A1;</span>
                Quick Scan
                <span className="btn-desc">Processes + startup entries only — takes seconds</span>
              </button>
              <button className="btn-warning btn-large" onClick={runFixBrowser} disabled={fixingBrowser}>
                <span className="btn-icon">&#x1F310;</span>
                {fixingBrowser ? 'Fixing...' : 'Fix Browsers'}
                <span className="btn-desc">Reset hijacked homepage, search engine, extensions</span>
              </button>
            </div>
            {browserFixed !== null && (
              <div className="info-box">Fixed {browserFixed} browser profile(s).</div>
            )}
          </div>
        )}

        {view === 'results' && scanResult && (
          <div className="results">
            <div className="summary-bar">
              <div className="summary-item" style={{borderColor: SEVERITY_COLORS.Critical}}>
                <span className="count">{scanResult.summary.critical}</span>
                <span className="label">Critical</span>
              </div>
              <div className="summary-item" style={{borderColor: SEVERITY_COLORS.High}}>
                <span className="count">{scanResult.summary.high}</span>
                <span className="label">High</span>
              </div>
              <div className="summary-item" style={{borderColor: SEVERITY_COLORS.Medium}}>
                <span className="count">{scanResult.summary.medium}</span>
                <span className="label">Medium</span>
              </div>
              <div className="summary-item" style={{borderColor: SEVERITY_COLORS.Low}}>
                <span className="count">{scanResult.summary.low}</span>
                <span className="label">Low</span>
              </div>
              <div className="summary-item total">
                <span className="count">{scanResult.summary.total}</span>
                <span className="label">Total</span>
              </div>
              <div className="summary-time">Scanned in {scanResult.duration_secs.toFixed(1)}s</div>
            </div>

            {scanResult.summary.total === 0 ? (
              <div className="clean-system">
                <span className="clean-icon">&#x2705;</span>
                <h3>System Clean</h3>
                <p>No threats detected. Your PC looks good.</p>
              </div>
            ) : (
              <>
                <div className="action-bar">
                  <button className="btn-danger" onClick={runNuke} disabled={nuking}>
                    {nuking ? 'Removing threats...' : `NUKE ${scanResult.summary.total} Threats`}
                  </button>
                  <button className="btn-ai" onClick={() => setView('claude')}>
                    Ask Claude AI for Analysis
                  </button>
                </div>
                {nukeResult && (
                  <div className={`nuke-result ${nukeResult.success ? 'success' : 'error'}`}>
                    {nukeResult.success
                      ? `Successfully removed ${nukeResult.removed} threats. Run another scan to verify.`
                      : `Error: ${nukeResult.error}`}
                  </div>
                )}
                <div className="threat-list">
                  {scanResult.threats.map((threat, i) => (
                    <div key={i} className="threat-card" style={{background: SEVERITY_BG[threat.severity], borderLeftColor: SEVERITY_COLORS[threat.severity]}}>
                      <div className="threat-header">
                        <span className="severity-badge" style={{background: SEVERITY_COLORS[threat.severity]}}>
                          {threat.severity}
                        </span>
                        <span className="threat-name">{threat.name}</span>
                        <span className="threat-category">{threat.category}</span>
                      </div>
                      <div className="threat-location">{threat.location}</div>
                      <div className="threat-desc">{threat.description}</div>
                      <div className="threat-action">Action: {formatAction(threat.action)}</div>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {view === 'claude' && (
          <div className="claude-view">
            <div className="claude-header">
              <span className="claude-icon">&#x1F916;</span>
              <div>
                <h2>Claude AI Cockpit</h2>
                <p>Get intelligent threat analysis from Claude</p>
              </div>
            </div>
            <div className="api-key-input">
              <label>Anthropic API Key:</label>
              <input
                type="password"
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="sk-ant-..."
              />
              <button className="btn-ai" onClick={askClaude} disabled={analyzing || !apiKey || !scanResult}>
                {analyzing ? 'Analyzing...' : 'Analyze Threats'}
              </button>
            </div>
            {!scanResult && (
              <div className="info-box">Run a scan first, then Claude can analyze the results.</div>
            )}
            {claudeAnalysis && (
              <div className="claude-response">
                <h3>Claude's Analysis:</h3>
                <div className="analysis-text">{claudeAnalysis}</div>
              </div>
            )}
          </div>
        )}

        {view === 'settings' && (
          <div className="settings-view">
            <h2>Settings</h2>
            <div className="setting-group">
              <h3>Admin Status</h3>
              <p>{isAdmin ? 'Running as Administrator — full removal capabilities.' : 'Running without admin. Some removals may fail. Restart as Administrator for full access.'}</p>
            </div>
            <div className="setting-group">
              <h3>Claude API Key</h3>
              <input
                type="password"
                value={apiKey}
                onChange={e => { setApiKey(e.target.value); localStorage.setItem('claude_api_key', e.target.value); }}
                placeholder="sk-ant-..."
              />
              <p className="hint">Your key is stored locally only. Never sent anywhere except Anthropic's API.</p>
            </div>
            <div className="setting-group">
              <h3>About</h3>
              <p>DOWN Security Scanner v0.3.0</p>
              <p>Built in Rust + React. Powered by Claude AI.</p>
              <p>No telemetry. No subscriptions. Your data stays on your PC.</p>
            </div>
          </div>
        )}
      </main>
    </div>
  )
}

function formatAction(action) {
  if (typeof action === 'string') return action
  if (action.KillProcess) return `Kill process (PID: ${action.KillProcess})`
  if (action.QuarantineFile) return `Quarantine: ${action.QuarantineFile}`
  if (action.UninstallProgram) return `Uninstall: ${action.UninstallProgram.name}`
  if (action.DeleteScheduledTask) return `Delete task: ${action.DeleteScheduledTask.task_name}`
  if (action.RemoveStartupEntry) return `Remove startup: ${action.RemoveStartupEntry.value_name}`
  if (action.DisableBrowserExtension) return `Remove extension: ${action.DisableBrowserExtension.ext_id}`
  if (action === 'ResetProxy') return 'Reset proxy settings'
  if (action === 'RestoreDefender') return 'Re-enable Windows Defender'
  if (action === 'ManualReview') return 'Manual review recommended'
  return JSON.stringify(action)
}
