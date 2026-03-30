/// Known malicious IP ranges and domains.
/// These are well-documented C2 (command & control) servers,
/// cryptominer pools, and phishing infrastructure.
///
/// Format: (pattern, description)
/// Patterns can be IP prefixes or domain substrings.

pub static KNOWN_BAD_IP_PREFIXES: &[(&str, &str)] = &[
    // Known C2 infrastructure ranges (documented by threat intel)
    ("185.220.101.", "Tor exit node / known C2 range"),
    ("91.243.44.", "Known malware C2 infrastructure"),
    ("45.33.32.", "Commonly abused hosting — verify manually"),
    ("198.51.100.", "Documentation range — should not appear in real traffic"),
    ("203.0.113.", "Documentation range — should not appear in real traffic"),
    // Cryptominer pools
    ("pool.minexmr.", "XMR mining pool"),
    ("pool.supportxmr.", "XMR mining pool"),
    ("xmr.pool.minergate.", "MinerGate XMR pool"),
    ("randomxmonero.", "RandomX Monero mining"),
];

/// Known malicious or suspicious domain patterns
pub static KNOWN_BAD_DOMAINS: &[(&str, &str)] = &[
    // Cryptominer domains
    ("coinhive.com", "CoinHive cryptocurrency miner"),
    ("coin-hive.com", "CoinHive variant"),
    ("crypto-loot.com", "Crypto-Loot miner"),
    ("minero.cc", "Minero JS miner"),
    ("authedmine.com", "AuthedMine miner"),
    ("ppoi.org", "Browser miner"),
    ("coinerra.com", "Coinerra miner"),
    // Known phishing/scam domains patterns
    ("securit-alert", "Fake security alert phishing"),
    ("account-verify", "Account verification phishing"),
    ("login-secure-", "Fake secure login phishing"),
    ("windowsupdate-error", "Fake Windows update scam"),
    ("virus-found-", "Scareware popup domain"),
    ("your-pc-is-infected", "Scareware popup domain"),
    ("computer-has-virus", "Scareware popup domain"),
    ("call-microsoft-support", "Tech support scam"),
    ("windows-firewall-alert", "Fake firewall alert"),
    // Adware/tracking
    ("tracking.directrev.com", "Adware tracking"),
    ("go.padsdel.com", "Adware redirect"),
    ("istatic.eshopcomp.com", "Adware injection"),
    // Known RAT C2 patterns
    (".duckdns.org", "DuckDNS — commonly used by RATs for dynamic DNS"),
    (".no-ip.org", "No-IP — commonly used by RATs for dynamic DNS"),
    (".zapto.org", "Zapto — commonly used by RATs for dynamic DNS"),
    (".hopto.org", "Hopto — commonly used by RATs for dynamic DNS"),
    (".servegame.com", "Dynamic DNS — commonly abused by malware"),
];

/// Default legitimate hosts file entries — anything else is suspicious
pub static LEGITIMATE_HOSTS_ENTRIES: &[&str] = &[
    "localhost",
    "127.0.0.1",
    "::1",
    "broadcasthost",
    "ip6-localhost",
    "ip6-loopback",
    "ip6-localnet",
    "ip6-mcastprefix",
    "ip6-allnodes",
    "ip6-allrouters",
];

/// Known malicious DNS server IPs
pub static KNOWN_BAD_DNS: &[(&str, &str)] = &[
    ("38.134.121.95", "Known malware DNS redirector"),
    ("85.255.112.36", "Known DNS hijacker (Zlob)"),
    ("85.255.113.66", "Known DNS hijacker (Zlob)"),
    ("67.210.0.0", "Known DNS changer malware range"),
    ("93.188.166.0", "Known DNS changer malware range"),
];
