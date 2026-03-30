/// Known malicious or unwanted browser extension IDs (Chrome Web Store / Edge Add-ons).
/// Format: (extension_id, name, reason)
pub static KNOWN_BAD_EXTENSIONS: &[(&str, &str, &str)] = &[
    // Known adware extensions
    ("efaidnbmnnnibpcajpcglclefindmkaj", "Fake PDF Viewer", "Known adware distribution vector"),
    ("kbfnbcaeplbcioakkpcpgfkobkghlhen", "Grammarly Fake", "Impersonates Grammarly to steal data"),
    // Browser hijackers
    ("jpfpebmajhopeonhlcgidhclcccjcpda", "MyWebSearch", "Browser search hijacker"),
    ("bopakagnckmlgajfccecajhnimjiiedh", "Conduit Search", "Browser hijacker / toolbar"),
    ("pkcdkfofjmgmcpelaampcmofpjnkijjl", "Babylon Toolbar", "Search hijacker"),
    ("pgifblbjgdjhcelbanblbhkhmbghikgo", "Delta Toolbar", "Search hijacker"),
    ("aaaangaohdajkgeopjhpbnlpkehbhmbg", "SweetIM", "Adware toolbar"),
    ("blaaborhiifgiaedigdlhkeenoalgmjp", "Iminent Toolbar", "Adware and search hijacker"),
    // Data thieves
    ("lmjnegcaeklhafolokijcfjliaokphfk", "Hola VPN (old)", "Known to sell user bandwidth"),
    ("gcknhkkoolaabfmlnjonogaaifnjlfnp", "FVD Video Downloader", "Tracks browsing without consent"),
    // Fake security extensions
    ("djflhoibgkdhkhhcedjiklpkjnoahfmg", "Fake AV Shield", "Scareware — shows fake virus alerts"),
    ("akdbimojhjcgfbklidcjkmifdnalfnkl", "SafeBrowse", "Injects cryptocurrency miner"),
    // Cryptominers
    ("hnmpcagpplmpfistknnnfhpijjmiecih", "CoinHive Miner", "Browser-based cryptocurrency miner"),
    ("pnhechapfaindjhompbnflcldabbghjo", "Crypto-Loot", "Hidden cryptocurrency miner"),
    // Known PUPs
    ("ogfjmhfnldnajmfaofeiaegolggpcjkc", "SuperFish", "Injects ads and compromises HTTPS"),
    ("flliilndjeohchalpbbcdekjklbdgfkk", "BrowseFox", "Injects ads into web pages"),
];

/// Permissions that are suspicious when combined (any extension requesting ALL of these is suspect)
pub static SUSPICIOUS_PERMISSIONS: &[&str] = &[
    "<all_urls>",
    "webRequest",
    "webRequestBlocking",
    "cookies",
    "tabs",
    "storage",
    "nativeMessaging",
    "clipboardRead",
    "clipboardWrite",
    "management",
    "proxy",
    "debugger",
    "webNavigation",
    "history",
    "bookmarks",
    "topSites",
    "browsingData",
];

/// Number of suspicious permissions that triggers a warning
pub const SUSPICIOUS_PERMISSION_THRESHOLD: usize = 5;
