/// Known legitimate Windows scheduled task name patterns.
/// Tasks matching these should NOT be flagged as threats.
pub static SAFE_TASK_PATTERNS: &[&str] = &[
    // Microsoft / Windows core
    "\\microsoft\\windows\\",
    "\\microsoft\\office\\",
    "\\microsoft\\edgeupdate\\",
    "\\microsoft\\.net\\",
    "\\microsoft\\xboxlive\\",
    "\\microsoft\\onedrive\\",
    "windows defender",
    "windows update",
    "windowsupdate",
    "microsoftedge",
    "microsoft compatibility",
    "microsoft\\windows\\windowsupdate",
    "microsoft\\windows\\rempl\\",
    "microsoft\\windows\\wdi\\",
    "microsoft\\windows\\defrag",
    "microsoft\\windows\\diagnosis",
    "microsoft\\windows\\diskcleanup",
    "microsoft\\windows\\maintenance",
    "microsoft\\windows\\servicing",
    "microsoft\\windows\\shell",
    "microsoft\\windows\\task scheduler",
    "microsoft\\windows\\wininet",
    "microsoft\\windows\\customer experience",
    // Google
    "googleupdate",
    "google\\chrome",
    // Mozilla
    "mozilla\\firefox",
    // NVIDIA
    "nvtm",
    "nvidia",
    // Intel
    "intel\\",
    // AMD
    "amd\\",
    "startcn",
    // Adobe
    "adobe\\",
    "adobe acrobat",
    // Common safe programs
    "dropbox",
    "steam",
    "discord",
    "slack",
    "zoom",
    "spotify",
    "onedrive",
    "teams",
];
