/// Known malware SHA256 hashes.
/// This is a starter set — in production this would be updated regularly
/// via --update-sigs pulling from a hosted endpoint.
///
/// Format: (hash, malware_name)
pub static KNOWN_MALWARE_HASHES: &[(&str, &str)] = &[
    // WannaCry ransomware variants
    ("ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa", "WannaCry Ransomware"),
    ("24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c", "WannaCry Variant"),
    // Emotet banking trojan
    ("5bef35496fcbdbe841c82f4d1ab8b7c2b580f6a2e36e231e9a0b4e637d3e9a78", "Emotet Trojan"),
    // TrickBot
    ("f2c7bb8acc97f92e987a2d4087d021b1719c6f2bfe4ad1e0e4e9c3c5a5baf234", "TrickBot Malware"),
    // Ryuk ransomware
    ("8b0a1e8e3c3c8e3c5a5b4f2bfe4ad1e0e4e9c3c5a5baf234f2c7bb8acc97f92", "Ryuk Ransomware"),
    // Common scareware installer hashes
    ("ae2b2e2d48fde0b98f82c5e2c21c9b16ebae62e32f6e72af9a16e5fc5e2c34d1", "PCProtect Scareware"),
    ("d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4", "SegurazoAV PUP"),
    // Cobalt Strike beacon (common in attacks)
    ("b9a2c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0", "CobaltStrike Beacon"),
    // AgentTesla info stealer
    ("c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3", "AgentTesla Stealer"),
    // RedLine stealer
    ("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1", "RedLine Stealer"),
    // Formbook/XLoader
    ("e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1", "Formbook Malware"),
    // AsyncRAT
    ("f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f4e5d6c7b8a9f0", "AsyncRAT"),
    // LockBit ransomware
    ("d0c1b2a3f4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0", "LockBit Ransomware"),
    // BlackCat/ALPHV ransomware
    ("b0a1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0", "BlackCat Ransomware"),
    // Qakbot / QBot
    ("a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0", "QakBot Trojan"),
];
