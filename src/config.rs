use std::collections::HashMap;
use std::process::Command;

pub struct Config {
    pub enabled: bool,
    pub refresh_interval: u64,
    pub max_connections: usize,
    pub dns_cache_ttl: u64,
    pub db_path: String,
    pub nflog_group: u16,
}

impl Config {
    pub fn load() -> Self {
        // Read from UCI config /etc/config/netguard
        let enabled_output = Command::new("uci")
            .args(["get", "netguard.config.enabled"])
            .output();
        let enabled = enabled_output.map(|o| String::from_utf8_lossy(&o.stdout).trim() == "1").unwrap_or(true);

        let db_path_output = Command::new("uci")
            .args(["get", "netguard.database.db_path"])
            .output();
        let db_path = db_path_output.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_else(|_| "/tmp/netguard.db".to_string());

        let nflog_output = Command::new("uci")
            .args(["get", "netguard.config.nflog_group"])
            .output();
        let nflog_group: u16 = nflog_output.map(|o| String::from_utf8_lossy(&o.stdout).trim().parse().unwrap_or(100)).unwrap_or(100);

        Self {
            enabled,
            refresh_interval: 3,
            max_connections: 5000,
            dns_cache_ttl: 300,
            db_path,
            nflog_group,
        }
    }

    pub fn get_all() -> HashMap<String, String> {
        let mut config = HashMap::new();
        // Query UCI for all netguard config options
        config
    }
}