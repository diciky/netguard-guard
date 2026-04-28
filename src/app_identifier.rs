// Application identifier module
// Identifies applications based on SNI and DNS patterns

use std::collections::HashMap;
use lazy_static::lazy_static;
use serde::Deserialize;
use regex::Regex;

use crate::types::{FlowKey, FlowValue};

lazy_static! {
    static ref APP_SIGNATURES: HashMap<String, AppSignature> = {
        let json_str = include_str!("../root/etc/netguard/app_signatures.json");
        let signatures: Vec<AppSignature> = serde_json::from_str(json_str).unwrap_or_default();
        signatures.into_iter().map(|s| (s.id.clone(), s)).collect()
    };
}

/// App signature definition
#[derive(Debug, Deserialize, Clone)]
pub struct AppSignature {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub sni_patterns: Vec<String>,
    #[serde(default)]
    pub dns_patterns: Vec<String>,
    #[serde(default)]
    pub app_signature: Option<String>,
}

/// Application identifier
pub struct AppIdentifier {
    sni_regexes: HashMap<String, Vec<Regex>>,
}

impl AppIdentifier {
    /// Create a new app identifier with pre-compiled regex patterns
    pub fn new() -> Self {
        let mut sni_regexes = HashMap::new();
        for (id, sig) in APP_SIGNATURES.iter() {
            let patterns: Vec<Regex> = sig.sni_patterns.iter()
                .filter_map(|p| {
                    let escaped = p.replace("*", ".*").replace(".", "\\.");
                    Regex::new(&format!("^{}$", escaped)).ok()
                })
                .collect();
            if !patterns.is_empty() {
                sni_regexes.insert(id.clone(), patterns);
            }
        }
        Self { sni_regexes }
    }

    /// Identify app by SNI
    pub fn identify_by_sni(&self, sni: &str) -> Option<(String, String)> {
        for (id, regexes) in &self.sni_regexes {
            for regex in regexes {
                if regex.is_match(sni) {
                    if let Some(sig) = APP_SIGNATURES.get(id) {
                        return Some((id.clone(), sig.name.clone()));
                    }
                }
            }
        }
        None
    }

    /// Identify app by domain
    pub fn identify_by_domain(&self, domain: &str) -> Option<(String, String)> {
        for (id, sig) in APP_SIGNATURES.iter() {
            for pattern in &sig.dns_patterns {
                let escaped = pattern.replace("*", ".*").replace(".", "\\.");
                if let Ok(re) = Regex::new(&format!("^{}$", escaped)) {
                    if re.is_match(domain) {
                        return Some((id.clone(), sig.name.clone()));
                    }
                }
            }
        }
        None
    }

    /// Get all registered apps
    pub fn get_all_apps(&self) -> Vec<(String, String)> {
        APP_SIGNATURES.iter()
            .map(|(id, sig)| (id.clone(), sig.name.clone()))
            .collect()
    }
}

impl Default for AppIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Identify application from flow metadata (standalone function)
pub fn identify_app(flow: &FlowKey, sni: Option<&str>) -> (String, String) {
    if let Some(sni) = sni {
        let identifier = AppIdentifier::new();
        if let Some((id, name)) = identifier.identify_by_sni(sni) {
            return (id, name);
        }
    }
    ("unknown".to_string(), "未知".to_string())
}

/// Get app ID from SNI pattern (standalone function)
pub fn get_app_id_from_sni(sni: &str) -> Option<String> {
    let identifier = AppIdentifier::new();
    identifier.identify_by_sni(sni).map(|(id, _)| id)
}