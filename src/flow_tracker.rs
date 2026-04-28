// Flow tracker module
// Tracks active network flows and their metadata

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::types::{FlowKey, FlowValue};

/// Maximum number of active flows before FIFO eviction
const MAX_ACTIVE_FLOWS: usize = 5000;

/// Flow tracker for managing active network flows
pub struct FlowTracker {
    flows: Arc<RwLock<HashMap<FlowKey, FlowValue>>>,
}

impl FlowTracker {
    /// Create a new flow tracker
    pub fn new() -> Self {
        Self {
            flows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get reference to flows for reading
    pub fn get_flows(&self) -> Arc<RwLock<HashMap<FlowKey, FlowValue>>> {
        self.flows.clone()
    }

    /// Update or create a flow entry
    pub fn update_flow(
        &self,
        key: FlowKey,
        app_id: String,
        app_name: String,
        sni: Option<String>,
        bytes: u64,
        packets: u64,
    ) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut flows_guard = self.flows.write();

        // FIFO eviction if at max capacity and key doesn't exist
        if flows_guard.len() >= MAX_ACTIVE_FLOWS && !flows_guard.contains_key(&key) {
            if let Some(oldest_key) = flows_guard.keys().next().cloned() {
                flows_guard.remove(&oldest_key);
            }
        }

        if let Some(flow) = flows_guard.get_mut(&key) {
            flow.last_active = now;
            flow.bytes_counter += bytes;
            flow.packets += packets;
        } else {
            flows_guard.insert(key, FlowValue {
                app_id,
                app_name,
                sni,
                domain: None,
                start_time: now,
                last_active: now,
                bytes_counter: bytes,
                packets,
            });
        }
    }

    /// Get a specific flow
    pub fn get_flow(&self, key: &FlowKey) -> Option<FlowValue> {
        self.flows.read().get(key).cloned()
    }

    /// Get all flows (snapshot)
    pub fn get_all_flows(&self) -> HashMap<FlowKey, FlowValue> {
        self.flows.read().clone()
    }

    /// Remove a flow
    pub fn remove_flow(&self, key: &FlowKey) -> Option<FlowValue> {
        self.flows.write().remove(key)
    }

    /// Get flows that have timed out
    pub fn get_expired_flows(&self, timeout_secs: u64) -> Vec<(FlowKey, FlowValue)> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        self.flows.read()
            .iter()
            .filter(|(_, v)| now - v.last_active > timeout_secs)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

impl Default for FlowTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Update or create a flow entry (standalone function)
pub fn update_flow(
    flows: &Arc<RwLock<HashMap<FlowKey, FlowValue>>>,
    key: FlowKey,
    app_id: String,
    app_name: String,
    sni: Option<String>,
    bytes: u64,
    packets: u64,
) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut flows_guard = flows.write();

    // FIFO eviction if at max capacity and key doesn't exist
    if flows_guard.len() >= MAX_ACTIVE_FLOWS && !flows_guard.contains_key(&key) {
        if let Some(oldest_key) = flows_guard.keys().next().cloned() {
            flows_guard.remove(&oldest_key);
        }
    }

    if let Some(flow) = flows_guard.get_mut(&key) {
        flow.last_active = now;
        flow.bytes_counter += bytes;
        flow.packets += packets;
    } else {
        flows_guard.insert(key, FlowValue {
            app_id,
            app_name,
            sni,
            domain: None,
            start_time: now,
            last_active: now,
            bytes_counter: bytes,
            packets,
        });
    }
}

/// Remove timed-out flows and return them
pub fn cleanup_timeout_flows(
    flows: &Arc<RwLock<HashMap<FlowKey, FlowValue>>>,
    timeout_secs: u64,
) -> Vec<(FlowKey, FlowValue)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut flows_guard = flows.write();
    let mut removed = Vec::new();

    flows_guard.retain(|key, flow| {
        if now - flow.last_active > timeout_secs {
            removed.push((key.clone(), flow.clone()));
            false
        } else {
            true
        }
    });

    removed
}