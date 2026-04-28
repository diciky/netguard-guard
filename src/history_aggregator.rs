// History aggregator module
// Aggregates flow data into historical records

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use chrono::Local;

use crate::types::{FlowKey, FlowValue, HistoryKey, HistoryValue};

/// Aggregate flow into history
pub fn aggregate_flow(
    history: &Arc<RwLock<HashMap<HistoryKey, HistoryValue>>>,
    flow_key: &FlowKey,
    flow_value: &FlowValue,
) {
    let today = Local::now().format("%Y%m%d").to_string();
    let history_key = HistoryKey {
        src_ip: flow_key.src_ip,
        app_id: flow_value.app_id.clone(),
        date: today,
    };

    let duration = flow_value.last_active - flow_value.start_time;

    let mut history_guard = history.write();
    if let Some(h) = history_guard.get_mut(&history_key) {
        h.total_duration += duration;
        h.total_bytes += flow_value.bytes_counter;
    } else {
        history_guard.insert(history_key, HistoryValue {
            total_duration: duration,
            total_bytes: flow_value.bytes_counter,
        });
    }
}

/// Get daily summary for an IP
pub fn get_daily_summary(
    history: &Arc<RwLock<HashMap<HistoryKey, HistoryValue>>>,
    src_ip: u32,
    date: &str,
) -> Vec<HistoryValue> {
    let history_guard = history.read();
    history_guard
        .iter()
        .filter(|(k, _)| k.src_ip == src_ip && k.date == date)
        .map(|(_, v)| v.clone())
        .collect()
}

/// HistoryAggregator struct for managing historical data
pub struct HistoryAggregator {
    history: Arc<RwLock<HashMap<HistoryKey, HistoryValue>>>,
}

impl HistoryAggregator {
    /// Create a new history aggregator
    pub fn new() -> Self {
        Self {
            history: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get reference to history
    pub fn get_history(&self) -> Arc<RwLock<HashMap<HistoryKey, HistoryValue>>> {
        self.history.clone()
    }

    /// Get all history entries
    pub fn get_summary(&self) -> HashMap<HistoryKey, HistoryValue> {
        self.history.read().clone()
    }

    /// Get history by date
    pub fn get_by_date(&self, date: &str) -> HashMap<(u32, String), HistoryValue> {
        self.history.read()
            .iter()
            .filter(|(k, _)| k.date == date)
            .map(|(k, v)| ((k.src_ip, k.app_id.clone()), v.clone()))
            .collect()
    }

    /// Aggregate a flow into history
    pub fn aggregate(&self, flow_key: &FlowKey, flow_value: &FlowValue) {
        aggregate_flow(&self.history, flow_key, flow_value);
    }
}

impl Default for HistoryAggregator {
    fn default() -> Self {
        Self::new()
    }
}
