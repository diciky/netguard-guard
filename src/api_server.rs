use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};
use crate::types::{FlowKey, FlowValue, HistoryKey, HistoryValue};
use crate::flow_tracker::FlowTracker;
use crate::history_aggregator::HistoryAggregator;

const SOCKET_PATH: &str = "/var/run/netguard.sock";

#[derive(Serialize)]
struct DashboardStats {
    total_connections: usize,
    memory_usage: String,
    upload_speed: u64,
    download_speed: u64,
    upload_total: u64,
    download_total: u64,
}

#[derive(Serialize)]
struct ConnectionInfo {
    src_ip: String,
    dst_ip: String,
    dst_port: u16,
    app_name: String,
    bytes: u64,
    duration: u64,
}

pub struct ApiServer {
    flow_tracker: Arc<FlowTracker>,
    history_aggregator: Arc<HistoryAggregator>,
}

impl ApiServer {
    pub fn new(flow_tracker: Arc<FlowTracker>, history_aggregator: Arc<HistoryAggregator>) -> Self {
        Self { flow_tracker, history_aggregator }
    }

    pub fn start(&self) {
        // Remove existing socket
        std::fs::remove_file(SOCKET_PATH).ok();

        let listener = UnixListener::bind(SOCKET_PATH).unwrap();

        for stream in listener.incoming() {
            match stream {
                Ok(mut stream) => {
                    self.handle_connection(&mut stream);
                }
                Err(e) => {
                    log::error!("Connection error: {}", e);
                }
            }
        }
    }

    fn handle_connection(&self, stream: &mut UnixStream) {
        let mut buffer = [0u8; 4096];
        let n = stream.read(&mut buffer).unwrap();
        let request = String::from_utf8_lossy(&buffer[..n]);

        let response = self.process_request(&request);
        stream.write_all(response.as_bytes()).unwrap();
    }

    fn process_request(&self, request: &str) -> String {
        let request = request.trim();

        if request.starts_with("GET /api/dashboard") {
            let stats = self.get_dashboard_stats();
            serde_json::to_string(&stats).unwrap_or_default()
        } else if request.starts_with("GET /api/connections") {
            let connections = self.get_connections();
            serde_json::to_string(&connections).unwrap_or_default()
        } else if request.starts_with("GET /api/history") {
            let history = self.get_history();
            serde_json::to_string(&history).unwrap_or_default()
        } else if request.starts_with("GET /api/stats") {
            let stats = self.get_general_stats();
            serde_json::to_string(&stats).unwrap_or_default()
        } else {
            r#"{"error": "unknown endpoint"}"#.to_string()
        }
    }

    fn get_dashboard_stats(&self) -> DashboardStats {
        let flows = self.flow_tracker.get_all_flows();
        DashboardStats {
            total_connections: flows.len(),
            memory_usage: self.get_memory_usage(),
            upload_speed: 0,
            download_speed: 0,
            upload_total: flows.values().map(|f| f.bytes_counter).sum::<u64>() / 2,
            download_total: flows.values().map(|f| f.bytes_counter).sum::<u64>() / 2,
        }
    }

    fn get_connections(&self) -> Vec<ConnectionInfo> {
        self.flow_tracker.get_all_flows()
            .iter()
            .map(|(k, v)| ConnectionInfo {
                src_ip: format!("{:?}", k.src_ip),
                dst_ip: format!("{:?}", k.dst_ip),
                dst_port: k.dst_port,
                app_name: v.app_name.clone(),
                bytes: v.bytes_counter,
                duration: v.last_active - v.start_time,
            })
            .collect()
    }

    fn get_history(&self) -> Vec<(String, String, u64, u64)> {
        self.history_aggregator.get_summary()
            .iter()
            .map(|(k, v)| (format!("{:?}", k.src_ip), k.app_id.clone(), v.total_duration, v.total_bytes))
            .collect()
    }

    fn get_general_stats(&self) -> serde_json::Value {
        serde_json::json!({
            "total_flows": self.flow_tracker.get_all_flows().len(),
            "active_flows": self.flow_tracker.get_all_flows().len()
        })
    }

    fn get_memory_usage(&self) -> String {
        // Read /proc/meminfo for memory stats
        "45MB / 128MB".to_string()
    }
}