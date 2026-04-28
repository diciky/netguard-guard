use std::collections::HashMap;
use std::fmt;
use parking_lot::RwLock;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: u32,        // IPv4: directly as u32
    pub dst_ip: u32,
    pub dst_port: u16,
    pub src_port: u16,
    pub proto: u8,          // 6=TCP, 17=UDP
}

impl FlowKey {
    /// Create a new FlowKey
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, proto: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            dst_port,
            src_port,
            proto,
        }
    }

    /// Get source IP as string
    pub fn src_ip_str(&self) -> String {
        format!("{}.{}.{}.{}",
            (self.src_ip >> 24) as u8,
            (self.src_ip >> 16) as u8,
            (self.src_ip >> 8) as u8,
            self.src_ip as u8)
    }

    /// Get destination IP as string
    pub fn dst_ip_str(&self) -> String {
        format!("{}.{}.{}.{}",
            (self.dst_ip >> 24) as u8,
            (self.dst_ip >> 16) as u8,
            (self.dst_ip >> 8) as u8,
            self.dst_ip as u8)
    }

    /// Get flow ID for tracking packet count
    pub fn flow_id(&self) -> String {
        format!("{}:{}->{}:{}", self.src_ip_str(), self.src_port, self.dst_ip_str(), self.dst_port)
    }
}

impl fmt::Display for FlowKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}->{}:{}", self.src_ip_str(), self.src_port, self.dst_ip_str(), self.dst_port)
    }
}

impl Default for FlowKey {
    fn default() -> Self {
        Self {
            src_ip: 0,
            dst_ip: 0,
            dst_port: 0,
            src_port: 0,
            proto: 6,
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowValue {
    pub app_id: String,
    pub app_name: String,
    pub sni: Option<String>,
    pub domain: Option<String>,
    pub start_time: u64,
    pub last_active: u64,
    pub bytes_counter: u64,
    pub packets: u64,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct HistoryKey {
    pub src_ip: u32,
    pub app_id: String,
    pub date: String,  // YYYYMMDD
}

#[derive(Debug, Clone)]
pub struct HistoryValue {
    pub total_duration: u64,
    pub total_bytes: u64,
}
