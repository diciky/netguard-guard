// SNI (Server Name Indication) parser module
// Extracts SNI from TLS ClientHello packets

use std::collections::HashMap;

/// TLS Record Type for Handshake
const TLS_RECORD_TYPE_HANDSHAKE: u8 = 0x16;
/// TLS ClientHello Handshake Type
const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 0x01;
/// Extension Type for SNI
const EXTENSION_TYPE_SNI: u16 = 0x0000;

/// SNI parser with packet counting per flow
pub struct SniParser {
    /// Track packet count per flow to limit parsing to first 10 packets
    packet_counts: HashMap<String, u8>,
}

impl SniParser {
    /// Create a new SNI parser
    pub fn new() -> Self {
        Self {
            packet_counts: HashMap::new(),
        }
    }

    /// Check if we should parse this flow (only first 10 packets)
    pub fn should_parse(&mut self, flow_id: &str) -> bool {
        let count = self.packet_counts.entry(flow_id.to_string()).or_insert(0);
        if *count < 10 {
            *count += 1;
            true
        } else {
            false
        }
    }

    /// Reset parser state
    pub fn reset(&mut self) {
        self.packet_counts.clear();
    }

    /// Extract SNI from TLS ClientHello packet
    pub fn extract_sni(&self, packet: &[u8]) -> Option<String> {
        // Skip Ethernet header (14 bytes)
        if packet.len() < 34 {
            return None;
        }

        let ip_header_len = 20;
        let tcp_start = 14 + ip_header_len;

        if packet.len() < tcp_start + 20 {
            return None;
        }

        // TCP header parsing
        let tcp_header = &packet[tcp_start..];
        let data_offset = ((tcp_header[13] >> 4) * 4) as usize;
        if data_offset < 20 {
            return None;
        }

        let payload = &tcp_header[data_offset..];
        if payload.len() < 11 {
            return None;
        }

        // Check TLS Record Layer
        let content_type = payload[0];
        if content_type != TLS_RECORD_TYPE_HANDSHAKE {
            return None;
        }

        // TLS version (bytes 1-2)
        let tls_version = u16::from_be_bytes([payload[1], payload[2]]);
        if tls_version < 0x0301 {
            // TLS 1.0 or higher required
            return None;
        }

        // Record length (bytes 3-4)
        let record_len = u16::from_be_bytes([payload[3], payload[4]]) as usize;

        // Handshake starts at byte 5
        if payload.len() < 6 {
            return None;
        }

        let handshake_type = payload[5];
        if handshake_type != HANDSHAKE_TYPE_CLIENT_HELLO {
            return None;
        }

        // Handshake message length (bytes 6-9, 3 bytes)
        let handshake_len = ((payload[6] as usize) << 16) | ((payload[7] as usize) << 8) | (payload[8] as usize);

        // ClientHello starts at byte 10
        let hello_start = 10;

        // Session ID length (1 byte)
        let session_id_len = if hello_start < payload.len() { payload[hello_start] as usize } else { 0 };
        let session_id_end = hello_start + 1 + session_id_len;

        // Cipher suites length (2 bytes)
        if session_id_end + 2 > payload.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([payload[session_id_end], payload[session_id_end + 1]]) as usize;
        let cipher_suites_end = session_id_end + 2 + cipher_suites_len;

        // Compression methods length (1 byte)
        if cipher_suites_end + 1 > payload.len() {
            return None;
        }
        let compression_len = payload[cipher_suites_end] as usize;
        let compression_end = cipher_suites_end + 1 + compression_len;

        // Extensions start
        if compression_end + 2 > payload.len() {
            return None;
        }
        let extensions_len = u16::from_be_bytes([payload[compression_end], payload[compression_end + 1]]) as usize;
        let extensions_start = compression_end + 2;

        if extensions_len == 0 {
            return None;
        }

        // Parse extensions
        let mut offset = extensions_start;
        let extensions_end = (extensions_start + extensions_len).min(payload.len());

        while offset + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
            let ext_len = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) as usize;

            if ext_type == EXTENSION_TYPE_SNI {
                // Found SNI extension
                let sni_list_start = offset + 4;
                if sni_list_start + 2 > extensions_end {
                    return None;
                }

                // Server name list length (2 bytes)
                let _sni_list_len = u16::from_be_bytes([payload[sni_list_start], payload[sni_list_start + 1]]);
                let sni_start = sni_list_start + 2;

                if sni_start + 2 > extensions_end {
                    return None;
                }

                // Server name length (2 bytes)
                let sni_len = u16::from_be_bytes([payload[sni_start], payload[sni_start + 1]]) as usize;
                let sni_data_start = sni_start + 2;

                if sni_data_start + sni_len > extensions_end {
                    return None;
                }

                let sni = String::from_utf8_lossy(&payload[sni_data_start..sni_data_start + sni_len]).to_string();
                return Some(sni);
            }

            offset += 4 + ext_len;
        }

        None
    }

    /// Check if packet looks like TLS ClientHello (quick check)
    pub fn is_tls_client_hello(&self, packet: &[u8]) -> bool {
        // Quick check: destination port 443 and TLS record type
        if packet.len() < 50 {
            return false;
        }

        // Check TCP destination port 443 (bytes 36-37 after Ethernet + IP)
        // Ethernet (14) + IP (20) + TCP (20) = 54
        if packet.len() >= 56 {
            let tcp_header = &packet[34..];
            let dst_port = u16::from_be_bytes([tcp_header[2], tcp_header[3]]);
            if dst_port != 443 {
                return false;
            }
        }

        // Check TLS record type at TCP data offset
        let ip_header_len = ((packet[14] & 0x0F) * 4) as usize;
        let tcp_data_offset = (14 + ip_header_len + 13) as usize;  // 13 = offset to data offset byte
        if packet.len() <= tcp_data_offset {
            return false;
        }

        let tls_record_type = packet[tcp_data_offset];
        tls_record_type == TLS_RECORD_TYPE_HANDSHAKE
    }
}

impl Default for SniParser {
    fn default() -> Self {
        Self::new()
    }
}