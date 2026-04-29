// NFLog listener module
// Handles packet capture via NFLog netlink socket
// Note: On macOS, this is a stub; on Linux, it uses netlink

use std::io;
#[cfg(target_os = "linux")]
use libc::{c_int, sockaddr_nl, sa_family_t, socklen_t, AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER};

use crate::types::FlowKey;

/// NFLog group to listen on
const DEFAULT_NFLOG_GROUP: u16 = 100;

/// NFLog listener for capturing packets via netlink
pub struct NflogListener {
    #[cfg(target_os = "linux")]
    fd: c_int,
    #[cfg(target_os = "linux")]
    group: u16,
    #[cfg(not(target_os = "linux"))]
    _dummy: i32,
}

#[cfg(target_os = "linux")]
impl NflogListener {
    /// Create a new NFLog listener bound to the specified group
    pub fn new(group: u16) -> io::Result<Self> {
        // Create netlink socket
        let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Set socket options
        let reuse = 1i32;
        unsafe {
            libc::setsockopt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR, &reuse as *const i32 as *const libc::c_void, std::mem::size_of::<i32>() as socklen_t);
        }

        // Bind to NFLog group
        unsafe {
            let mut addr: sockaddr_nl = std::mem::zeroed();
            addr.nl_family = AF_NETLINK as sa_family_t;
            addr.nl_pid = 0;
            addr.nl_groups = 1u32 << (group - 1);
            let addr_len = std::mem::size_of::<sockaddr_nl>() as socklen_t;
            if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, addr_len) < 0 {
                libc::close(fd);
                return Err(io::Error::last_os_error());
            }
        }

        Ok(Self { fd, group })
    }

    /// Receive a packet from NFLog
    pub fn recv(&self, buffer: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let len = libc::recv(self.fd, buffer.as_mut_ptr() as *mut libc::c_void, buffer.len(), 0);
            if len < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(len as usize)
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl NflogListener {
    /// Create a new NFLog listener (stub on macOS)
    pub fn new(_group: u16) -> io::Result<Self> {
        // On macOS, we can't use NFLog; return an error
        Err(io::Error::new(io::ErrorKind::Other, "NFLog not supported on macOS"))
    }

    /// Receive a packet (stub on macOS)
    pub fn recv(&self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::Other, "NFLog not supported on macOS"))
    }
}

impl Drop for NflogListener {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        unsafe { libc::close(self.fd) };
    }
}

/// Parse IP header and extract flow information
pub fn parse_ip_header(packet: &[u8]) -> Option<(u32, u32, u8, u16, u16)> {
    if packet.len() < 20 {
        return None;
    }

    // Version (4 bits) + IHL (4 bits)
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }

    let ihl = (packet[0] & 0x0F) as usize;
    if ihl < 5 {
        return None;
    }

    let header_len = ihl * 4;
    if packet.len() < header_len {
        return None;
    }

    let protocol = packet[9];
    let src_ip_bytes = [packet[12], packet[13], packet[14], packet[15]];
    let dst_ip_bytes = [packet[16], packet[17], packet[18], packet[19]];

    let src_ip = u32::from_le_bytes(src_ip_bytes);
    let dst_ip = u32::from_le_bytes(dst_ip_bytes);

    // Parse TCP/UDP header if present
    if packet.len() >= header_len + 4 {
        let transport = &packet[header_len..];
        let src_port = u16::from_be_bytes([transport[0], transport[1]]);
        let dst_port = u16::from_be_bytes([transport[2], transport[3]]);
        Some((src_ip, dst_ip, protocol, src_port, dst_port))
    } else {
        Some((src_ip, dst_ip, protocol, 0, 0))
    }
}

/// Parse packet and extract flow key
pub fn parse_packet(packet: &[u8]) -> Option<(FlowKey, Option<String>)> {
    if packet.len() < 34 {
        return None;
    }

    // Skip Ethernet header (14 bytes)
    let ip_start = 14;
    let ip_header = &packet[ip_start..];

    if let Some((src_ip, dst_ip, proto, src_port, dst_port)) = parse_ip_header(ip_header) {
        let flow_key = FlowKey::new(src_ip, dst_ip, src_port, dst_port, proto);
        Some((flow_key, None))
    } else {
        None
    }
}