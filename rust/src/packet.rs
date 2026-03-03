//! Packet inspection utilities for debugging and routing.

use std::net::Ipv4Addr;

/// Extract source and destination IPv4 addresses from a raw IP packet.
pub fn extract_ipv4_addrs(packet: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if packet.len() < 20 {
        return None;
    }
    // Version check: must be IPv4
    if (packet[0] >> 4) != 4 {
        return None;
    }
    let src = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Some((src, dst))
}

/// Get the IP protocol number from a raw IPv4 packet.
pub fn ipv4_protocol(packet: &[u8]) -> Option<u8> {
    if packet.len() < 20 {
        return None;
    }
    Some(packet[9])
}

/// IP protocol numbers.
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;

/// Get the total length of an IPv4 packet from the header.
pub fn ipv4_total_length(packet: &[u8]) -> Option<u16> {
    if packet.len() < 20 {
        return None;
    }
    Some(u16::from_be_bytes([packet[2], packet[3]]))
}
