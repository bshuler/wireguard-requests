use crate::error::{Result, WireGuardError};
use pyo3::prelude::*;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// A WireGuard peer configuration.
#[pyclass]
#[derive(Clone, Debug)]
pub struct WgPeer {
    #[pyo3(get, set)]
    pub public_key: String,

    #[pyo3(get, set)]
    pub endpoint: String,

    #[pyo3(get, set)]
    pub allowed_ips: Vec<String>,

    #[pyo3(get, set)]
    pub persistent_keepalive: Option<u16>,

    #[pyo3(get, set)]
    pub preshared_key: Option<String>,
}

#[pymethods]
impl WgPeer {
    #[new]
    #[pyo3(signature = (public_key, endpoint, allowed_ips, persistent_keepalive=None, preshared_key=None))]
    fn new(
        public_key: String,
        endpoint: String,
        allowed_ips: Vec<String>,
        persistent_keepalive: Option<u16>,
        preshared_key: Option<String>,
    ) -> Self {
        WgPeer {
            public_key,
            endpoint,
            allowed_ips,
            persistent_keepalive,
            preshared_key,
        }
    }

    fn __repr__(&self) -> String {
        format!(
            "WgPeer(public_key='{}...', endpoint='{}', allowed_ips={:?})",
            &self.public_key[..8.min(self.public_key.len())],
            self.endpoint,
            self.allowed_ips
        )
    }
}

impl WgPeer {
    /// Parse endpoint string into SocketAddr.
    pub fn endpoint_addr(&self) -> Result<SocketAddr> {
        self.endpoint.parse::<SocketAddr>().map_err(|e| {
            WireGuardError::Config(format!("Invalid endpoint '{}': {}", self.endpoint, e))
        })
    }

    /// Decode the base64 public key into 32 bytes.
    pub fn public_key_bytes(&self) -> Result<[u8; 32]> {
        decode_key(&self.public_key)
    }

    /// Decode the optional base64 preshared key into 32 bytes.
    pub fn preshared_key_bytes(&self) -> Result<Option<[u8; 32]>> {
        match &self.preshared_key {
            Some(key) => Ok(Some(decode_key(key)?)),
            None => Ok(None),
        }
    }
}

/// Full WireGuard tunnel configuration.
#[pyclass]
#[derive(Clone, Debug)]
pub struct WgConfig {
    #[pyo3(get, set)]
    pub private_key: String,

    #[pyo3(get, set)]
    pub address: String,

    #[pyo3(get, set)]
    pub prefix_len: u8,

    #[pyo3(get, set)]
    pub listen_port: u16,

    #[pyo3(get, set)]
    pub mtu: u16,

    #[pyo3(get, set)]
    pub dns: Vec<String>,

    #[pyo3(get, set)]
    pub peers: Vec<WgPeer>,

    #[pyo3(get, set)]
    pub address_v6: Option<String>,

    #[pyo3(get, set)]
    pub prefix_len_v6: Option<u8>,
}

#[pymethods]
impl WgConfig {
    #[new]
    #[pyo3(signature = (private_key, address, peers, prefix_len=24, listen_port=0, mtu=1420, dns=vec![], address_v6=None, prefix_len_v6=None))]
    fn new(
        private_key: String,
        address: String,
        peers: Vec<WgPeer>,
        prefix_len: u8,
        listen_port: u16,
        mtu: u16,
        dns: Vec<String>,
        address_v6: Option<String>,
        prefix_len_v6: Option<u8>,
    ) -> Self {
        WgConfig {
            private_key,
            address,
            prefix_len,
            listen_port,
            mtu,
            dns,
            peers,
            address_v6,
            prefix_len_v6,
        }
    }

    /// Parse a WireGuard .conf file.
    #[staticmethod]
    fn from_file(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| WireGuardError::Config(format!("Cannot read '{}': {}", path, e)))?;
        Self::from_str(&content)
    }

    /// Parse a WireGuard config from a string.
    #[staticmethod]
    fn from_str(content: &str) -> Result<Self> {
        parse_conf(content)
    }

    fn __repr__(&self) -> String {
        format!(
            "WgConfig(address='{}', peers={})",
            self.address,
            self.peers.len()
        )
    }
}

impl WgConfig {
    /// Decode the base64 private key into 32 bytes.
    pub fn private_key_bytes(&self) -> Result<[u8; 32]> {
        decode_key(&self.private_key)
    }

    /// Parse address string into IpAddr.
    pub fn ip_addr(&self) -> Result<IpAddr> {
        self.address.parse::<IpAddr>().map_err(|e| {
            WireGuardError::Config(format!("Invalid address '{}': {}", self.address, e))
        })
    }

    /// Parse address as Ipv4.
    pub fn ipv4_addr(&self) -> Result<Ipv4Addr> {
        self.address.parse::<Ipv4Addr>().map_err(|e| {
            WireGuardError::Config(format!("Invalid IPv4 address '{}': {}", self.address, e))
        })
    }

    /// Parse IPv6 address string into Ipv6Addr.
    pub fn ipv6_addr(&self) -> Result<Ipv6Addr> {
        self.address_v6
            .as_ref()
            .ok_or_else(|| WireGuardError::Config("No IPv6 address configured".into()))?
            .parse::<Ipv6Addr>()
            .map_err(|e| WireGuardError::Config(format!("Invalid IPv6 address: {}", e)))
    }
}

/// Decode a base64-encoded WireGuard key into 32 bytes.
fn decode_key(key: &str) -> Result<[u8; 32]> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;

    let decoded = STANDARD
        .decode(key.trim())
        .map_err(|e| WireGuardError::Config(format!("Invalid base64 key: {}", e)))?;

    if decoded.len() != 32 {
        return Err(WireGuardError::Config(format!(
            "Key must be 32 bytes, got {}",
            decoded.len()
        )));
    }

    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&decoded);
    Ok(key_bytes)
}

/// Parse INI-style WireGuard configuration.
fn parse_conf(content: &str) -> Result<WgConfig> {
    let mut private_key = String::new();
    let mut address = String::new();
    let mut prefix_len: u8 = 24;
    let mut listen_port: u16 = 0;
    let mut mtu: u16 = 1420;
    let mut dns: Vec<String> = Vec::new();
    let mut peers: Vec<WgPeer> = Vec::new();
    let mut address_v6: Option<String> = None;
    let mut prefix_len_v6: Option<u8> = None;

    let mut current_section: Option<&str> = None;
    let mut current_peer_pubkey = String::new();
    let mut current_peer_endpoint = String::new();
    let mut current_peer_allowed_ips: Vec<String> = Vec::new();
    let mut current_peer_keepalive: Option<u16> = None;
    let mut current_peer_preshared_key: Option<String> = None;

    let flush_peer = |pubkey: &mut String,
                      endpoint: &mut String,
                      allowed_ips: &mut Vec<String>,
                      keepalive: &mut Option<u16>,
                      preshared_key: &mut Option<String>,
                      peers: &mut Vec<WgPeer>| {
        if !pubkey.is_empty() {
            peers.push(WgPeer {
                public_key: std::mem::take(pubkey),
                endpoint: std::mem::take(endpoint),
                allowed_ips: std::mem::take(allowed_ips),
                persistent_keepalive: keepalive.take(),
                preshared_key: preshared_key.take(),
            });
        }
    };

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        // Section header
        if line.starts_with('[') && line.ends_with(']') {
            let section = &line[1..line.len() - 1];
            if section == "Peer" && current_section == Some("Peer") {
                flush_peer(
                    &mut current_peer_pubkey,
                    &mut current_peer_endpoint,
                    &mut current_peer_allowed_ips,
                    &mut current_peer_keepalive,
                    &mut current_peer_preshared_key,
                    &mut peers,
                );
            }
            current_section = match section {
                "Interface" => Some("Interface"),
                "Peer" => Some("Peer"),
                _ => None,
            };
            continue;
        }

        // Key = Value
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim();

        match current_section {
            Some("Interface") => match key {
                "PrivateKey" => private_key = value.to_string(),
                "Address" => {
                    // Support dual-stack: Address = 10.0.0.2/24, fd00::2/64
                    for part in value.split(',') {
                        let part = part.trim();
                        let (addr, plen) = if let Some((a, p)) = part.split_once('/') {
                            let parsed_plen: u8 = p
                                .trim()
                                .parse()
                                .map_err(|_| WireGuardError::Config("Invalid prefix length".into()))?;
                            (a.trim().to_string(), Some(parsed_plen))
                        } else {
                            (part.to_string(), None)
                        };

                        // Detect IPv6 by presence of ':' character
                        if addr.contains(':') {
                            address_v6 = Some(addr);
                            prefix_len_v6 = Some(plen.unwrap_or(64));
                        } else {
                            address = addr;
                            prefix_len = plen.unwrap_or(24);
                        }
                    }
                }
                "ListenPort" => {
                    listen_port = value
                        .parse()
                        .map_err(|_| WireGuardError::Config("Invalid ListenPort".into()))?;
                }
                "MTU" => {
                    mtu = value
                        .parse()
                        .map_err(|_| WireGuardError::Config("Invalid MTU".into()))?;
                }
                "DNS" => {
                    dns = value.split(',').map(|s| s.trim().to_string()).collect();
                }
                _ => {} // Ignore unknown keys
            },
            Some("Peer") => match key {
                "PublicKey" => current_peer_pubkey = value.to_string(),
                "Endpoint" => current_peer_endpoint = value.to_string(),
                "AllowedIPs" => {
                    current_peer_allowed_ips =
                        value.split(',').map(|s| s.trim().to_string()).collect();
                }
                "PersistentKeepalive" => {
                    current_peer_keepalive = Some(value.parse().map_err(|_| {
                        WireGuardError::Config("Invalid PersistentKeepalive".into())
                    })?);
                }
                "PresharedKey" => current_peer_preshared_key = Some(value.to_string()),
                _ => {}
            },
            _ => {}
        }
    }

    // Flush last peer
    flush_peer(
        &mut current_peer_pubkey,
        &mut current_peer_endpoint,
        &mut current_peer_allowed_ips,
        &mut current_peer_keepalive,
        &mut current_peer_preshared_key,
        &mut peers,
    );

    if private_key.is_empty() {
        return Err(WireGuardError::Config("Missing PrivateKey".into()));
    }
    if address.is_empty() {
        return Err(WireGuardError::Config("Missing Address".into()));
    }
    if peers.is_empty() {
        return Err(WireGuardError::Config("No peers configured".into()));
    }

    Ok(WgConfig {
        private_key,
        address,
        prefix_len,
        listen_port,
        mtu,
        dns,
        peers,
        address_v6,
        prefix_len_v6,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic_conf() {
        let conf = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24
ListenPort = 51820
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"#;
        let config = parse_conf(conf).unwrap();
        assert_eq!(config.address, "10.0.0.2");
        assert_eq!(config.prefix_len, 24);
        assert_eq!(config.listen_port, 51820);
        assert_eq!(config.dns, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(config.peers.len(), 1);
        assert_eq!(config.peers[0].endpoint, "203.0.113.1:51820");
        assert_eq!(config.peers[0].persistent_keepalive, Some(25));
    }

    #[test]
    fn test_parse_multiple_peers() {
        let conf = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2piVFBs2LR3PGk=
Endpoint = 203.0.113.2:51820
AllowedIPs = 10.0.1.0/24
"#;
        let config = parse_conf(conf).unwrap();
        assert_eq!(config.peers.len(), 2);
    }

    #[test]
    fn test_parse_dual_stack_conf() {
        let conf = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24, fd00::2/64
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
"#;
        let config = parse_conf(conf).unwrap();
        assert_eq!(config.address, "10.0.0.2");
        assert_eq!(config.prefix_len, 24);
        assert_eq!(config.address_v6, Some("fd00::2".to_string()));
        assert_eq!(config.prefix_len_v6, Some(64));
    }

    #[test]
    fn test_parse_ipv4_only_conf() {
        let conf = r#"
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"#;
        let config = parse_conf(conf).unwrap();
        assert_eq!(config.address, "10.0.0.2");
        assert_eq!(config.prefix_len, 24);
        assert_eq!(config.address_v6, None);
        assert_eq!(config.prefix_len_v6, None);
    }

    #[test]
    fn test_missing_private_key() {
        let conf = r#"
[Interface]
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"#;
        assert!(parse_conf(conf).is_err());
    }
}
