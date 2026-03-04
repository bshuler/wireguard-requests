//! Core WireGuard tunnel management with background poll loop.
//!
//! `WgTunnel` manages the lifecycle of a WireGuard connection:
//! - boringtun handles the WireGuard protocol (handshake, encryption)
//! - smoltcp provides a userspace TCP/IP stack
//! - A background thread continuously polls both, shuttling packets
//!   between smoltcp <-> boringtun <-> a real UDP socket
//!
//! Python creates a `WgTunnel`, then calls `create_stream()` to open
//! TCP connections through the tunnel, `create_udp_socket()` for UDP,
//! or `resolve_dns()` to resolve hostnames through the tunnel.

use crate::config::WgConfig;
use crate::error::{Result, WireGuardError};
use crate::stream::WgStream;
use crate::tun_interface::VirtualDevice;
use crate::udp_socket::WgUdpSocket;

use boringtun::noise::{Tunn, TunnResult};
use crossbeam_channel::{Receiver, Sender};
use pyo3::prelude::*;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::{dns, tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address, Ipv6Address};
use std::collections::{HashMap, HashSet};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// Size of TCP socket rx/tx buffers in smoltcp.
const TCP_RX_BUF_SIZE: usize = 65535;
const TCP_TX_BUF_SIZE: usize = 65535;

/// Max size of a single encrypted WireGuard packet.
const MAX_PACKET_SIZE: usize = 1500;

/// Commands sent from Python thread to the background poll loop.
pub enum TunnelCommand {
    /// Open a new TCP connection through the tunnel.
    CreateStream {
        dst_addr: IpAddress,
        dst_port: u16,
        response: Sender<Result<SocketHandle>>,
    },
    /// Close a TCP stream.
    CloseStream { handle: SocketHandle },
    /// Write data into a TCP stream.
    WriteData {
        handle: SocketHandle,
        data: Vec<u8>,
        response: Sender<Result<usize>>,
    },
    /// Read data from a TCP stream.
    ReadData {
        handle: SocketHandle,
        max_len: usize,
        response: Sender<Result<Vec<u8>>>,
    },
    /// Check if a TCP stream is connected.
    IsConnected {
        handle: SocketHandle,
        response: Sender<bool>,
    },
    /// Create a UDP socket bound to a port inside the tunnel.
    CreateUdpSocket {
        bind_port: u16,
        response: Sender<Result<SocketHandle>>,
    },
    /// Close a UDP socket.
    CloseUdpSocket { handle: SocketHandle },
    /// Send a UDP datagram through the tunnel.
    UdpSendTo {
        handle: SocketHandle,
        data: Vec<u8>,
        dst: smoltcp::wire::IpEndpoint,
        response: Sender<Result<()>>,
    },
    /// Receive a UDP datagram from the tunnel.
    UdpRecvFrom {
        handle: SocketHandle,
        max_len: usize,
        response: Sender<Result<(Vec<u8>, smoltcp::wire::IpEndpoint)>>,
    },
    /// Resolve a hostname using the tunnel's DNS servers.
    ResolveDns {
        hostname: String,
        response: Sender<Result<IpAddress>>,
    },
    /// Shutdown the tunnel.
    Shutdown,
}

/// Shared state between the tunnel and its streams.
pub struct TunnelShared {
    /// Channel to send commands to the poll loop.
    pub cmd_tx: Sender<TunnelCommand>,
    /// Whether the tunnel is still running.
    pub alive: AtomicBool,
}

/// The main WireGuard tunnel object exposed to Python.
#[pyclass]
pub struct WgTunnel {
    shared: Arc<TunnelShared>,
    poll_thread: Option<JoinHandle<()>>,
    config: WgConfig,
}

#[pymethods]
impl WgTunnel {
    /// Create a new WireGuard tunnel from configuration.
    #[new]
    fn new(config: WgConfig) -> Result<Self> {
        let tunnel = Self::create(config)?;
        Ok(tunnel)
    }

    /// Open a TCP connection through the WireGuard tunnel.
    ///
    /// Performs DNS resolution (through the tunnel if DNS servers are configured,
    /// otherwise via the system resolver), then establishes a TCP connection
    /// through smoltcp/boringtun to the resolved IP.
    ///
    /// Args:
    ///     host: Hostname or IP address to connect to.
    ///     port: TCP port number.
    ///
    /// Returns:
    ///     WgStream object for reading/writing data.
    fn create_stream(&self, host: &str, port: u16) -> Result<WgStream> {
        if !self.shared.alive.load(Ordering::SeqCst) {
            return Err(WireGuardError::TunnelClosed);
        }

        // Try to parse as IP address first.
        let dst_addr: IpAddress = if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
            IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets()))
        } else if let Ok(v6) = host.parse::<std::net::Ipv6Addr>() {
            IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets()))
        } else if !self.config.dns.is_empty() {
            // Use tunnel DNS resolution
            self.resolve_dns_internal(host)?
        } else {
            // DNS resolution via system resolver
            use std::net::ToSocketAddrs;
            let addr = format!("{}:{}", host, port);
            let has_ipv6 = self.config.address_v6.is_some();
            let resolved = addr.to_socket_addrs().map_err(|e| {
                WireGuardError::Config(format!("DNS resolution failed for '{}': {}", host, e))
            })?;

            let mut v4_addr = None;
            let mut v6_addr = None;
            for a in resolved {
                match a.ip() {
                    std::net::IpAddr::V4(v4) if v4_addr.is_none() => v4_addr = Some(v4),
                    std::net::IpAddr::V6(v6) if v6_addr.is_none() => v6_addr = Some(v6),
                    _ => {}
                }
            }

            // Prefer IPv6 if tunnel has IPv6, otherwise prefer IPv4
            if has_ipv6 {
                if let Some(v6) = v6_addr {
                    IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets()))
                } else if let Some(v4) = v4_addr {
                    IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets()))
                } else {
                    return Err(WireGuardError::Config(format!(
                        "No address found for '{}'",
                        host
                    )));
                }
            } else if let Some(v4) = v4_addr {
                IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets()))
            } else {
                return Err(WireGuardError::Config(format!(
                    "No IPv4 address found for '{}'",
                    host
                )));
            }
        };

        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);

        self.shared
            .cmd_tx
            .send(TunnelCommand::CreateStream {
                dst_addr,
                dst_port: port,
                response: resp_tx,
            })
            .map_err(WireGuardError::from)?;

        // Wait for the connection to be established (with timeout).
        let handle = resp_rx
            .recv_timeout(Duration::from_secs(30))
            .map_err(|_| WireGuardError::Timeout)??;

        Ok(WgStream::new(self.shared.clone(), handle))
    }

    /// Create a UDP socket bound inside the WireGuard tunnel.
    ///
    /// Args:
    ///     bind_port: Local port to bind to (0 for auto-assign).
    ///
    /// Returns:
    ///     WgUdpSocket object for sending/receiving datagrams.
    #[pyo3(signature = (bind_port=0))]
    fn create_udp_socket(&self, bind_port: u16) -> Result<WgUdpSocket> {
        if !self.shared.alive.load(Ordering::SeqCst) {
            return Err(WireGuardError::TunnelClosed);
        }
        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
        self.shared
            .cmd_tx
            .send(TunnelCommand::CreateUdpSocket {
                bind_port,
                response: resp_tx,
            })
            .map_err(WireGuardError::from)?;
        let handle = resp_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| WireGuardError::Timeout)??;
        Ok(WgUdpSocket::new(self.shared.clone(), handle))
    }

    /// Resolve a hostname using the tunnel's DNS servers.
    ///
    /// Args:
    ///     hostname: The hostname to resolve.
    ///
    /// Returns:
    ///     The resolved IP address as a string.
    fn resolve_dns(&self, hostname: &str) -> Result<String> {
        if !self.shared.alive.load(Ordering::SeqCst) {
            return Err(WireGuardError::TunnelClosed);
        }
        if self.config.dns.is_empty() {
            return Err(WireGuardError::Config(
                "No DNS servers configured in tunnel".into(),
            ));
        }
        let addr = self.resolve_dns_internal(hostname)?;
        Ok(format!("{}", addr))
    }

    /// Close the tunnel and stop the background thread.
    fn close(&mut self) -> Result<()> {
        self.shared.alive.store(false, Ordering::SeqCst);
        let _ = self.shared.cmd_tx.send(TunnelCommand::Shutdown);
        if let Some(thread) = self.poll_thread.take() {
            let _ = thread.join();
        }
        Ok(())
    }

    /// Check if the tunnel is still running.
    fn is_alive(&self) -> bool {
        self.shared.alive.load(Ordering::SeqCst)
    }

    fn __repr__(&self) -> String {
        format!(
            "WgTunnel(address='{}', alive={})",
            self.config.address,
            self.is_alive()
        )
    }
}

impl Drop for WgTunnel {
    fn drop(&mut self) {
        self.shared.alive.store(false, Ordering::SeqCst);
        let _ = self.shared.cmd_tx.send(TunnelCommand::Shutdown);
    }
}

impl WgTunnel {
    /// Internal DNS resolution that returns an IpAddress directly.
    fn resolve_dns_internal(&self, hostname: &str) -> Result<IpAddress> {
        if !self.shared.alive.load(Ordering::SeqCst) {
            return Err(WireGuardError::TunnelClosed);
        }
        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
        self.shared
            .cmd_tx
            .send(TunnelCommand::ResolveDns {
                hostname: hostname.to_string(),
                response: resp_tx,
            })
            .map_err(WireGuardError::from)?;
        resp_rx
            .recv_timeout(Duration::from_secs(10))
            .map_err(|_| WireGuardError::Timeout)?
    }

    fn create(config: WgConfig) -> Result<Self> {
        // Decode keys.
        let private_key = config.private_key_bytes()?;
        let peer = config
            .peers
            .first()
            .ok_or_else(|| WireGuardError::Config("No peers configured".into()))?;
        let peer_public_key = peer.public_key_bytes()?;
        let endpoint = peer.endpoint_addr()?;
        let keepalive = peer.persistent_keepalive;
        let preshared_key = peer.preshared_key_bytes()?;

        // Create boringtun tunnel instance.
        let tunn = Tunn::new(
            private_key.into(),
            peer_public_key.into(),
            preshared_key,
            keepalive,
            0,    // tunnel index
            None, // rate limiter
        )
        .map_err(|e| WireGuardError::BoringTun(e.to_string()))?;

        // Create UDP socket to WireGuard endpoint.
        // Bind to appropriate address family based on endpoint.
        let bind_addr = match endpoint {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };
        let udp_socket = UdpSocket::bind(bind_addr).map_err(WireGuardError::Io)?;
        udp_socket.connect(endpoint).map_err(WireGuardError::Io)?;
        udp_socket
            .set_nonblocking(true)
            .map_err(WireGuardError::Io)?;

        // Parse our tunnel IP address.
        let tunnel_ip = config.ipv4_addr()?;
        let prefix_len = config.prefix_len;
        let mtu = config.mtu;

        // Parse optional IPv6 tunnel address.
        let tunnel_ipv6: Option<std::net::Ipv6Addr> =
            config.address_v6.as_ref().and_then(|a| a.parse().ok());
        let prefix_len_v6 = config.prefix_len_v6;

        // Collect DNS servers.
        let dns_servers: Vec<String> = config.dns.clone();

        // Create command channel.
        let (cmd_tx, cmd_rx) = crossbeam_channel::unbounded();

        let shared = Arc::new(TunnelShared {
            cmd_tx,
            alive: AtomicBool::new(true),
        });

        let shared_clone = shared.clone();

        // Spawn the background poll thread.
        let poll_thread = std::thread::Builder::new()
            .name("wg-tunnel-poll".into())
            .spawn(move || {
                Self::poll_loop(
                    Box::new(tunn),
                    udp_socket,
                    tunnel_ip,
                    prefix_len,
                    mtu,
                    cmd_rx,
                    shared_clone,
                    tunnel_ipv6,
                    prefix_len_v6,
                    dns_servers,
                );
            })
            .map_err(WireGuardError::Io)?;

        Ok(WgTunnel {
            shared,
            poll_thread: Some(poll_thread),
            config,
        })
    }

    /// The main background event loop.
    #[allow(clippy::too_many_arguments)]
    fn poll_loop(
        mut tunn: Box<Tunn>,
        udp_socket: UdpSocket,
        tunnel_ip: std::net::Ipv4Addr,
        prefix_len: u8,
        mtu: u16,
        cmd_rx: Receiver<TunnelCommand>,
        shared: Arc<TunnelShared>,
        tunnel_ipv6: Option<std::net::Ipv6Addr>,
        prefix_len_v6: Option<u8>,
        dns_servers: Vec<String>,
    ) {
        // Initialize smoltcp virtual device and interface.
        let mut device = VirtualDevice::new(mtu);

        let iface_config = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, &mut device, Self::smoltcp_now());

        // Set our IPv4 address on the interface.
        let ip_addr = IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::from_bytes(&tunnel_ip.octets())),
            prefix_len,
        );
        iface.update_ip_addrs(|addrs| {
            addrs.push(ip_addr).ok();
        });

        // Set optional IPv6 address on the interface.
        if let Some(v6) = tunnel_ipv6 {
            let ipv6_cidr = IpCidr::new(
                IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())),
                prefix_len_v6.unwrap_or(64),
            );
            iface.update_ip_addrs(|addrs| {
                addrs.push(ipv6_cidr).ok();
            });
        }

        // Create socket set for managing connections.
        let mut sockets = SocketSet::new(Vec::new());

        // Map of socket handles to their connection state.
        let mut pending_connects: HashMap<SocketHandle, Sender<Result<SocketHandle>>> =
            HashMap::new();

        // Track active socket handles so we can safely check before accessing.
        let mut active_handles: HashSet<SocketHandle> = HashSet::new();

        // Port counter for local ephemeral ports.
        let mut next_local_port: u16 = 49152;

        // Buffers for packet I/O.
        let mut udp_recv_buf = vec![0u8; MAX_PACKET_SIZE];
        let mut wg_send_buf = vec![0u8; MAX_PACKET_SIZE + 148]; // WG overhead

        // --- DNS setup ---
        // Parse DNS server addresses and create DNS socket if configured.
        let mut dns_socket_handle: Option<SocketHandle> = None;
        if !dns_servers.is_empty() {
            let mut server_addrs: Vec<IpAddress> = Vec::new();
            for s in &dns_servers {
                if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
                    server_addrs.push(IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets())));
                } else if let Ok(v6) = s.parse::<std::net::Ipv6Addr>() {
                    server_addrs.push(IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets())));
                } else {
                    log::warn!("Ignoring unparseable DNS server address: {}", s);
                }
            }
            if !server_addrs.is_empty() {
                let dns_sock = dns::Socket::new(&server_addrs, vec![]);
                let handle = sockets.add(dns_sock);
                dns_socket_handle = Some(handle);
            }
        }

        // Pending DNS queries: Vec of (query_handle_index, sender, can_fallback_to_A).
        // We track query_handle_index as a usize because dns::QueryHandle is opaque.
        // Instead, store the QueryHandle directly and the response channel.
        struct PendingDns {
            query_handle: dns::QueryHandle,
            response: Sender<Result<IpAddress>>,
            can_fallback: bool,
            hostname: String,
        }
        let mut pending_dns: Vec<PendingDns> = Vec::new();

        // Trigger initial handshake.
        if let TunnResult::WriteToNetwork(data) =
            tunn.format_handshake_initiation(&mut wg_send_buf, false)
        {
            let _ = udp_socket.send(data);
        }

        loop {
            if !shared.alive.load(Ordering::SeqCst) {
                break;
            }

            // 1. Process commands from Python.
            while let Ok(cmd) = cmd_rx.try_recv() {
                match cmd {
                    TunnelCommand::CreateStream {
                        dst_addr,
                        dst_port,
                        response,
                    } => {
                        // Allocate a new TCP socket in smoltcp.
                        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
                        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
                        let tcp_socket = tcp::Socket::new(rx_buf, tx_buf);
                        let handle = sockets.add(tcp_socket);

                        // Get a local port.
                        let local_port = next_local_port;
                        next_local_port = next_local_port.wrapping_add(1);
                        if next_local_port < 49152 {
                            next_local_port = 49152;
                        }

                        // Choose local address matching the destination address family.
                        let local_addr = match dst_addr {
                            IpAddress::Ipv4(_) => {
                                IpAddress::Ipv4(Ipv4Address::from_bytes(&tunnel_ip.octets()))
                            }
                            IpAddress::Ipv6(_) => {
                                if let Some(ref v6) = tunnel_ipv6 {
                                    IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets()))
                                } else {
                                    let _ = response.send(Err(WireGuardError::Config(
                                        "Cannot connect to IPv6 destination: tunnel has no IPv6 address configured".into(),
                                    )));
                                    sockets.remove(handle);
                                    continue;
                                }
                            }
                        };

                        // Initiate TCP connection.
                        let local_endpoint = smoltcp::wire::IpEndpoint::new(local_addr, local_port);
                        let remote_endpoint = smoltcp::wire::IpEndpoint::new(dst_addr, dst_port);

                        let sock = sockets.get_mut::<tcp::Socket>(handle);
                        match sock.connect(iface.context(), remote_endpoint, local_endpoint) {
                            Ok(()) => {
                                active_handles.insert(handle);
                                pending_connects.insert(handle, response);
                            }
                            Err(e) => {
                                let _ = response.send(Err(WireGuardError::SmolTcp(format!(
                                    "TCP connect failed: {}",
                                    e
                                ))));
                                sockets.remove(handle);
                            }
                        }
                    }
                    TunnelCommand::CloseStream { handle } => {
                        if active_handles.contains(&handle) {
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            sock.close();
                        }
                    }
                    TunnelCommand::WriteData {
                        handle,
                        data,
                        response,
                    } => {
                        if active_handles.contains(&handle) {
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            match sock.send_slice(&data) {
                                Ok(n) => {
                                    let _ = response.send(Ok(n));
                                }
                                Err(e) => {
                                    let _ = response.send(Err(WireGuardError::SmolTcp(format!(
                                        "TCP send failed: {}",
                                        e
                                    ))));
                                }
                            }
                        } else {
                            let _ = response.send(Err(WireGuardError::StreamClosed));
                        }
                    }
                    TunnelCommand::ReadData {
                        handle,
                        max_len,
                        response,
                    } => {
                        if active_handles.contains(&handle) {
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            let mut buf = vec![0u8; max_len];
                            match sock.recv_slice(&mut buf) {
                                Ok(n) => {
                                    buf.truncate(n);
                                    let _ = response.send(Ok(buf));
                                }
                                Err(smoltcp::socket::tcp::RecvError::Finished) => {
                                    // EOF: peer closed the connection. Signal with StreamClosed
                                    // so the stream can return empty bytes immediately.
                                    let _ = response.send(Err(WireGuardError::StreamClosed));
                                }
                                Err(e) => {
                                    let _ = response.send(Err(WireGuardError::SmolTcp(format!(
                                        "TCP recv failed: {}",
                                        e
                                    ))));
                                }
                            }
                        } else {
                            let _ = response.send(Err(WireGuardError::StreamClosed));
                        }
                    }
                    TunnelCommand::IsConnected { handle, response } => {
                        let connected = if active_handles.contains(&handle) {
                            let sock = sockets.get_mut::<tcp::Socket>(handle);
                            sock.is_active()
                        } else {
                            false
                        };
                        let _ = response.send(connected);
                    }
                    TunnelCommand::CreateUdpSocket {
                        bind_port,
                        response,
                    } => {
                        // Create smoltcp UDP socket.
                        let rx_buf = udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 16],
                            vec![0u8; 65535],
                        );
                        let tx_buf = udp::PacketBuffer::new(
                            vec![udp::PacketMetadata::EMPTY; 16],
                            vec![0u8; 65535],
                        );
                        let udp_sock = udp::Socket::new(rx_buf, tx_buf);
                        let handle = sockets.add(udp_sock);

                        // Determine port: smoltcp rejects port 0, so auto-assign.
                        let port = if bind_port == 0 {
                            let p = next_local_port;
                            next_local_port = next_local_port.wrapping_add(1);
                            if next_local_port < 49152 {
                                next_local_port = 49152;
                            }
                            p
                        } else {
                            bind_port
                        };

                        let sock = sockets.get_mut::<udp::Socket>(handle);
                        match sock.bind(port) {
                            Ok(()) => {
                                active_handles.insert(handle);
                                let _ = response.send(Ok(handle));
                            }
                            Err(e) => {
                                let _ = response.send(Err(WireGuardError::SmolTcp(format!(
                                    "UDP bind failed: {:?}",
                                    e
                                ))));
                                sockets.remove(handle);
                            }
                        }
                    }
                    TunnelCommand::CloseUdpSocket { handle } => {
                        if active_handles.remove(&handle) {
                            let sock = sockets.get_mut::<udp::Socket>(handle);
                            sock.close();
                            sockets.remove(handle);
                        }
                    }
                    TunnelCommand::UdpSendTo {
                        handle,
                        data,
                        dst,
                        response,
                    } => {
                        if active_handles.contains(&handle) {
                            let sock = sockets.get_mut::<udp::Socket>(handle);
                            match sock.send_slice(&data, dst) {
                                Ok(()) => {
                                    let _ = response.send(Ok(()));
                                }
                                Err(e) => {
                                    let _ = response.send(Err(WireGuardError::SmolTcp(format!(
                                        "UDP send failed: {:?}",
                                        e
                                    ))));
                                }
                            }
                        } else {
                            let _ = response.send(Err(WireGuardError::InvalidState(
                                "UDP socket not found".into(),
                            )));
                        }
                    }
                    TunnelCommand::UdpRecvFrom {
                        handle,
                        max_len,
                        response,
                    } => {
                        if active_handles.contains(&handle) {
                            let sock = sockets.get_mut::<udp::Socket>(handle);
                            if sock.can_recv() {
                                let mut buf = vec![0u8; max_len];
                                match sock.recv_slice(&mut buf) {
                                    Ok((n, metadata)) => {
                                        buf.truncate(n);
                                        let _ = response.send(Ok((buf, metadata.endpoint)));
                                    }
                                    Err(e) => {
                                        let _ = response.send(Err(WireGuardError::SmolTcp(
                                            format!("UDP recv failed: {:?}", e),
                                        )));
                                    }
                                }
                            } else {
                                let _ = response
                                    .send(Err(WireGuardError::SmolTcp("no data available".into())));
                            }
                        } else {
                            let _ = response.send(Err(WireGuardError::InvalidState(
                                "UDP socket not found".into(),
                            )));
                        }
                    }
                    TunnelCommand::ResolveDns { hostname, response } => {
                        if let Some(dns_handle) = dns_socket_handle {
                            let dns_sock = sockets.get_mut::<dns::Socket>(dns_handle);
                            // If tunnel has IPv6, try AAAA first with fallback to A.
                            // Otherwise, just query A directly.
                            let (query_type, can_fallback) = if tunnel_ipv6.is_some() {
                                (smoltcp::wire::DnsQueryType::Aaaa, true)
                            } else {
                                (smoltcp::wire::DnsQueryType::A, false)
                            };
                            match dns_sock.start_query(iface.context(), &hostname, query_type) {
                                Ok(qh) => {
                                    pending_dns.push(PendingDns {
                                        query_handle: qh,
                                        response,
                                        can_fallback,
                                        hostname,
                                    });
                                }
                                Err(e) => {
                                    let _ = response.send(Err(WireGuardError::Config(format!(
                                        "DNS query start failed: {}",
                                        e
                                    ))));
                                }
                            }
                        } else {
                            let _ = response.send(Err(WireGuardError::Config(
                                "No DNS servers configured in tunnel".into(),
                            )));
                        }
                    }
                    TunnelCommand::Shutdown => {
                        shared.alive.store(false, Ordering::SeqCst);
                        return;
                    }
                }
            }

            // 2. Receive from UDP socket (WireGuard endpoint).
            loop {
                match udp_socket.recv(&mut udp_recv_buf) {
                    Ok(n) => {
                        // Decrypt with boringtun.
                        match tunn.decapsulate(None, &udp_recv_buf[..n], &mut wg_send_buf) {
                            TunnResult::Done => {}
                            TunnResult::WriteToNetwork(data) => {
                                // This is a handshake response -- send it back.
                                let _ = udp_socket.send(data);

                                // After sending handshake response, check for more results.
                                loop {
                                    let mut buf2 = vec![0u8; MAX_PACKET_SIZE + 148];
                                    match tunn.decapsulate(None, &[], &mut buf2) {
                                        TunnResult::WriteToNetwork(data2) => {
                                            let _ = udp_socket.send(data2);
                                        }
                                        TunnResult::WriteToTunnelV4(data2, _) => {
                                            device.inject_rx(data2.to_vec());
                                        }
                                        TunnResult::WriteToTunnelV6(data2, _) => {
                                            device.inject_rx(data2.to_vec());
                                        }
                                        _ => break,
                                    }
                                }
                            }
                            TunnResult::WriteToTunnelV4(data, _addr) => {
                                // Decrypted IP packet -- inject into smoltcp.
                                device.inject_rx(data.to_vec());
                            }
                            TunnResult::WriteToTunnelV6(data, _addr) => {
                                device.inject_rx(data.to_vec());
                            }
                            TunnResult::Err(e) => {
                                log::debug!("boringtun decapsulate error: {:?}", e);
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::error!("UDP recv error: {}", e);
                        break;
                    }
                }
            }

            // 3. Poll smoltcp.
            let timestamp = Self::smoltcp_now();
            let _changed = iface.poll(timestamp, &mut device, &mut sockets);

            // 4. Check for newly connected sockets.
            let mut completed: Vec<SocketHandle> = Vec::new();
            for (handle, _) in pending_connects.iter() {
                if active_handles.contains(handle) {
                    let sock = sockets.get_mut::<tcp::Socket>(*handle);
                    if (sock.is_active() && sock.may_send()) || sock.state() == tcp::State::Closed {
                        completed.push(*handle);
                    }
                }
            }
            for handle in completed {
                if let Some(response) = pending_connects.remove(&handle) {
                    let sock = sockets.get_mut::<tcp::Socket>(handle);
                    if sock.is_active() {
                        let _ = response.send(Ok(handle));
                    } else {
                        let _ = response.send(Err(WireGuardError::ConnectionRefused(
                            "TCP connection failed".into(),
                        )));
                        active_handles.remove(&handle);
                        sockets.remove(handle);
                    }
                }
            }

            // 4b. Check pending DNS queries.
            if let Some(dns_handle) = dns_socket_handle {
                if !pending_dns.is_empty() {
                    let mut i = 0;
                    while i < pending_dns.len() {
                        let dns_sock = sockets.get_mut::<dns::Socket>(dns_handle);
                        match dns_sock.get_query_result(pending_dns[i].query_handle) {
                            Ok(addrs) if !addrs.is_empty() => {
                                let entry = pending_dns.swap_remove(i);
                                let _ = entry.response.send(Ok(addrs[0]));
                                // Don't increment i; swap_remove moved last element here
                            }
                            Ok(_) if pending_dns[i].can_fallback => {
                                // AAAA returned empty, try A query as fallback.
                                let hostname = pending_dns[i].hostname.clone();
                                let dns_sock = sockets.get_mut::<dns::Socket>(dns_handle);
                                match dns_sock.start_query(
                                    iface.context(),
                                    &hostname,
                                    smoltcp::wire::DnsQueryType::A,
                                ) {
                                    Ok(new_qh) => {
                                        pending_dns[i].query_handle = new_qh;
                                        pending_dns[i].can_fallback = false;
                                        i += 1;
                                    }
                                    Err(e) => {
                                        let entry = pending_dns.swap_remove(i);
                                        let _ = entry.response.send(Err(WireGuardError::Config(
                                            format!("DNS fallback query failed: {}", e),
                                        )));
                                    }
                                }
                            }
                            Ok(_) => {
                                // No results and no fallback available.
                                let entry = pending_dns.swap_remove(i);
                                let _ = entry.response.send(Err(WireGuardError::Config(
                                    "DNS query returned no results".into(),
                                )));
                            }
                            Err(dns::GetQueryResultError::Pending) => {
                                // Still waiting, skip.
                                i += 1;
                            }
                            Err(dns::GetQueryResultError::Failed)
                                if pending_dns[i].can_fallback =>
                            {
                                // AAAA failed, try A query as fallback.
                                let hostname = pending_dns[i].hostname.clone();
                                let dns_sock = sockets.get_mut::<dns::Socket>(dns_handle);
                                match dns_sock.start_query(
                                    iface.context(),
                                    &hostname,
                                    smoltcp::wire::DnsQueryType::A,
                                ) {
                                    Ok(new_qh) => {
                                        pending_dns[i].query_handle = new_qh;
                                        pending_dns[i].can_fallback = false;
                                        i += 1;
                                    }
                                    Err(e) => {
                                        let entry = pending_dns.swap_remove(i);
                                        let _ = entry.response.send(Err(WireGuardError::Config(
                                            format!("DNS fallback query failed: {}", e),
                                        )));
                                    }
                                }
                            }
                            Err(_) => {
                                let entry = pending_dns.swap_remove(i);
                                let _ = entry
                                    .response
                                    .send(Err(WireGuardError::Config("DNS query failed".into())));
                            }
                        }
                    }
                }
            }

            // 5. Send outgoing packets from smoltcp through boringtun.
            for packet in device.drain_tx() {
                match tunn.encapsulate(&packet, &mut wg_send_buf) {
                    TunnResult::WriteToNetwork(data) => {
                        let _ = udp_socket.send(data);
                    }
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        log::debug!("boringtun encapsulate error: {:?}", e);
                    }
                    _ => {}
                }
            }

            // 6. Tick boringtun timers (keepalive, handshake retry).
            match tunn.update_timers(&mut wg_send_buf) {
                TunnResult::WriteToNetwork(data) => {
                    let _ = udp_socket.send(data);
                }
                TunnResult::Done => {}
                TunnResult::Err(e) => {
                    log::debug!("boringtun timer error: {:?}", e);
                }
                _ => {}
            }

            // 7. Sleep briefly to avoid busy-looping.
            // Use shorter sleep if there's pending work.
            let sleep_duration = if device.has_rx() || device.has_tx() {
                Duration::from_micros(100)
            } else {
                Duration::from_millis(1)
            };
            std::thread::sleep(sleep_duration);
        }
    }

    /// Get current time in smoltcp format.
    fn smoltcp_now() -> Instant {
        let duration = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap();
        Instant::from_millis(duration.as_millis() as i64)
    }
}
