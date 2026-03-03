//! Core WireGuard tunnel management with background poll loop.
//!
//! `WgTunnel` manages the lifecycle of a WireGuard connection:
//! - boringtun handles the WireGuard protocol (handshake, encryption)
//! - smoltcp provides a userspace TCP/IP stack
//! - A background thread continuously polls both, shuttling packets
//!   between smoltcp ↔ boringtun ↔ a real UDP socket
//!
//! Python creates a `WgTunnel`, then calls `create_stream()` to open
//! TCP connections through the tunnel.

use crate::config::WgConfig;
use crate::error::{Result, WireGuardError};
use crate::stream::WgStream;
use crate::tun_interface::VirtualDevice;

use boringtun::noise::{Tunn, TunnResult};
use crossbeam_channel::{Receiver, Sender};
use pyo3::prelude::*;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{IpAddress, IpCidr, Ipv4Address};
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
        dst_addr: Ipv4Address,
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
    /// Performs DNS resolution on the host side, then establishes a TCP
    /// connection through smoltcp/boringtun to the resolved IP.
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

        // Resolve hostname to IP on the host side.
        // DNS goes through the normal system resolver, not through the tunnel.
        let ip: std::net::Ipv4Addr = if let Ok(ip) = host.parse() {
            ip
        } else {
            // DNS resolution via system resolver
            use std::net::ToSocketAddrs;
            let addr = format!("{}:{}", host, port);
            let resolved = addr
                .to_socket_addrs()
                .map_err(|e| {
                    WireGuardError::Config(format!("DNS resolution failed for '{}': {}", host, e))
                })?
                .find(|a| a.is_ipv4())
                .ok_or_else(|| {
                    WireGuardError::Config(format!("No IPv4 address found for '{}'", host))
                })?;
            match resolved.ip() {
                std::net::IpAddr::V4(v4) => v4,
                _ => unreachable!(),
            }
        };

        let dst_addr = Ipv4Address::from_bytes(&ip.octets());
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

        // Create boringtun tunnel instance.
        let tunn = Tunn::new(
            private_key.into(),
            peer_public_key.into(),
            None, // preshared key
            keepalive,
            0,    // tunnel index
            None, // rate limiter
        )
        .map_err(|e| WireGuardError::BoringTun(e.to_string()))?;

        // Create UDP socket to WireGuard endpoint.
        let udp_socket = UdpSocket::bind("0.0.0.0:0").map_err(WireGuardError::Io)?;
        udp_socket.connect(endpoint).map_err(WireGuardError::Io)?;
        udp_socket
            .set_nonblocking(true)
            .map_err(WireGuardError::Io)?;

        // Parse our tunnel IP address.
        let tunnel_ip = config.ipv4_addr()?;
        let prefix_len = config.prefix_len;
        let mtu = config.mtu;

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
    fn poll_loop(
        mut tunn: Box<Tunn>,
        udp_socket: UdpSocket,
        tunnel_ip: std::net::Ipv4Addr,
        prefix_len: u8,
        mtu: u16,
        cmd_rx: Receiver<TunnelCommand>,
        shared: Arc<TunnelShared>,
    ) {
        // Initialize smoltcp virtual device and interface.
        let mut device = VirtualDevice::new(mtu);

        let iface_config = IfaceConfig::new(smoltcp::wire::HardwareAddress::Ip);
        let mut iface = Interface::new(iface_config, &mut device, Self::smoltcp_now());

        // Set our IP address on the interface.
        let ip_addr = IpCidr::new(
            IpAddress::Ipv4(Ipv4Address::from_bytes(&tunnel_ip.octets())),
            prefix_len,
        );
        iface.update_ip_addrs(|addrs| {
            addrs.push(ip_addr).ok();
        });

        // Create socket set for managing TCP connections.
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

                        // Initiate TCP connection.
                        let local_endpoint = smoltcp::wire::IpEndpoint::new(
                            IpAddress::Ipv4(Ipv4Address::from_bytes(&tunnel_ip.octets())),
                            local_port,
                        );
                        let remote_endpoint =
                            smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(dst_addr), dst_port);

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
                                // This is a handshake response — send it back.
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
                                        _ => break,
                                    }
                                }
                            }
                            TunnResult::WriteToTunnelV4(data, _addr) => {
                                // Decrypted IP packet — inject into smoltcp.
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
