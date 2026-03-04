//! UDP socket wrapper exposed to Python.
//!
//! `WgUdpSocket` represents a UDP socket bound inside the WireGuard tunnel.
//! It communicates with the background poll loop via channels to send/receive
//! datagrams through the smoltcp UDP socket.

use crate::error::{Result, WireGuardError};
use crate::tunnel::{TunnelCommand, TunnelShared};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use smoltcp::iface::SocketHandle;
use smoltcp::wire::{IpAddress, Ipv4Address, Ipv6Address};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Default timeout for UDP operations (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// A UDP socket bound inside a WireGuard tunnel.
///
/// Provides a blocking, socket-like API for sending and receiving datagrams.
/// Thread-safe: the actual I/O is performed by the tunnel's background thread.
#[pyclass]
pub struct WgUdpSocket {
    shared: Arc<TunnelShared>,
    handle: SocketHandle,
    timeout: Duration,
    closed: bool,
}

impl WgUdpSocket {
    pub fn new(shared: Arc<TunnelShared>, handle: SocketHandle) -> Self {
        WgUdpSocket {
            shared,
            handle,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            closed: false,
        }
    }

    fn check_alive(&self) -> Result<()> {
        if self.closed {
            return Err(WireGuardError::InvalidState("UDP socket is closed".into()));
        }
        if !self.shared.alive.load(Ordering::SeqCst) {
            return Err(WireGuardError::TunnelClosed);
        }
        Ok(())
    }

    /// Parse a (host, port) tuple into a smoltcp IpEndpoint.
    fn parse_endpoint(addr: &str, port: u16) -> Result<smoltcp::wire::IpEndpoint> {
        let ip: IpAddress = if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
            IpAddress::Ipv4(Ipv4Address::from_bytes(&v4.octets()))
        } else if let Ok(v6) = addr.parse::<std::net::Ipv6Addr>() {
            IpAddress::Ipv6(Ipv6Address::from_bytes(&v6.octets()))
        } else {
            return Err(WireGuardError::Config(format!(
                "Invalid IP address: '{}'",
                addr
            )));
        };
        Ok(smoltcp::wire::IpEndpoint::new(ip, port))
    }
}

#[pymethods]
impl WgUdpSocket {
    /// Send a datagram to the specified address.
    ///
    /// Args:
    ///     data: Bytes to send.
    ///     addr: Tuple of (host, port) to send to.
    ///
    /// Returns:
    ///     Number of bytes sent.
    fn send_to(&self, data: &[u8], addr: (String, u16)) -> Result<usize> {
        self.check_alive()?;

        let dst = Self::parse_endpoint(&addr.0, addr.1)?;
        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
        self.shared
            .cmd_tx
            .send(TunnelCommand::UdpSendTo {
                handle: self.handle,
                data: data.to_vec(),
                dst,
                response: resp_tx,
            })
            .map_err(WireGuardError::from)?;

        resp_rx
            .recv_timeout(self.timeout)
            .map_err(|_| WireGuardError::Timeout)??;

        Ok(data.len())
    }

    /// Receive a datagram from the socket.
    ///
    /// Args:
    ///     max_len: Maximum number of bytes to receive.
    ///
    /// Returns:
    ///     Tuple of (data, (host, port)) where data is bytes and host is a string IP.
    fn recv_from<'py>(
        &self,
        py: Python<'py>,
        max_len: usize,
    ) -> Result<(Bound<'py, PyBytes>, (String, u16))> {
        self.check_alive()?;

        let deadline = std::time::Instant::now() + self.timeout;

        loop {
            let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
            self.shared
                .cmd_tx
                .send(TunnelCommand::UdpRecvFrom {
                    handle: self.handle,
                    max_len,
                    response: resp_tx,
                })
                .map_err(WireGuardError::from)?;

            match resp_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok((data, endpoint))) => {
                    let addr_str = format!("{}", endpoint.addr);
                    return Ok((PyBytes::new_bound(py, &data), (addr_str, endpoint.port)));
                }
                Ok(Err(WireGuardError::SmolTcp(ref msg))) if msg.contains("no data") => {
                    // No data available yet, keep polling.
                }
                Ok(Err(e)) => {
                    return Err(e);
                }
                Err(_) => {
                    // Channel timeout, retry.
                }
            }

            if std::time::Instant::now() >= deadline {
                return Err(WireGuardError::Timeout);
            }

            // Release the GIL while we sleep so other Python threads can run.
            py.allow_threads(|| {
                std::thread::sleep(Duration::from_millis(5));
            });
        }
    }

    /// Close the UDP socket.
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        if self.shared.alive.load(Ordering::SeqCst) {
            let _ = self.shared.cmd_tx.send(TunnelCommand::CloseUdpSocket {
                handle: self.handle,
            });
        }
        Ok(())
    }

    /// Set the timeout for send/recv operations.
    ///
    /// Args:
    ///     timeout_secs: Timeout in seconds (None for default 30s).
    #[pyo3(signature = (timeout_secs=None))]
    fn set_timeout(&mut self, timeout_secs: Option<f64>) -> Result<()> {
        self.timeout = match timeout_secs {
            Some(t) => Duration::from_secs_f64(t),
            None => Duration::from_secs(DEFAULT_TIMEOUT_SECS),
        };
        Ok(())
    }

    fn __repr__(&self) -> String {
        format!(
            "WgUdpSocket(handle={:?}, closed={})",
            self.handle, self.closed
        )
    }
}

impl Drop for WgUdpSocket {
    fn drop(&mut self) {
        if !self.closed && self.shared.alive.load(Ordering::SeqCst) {
            let _ = self.shared.cmd_tx.send(TunnelCommand::CloseUdpSocket {
                handle: self.handle,
            });
        }
    }
}
