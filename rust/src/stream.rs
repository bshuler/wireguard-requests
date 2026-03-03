//! TCP stream wrapper exposed to Python.
//!
//! `WgStream` represents a single TCP connection through the WireGuard tunnel.
//! It communicates with the background poll loop via channels to send/receive
//! data through the smoltcp TCP socket.

use crate::error::{Result, WireGuardError};
use crate::tunnel::{TunnelCommand, TunnelShared};

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use smoltcp::iface::SocketHandle;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

/// Default timeout for stream operations (seconds).
const DEFAULT_TIMEOUT_SECS: u64 = 30;

/// A single TCP connection through a WireGuard tunnel.
///
/// Provides a blocking, socket-like API for reading and writing data.
/// Thread-safe: the actual I/O is performed by the tunnel's background thread.
#[pyclass]
pub struct WgStream {
    shared: Arc<TunnelShared>,
    handle: SocketHandle,
    timeout: Duration,
    closed: bool,
}

impl WgStream {
    pub fn new(shared: Arc<TunnelShared>, handle: SocketHandle) -> Self {
        WgStream {
            shared,
            handle,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            closed: false,
        }
    }
}

#[pymethods]
impl WgStream {
    /// Send data through the TCP connection.
    ///
    /// Args:
    ///     data: Bytes to send.
    ///
    /// Returns:
    ///     Number of bytes actually sent (may be less than len(data)).
    fn send(&self, data: &[u8]) -> Result<usize> {
        self.check_alive()?;

        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
        self.shared
            .cmd_tx
            .send(TunnelCommand::WriteData {
                handle: self.handle,
                data: data.to_vec(),
                response: resp_tx,
            })
            .map_err(WireGuardError::from)?;

        // If smoltcp's buffer is full, retry with backoff.
        let result = resp_rx
            .recv_timeout(self.timeout)
            .map_err(|_| WireGuardError::Timeout)??;

        Ok(result)
    }

    /// Send all data through the TCP connection.
    ///
    /// Blocks until all bytes are sent or an error occurs.
    fn sendall(&self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let n = self.send(&data[offset..])?;
            if n == 0 {
                // Buffer full, wait a bit and retry.
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            offset += n;
        }
        Ok(())
    }

    /// Receive data from the TCP connection.
    ///
    /// Args:
    ///     max_len: Maximum number of bytes to receive.
    ///
    /// Returns:
    ///     Bytes received (empty bytes means connection closed by peer).
    fn recv<'py>(&self, py: Python<'py>, max_len: usize) -> Result<Bound<'py, PyBytes>> {
        self.check_alive()?;

        // Poll with short timeout, retrying until data arrives or timeout.
        let deadline = std::time::Instant::now() + self.timeout;

        loop {
            let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
            self.shared
                .cmd_tx
                .send(TunnelCommand::ReadData {
                    handle: self.handle,
                    max_len,
                    response: resp_tx,
                })
                .map_err(WireGuardError::from)?;

            match resp_rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(data)) => {
                    if !data.is_empty() {
                        return Ok(PyBytes::new_bound(py, &data));
                    }
                    // Empty data means no data available yet — keep polling.
                }
                Ok(Err(WireGuardError::StreamClosed)) => {
                    // EOF: peer closed the connection. Return empty bytes.
                    return Ok(PyBytes::new_bound(py, &[]));
                }
                Ok(Err(e)) => {
                    return Err(e);
                }
                Err(_) => {
                    // Channel timeout — just retry.
                }
            }

            // No data yet — check if we've timed out.
            if std::time::Instant::now() >= deadline {
                return Err(WireGuardError::Timeout);
            }

            // Release the GIL while we sleep so other Python threads can run.
            py.allow_threads(|| {
                std::thread::sleep(Duration::from_millis(5));
            });
        }
    }

    /// Close the TCP connection gracefully.
    fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;

        if self.shared.alive.load(Ordering::SeqCst) {
            let _ = self.shared.cmd_tx.send(TunnelCommand::CloseStream {
                handle: self.handle,
            });
        }
        Ok(())
    }

    /// Check if the stream is still connected.
    fn is_connected(&self) -> Result<bool> {
        if self.closed || !self.shared.alive.load(Ordering::SeqCst) {
            return Ok(false);
        }

        let (resp_tx, resp_rx) = crossbeam_channel::bounded(1);
        self.shared
            .cmd_tx
            .send(TunnelCommand::IsConnected {
                handle: self.handle,
                response: resp_tx,
            })
            .map_err(WireGuardError::from)?;

        let connected = resp_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or(false);
        Ok(connected)
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
        format!("WgStream(handle={:?}, closed={})", self.handle, self.closed)
    }
}

impl WgStream {
    fn check_alive(&self) -> Result<()> {
        if self.closed {
            return Err(WireGuardError::StreamClosed);
        }
        if !self.shared.alive.load(Ordering::SeqCst) {
            return Err(WireGuardError::TunnelClosed);
        }
        Ok(())
    }
}

impl Drop for WgStream {
    fn drop(&mut self) {
        if !self.closed && self.shared.alive.load(Ordering::SeqCst) {
            let _ = self.shared.cmd_tx.send(TunnelCommand::CloseStream {
                handle: self.handle,
            });
        }
    }
}
