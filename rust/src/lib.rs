//! wireguard-requests native extension module.
//!
//! This crate provides the Rust core for the `wireguard-requests` Python package.
//! It combines boringtun (WireGuard protocol) with smoltcp (userspace TCP/IP stack)
//! to create a transparent WireGuard tunnel accessible from Python.

mod config;
mod error;
mod packet;
mod stream;
mod tun_interface;
mod tunnel;

use config::{WgConfig, WgPeer};
use pyo3::prelude::*;
use stream::WgStream;
use tunnel::WgTunnel;

/// Native extension module for wireguard-requests.
///
/// This module is not meant to be used directly. Use the `wireguard_requests`
/// Python package instead, which provides a high-level socket-compatible API.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Initialize logging (respects RUST_LOG env var).
    let _ = env_logger::try_init();

    m.add_class::<WgTunnel>()?;
    m.add_class::<WgStream>()?;
    m.add_class::<WgConfig>()?;
    m.add_class::<WgPeer>()?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
