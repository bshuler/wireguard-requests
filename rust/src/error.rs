use pyo3::exceptions::{
    PyConnectionError, PyOSError, PyRuntimeError, PyTimeoutError, PyValueError,
};
use pyo3::PyErr;
use thiserror::Error;

/// All errors that can occur in the wireguard-requests library.
#[derive(Error, Debug)]
pub enum WireGuardError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("WireGuard protocol error: {0}")]
    BoringTun(String),

    #[error("TCP/IP stack error: {0}")]
    SmolTcp(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Channel communication error: {0}")]
    Channel(String),

    #[error("Connection refused: {0}")]
    ConnectionRefused(String),

    #[error("Connection reset: {0}")]
    ConnectionReset(String),

    #[error("Connection timed out")]
    Timeout,

    #[error("Tunnel is closed")]
    TunnelClosed,

    #[error("Stream is closed")]
    StreamClosed,

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<WireGuardError> for PyErr {
    fn from(err: WireGuardError) -> PyErr {
        match &err {
            WireGuardError::Io(_) => PyOSError::new_err(err.to_string()),
            WireGuardError::Config(_) => PyValueError::new_err(err.to_string()),
            WireGuardError::Timeout => PyTimeoutError::new_err(err.to_string()),
            WireGuardError::ConnectionRefused(_) | WireGuardError::ConnectionReset(_) => {
                PyConnectionError::new_err(err.to_string())
            }
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

impl<T> From<crossbeam_channel::SendError<T>> for WireGuardError {
    fn from(err: crossbeam_channel::SendError<T>) -> Self {
        WireGuardError::Channel(format!("Send error: {}", err))
    }
}

impl From<crossbeam_channel::RecvError> for WireGuardError {
    fn from(err: crossbeam_channel::RecvError) -> Self {
        WireGuardError::Channel(format!("Recv error: {}", err))
    }
}

impl From<crossbeam_channel::RecvTimeoutError> for WireGuardError {
    fn from(err: crossbeam_channel::RecvTimeoutError) -> Self {
        match err {
            crossbeam_channel::RecvTimeoutError::Timeout => WireGuardError::Timeout,
            crossbeam_channel::RecvTimeoutError::Disconnected => {
                WireGuardError::Channel("Channel disconnected".into())
            }
        }
    }
}

pub type Result<T> = std::result::Result<T, WireGuardError>;
