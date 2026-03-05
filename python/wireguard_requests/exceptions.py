"""Exception hierarchy for wireguard-requests."""

from __future__ import annotations


class WireGuardError(Exception):
    """Base exception for all wireguard-requests errors."""


class ConfigError(WireGuardError):
    """Error parsing WireGuard configuration."""


class TunnelError(WireGuardError):
    """Error during tunnel lifecycle (creation, polling, shutdown)."""


class StreamError(WireGuardError):
    """Error during stream I/O (connect, send, recv)."""


class TunnelClosedError(TunnelError):
    """Raised when attempting to use a closed tunnel."""


class StreamClosedError(StreamError):
    """Raised when attempting to use a closed stream."""


class NatPmpError(WireGuardError):
    """Error from NAT-PMP port mapping protocol."""

    def __init__(self, message: str, *, result_code: int | None = None) -> None:
        super().__init__(message)
        self.result_code: int | None = result_code


class NatPmpTimeoutError(NatPmpError):
    """NAT-PMP request timed out."""


class NatPmpUnsupportedError(NatPmpError):
    """NAT-PMP not supported by the gateway."""
