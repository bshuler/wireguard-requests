"""Exception hierarchy for wireguard-requests."""


class WireGuardError(Exception):
    """Base exception for all wireguard-requests errors."""

    pass


class ConfigError(WireGuardError):
    """Error parsing WireGuard configuration."""

    pass


class TunnelError(WireGuardError):
    """Error during tunnel lifecycle (creation, polling, shutdown)."""

    pass


class StreamError(WireGuardError):
    """Error during stream I/O (connect, send, recv)."""

    pass


class TunnelClosedError(TunnelError):
    """Raised when attempting to use a closed tunnel."""

    pass


class StreamClosedError(StreamError):
    """Raised when attempting to use a closed stream."""

    pass
