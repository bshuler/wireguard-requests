"""wireguard-requests: Transparent WireGuard tunneling for Python.

Drop-in socket replacement that routes TCP traffic through a WireGuard
tunnel without installing WireGuard on the operating system.

Quick Start:
    from wireguard_requests import WireGuardConfig, wireguard_context
    import requests

    config = WireGuardConfig.from_file("wg0.conf")
    with wireguard_context(config):
        # All TCP traffic now goes through the WireGuard tunnel.
        r = requests.get("https://ifconfig.me")
        print(r.text)
"""

from .config import Peer, WireGuardConfig
from .exceptions import (
    ConfigError,
    StreamClosedError,
    StreamError,
    TunnelClosedError,
    TunnelError,
    WireGuardError,
)


def __getattr__(name):
    """Lazy imports for components that depend on the native Rust module."""
    if name == "WireGuardSocket":
        from .socket import WireGuardSocket

        return WireGuardSocket
    if name == "WireGuardUdpSocket":
        from .udp_socket import WireGuardUdpSocket

        return WireGuardUdpSocket
    if name == "AsyncWireGuardSocket":
        from .async_socket import AsyncWireGuardSocket

        return AsyncWireGuardSocket
    if name == "wireguard_context":
        from .context import wireguard_context

        return wireguard_context
    if name == "create_session":
        from .session import create_session

        return create_session
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__version__ = "0.0.2"

__all__ = [
    # Core
    "WireGuardSocket",
    "WireGuardUdpSocket",
    "AsyncWireGuardSocket",
    "WireGuardConfig",
    "Peer",
    # Convenience
    "wireguard_context",
    "create_session",
    # Exceptions
    "WireGuardError",
    "ConfigError",
    "TunnelError",
    "TunnelClosedError",
    "StreamError",
    "StreamClosedError",
]
