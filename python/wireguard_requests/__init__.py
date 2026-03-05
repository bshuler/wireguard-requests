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

from __future__ import annotations

from .config import Peer, WireGuardConfig
from .exceptions import (
    ConfigError,
    NatPmpError,
    NatPmpTimeoutError,
    NatPmpUnsupportedError,
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

        globals()["WireGuardSocket"] = WireGuardSocket
        return WireGuardSocket
    if name == "WireGuardUdpSocket":
        from .udp_socket import WireGuardUdpSocket

        globals()["WireGuardUdpSocket"] = WireGuardUdpSocket
        return WireGuardUdpSocket
    if name == "AsyncWireGuardSocket":
        from .async_socket import AsyncWireGuardSocket

        globals()["AsyncWireGuardSocket"] = AsyncWireGuardSocket
        return AsyncWireGuardSocket
    if name == "wireguard_context":
        from .context import wireguard_context

        globals()["wireguard_context"] = wireguard_context
        return wireguard_context
    if name == "create_session":
        from .session import create_session

        globals()["create_session"] = create_session
        return create_session
    if name == "NatPmpClient":
        from .natpmp import NatPmpClient

        globals()["NatPmpClient"] = NatPmpClient
        return NatPmpClient
    if name == "ExternalAddressResponse":
        from .natpmp import ExternalAddressResponse

        globals()["ExternalAddressResponse"] = ExternalAddressResponse
        return ExternalAddressResponse
    if name == "PortMappingResponse":
        from .natpmp import PortMappingResponse

        globals()["PortMappingResponse"] = PortMappingResponse
        return PortMappingResponse
    if name == "NatPmpOpcode":
        from .natpmp import NatPmpOpcode

        globals()["NatPmpOpcode"] = NatPmpOpcode
        return NatPmpOpcode
    if name == "NatPmpResultCode":
        from .natpmp import NatPmpResultCode

        globals()["NatPmpResultCode"] = NatPmpResultCode
        return NatPmpResultCode
    if name == "NATPMP_PORT":
        from .natpmp import NATPMP_PORT

        globals()["NATPMP_PORT"] = NATPMP_PORT
        return NATPMP_PORT
    if name == "NATPMP_VERSION":
        from .natpmp import NATPMP_VERSION

        globals()["NATPMP_VERSION"] = NATPMP_VERSION
        return NATPMP_VERSION
    if name == "UdpSocketLike":
        from .natpmp import UdpSocketLike

        globals()["UdpSocketLike"] = UdpSocketLike
        return UdpSocketLike
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
    # NAT-PMP
    "NatPmpClient",
    "ExternalAddressResponse",
    "PortMappingResponse",
    "NatPmpOpcode",
    "NatPmpResultCode",
    "NATPMP_PORT",
    "NATPMP_VERSION",
    "UdpSocketLike",
    # NAT-PMP Exceptions
    "NatPmpError",
    "NatPmpTimeoutError",
    "NatPmpUnsupportedError",
]
