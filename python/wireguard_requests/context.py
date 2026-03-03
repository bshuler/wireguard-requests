"""Context manager for transparent WireGuard tunneling.

Provides `wireguard_context()` which monkeypatches `socket.socket` so that
all TCP connections in the block go through a WireGuard tunnel. This enables
any Python library that uses sockets (requests, urllib3, httpx, etc.) to
transparently tunnel through WireGuard.
"""

from __future__ import annotations

import socket as stdlib_socket
from contextlib import contextmanager
from typing import Iterator, Optional, Type

from .config import WireGuardConfig
from .socket import WireGuardSocket

_original_socket_class: Optional[Type] = None


@contextmanager
def wireguard_context(config: WireGuardConfig) -> Iterator[object]:
    """Context manager that routes all TCP connections through WireGuard.

    Monkeypatches `socket.socket` so that any AF_INET + SOCK_STREAM socket
    creation returns a WireGuardSocket instead. Non-TCP sockets (UDP, Unix,
    etc.) continue to use the real socket implementation.

    The tunnel is created on entry and closed on exit.

    Args:
        config: WireGuard configuration (from .conf file or manual).

    Yields:
        The WgTunnel instance (in case you need direct access).

    Example:
        config = WireGuardConfig.from_file("wg0.conf")
        with wireguard_context(config):
            import requests
            # This HTTP request goes through the WireGuard tunnel!
            r = requests.get("https://ifconfig.me")
            print(r.text)
    """
    global _original_socket_class

    # Create the Rust tunnel (import lazily to avoid import-time dependency).
    from . import _native

    native_config = config.to_native()
    tunnel = _native.WgTunnel(native_config)

    # Save the original socket class.
    _original_socket_class = stdlib_socket.socket

    # Create a factory that intercepts TCP socket creation.
    original = _original_socket_class

    class PatchedSocket(original):
        """socket.socket subclass that intercepts TCP connections."""

        def __new__(
            cls,
            family: int = stdlib_socket.AF_INET,
            type: int = stdlib_socket.SOCK_STREAM,
            proto: int = 0,
            fileno=None,
        ):
            # Only intercept AF_INET + SOCK_STREAM (TCP over IPv4).
            if (
                family == stdlib_socket.AF_INET
                and (type & stdlib_socket.SOCK_STREAM)
                and fileno is None
            ):
                return WireGuardSocket(tunnel)
            # Everything else (UDP, Unix, IPv6, etc.) uses real sockets.
            return original(family, type, proto, fileno)

    # Apply the monkeypatch.
    stdlib_socket.socket = PatchedSocket

    try:
        yield tunnel
    finally:
        # Restore original socket class.
        stdlib_socket.socket = original
        _original_socket_class = None

        # Shut down the tunnel.
        tunnel.close()
