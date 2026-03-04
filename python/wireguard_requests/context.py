"""Context manager for transparent WireGuard tunneling.

Provides `wireguard_context()` which monkeypatches `socket.socket` so that
all TCP connections in the block go through a WireGuard tunnel. This enables
any Python library that uses sockets (requests, urllib3, httpx, etc.) to
transparently tunnel through WireGuard.
"""

from __future__ import annotations

import socket as stdlib_socket
import ssl as stdlib_ssl
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

    Also monkeypatches `ssl.SSLContext.wrap_socket` so that when libraries
    like urllib3/requests wrap a WireGuardSocket with TLS, we use memory
    BIOs instead of requiring a real file descriptor.

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
    from .tls import WireGuardTlsSocket

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
            # Intercept TCP sockets for both IPv4 and IPv6 — the Rust side
            # handles address resolution and picks the right family.
            if (
                family in (stdlib_socket.AF_INET, stdlib_socket.AF_INET6)
                and (type & stdlib_socket.SOCK_STREAM)
                and fileno is None
            ):
                return WireGuardSocket(tunnel)
            # Everything else (UDP, Unix, etc.) uses real sockets.
            return original(family, type, proto, fileno)

    # Monkeypatch ssl.SSLContext.wrap_socket to handle WireGuardSocket.
    # urllib3 calls ctx.wrap_socket(sock, server_hostname=host) which
    # fails because ssl needs a real fd. We intercept and use memory BIOs.
    original_wrap_socket = stdlib_ssl.SSLContext.wrap_socket

    def patched_wrap_socket(self, sock, *args, **kwargs):
        if isinstance(sock, WireGuardSocket):
            server_hostname = kwargs.get("server_hostname")
            return WireGuardTlsSocket(
                sock,
                self,
                server_hostname=server_hostname,
            )
        return original_wrap_socket(self, sock, *args, **kwargs)

    # Apply the monkeypatches.
    stdlib_socket.socket = PatchedSocket
    stdlib_ssl.SSLContext.wrap_socket = patched_wrap_socket

    try:
        yield tunnel
    finally:
        # Restore originals.
        stdlib_socket.socket = original
        stdlib_ssl.SSLContext.wrap_socket = original_wrap_socket
        _original_socket_class = None

        # Shut down the tunnel.
        tunnel.close()
