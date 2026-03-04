"""UDP socket wrapper for WireGuard tunnel.

WireGuardUdpSocket provides a socket.socket-like API for UDP (SOCK_DGRAM)
datagrams through the WireGuard tunnel. Unlike TCP, UDP sockets are NOT
monkeypatched — they must be created explicitly via tunnel.create_udp_socket().
"""

from __future__ import annotations

import socket as stdlib_socket
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from . import _native


class WireGuardUdpSocket:
    """A UDP socket that tunnels datagrams through WireGuard.

    Must be created explicitly — NOT via monkeypatch:

        with wireguard_context(config) as tunnel:
            udp = tunnel.create_udp_socket(0)
            udp.sendto(b"hello", ("10.0.0.1", 9999))
            data, addr = udp.recvfrom(4096)

    UDP is intentionally excluded from the monkeypatch because many system
    services (DNS resolvers, NTP, etc.) use UDP and should not be redirected
    through the tunnel automatically.
    """

    # Class-level constants matching socket module.
    AF_INET = stdlib_socket.AF_INET
    AF_INET6 = stdlib_socket.AF_INET6
    SOCK_DGRAM = stdlib_socket.SOCK_DGRAM

    def __init__(self, native_udp_socket: _native.WgUdpSocket):
        self._socket = native_udp_socket
        self._timeout: Optional[float] = None
        self._closed = False

    def sendto(self, data: bytes, address: Tuple[str, int]) -> int:
        """Send a datagram to the given address.

        Args:
            data: Bytes to send.
            address: (host, port) destination tuple.

        Returns:
            Number of bytes sent (always len(data) on success).
        """
        if self._closed:
            raise OSError("Socket is closed")
        self._socket.send_to(data, address)
        return len(data)

    def recvfrom(self, bufsize: int) -> Tuple[bytes, Tuple[str, int]]:
        """Receive a datagram and the sender's address.

        Args:
            bufsize: Maximum number of bytes to receive.

        Returns:
            (data, (host, port)) tuple.
        """
        if self._closed:
            raise OSError("Socket is closed")
        data, addr = self._socket.recv_from(bufsize)
        return bytes(data), addr

    def close(self) -> None:
        """Close the UDP socket and release resources."""
        if self._closed:
            return
        self._closed = True
        self._socket.close()

    def settimeout(self, timeout: Optional[float]) -> None:
        """Set the socket timeout in seconds (None for blocking)."""
        self._timeout = timeout
        self._socket.set_timeout(timeout)

    def gettimeout(self) -> Optional[float]:
        """Return the current socket timeout."""
        return self._timeout

    def fileno(self) -> int:
        """Return -1 — WireGuard UDP sockets have no real file descriptor."""
        return -1

    @property
    def family(self) -> int:
        return stdlib_socket.AF_INET

    @property
    def type(self) -> int:
        return stdlib_socket.SOCK_DGRAM

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"<WireGuardUdpSocket {state}>"
