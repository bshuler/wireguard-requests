"""Drop-in socket.socket replacement that tunnels through WireGuard.

WireGuardSocket implements the same interface as socket.socket for
TCP (AF_INET, SOCK_STREAM) connections. When used as a replacement,
all TCP traffic is transparently routed through a WireGuard tunnel.
"""

from __future__ import annotations

import io
import socket as stdlib_socket
from typing import TYPE_CHECKING, Any, Optional, Tuple

if TYPE_CHECKING:
    from . import _native


class WireGuardSocket:
    """A socket-like object that tunnels TCP through WireGuard.

    Implements the essential subset of the socket.socket API used by
    urllib3, requests, httpx, and other HTTP libraries.

    Not a true subclass of socket.socket because we don't create a
    real file descriptor — all I/O goes through the Rust tunnel.
    """

    # Class-level constants matching socket module.
    AF_INET = stdlib_socket.AF_INET
    AF_INET6 = stdlib_socket.AF_INET6
    SOCK_STREAM = stdlib_socket.SOCK_STREAM

    def __init__(self, tunnel: _native.WgTunnel):
        self._tunnel = tunnel
        self._stream: Optional[_native.WgStream] = None
        self._remote_addr: Optional[Tuple[str, int]] = None
        self._timeout: Optional[float] = None
        self._closed = False
        self._makefile_refs = 0

    def connect(self, address: Tuple[str, int]) -> None:
        """Connect to a remote host through the WireGuard tunnel.

        Args:
            address: (host, port) tuple. Host can be a hostname or IP.
        """
        if self._stream is not None:
            raise OSError("Already connected")
        if self._closed:
            raise OSError("Socket is closed")

        host, port = address
        self._remote_addr = address
        self._stream = self._tunnel.create_stream(host, port)

    def send(self, data: bytes, flags: int = 0) -> int:
        """Send data through the tunnel.

        Args:
            data: Bytes to send.
            flags: Ignored (present for API compatibility).

        Returns:
            Number of bytes sent.
        """
        if self._stream is None:
            raise OSError("Not connected")
        return self._stream.send(data)

    def sendall(self, data: bytes, flags: int = 0) -> None:
        """Send all data through the tunnel.

        Blocks until all bytes are sent or an error occurs.
        """
        if self._stream is None:
            raise OSError("Not connected")
        self._stream.sendall(data)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        """Receive data from the tunnel.

        Args:
            bufsize: Maximum number of bytes to receive.
            flags: Ignored (present for API compatibility).

        Returns:
            Bytes received. Empty bytes means the peer closed the connection.
        """
        if self._stream is None:
            if self._closed:
                return b""
            raise OSError("Not connected")
        return bytes(self._stream.recv(bufsize))

    def recv_into(self, buffer: bytearray, nbytes: int = 0, flags: int = 0) -> int:
        """Receive data into a pre-allocated buffer."""
        data = self.recv(nbytes or len(buffer), flags)
        n = len(data)
        buffer[:n] = data
        return n

    def close(self) -> None:
        """Close the connection.

        If makefile() wrappers are still active, defer stream destruction
        until the last wrapper closes — matching real socket fd ref-counting.
        """
        if self._closed:
            return
        self._closed = True
        if self._makefile_refs < 1 and self._stream is not None:
            self._stream.close()
            self._stream = None

    def _decref_socketios(self) -> None:
        """Called by _SocketFileWrapper.close() to decrement makefile refs."""
        self._makefile_refs -= 1
        if self._closed and self._makefile_refs < 1 and self._stream is not None:
            self._stream.close()
            self._stream = None

    def shutdown(self, how: int) -> None:
        """Shut down the connection.

        For WireGuard sockets, this is equivalent to close().
        """
        self.close()

    def settimeout(self, timeout: Optional[float]) -> None:
        """Set socket timeout."""
        self._timeout = timeout
        if self._stream is not None:
            self._stream.set_timeout(timeout)

    def gettimeout(self) -> Optional[float]:
        """Get socket timeout."""
        return self._timeout

    def setblocking(self, flag: bool) -> None:
        """Set blocking/non-blocking mode."""
        if flag:
            self.settimeout(None)
        else:
            self.settimeout(0.0)

    def setsockopt(self, level: int, optname: int, value: Any) -> None:
        """Set socket option (no-op for WireGuard sockets)."""
        # Silently ignore socket options — they don't apply to our tunnel.
        pass

    def getsockopt(self, level: int, optname: int, buflen: int = 0) -> int:
        """Get socket option (stub)."""
        return 0

    def getsockname(self) -> Tuple[str, int]:
        """Get the local address of the socket."""
        # Return the tunnel's IP with an ephemeral port.
        return ("0.0.0.0", 0)

    def getpeername(self) -> Tuple[str, int]:
        """Get the remote address of the socket."""
        if self._remote_addr is None:
            raise OSError("Not connected")
        return self._remote_addr

    def fileno(self) -> int:
        """Return the file descriptor.

        Returns -1 since we don't use real file descriptors.
        Note: Some libraries check fileno() — returning -1 signals
        that select/poll won't work, which is correct for our case.
        """
        return -1

    def makefile(self, mode: str = "r", buffering: int = -1, **kwargs) -> io.IOBase:
        """Create a file-like object for the socket.

        This is used by http.client.HTTPConnection for reading responses.
        Increments a reference counter so that close() defers stream
        destruction until all makefile wrappers are closed.
        """
        if "b" not in mode:
            mode = mode + "b"

        self._makefile_refs += 1
        raw = _SocketFileWrapper(self)

        if buffering == 0 or ("b" in mode and buffering < 0):
            return raw

        if buffering < 0:
            buffering = io.DEFAULT_BUFFER_SIZE

        if "r" in mode:
            return io.BufferedReader(raw, buffer_size=buffering)
        elif "w" in mode:
            return io.BufferedWriter(raw, buffer_size=buffering)
        else:
            return io.BufferedRWPair(raw, raw, buffer_size=buffering)

    @property
    def family(self) -> int:
        # Report the correct address family based on the connected address.
        if self._remote_addr is not None and ":" in self._remote_addr[0]:
            return stdlib_socket.AF_INET6
        return stdlib_socket.AF_INET

    @property
    def type(self) -> int:
        return stdlib_socket.SOCK_STREAM

    @property
    def proto(self) -> int:
        return 0

    def wrap_tls(self, hostname: str, context=None):
        """Wrap this socket with TLS for HTTPS communication.

        Uses memory BIOs (ssl.MemoryBIO + ssl.SSLObject) since we don't
        have a real file descriptor that ssl.wrap_socket() requires.

        Args:
            hostname: Server hostname for SNI and certificate verification.
            context: Optional ssl.SSLContext. Uses the default secure context if None.

        Returns:
            WireGuardTlsSocket wrapping this WireGuard socket.

        Example:
            with wireguard_context(config) as tunnel:
                sock = WireGuardSocket(tunnel)
                sock.connect(("example.com", 443))
                tls = sock.wrap_tls("example.com")
                tls.sendall(b"GET / HTTP/1.0\\r\\nHost: example.com\\r\\n\\r\\n")
        """
        import ssl

        from .tls import WireGuardTlsSocket

        if context is None:
            context = ssl.create_default_context()
        return WireGuardTlsSocket(self, context, server_hostname=hostname)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def __repr__(self) -> str:
        state = "connected" if self._stream else "idle"
        return f"<WireGuardSocket {state} remote={self._remote_addr}>"


class _SocketFileWrapper(io.RawIOBase):
    """Wraps a WireGuardSocket as an io.RawIOBase for makefile() support.

    This is needed because http.client reads from a file-like object,
    not directly from the socket.
    """

    def __init__(self, sock: WireGuardSocket):
        self._sock = sock

    def readinto(self, b: bytearray) -> int:
        data = self._sock.recv(len(b))
        n = len(data)
        b[:n] = data
        return n

    def write(self, b: bytes) -> int:
        self._sock.sendall(b)
        return len(b)

    def readable(self) -> bool:
        return True

    def writable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._sock.fileno()

    def close(self) -> None:
        if not self.closed:
            super().close()
            self._sock._decref_socketios()
