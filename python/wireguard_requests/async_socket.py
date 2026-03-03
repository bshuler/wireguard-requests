"""Asyncio-compatible WireGuard socket wrapper.

Provides `AsyncWireGuardSocket` for use with asyncio-based libraries.
The async wrapper runs blocking Rust I/O calls in a thread executor
so they don't block the event loop.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Optional, Tuple

if TYPE_CHECKING:
    from . import _native


class AsyncWireGuardSocket:
    """An asyncio-compatible socket that tunnels through WireGuard.

    All I/O operations are run in a thread executor to avoid blocking
    the asyncio event loop.

    Example:
        tunnel = WgTunnel(config)
        sock = AsyncWireGuardSocket(tunnel)
        await sock.connect(("example.com", 80))
        await sock.send(b"GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
        data = await sock.recv(4096)
        await sock.close()
    """

    def __init__(
        self,
        tunnel: _native.WgTunnel,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self._tunnel = tunnel
        self._stream: Optional[_native.WgStream] = None
        self._remote_addr: Optional[Tuple[str, int]] = None
        self._loop = loop
        self._closed = False

    def _get_loop(self) -> asyncio.AbstractEventLoop:
        if self._loop is not None:
            return self._loop
        return asyncio.get_running_loop()

    async def connect(self, address: Tuple[str, int]) -> None:
        """Connect to a remote host through the WireGuard tunnel.

        Args:
            address: (host, port) tuple.
        """
        if self._stream is not None:
            raise OSError("Already connected")
        if self._closed:
            raise OSError("Socket is closed")

        host, port = address
        self._remote_addr = address

        loop = self._get_loop()
        self._stream = await loop.run_in_executor(
            None, self._tunnel.create_stream, host, port
        )

    async def send(self, data: bytes) -> int:
        """Send data through the tunnel.

        Args:
            data: Bytes to send.

        Returns:
            Number of bytes sent.
        """
        if self._stream is None:
            raise OSError("Not connected")

        loop = self._get_loop()
        return await loop.run_in_executor(None, self._stream.send, data)

    async def sendall(self, data: bytes) -> None:
        """Send all data through the tunnel."""
        if self._stream is None:
            raise OSError("Not connected")

        loop = self._get_loop()
        await loop.run_in_executor(None, self._stream.sendall, data)

    async def recv(self, bufsize: int) -> bytes:
        """Receive data from the tunnel.

        Args:
            bufsize: Maximum number of bytes to receive.

        Returns:
            Bytes received. Empty bytes means connection closed.
        """
        if self._stream is None:
            raise OSError("Not connected")

        loop = self._get_loop()
        return await loop.run_in_executor(None, self._stream.recv, bufsize)

    async def close(self) -> None:
        """Close the connection."""
        if self._closed:
            return
        self._closed = True
        if self._stream is not None:
            loop = self._get_loop()
            await loop.run_in_executor(None, self._stream.close)
            self._stream = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()

    def __repr__(self) -> str:
        state = "connected" if self._stream else "idle"
        return f"<AsyncWireGuardSocket {state} remote={self._remote_addr}>"
