"""Unit tests for AsyncWireGuardSocket."""

import asyncio
from unittest.mock import MagicMock

import pytest

from wireguard_requests.async_socket import AsyncWireGuardSocket


@pytest.fixture
def mock_tunnel():
    tunnel = MagicMock()
    stream = MagicMock()
    stream.send.return_value = 5
    stream.recv.return_value = b"hello"
    tunnel.create_stream.return_value = stream
    return tunnel


@pytest.mark.asyncio
async def test_async_connect(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    await sock.connect(("example.com", 80))
    mock_tunnel.create_stream.assert_called_once_with("example.com", 80)


@pytest.mark.asyncio
async def test_async_send(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    await sock.connect(("example.com", 80))
    n = await sock.send(b"hello")
    assert n == 5


@pytest.mark.asyncio
async def test_async_recv(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    await sock.connect(("example.com", 80))
    data = await sock.recv(1024)
    assert data == b"hello"


@pytest.mark.asyncio
async def test_async_close(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    await sock.connect(("example.com", 80))
    await sock.close()
    mock_tunnel.create_stream.return_value.close.assert_called_once()


@pytest.mark.asyncio
async def test_async_close_idempotent(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    await sock.connect(("example.com", 80))
    await sock.close()
    await sock.close()  # Should not raise.


@pytest.mark.asyncio
async def test_async_context_manager(mock_tunnel):
    async with AsyncWireGuardSocket(mock_tunnel) as sock:
        await sock.connect(("example.com", 80))
    mock_tunnel.create_stream.return_value.close.assert_called()


@pytest.mark.asyncio
async def test_async_connect_twice_raises(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    await sock.connect(("example.com", 80))
    with pytest.raises(OSError, match="Already connected"):
        await sock.connect(("example.com", 443))


@pytest.mark.asyncio
async def test_async_send_before_connect(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    with pytest.raises(OSError, match="Not connected"):
        await sock.send(b"hello")


@pytest.mark.asyncio
async def test_async_repr(mock_tunnel):
    sock = AsyncWireGuardSocket(mock_tunnel)
    assert "idle" in repr(sock)
    await sock.connect(("example.com", 80))
    assert "connected" in repr(sock)
