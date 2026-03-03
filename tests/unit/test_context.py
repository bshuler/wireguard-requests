"""Unit tests for wireguard_context monkeypatching."""

import socket as stdlib_socket
import sys
from unittest.mock import MagicMock

import pytest
from wireguard_requests.config import Peer, WireGuardConfig


@pytest.fixture
def mock_config():
    return WireGuardConfig(
        private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
        address="10.0.0.2",
        peers=[
            Peer(
                public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                endpoint="203.0.113.1:51820",
            )
        ],
    )


@pytest.fixture(autouse=True)
def mock_native():
    """Inject a fake _native module so context.py can 'from . import _native'."""
    mock_mod = MagicMock()
    mock_tunnel = MagicMock()
    mock_mod.WgTunnel.return_value = mock_tunnel
    mock_mod.WgPeer = MagicMock
    mock_mod.WgConfig = MagicMock

    key = "wireguard_requests._native"
    old = sys.modules.get(key)
    sys.modules[key] = mock_mod

    yield mock_mod, mock_tunnel

    if old is None:
        sys.modules.pop(key, None)
    else:
        sys.modules[key] = old


class TestWireguardContext:
    def test_socket_restored_after_context(self, mock_native, mock_config):
        """socket.socket should be restored to original after context exits."""
        original_socket = stdlib_socket.socket

        from wireguard_requests.context import wireguard_context

        with wireguard_context(mock_config):
            assert stdlib_socket.socket is not original_socket

        assert stdlib_socket.socket is original_socket

    def test_socket_restored_on_exception(self, mock_native, mock_config):
        """socket.socket should be restored even if an exception occurs."""
        original_socket = stdlib_socket.socket

        from wireguard_requests.context import wireguard_context

        with pytest.raises(RuntimeError):
            with wireguard_context(mock_config):
                raise RuntimeError("test error")

        assert stdlib_socket.socket is original_socket

    def test_tunnel_closed_on_exit(self, mock_native, mock_config):
        """Tunnel should be closed when context exits."""
        _, mock_tunnel = mock_native

        from wireguard_requests.context import wireguard_context

        with wireguard_context(mock_config) as _tunnel:
            pass

        mock_tunnel.close.assert_called_once()
