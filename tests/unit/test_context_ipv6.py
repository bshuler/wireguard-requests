"""Unit tests for IPv6 socket interception in wireguard_context."""

import socket as stdlib_socket
import sys
from unittest.mock import MagicMock

import pytest
from wireguard_requests.config import Peer, WireGuardConfig
from wireguard_requests.socket import WireGuardSocket


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


class TestWireguardContextIPv6:
    def test_ipv4_tcp_intercepted(self, mock_native, mock_config):
        from wireguard_requests.context import wireguard_context

        with wireguard_context(mock_config) as tunnel:
            s = stdlib_socket.socket(stdlib_socket.AF_INET, stdlib_socket.SOCK_STREAM)
            assert isinstance(s, WireGuardSocket)

    def test_ipv6_tcp_intercepted(self, mock_native, mock_config):
        from wireguard_requests.context import wireguard_context

        with wireguard_context(mock_config) as tunnel:
            s = stdlib_socket.socket(stdlib_socket.AF_INET6, stdlib_socket.SOCK_STREAM)
            assert isinstance(s, WireGuardSocket)

    def test_udp_not_intercepted(self, mock_native, mock_config):
        from wireguard_requests.context import wireguard_context

        with wireguard_context(mock_config) as tunnel:
            s = stdlib_socket.socket(stdlib_socket.AF_INET, stdlib_socket.SOCK_DGRAM)
            assert not isinstance(s, WireGuardSocket)
            s.close()

    def test_ipv6_udp_not_intercepted(self, mock_native, mock_config):
        from wireguard_requests.context import wireguard_context

        with wireguard_context(mock_config) as tunnel:
            s = stdlib_socket.socket(stdlib_socket.AF_INET6, stdlib_socket.SOCK_DGRAM)
            assert not isinstance(s, WireGuardSocket)
            s.close()
