import socket as stdlib_socket
from unittest.mock import MagicMock, patch

import pytest
from wireguard_requests.socket import WireGuardSocket


@pytest.fixture
def mock_tunnel():
    tunnel = MagicMock()
    stream = MagicMock()
    tunnel.create_stream.return_value = stream
    return tunnel


@pytest.fixture
def sock(mock_tunnel):
    s = WireGuardSocket(mock_tunnel)
    s.connect(("example.com", 443))
    return s


class TestWrapTls:
    def test_wrap_tls_default_context(self, sock):
        """wrap_tls with default context creates a WireGuardTlsSocket."""
        mock_context = MagicMock()
        with patch("ssl.create_default_context", return_value=mock_context):
            tls = sock.wrap_tls("example.com")
        from wireguard_requests.tls import WireGuardTlsSocket

        assert isinstance(tls, WireGuardTlsSocket)
        mock_context.wrap_bio.assert_called_once()

    def test_wrap_tls_custom_context(self, sock):
        """wrap_tls with custom context passes it through."""
        mock_context = MagicMock()
        tls = sock.wrap_tls("example.com", context=mock_context)
        from wireguard_requests.tls import WireGuardTlsSocket

        assert isinstance(tls, WireGuardTlsSocket)
        mock_context.wrap_bio.assert_called_once()

    def test_socket_family_ipv4(self, mock_tunnel):
        s = WireGuardSocket(mock_tunnel)
        s.connect(("93.184.216.34", 443))
        assert s.family == stdlib_socket.AF_INET

    def test_socket_family_ipv6(self, mock_tunnel):
        s = WireGuardSocket(mock_tunnel)
        s.connect(("::1", 443))
        assert s.family == stdlib_socket.AF_INET6
