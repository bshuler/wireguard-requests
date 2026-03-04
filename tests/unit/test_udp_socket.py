import socket as stdlib_socket
from unittest.mock import MagicMock

import pytest
from wireguard_requests.udp_socket import WireGuardUdpSocket


@pytest.fixture
def mock_udp_native():
    native = MagicMock()
    native.recv_from.return_value = (b"response", ("10.0.0.1", 9999))
    return native


@pytest.fixture
def udp_sock(mock_udp_native):
    return WireGuardUdpSocket(mock_udp_native)


class TestWireGuardUdpSocket:
    def test_initial_state(self, udp_sock):
        assert udp_sock.fileno() == -1
        assert udp_sock.family == stdlib_socket.AF_INET
        assert udp_sock.type == stdlib_socket.SOCK_DGRAM
        assert udp_sock.gettimeout() is None

    def test_sendto(self, udp_sock, mock_udp_native):
        data = b"hello udp"
        n = udp_sock.sendto(data, ("10.0.0.1", 9999))
        assert n == len(data)
        mock_udp_native.send_to.assert_called_once_with(data, ("10.0.0.1", 9999))

    def test_recvfrom(self, udp_sock, mock_udp_native):
        data, addr = udp_sock.recvfrom(4096)
        assert data == b"response"
        assert addr == ("10.0.0.1", 9999)
        mock_udp_native.recv_from.assert_called_once_with(4096)

    def test_sendto_closed_raises(self, udp_sock):
        udp_sock.close()
        with pytest.raises(OSError):
            udp_sock.sendto(b"hello", ("10.0.0.1", 9999))

    def test_recvfrom_closed_raises(self, udp_sock):
        udp_sock.close()
        with pytest.raises(OSError):
            udp_sock.recvfrom(4096)

    def test_close_idempotent(self, udp_sock, mock_udp_native):
        udp_sock.close()
        udp_sock.close()  # Should not raise.
        mock_udp_native.close.assert_called_once()

    def test_settimeout(self, udp_sock, mock_udp_native):
        udp_sock.settimeout(3.0)
        assert udp_sock.gettimeout() == 3.0
        mock_udp_native.set_timeout.assert_called_with(3.0)

    def test_context_manager(self, mock_udp_native):
        with WireGuardUdpSocket(mock_udp_native) as sock:
            sock.sendto(b"ping", ("10.0.0.1", 9999))
        mock_udp_native.close.assert_called_once()

    def test_repr_open(self, udp_sock):
        assert "open" in repr(udp_sock)

    def test_repr_closed(self, udp_sock):
        udp_sock.close()
        assert "closed" in repr(udp_sock)
