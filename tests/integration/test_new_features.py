"""Integration tests for new protocol features.

Tests: IPv6 config parsing, UDP tunneling, DNS through tunnel, TLS wrap.
Run with: pytest tests/integration -v -m integration
"""

import pytest

pytestmark = pytest.mark.integration


def _udp_send_recv(udp, msg, dest, retries=3, timeout=10.0):
    """Send a UDP datagram and receive the response with retry logic.

    The first packet on a fresh WireGuard tunnel triggers a handshake that
    may cause the initial datagram to be lost.  Retrying handles this.
    """
    udp.settimeout(timeout)
    for attempt in range(retries):
        udp.sendto(msg, dest)
        try:
            return udp.recvfrom(4096)
        except TimeoutError:
            if attempt == retries - 1:
                raise


class TestUdpTunneling:
    def test_udp_echo(self, wg_config):
        """Send a UDP datagram through tunnel and receive echo response."""
        from wireguard_requests import WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                data, addr = _udp_send_recv(udp, b"hello-wg", ("10.13.13.1", 9999))
                assert data == b"ECHO:hello-wg"
            finally:
                udp.close()

    def test_udp_multiple_datagrams(self, wg_config):
        """Send multiple UDP datagrams through tunnel."""
        from wireguard_requests import WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                # Warm-up probe: first datagram triggers WireGuard handshake.
                _udp_send_recv(udp, b"warmup", ("10.13.13.1", 9999))
                for i in range(3):
                    msg = f"msg-{i}".encode()
                    data, addr = _udp_send_recv(udp, msg, ("10.13.13.1", 9999))
                    assert data == b"ECHO:" + msg
            finally:
                udp.close()

    def test_udp_context_manager(self, wg_config):
        """Test UDP socket as context manager."""
        from wireguard_requests import WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            with WireGuardUdpSocket(native_udp) as udp:
                data, _ = _udp_send_recv(udp, b"ctx-test", ("10.13.13.1", 9999))
                assert data == b"ECHO:ctx-test"


class TestDnsResolution:
    def test_resolve_through_tunnel(self, wg_config_with_dns):
        """Resolve a hostname through the tunnel's DNS server."""
        from wireguard_requests import wireguard_context

        with wireguard_context(wg_config_with_dns) as tunnel:
            ip = tunnel.resolve_dns("test.wg.local")
            assert ip == "10.13.13.1"

    def test_http_via_resolved_ip(self, wg_config_with_dns):
        """Resolve DNS through tunnel, then make HTTP request to the IP."""
        from wireguard_requests import wireguard_context

        try:
            import requests
        except ImportError:
            pytest.skip("requests not installed")

        with wireguard_context(wg_config_with_dns) as tunnel:
            # Resolve hostname through tunnel DNS
            ip = tunnel.resolve_dns("test.wg.local")
            assert ip == "10.13.13.1"
            # Use the resolved IP for the HTTP request
            response = requests.get(f"http://{ip}:8080/dns-test", timeout=10)
            assert response.status_code == 200
            data = response.json()
            assert data["path"] == "/dns-test"

    def test_create_stream_with_hostname(self, wg_config_with_dns):
        """Test that create_stream resolves hostnames via tunnel DNS."""
        from wireguard_requests import WireGuardSocket, wireguard_context

        with wireguard_context(wg_config_with_dns) as tunnel:
            sock = WireGuardSocket(tunnel)
            # connect() calls create_stream which uses tunnel DNS
            sock.connect(("test.wg.local", 8080))
            try:
                sock.sendall(b"GET /dns-stream HTTP/1.0\r\nHost: test.wg.local\r\n\r\n")
                response = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                assert b"200 OK" in response
                assert b"/dns-stream" in response
            finally:
                sock.close()


class TestTlsWrap:
    def test_wrap_tls_raw_socket(self, wg_config):
        """Test TLS connection via wrap_tls on a raw WireGuardSocket."""
        import ssl

        from wireguard_requests import WireGuardSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            sock = WireGuardSocket(tunnel)
            sock.connect(("10.13.13.1", 8443))
            # Use a custom SSL context that skips verification (self-signed cert).
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            tls_sock = sock.wrap_tls("10.13.13.1", context=ctx)
            try:
                tls_sock.sendall(b"GET /tls-test HTTP/1.0\r\nHost: 10.13.13.1\r\n\r\n")
                response = b""
                while True:
                    chunk = tls_sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                assert b"200 OK" in response
                assert b'"tls": true' in response
            finally:
                tls_sock.close()
                sock.close()

    def test_https_via_requests(self, wg_config):
        """Test HTTPS via requests library (which handles TLS automatically)."""
        try:
            import requests
            import urllib3
        except ImportError:
            pytest.skip("requests not installed")

        from wireguard_requests import wireguard_context

        # Suppress InsecureRequestWarning for self-signed cert.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        with wireguard_context(wg_config):
            response = requests.get(
                "https://10.13.13.1:8443/https-test",
                verify=False,
                timeout=10,
            )
            assert response.status_code == 200
            data = response.json()
            assert data["tls"] is True


class TestIpv6Config:
    def test_dual_stack_config_parsed(self, wg_config):
        """Verify the config has proper IPv4 fields (IPv6 requires v6-enabled peer)."""
        assert wg_config.address is not None
        assert wg_config.prefix_len > 0
        assert len(wg_config.peers) > 0

    def test_manual_dual_stack_config(self):
        """Test that a manually-created dual-stack config has correct fields."""
        from wireguard_requests.config import Peer, WireGuardConfig

        config = WireGuardConfig(
            private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            address="10.0.0.2",
            address_v6="fd00::2",
            prefix_len=24,
            prefix_len_v6=64,
            peers=[
                Peer(
                    public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    endpoint="203.0.113.1:51820",
                    allowed_ips=["0.0.0.0/0", "::/0"],
                )
            ],
        )
        assert config.address_v6 == "fd00::2"
        assert config.prefix_len_v6 == 64
        assert config.peers[0].allowed_ips == ["0.0.0.0/0", "::/0"]

    def test_dual_stack_conf_parsing(self):
        """Test parsing a dual-stack .conf file."""
        from wireguard_requests.config import WireGuardConfig

        conf = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24, fd00::2/64
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
"""
        config = WireGuardConfig.from_string(conf)
        assert config.address == "10.0.0.2"
        assert config.prefix_len == 24
        assert config.address_v6 == "fd00::2"
        assert config.prefix_len_v6 == 64


class TestNatPmp:
    def test_get_external_address(self, wg_config):
        """Get the external IP address from the NAT-PMP gateway."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(udp, gateway="10.13.13.1", timeout=10.0)
                resp = client.get_external_address()
                assert resp.external_ip == "203.0.113.42"
                assert resp.epoch > 0
            finally:
                udp.close()

    def test_request_port_mapping(self, wg_config):
        """Request a port mapping through NAT-PMP."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(udp, gateway="10.13.13.1", timeout=10.0)
                resp = client.request_mapping("UDP", internal_port=8080, lifetime=60)
                assert resp.internal_port == 8080
                assert resp.external_port > 0
                assert resp.lifetime == 60
            finally:
                udp.close()

    def test_port_mapping_context_manager(self, wg_config):
        """Test auto-renewing port mapping context manager."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(udp, gateway="10.13.13.1", timeout=10.0)
                with client.port_mapping("TCP", internal_port=8080, lifetime=60) as pm:
                    assert pm.external_port > 0
                    assert pm.lifetime == 60
            finally:
                udp.close()

    def test_delete_mapping(self, wg_config):
        """Delete a port mapping via NAT-PMP."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(udp, gateway="10.13.13.1", timeout=10.0)
                # Warm up tunnel to complete WireGuard handshake; avoids
                # retry-induced stale responses contaminating the delete.
                client.get_external_address()
                # First create a mapping
                client.request_mapping("UDP", internal_port=9090, lifetime=60)
                # Then delete it
                resp = client.delete_mapping("UDP", internal_port=9090)
                assert resp.lifetime == 0
            finally:
                udp.close()

    def test_tcp_mapping(self, wg_config):
        """Request a TCP port mapping."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(udp, gateway="10.13.13.1", timeout=10.0)
                resp = client.request_mapping("TCP", internal_port=8080, lifetime=60)
                assert resp.internal_port == 8080
                assert resp.external_port > 0
            finally:
                udp.close()

    def test_specific_external_port(self, wg_config):
        """Request a specific external port."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(udp, gateway="10.13.13.1", timeout=10.0)
                resp = client.request_mapping(
                    "UDP", internal_port=8080, external_port=12345, lifetime=60
                )
                assert resp.external_port == 12345
                assert resp.internal_port == 8080
            finally:
                udp.close()

    def test_delete_all_mappings(self, wg_config):
        """Delete all mappings for a protocol via NAT-PMP."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(udp, gateway="10.13.13.1", timeout=10.0)
                # Warm up tunnel to complete WireGuard handshake.
                client.get_external_address()
                client.request_mapping("UDP", internal_port=7070, lifetime=60)
                client.request_mapping("UDP", internal_port=7071, lifetime=60)
                resp = client.delete_all_mappings("UDP")
                assert resp.lifetime == 0
                assert resp.external_port == 0
            finally:
                udp.close()


class TestNatPmpNegativePaths:
    def test_wrong_gateway_timeout(self, wg_config):
        """Connecting to wrong gateway IP should timeout."""
        from wireguard_requests import NatPmpClient, WireGuardUdpSocket, wireguard_context
        from wireguard_requests.exceptions import NatPmpTimeoutError

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                client = NatPmpClient(
                    udp,
                    gateway="10.13.13.99",
                    max_retries=3,
                    initial_timeout=0.25,
                )
                with pytest.raises(NatPmpTimeoutError):
                    client.get_external_address()
            finally:
                udp.close()

    def test_unsupported_version_error(self, wg_config):
        """Sending wrong version triggers error result code from server."""
        import struct

        from wireguard_requests import WireGuardUdpSocket, wireguard_context
        from wireguard_requests.exceptions import NatPmpUnsupportedError
        from wireguard_requests.natpmp import (
            NATPMP_PORT,
            _decode_external_address_response,
        )

        with wireguard_context(wg_config) as tunnel:
            native_udp = tunnel.create_udp_socket(0)
            udp = WireGuardUdpSocket(native_udp)
            try:
                bad_request = struct.pack("!BB", 1, 0)
                udp.settimeout(10.0)
                udp.sendto(bad_request, ("10.13.13.1", NATPMP_PORT))
                data, addr = udp.recvfrom(1024)
                with pytest.raises(NatPmpUnsupportedError):
                    _decode_external_address_response(data)
            finally:
                udp.close()
