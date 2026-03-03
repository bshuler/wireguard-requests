"""Integration tests with a real WireGuard tunnel.

These tests require Docker to be running. They start a WireGuard server
container with an HTTP server behind it and verify that our library can
tunnel HTTP requests through the WireGuard connection.

Run with: pytest tests/integration -v -m integration
"""

import pytest

pytestmark = pytest.mark.integration


class TestRealTunnel:
    def test_http_get_through_tunnel(self, wg_config):
        """Make an HTTP GET request through the WireGuard tunnel."""
        from wireguard_requests import wireguard_context

        try:
            import requests
        except ImportError:
            pytest.skip("requests not installed")

        with wireguard_context(wg_config):
            response = requests.get("http://10.13.13.1:8080/test", timeout=10)
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "ok"
            assert data["path"] == "/test"
            assert data["tunnel"] == "wireguard"

    def test_create_session_helper(self, wg_config):
        """Test the create_session() convenience function."""
        from wireguard_requests import create_session

        try:
            import requests  # noqa: F401
        except ImportError:
            pytest.skip("requests not installed")

        session = create_session(wg_config)
        try:
            response = session.get("http://10.13.13.1:8080/session-test", timeout=10)
            assert response.status_code == 200
            data = response.json()
            assert data["path"] == "/session-test"
        finally:
            session.close()

    def test_multiple_requests(self, wg_config):
        """Make multiple sequential requests through the tunnel."""
        from wireguard_requests import wireguard_context

        try:
            import requests
        except ImportError:
            pytest.skip("requests not installed")

        with wireguard_context(wg_config):
            for i in range(5):
                response = requests.get(f"http://10.13.13.1:8080/multi/{i}", timeout=10)
                assert response.status_code == 200
                data = response.json()
                assert data["path"] == f"/multi/{i}"

    def test_tunnel_close_and_reopen(self, wg_config):
        """Test closing and reopening the tunnel."""
        from wireguard_requests import wireguard_context

        try:
            import requests
        except ImportError:
            pytest.skip("requests not installed")

        # First tunnel.
        with wireguard_context(wg_config):
            r = requests.get("http://10.13.13.1:8080/first", timeout=10)
            assert r.status_code == 200

        # Second tunnel (same config).
        with wireguard_context(wg_config):
            r = requests.get("http://10.13.13.1:8080/second", timeout=10)
            assert r.status_code == 200
