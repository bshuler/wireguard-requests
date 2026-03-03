"""Convenience helpers for using wireguard-requests with popular HTTP libraries."""

from __future__ import annotations

from . import _native
from .config import WireGuardConfig
from .socket import WireGuardSocket


def create_session(config: WireGuardConfig, **kwargs):
    """Create a requests.Session that routes all traffic through WireGuard.

    This is a convenience wrapper that creates a tunnel and patches the
    session's connection handling to use WireGuard sockets.

    Args:
        config: WireGuard configuration.
        **kwargs: Additional arguments passed to requests.Session.

    Returns:
        A requests.Session with WireGuard tunneling enabled.

    Example:
        config = WireGuardConfig.from_file("wg0.conf")
        session = create_session(config)
        response = session.get("https://example.com")
        print(response.text)
        session.close()  # Also closes the WireGuard tunnel.

    Note:
        The returned session holds a reference to the WireGuard tunnel.
        Call session.close() when done to clean up the tunnel.
        Alternatively, use `wireguard_context()` for automatic cleanup.
    """
    try:
        import requests
        import urllib3.util.connection  # noqa: F401
    except ImportError:
        raise ImportError(
            "The 'requests' package is required for create_session(). "
            "Install it with: pip install wireguard-requests[requests]"
        )

    # Create the tunnel.
    native_config = config.to_native()
    tunnel = _native.WgTunnel(native_config)

    # Create a custom HTTPAdapter that uses WireGuard sockets.
    class WireGuardAdapter(requests.adapters.HTTPAdapter):
        def __init__(self, wg_tunnel, **adapter_kwargs):
            self._wg_tunnel = wg_tunnel
            super().__init__(**adapter_kwargs)

        def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
            # Monkeypatch urllib3's create_connection for this request.
            import urllib3.util.connection

            original_create_connection = urllib3.util.connection.create_connection

            def wg_create_connection(
                address, timeout=None, source_address=None, socket_options=None
            ):
                sock = WireGuardSocket(self._wg_tunnel)
                if timeout is not None:
                    sock.settimeout(timeout)
                sock.connect(address)
                return sock

            urllib3.util.connection.create_connection = wg_create_connection
            try:
                return super().send(request, stream, timeout, verify, cert, proxies)
            finally:
                urllib3.util.connection.create_connection = original_create_connection

    # Build the session.
    session = requests.Session(**kwargs) if kwargs else requests.Session()

    # Mount WireGuard adapter for all URLs.
    adapter = WireGuardAdapter(tunnel)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    # Store tunnel reference so it can be closed with the session.
    session._wg_tunnel = tunnel

    # Wrap close() to also shut down the tunnel.
    original_close = session.close

    def close_with_tunnel():
        original_close()
        tunnel.close()

    session.close = close_with_tunnel

    return session
