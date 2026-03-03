"""Example: using create_session() for a scoped WireGuard session.

This is useful when you want a requests.Session that tunnels through
WireGuard without affecting other sockets in the process.

Usage:
    python examples/requests_session.py /path/to/wg.conf
"""

import sys

from wireguard_requests import WireGuardConfig, create_session


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <wg-config-file>")
        sys.exit(1)

    config = WireGuardConfig.from_file(sys.argv[1])

    # Create a session scoped to this WireGuard tunnel.
    # Only requests made through this session go through the tunnel.
    session = create_session(config)

    try:
        # This goes through WireGuard.
        r = session.get("https://ifconfig.me", timeout=15)
        print(f"WireGuard IP: {r.text.strip()}")

        # Regular requests still use the normal network.
        import requests

        r2 = requests.get("https://ifconfig.me", timeout=15)
        print(f"Normal IP:    {r2.text.strip()}")
    finally:
        session.close()  # Also closes the WireGuard tunnel.


if __name__ == "__main__":
    main()
