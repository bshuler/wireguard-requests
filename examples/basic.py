"""Basic example: make an HTTP request through a WireGuard tunnel.

Usage:
    python examples/basic.py /path/to/wg.conf
"""

import sys
from wireguard_requests import WireGuardConfig, wireguard_context

try:
    import requests
except ImportError:
    print("Install requests: pip install requests")
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <wg-config-file>")
        sys.exit(1)

    config_path = sys.argv[1]
    config = WireGuardConfig.from_file(config_path)
    print(f"Loaded config: {config.address} -> {config.peers[0].endpoint}")

    # Everything inside this context manager goes through WireGuard.
    with wireguard_context(config):
        print("Tunnel established. Making request...")
        response = requests.get("https://ifconfig.me", timeout=15)
        print(f"Your IP through WireGuard: {response.text.strip()}")


if __name__ == "__main__":
    main()
