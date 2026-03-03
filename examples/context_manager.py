"""Example: wireguard_context for global socket replacement.

Inside the context, ALL TCP connections go through WireGuard.
This affects every library that uses sockets: requests, urllib3,
httpx, aiohttp, etc.

Usage:
    python examples/context_manager.py /path/to/wg.conf
"""

import sys
from wireguard_requests import WireGuardConfig, wireguard_context


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <wg-config-file>")
        sys.exit(1)

    config = WireGuardConfig.from_file(sys.argv[1])

    print("Before tunnel:")
    import urllib.request
    ip = urllib.request.urlopen("https://ifconfig.me", timeout=10).read().decode().strip()
    print(f"  IP: {ip}")

    print("\nInside WireGuard tunnel:")
    with wireguard_context(config):
        # urllib, requests, httpx — everything uses WireGuard now.
        ip = urllib.request.urlopen("https://ifconfig.me", timeout=10).read().decode().strip()
        print(f"  IP: {ip}")

    print("\nAfter tunnel (restored):")
    ip = urllib.request.urlopen("https://ifconfig.me", timeout=10).read().decode().strip()
    print(f"  IP: {ip}")


if __name__ == "__main__":
    main()
