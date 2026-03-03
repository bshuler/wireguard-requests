"""Async example: use AsyncWireGuardSocket with asyncio.

Usage:
    python examples/async_example.py /path/to/wg.conf
"""

import asyncio
import sys

from wireguard_requests import AsyncWireGuardSocket, WireGuardConfig
from wireguard_requests._native import WgTunnel


async def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <wg-config-file>")
        sys.exit(1)

    config = WireGuardConfig.from_file(sys.argv[1])
    native_config = config.to_native()
    tunnel = WgTunnel(native_config)

    print("Tunnel established.")

    async with AsyncWireGuardSocket(tunnel) as sock:
        await sock.connect(("ifconfig.me", 80))
        await sock.sendall(b"GET / HTTP/1.1\r\nHost: ifconfig.me\r\nConnection: close\r\n\r\n")
        response = await sock.recv(4096)
        print(f"Response:\n{response.decode()}")

    tunnel.close()
    print("Tunnel closed.")


if __name__ == "__main__":
    asyncio.run(main())
