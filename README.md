# wireguard-requests

Drop-in WireGuard tunneling for Python. Route any TCP traffic through a WireGuard tunnel without installing WireGuard on the OS.

```python
from wireguard_requests import WireGuardConfig, wireguard_context
import requests

config = WireGuardConfig.from_file("wg0.conf")
with wireguard_context(config):
    # All TCP traffic now goes through WireGuard
    r = requests.get("https://ifconfig.me")
    print(r.text)  # Shows the WireGuard endpoint IP
```

## How it works

`wireguard-requests` bundles a complete userspace WireGuard + TCP/IP stack:

- **[boringtun](https://github.com/cloudflare/boringtun)** — Cloudflare's WireGuard protocol implementation (Rust)
- **[smoltcp](https://github.com/smoltcp-rs/smoltcp)** — Userspace TCP/IP stack (Rust)
- **[PyO3](https://pyo3.rs)** — Rust ↔ Python bridge

No kernel modules, no root access, no TUN devices. Just `pip install` and go.

## Installation

```bash
pip install wireguard-requests
```

Pre-built wheels are available for:

| Platform | x86_64 | aarch64 |
|----------|--------|---------|
| Linux    | ✅     | ✅      |
| macOS    | ✅     | ✅      |
| Windows  | ✅     | ✅      |

Building from source requires Rust 1.70+.

## Usage

### Global tunneling (context manager)

Monkeypatches `socket.socket` so all TCP connections in the block use WireGuard:

```python
from wireguard_requests import WireGuardConfig, wireguard_context
import requests

config = WireGuardConfig.from_file("wg0.conf")
with wireguard_context(config):
    # requests, urllib3, httpx, aiohttp — everything tunnels through WireGuard
    r = requests.get("https://example.com")
```

### Scoped session (requests only)

Only routes traffic from a specific `requests.Session`:

```python
from wireguard_requests import WireGuardConfig, create_session

config = WireGuardConfig.from_file("wg0.conf")
session = create_session(config)

r = session.get("https://example.com")  # Through WireGuard
session.close()
```

### Direct socket API

Use `WireGuardSocket` as a drop-in for `socket.socket`:

```python
from wireguard_requests import WireGuardConfig, WireGuardSocket
from wireguard_requests._native import WgTunnel

config = WireGuardConfig.from_file("wg0.conf")
tunnel = WgTunnel(config.to_native())

sock = WireGuardSocket(tunnel)
sock.connect(("example.com", 80))
sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
data = sock.recv(4096)
sock.close()
tunnel.close()
```

### Async (asyncio)

```python
import asyncio
from wireguard_requests import AsyncWireGuardSocket, WireGuardConfig
from wireguard_requests._native import WgTunnel

async def main():
    config = WireGuardConfig.from_file("wg0.conf")
    tunnel = WgTunnel(config.to_native())

    async with AsyncWireGuardSocket(tunnel) as sock:
        await sock.connect(("example.com", 80))
        await sock.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        data = await sock.recv(4096)

    tunnel.close()

asyncio.run(main())
```

### Programmatic config

```python
from wireguard_requests import WireGuardConfig, Peer

config = WireGuardConfig(
    private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
    address="10.0.0.2",
    peers=[Peer(
        public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        endpoint="203.0.113.1:51820",
        allowed_ips=["0.0.0.0/0"],
        persistent_keepalive=25,
    )],
)
```

## Architecture

```
Your Python app (requests, aiohttp, etc.)
  → WireGuardSocket (drop-in socket.socket)
    → Rust WgTunnel (PyO3)
      → smoltcp (userspace TCP/IP)
        → boringtun (WireGuard encrypt/decrypt)
          → UDP socket → WireGuard endpoint
```

A background Rust thread runs the smoltcp ↔ boringtun ↔ UDP poll loop. Python communicates with it via lock-free channels. Each tunnel supports multiple concurrent TCP connections.

## Limitations

- **IPv4 only** (IPv6 support planned)
- **TCP only** — UDP tunneling not yet exposed to Python
- **DNS resolves on the host** — not through the tunnel (planned)
- **No TLS termination** — use `requests` or `httpx` for HTTPS (they handle TLS above the socket layer)

## Development

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/yourorg/wireguard-requests
cd wireguard-requests
pip install maturin
maturin develop --manifest-path rust/Cargo.toml

# Run tests
pip install pytest pytest-asyncio
pytest tests/unit -v

# Integration tests (requires Docker)
docker compose -f tests/integration/docker-compose.yml up -d
pytest tests/integration -v -m integration
```

## License

Apache-2.0
