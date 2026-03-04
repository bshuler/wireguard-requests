# wireguard-requests

Drop-in WireGuard tunneling for Python. Route TCP, UDP, and DNS traffic through a WireGuard tunnel without installing WireGuard on the OS.

```python
from wireguard_requests import WireGuardConfig, wireguard_context
import requests

config = WireGuardConfig.from_file("wg0.conf")
with wireguard_context(config):
    # All TCP traffic now goes through WireGuard — including HTTPS
    r = requests.get("https://ifconfig.me")
    print(r.text)  # Shows the WireGuard endpoint IP
```

## How it works

`wireguard-requests` bundles a complete userspace WireGuard + TCP/IP stack:

- **[boringtun](https://github.com/cloudflare/boringtun)** — Cloudflare's WireGuard protocol implementation (Rust)
- **[smoltcp](https://github.com/smoltcp-rs/smoltcp)** — Userspace TCP/IP stack with IPv4, IPv6, TCP, UDP, and DNS (Rust)
- **[PyO3](https://pyo3.rs)** — Rust ↔ Python bridge

No kernel modules, no root access, no TUN devices. Just `pip install` and go.

## Features

- **TCP tunneling** — transparent socket replacement for requests, urllib3, httpx, aiohttp
- **UDP tunneling** — send/receive datagrams through the WireGuard tunnel
- **DNS resolution** — resolve hostnames through the tunnel's DNS server
- **TLS/HTTPS** — transparent HTTPS support via memory BIOs (no real file descriptors needed)
- **IPv6** — dual-stack config parsing and IPv6 socket interception
- **Async** — asyncio support via `AsyncWireGuardSocket`

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

HTTPS works transparently — `wireguard_context` also intercepts `ssl.SSLContext.wrap_socket` so that TLS handshakes happen over the WireGuard tunnel using memory BIOs.

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

### TLS / HTTPS

Wrap any `WireGuardSocket` with TLS using `wrap_tls()`:

```python
from wireguard_requests import WireGuardConfig, WireGuardSocket, wireguard_context

config = WireGuardConfig.from_file("wg0.conf")
with wireguard_context(config) as tunnel:
    sock = WireGuardSocket(tunnel)
    sock.connect(("example.com", 443))
    tls = sock.wrap_tls("example.com")
    tls.sendall(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    data = tls.recv(4096)
    tls.close()
```

Uses `ssl.MemoryBIO` + `ssl.SSLObject` under the hood — no real file descriptors needed.

### UDP tunneling

Send and receive UDP datagrams through the tunnel:

```python
from wireguard_requests import WireGuardConfig, WireGuardUdpSocket, wireguard_context

config = WireGuardConfig.from_file("wg0.conf")
with wireguard_context(config) as tunnel:
    udp = WireGuardUdpSocket(tunnel.create_udp_socket(0))
    udp.settimeout(5.0)
    udp.sendto(b"hello", ("10.0.0.1", 9999))
    data, addr = udp.recvfrom(4096)
    udp.close()
```

### DNS resolution through the tunnel

Resolve hostnames using the tunnel's DNS server (configured via `DNS` in the .conf file):

```python
from wireguard_requests import WireGuardConfig, wireguard_context

config = WireGuardConfig.from_file("wg0.conf")
with wireguard_context(config) as tunnel:
    ip = tunnel.resolve_dns("internal.corp.local")
    print(ip)  # e.g. "10.0.0.50"
```

Hostnames passed to `WireGuardSocket.connect()` are also resolved through the tunnel DNS automatically.

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
    address_v6="fd00::2",        # Optional IPv6
    prefix_len_v6=64,
    peers=[Peer(
        public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
        endpoint="203.0.113.1:51820",
        allowed_ips=["0.0.0.0/0", "::/0"],
        persistent_keepalive=25,
        preshared_key="...",     # Optional
    )],
    dns=["10.0.0.1"],
)
```

Dual-stack configs are also parsed automatically from `.conf` files:

```ini
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24, fd00::2/64
DNS = 10.0.0.1
```

## Architecture

```
Your Python app (requests, aiohttp, etc.)
  → WireGuardSocket / WireGuardUdpSocket (drop-in socket API)
    → Rust WgTunnel (PyO3)
      → smoltcp (userspace TCP/IP + UDP + DNS)
        → boringtun (WireGuard encrypt/decrypt)
          → UDP socket → WireGuard endpoint
```

A background Rust thread runs the smoltcp ↔ boringtun ↔ UDP poll loop. Python communicates with it via lock-free channels. Each tunnel supports multiple concurrent TCP and UDP connections.

## Development

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone and build
git clone https://github.com/bshuler/wireguard-requests
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
