"""WireGuard configuration parsing and management.

Provides a pure-Python config parser as a convenience layer on top of the
Rust-side parser. This module can be used independently to inspect and
manipulate WireGuard configurations without creating a tunnel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Union


@dataclass
class Peer:
    """A WireGuard peer configuration."""

    public_key: str
    endpoint: str
    allowed_ips: List[str] = field(default_factory=lambda: ["0.0.0.0/0"])
    persistent_keepalive: Optional[int] = None
    preshared_key: Optional[str] = None


@dataclass
class WireGuardConfig:
    """Full WireGuard tunnel configuration.

    Can be created manually, from a dictionary, or parsed from a .conf file.

    Examples:
        # From a .conf file:
        config = WireGuardConfig.from_file("/etc/wireguard/wg0.conf")

        # From code:
        config = WireGuardConfig(
            private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            address="10.0.0.2",
            peers=[Peer(
                public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                endpoint="203.0.113.1:51820",
            )],
        )

        # Dual-stack (IPv4 + IPv6):
        config = WireGuardConfig(
            private_key="...",
            address="10.0.0.2",
            address_v6="fd00::2",
            prefix_len=24,
            prefix_len_v6=64,
            peers=[...],
        )
    """

    private_key: str
    address: str
    peers: List[Peer]
    prefix_len: int = 24
    listen_port: int = 0
    mtu: int = 1420
    dns: List[str] = field(default_factory=list)
    address_v6: Optional[str] = None
    prefix_len_v6: Optional[int] = None

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> WireGuardConfig:
        """Parse a WireGuard .conf file.

        Args:
            path: Path to the .conf file.

        Returns:
            Parsed configuration.

        Raises:
            FileNotFoundError: If the file doesn't exist.
            ValueError: If the configuration is invalid.
        """
        content = Path(path).read_text()
        return cls.from_string(content)

    @classmethod
    def from_string(cls, content: str) -> WireGuardConfig:
        """Parse a WireGuard config from a string.

        Args:
            content: INI-format WireGuard configuration.

        Returns:
            Parsed configuration.
        """
        config_data: dict = {}
        peers: List[Peer] = []
        current_section: Optional[str] = None
        current_peer: dict = {}

        def flush_peer():
            if current_peer.get("public_key"):
                peers.append(
                    Peer(
                        public_key=current_peer["public_key"],
                        endpoint=current_peer.get("endpoint", ""),
                        allowed_ips=current_peer.get("allowed_ips", ["0.0.0.0/0"]),
                        persistent_keepalive=current_peer.get("persistent_keepalive"),
                        preshared_key=current_peer.get("preshared_key"),
                    )
                )

        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            if line.startswith("[") and line.endswith("]"):
                if current_section == "Peer":
                    flush_peer()
                    current_peer = {}
                current_section = line[1:-1]
                continue

            if "=" not in line:
                continue

            key, value = line.split("=", 1)
            key = key.strip()
            value = value.strip()

            if current_section == "Interface":
                if key == "PrivateKey":
                    config_data["private_key"] = value
                elif key == "Address":
                    # Handle comma-separated addresses (e.g. dual-stack IPv4, IPv6).
                    addresses = [a.strip() for a in value.split(",")]
                    ipv4_addr = None
                    ipv6_addr = None
                    for addr_entry in addresses:
                        raw = addr_entry.split("/")[0]
                        if ":" in raw:
                            # IPv6 address — capture the first one found.
                            if ipv6_addr is None:
                                ipv6_addr = addr_entry
                        else:
                            # IPv4 address — capture the first one found.
                            if ipv4_addr is None:
                                ipv4_addr = addr_entry
                    if ipv4_addr is None:
                        # Pure IPv6 config: treat first address as the primary.
                        ipv4_addr = addresses[0]
                    if "/" in ipv4_addr:
                        addr, prefix = ipv4_addr.split("/", 1)
                        config_data["address"] = addr.strip()
                        config_data["prefix_len"] = int(prefix.strip())
                    else:
                        config_data["address"] = ipv4_addr
                    # Capture IPv6 address if present.
                    if ipv6_addr is not None:
                        if "/" in ipv6_addr:
                            addr6, prefix6 = ipv6_addr.split("/", 1)
                            config_data["address_v6"] = addr6.strip()
                            config_data["prefix_len_v6"] = int(prefix6.strip())
                        else:
                            config_data["address_v6"] = ipv6_addr
                elif key == "ListenPort":
                    config_data["listen_port"] = int(value)
                elif key == "MTU":
                    config_data["mtu"] = int(value)
                elif key == "DNS":
                    config_data["dns"] = [s.strip() for s in value.split(",")]

            elif current_section == "Peer":
                if key == "PublicKey":
                    current_peer["public_key"] = value
                elif key == "Endpoint":
                    current_peer["endpoint"] = value
                elif key == "AllowedIPs":
                    current_peer["allowed_ips"] = [s.strip() for s in value.split(",")]
                elif key == "PersistentKeepalive":
                    current_peer["persistent_keepalive"] = int(value)
                elif key == "PresharedKey":
                    current_peer["preshared_key"] = value

        # Flush last peer
        if current_section == "Peer":
            flush_peer()

        if "private_key" not in config_data:
            raise ValueError("Missing PrivateKey in [Interface] section")
        if "address" not in config_data:
            raise ValueError("Missing Address in [Interface] section")
        if not peers:
            raise ValueError("No [Peer] sections found")

        config_data["peers"] = peers
        return cls(**config_data)

    def to_native(self):
        """Convert to the Rust-side WgConfig object.

        Returns:
            Native WgConfig instance for use with WgTunnel.
        """
        from . import _native

        native_peers = [
            _native.WgPeer(
                public_key=p.public_key,
                endpoint=p.endpoint,
                allowed_ips=p.allowed_ips,
                persistent_keepalive=p.persistent_keepalive,
                preshared_key=p.preshared_key,
            )
            for p in self.peers
        ]
        return _native.WgConfig(
            private_key=self.private_key,
            address=self.address,
            peers=native_peers,
            prefix_len=self.prefix_len,
            listen_port=self.listen_port,
            mtu=self.mtu,
            dns=self.dns,
            address_v6=self.address_v6,
            prefix_len_v6=self.prefix_len_v6,
        )
