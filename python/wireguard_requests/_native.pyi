"""Type stubs for the Rust native extension module."""

from typing import List, Optional

__version__: str

class WgPeer:
    public_key: str
    endpoint: str
    allowed_ips: List[str]
    persistent_keepalive: Optional[int]
    preshared_key: Optional[str]

    def __init__(
        self,
        public_key: str,
        endpoint: str,
        allowed_ips: List[str],
        persistent_keepalive: Optional[int] = None,
        preshared_key: Optional[str] = None,
    ) -> None: ...

class WgConfig:
    private_key: str
    address: str
    prefix_len: int
    listen_port: int
    mtu: int
    dns: List[str]
    peers: List[WgPeer]
    address_v6: Optional[str]
    prefix_len_v6: Optional[int]

    def __init__(
        self,
        private_key: str,
        address: str,
        peers: List[WgPeer],
        prefix_len: int = 24,
        listen_port: int = 0,
        mtu: int = 1420,
        dns: List[str] = ...,
        address_v6: Optional[str] = None,
        prefix_len_v6: Optional[int] = None,
    ) -> None: ...
    @staticmethod
    def from_file(path: str) -> WgConfig: ...
    @staticmethod
    def from_str(content: str) -> WgConfig: ...

class WgTunnel:
    def __init__(self, config: WgConfig) -> None: ...
    def create_stream(self, host: str, port: int) -> WgStream: ...
    def create_udp_socket(self, bind_port: int = 0) -> WgUdpSocket: ...
    def resolve_dns(self, hostname: str) -> str: ...
    def close(self) -> None: ...
    def is_alive(self) -> bool: ...

class WgStream:
    def send(self, data: bytes) -> int: ...
    def sendall(self, data: bytes) -> None: ...
    def recv(self, max_len: int) -> bytes: ...
    def close(self) -> None: ...
    def is_connected(self) -> bool: ...
    def set_timeout(self, timeout_secs: Optional[float] = None) -> None: ...

class WgUdpSocket:
    def send_to(self, data: bytes, address: tuple[str, int]) -> None: ...
    def recv_from(self, max_len: int) -> tuple[bytes, tuple[str, int]]: ...
    def close(self) -> None: ...
    def set_timeout(self, timeout_secs: Optional[float] = None) -> None: ...
