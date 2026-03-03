"""Type stubs for the Rust native extension module."""

from typing import List, Optional

__version__: str

class WgPeer:
    public_key: str
    endpoint: str
    allowed_ips: List[str]
    persistent_keepalive: Optional[int]

    def __init__(
        self,
        public_key: str,
        endpoint: str,
        allowed_ips: List[str],
        persistent_keepalive: Optional[int] = None,
    ) -> None: ...

class WgConfig:
    private_key: str
    address: str
    prefix_len: int
    listen_port: int
    mtu: int
    dns: List[str]
    peers: List[WgPeer]

    def __init__(
        self,
        private_key: str,
        address: str,
        peers: List[WgPeer],
        prefix_len: int = 24,
        listen_port: int = 0,
        mtu: int = 1420,
        dns: List[str] = ...,
    ) -> None: ...
    @staticmethod
    def from_file(path: str) -> WgConfig: ...
    @staticmethod
    def from_str(content: str) -> WgConfig: ...

class WgTunnel:
    def __init__(self, config: WgConfig) -> None: ...
    def create_stream(self, host: str, port: int) -> WgStream: ...
    def close(self) -> None: ...
    def is_alive(self) -> bool: ...

class WgStream:
    def send(self, data: bytes) -> int: ...
    def sendall(self, data: bytes) -> None: ...
    def recv(self, max_len: int) -> bytes: ...
    def close(self) -> None: ...
    def is_connected(self) -> bool: ...
    def set_timeout(self, timeout_secs: Optional[float] = None) -> None: ...
