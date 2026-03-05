"""NAT-PMP client for port forwarding through WireGuard tunnels.

Implements the NAT-PMP protocol (RFC 6886) to request port mappings
from a NAT-PMP-capable gateway (e.g., ProtonVPN). The mapping lets
external traffic reach a listening port on the tunnel interface.

Usage:
    from wireguard_requests import (
        WireGuardConfig, WireGuardUdpSocket, wireguard_context, NatPmpClient,
    )

    config = WireGuardConfig.from_file("protonvpn.conf")
    with wireguard_context(config) as tunnel:
        udp = WireGuardUdpSocket(tunnel.create_udp_socket(0))
        client = NatPmpClient(udp, gateway="10.2.0.1")

        # One-shot mapping
        resp = client.request_mapping("UDP", internal_port=51820)
        print(resp.external_port)

        # Auto-renewing context manager
        addr = client.get_external_address()
        with client.port_mapping("TCP", internal_port=8080) as pm:
            print(f"Listening on {addr.external_ip}:{pm.external_port}")
            # ... accept connections ...
        # mapping deleted on exit
"""

from __future__ import annotations

import enum
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn, Protocol

if TYPE_CHECKING:
    from types import TracebackType

from .exceptions import NatPmpError, NatPmpTimeoutError, NatPmpUnsupportedError

logger = logging.getLogger(__name__)


class UdpSocketLike(Protocol):
    """Protocol for UDP sockets usable with NatPmpClient."""

    def sendto(self, data: bytes, address: tuple[str, int]) -> int: ...
    def recvfrom(self, bufsize: int) -> tuple[bytes, tuple[str, int]]: ...
    def settimeout(self, timeout: float | None) -> None: ...
    def close(self) -> None: ...


__all__ = [
    "NatPmpClient",
    "PortMapping",
    "ExternalAddressResponse",
    "PortMappingResponse",
    "NatPmpOpcode",
    "NatPmpResultCode",
    "UdpSocketLike",
    "NATPMP_PORT",
    "NATPMP_VERSION",
]

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
NATPMP_PORT = 5351
NATPMP_VERSION = 0

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class NatPmpOpcode(enum.IntEnum):
    """NAT-PMP request opcodes (RFC 6886 §3)."""

    EXTERNAL_ADDRESS = 0
    MAP_UDP = 1
    MAP_TCP = 2


class NatPmpResultCode(enum.IntEnum):
    """NAT-PMP result codes (RFC 6886 §3.5)."""

    SUCCESS = 0
    UNSUPPORTED_VERSION = 1
    NOT_AUTHORIZED = 2
    NETWORK_FAILURE = 3
    OUT_OF_RESOURCES = 4
    UNSUPPORTED_OPCODE = 5


_RESULT_CODE_NAMES = {v.value: v.name for v in NatPmpResultCode}


# ---------------------------------------------------------------------------
# Response dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExternalAddressResponse:
    """Response to an external-address request."""

    epoch: int
    external_ip: str


@dataclass(frozen=True)
class PortMappingResponse:
    """Response to a port-mapping request."""

    epoch: int
    internal_port: int
    external_port: int
    lifetime: int


# ---------------------------------------------------------------------------
# Wire-format helpers (private)
# ---------------------------------------------------------------------------


def _encode_external_address_request() -> bytes:
    """Encode a 2-byte external-address request: version + opcode 0."""
    return struct.pack("!BB", NATPMP_VERSION, NatPmpOpcode.EXTERNAL_ADDRESS)


def _encode_mapping_request(
    opcode: int,
    internal_port: int,
    external_port: int,
    lifetime: int,
) -> bytes:
    """Encode a 12-byte mapping request.

    Format: version(1) + opcode(1) + reserved(2) + internal_port(2)
            + external_port(2) + lifetime(4)
    """
    if not (0 <= internal_port <= 65535):
        raise ValueError(f"internal_port must be 0-65535, got {internal_port}")
    if not (0 <= external_port <= 65535):
        raise ValueError(f"external_port must be 0-65535, got {external_port}")
    if lifetime < 0:
        raise ValueError(f"lifetime must be non-negative, got {lifetime}")
    if lifetime > 0xFFFFFFFF:
        raise ValueError(f"lifetime must fit in 32 bits, got {lifetime}")
    return struct.pack(
        "!BB2xHHI",
        NATPMP_VERSION,
        opcode,
        internal_port,
        external_port,
        lifetime,
    )


def _decode_external_address_response(data: bytes) -> ExternalAddressResponse:
    """Decode a 12-byte external-address response.

    Format: version(1) + opcode(1) + result_code(2) + epoch(4) + ip(4)
    """
    if len(data) < 12:
        raise NatPmpError(f"Response too short: {len(data)} bytes, expected 12")
    ver, opcode, result_code, epoch = struct.unpack("!BBHI", data[:8])
    if ver != NATPMP_VERSION:
        raise NatPmpError(f"Unexpected NAT-PMP version: {ver}")
    if opcode != 128 + NatPmpOpcode.EXTERNAL_ADDRESS:
        raise NatPmpError(f"Unexpected response opcode: {opcode}, expected 128")
    if result_code != NatPmpResultCode.SUCCESS:
        _raise_for_result_code(result_code)
    ip_bytes = data[8:12]
    external_ip = socket.inet_ntoa(ip_bytes)
    return ExternalAddressResponse(epoch=epoch, external_ip=external_ip)


def _decode_mapping_response(
    data: bytes,
    expected_opcode: int,
) -> PortMappingResponse:
    """Decode a 16-byte mapping response.

    Format: version(1) + opcode(1) + result_code(2) + epoch(4)
            + internal_port(2) + external_port(2) + lifetime(4)
    """
    if len(data) < 16:
        raise NatPmpError(f"Response too short: {len(data)} bytes, expected 16")
    ver, opcode, result_code, epoch, internal_port, external_port, lifetime = struct.unpack(
        "!BBHIHHI", data[:16]
    )
    if ver != NATPMP_VERSION:
        raise NatPmpError(f"Unexpected NAT-PMP version: {ver}")
    if opcode != 128 + expected_opcode:
        raise NatPmpError(f"Unexpected response opcode: {opcode}, expected {128 + expected_opcode}")
    if result_code != NatPmpResultCode.SUCCESS:
        _raise_for_result_code(result_code)
    return PortMappingResponse(
        epoch=epoch,
        internal_port=internal_port,
        external_port=external_port,
        lifetime=lifetime,
    )


def _raise_for_result_code(result_code: int) -> NoReturn:
    """Raise an appropriate exception for a non-success result code."""
    if result_code == NatPmpResultCode.UNSUPPORTED_VERSION:
        raise NatPmpUnsupportedError(
            "Gateway does not support this NAT-PMP version",
            result_code=result_code,
        )
    if result_code == NatPmpResultCode.UNSUPPORTED_OPCODE:
        raise NatPmpUnsupportedError(
            "Gateway does not support this NAT-PMP opcode",
            result_code=result_code,
        )
    name = _RESULT_CODE_NAMES.get(result_code, f"UNKNOWN({result_code})")
    raise NatPmpError(
        f"NAT-PMP error: {name}",
        result_code=result_code,
    )


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

_PROTOCOL_OPCODES = {
    "UDP": NatPmpOpcode.MAP_UDP,
    "TCP": NatPmpOpcode.MAP_TCP,
}


def _resolve_opcode(protocol: str | int) -> int:
    """Convert a protocol string or int to the NAT-PMP opcode."""
    if isinstance(protocol, int):
        if not (0 <= protocol <= 127):
            raise ValueError(f"Opcode must be 0-127, got {protocol}")
        return protocol
    key = protocol.upper()
    if key not in _PROTOCOL_OPCODES:
        raise ValueError(f"Unknown protocol {protocol!r}, expected 'TCP' or 'UDP'")
    return _PROTOCOL_OPCODES[key]


# ---------------------------------------------------------------------------
# NatPmpClient
# ---------------------------------------------------------------------------


class NatPmpClient:
    """NAT-PMP client that communicates through a WireGuard UDP socket.

    The underlying ``udp_socket`` must remain open for the lifetime of this
    client and any active ``PortMapping`` instances created from it. Closing
    the socket while a ``PortMapping`` renewal thread is running will cause
    renewal failures.

    .. warning::

        NAT-PMP (RFC 6886) has no transaction ID in its protocol. If
        multiple ``PortMapping`` instances share the same ``NatPmpClient``,
        their requests are serialized via a lock, but there is a small
        window where a response intended for one mapping could be consumed
        by another. For concurrent port mappings, use separate
        ``NatPmpClient`` instances (and separate UDP sockets).

    Args:
        udp_socket: A ``WireGuardUdpSocket`` or any object satisfying
                    ``UdpSocketLike`` connected to the tunnel.
        gateway: IP address of the NAT-PMP gateway (usually the tunnel
                 gateway, e.g. ``10.2.0.1``).
        timeout: Per-attempt timeout ceiling in seconds (default: 64.0).
                 Actual per-attempt timeouts follow RFC 6886 exponential
                 backoff (starting at ``initial_timeout``, doubling each
                 attempt, capped at 64s) but are also capped by this value.
        max_retries: Maximum number of attempts (default 9 per RFC 6886).
                     Values above ~20 provide no additional backoff benefit
                     since per-attempt timeouts cap at 64 seconds.
        initial_timeout: Initial per-attempt timeout in seconds (default
                         0.25s per RFC 6886 Section 3.1).
    """

    def __init__(
        self,
        udp_socket: UdpSocketLike,
        gateway: str,
        timeout: float = 64.0,
        max_retries: int = 9,
        initial_timeout: float = 0.25,
    ):
        self._socket = udp_socket
        self._gateway = gateway
        self._timeout = timeout
        self._max_retries = max_retries
        self._initial_timeout = initial_timeout
        self._lock = threading.Lock()

    def __repr__(self) -> str:
        return (
            f"NatPmpClient(gateway={self._gateway!r}, "
            f"timeout={self._timeout}, max_retries={self._max_retries})"
        )

    @property
    def gateway(self) -> str:
        """The gateway IP address."""
        return self._gateway

    @property
    def timeout(self) -> float:
        """Per-attempt timeout ceiling in seconds."""
        return self._timeout

    @property
    def max_retries(self) -> int:
        """Maximum number of retry attempts."""
        return self._max_retries

    @property
    def initial_timeout(self) -> float:
        """Initial per-attempt timeout in seconds."""
        return self._initial_timeout

    def _send_and_receive(self, request: bytes) -> bytes:
        """Send a request and wait for a response with RFC 6886 exponential backoff.

        Makes up to ``max_retries`` attempts with exponential timeout doubling
        starting from ``initial_timeout`` (default 250ms), capped at 64 seconds
        and ``timeout`` per RFC 6886 Section 3.1. The ``timeout`` parameter
        serves as a per-attempt ceiling.

        Responses from unexpected sources are silently retried within the same
        attempt's deadline (H4). The entire method is serialized via a lock to
        prevent interleaved sends/receives from concurrent threads (H2).
        """
        with self._lock:
            last_failure_reason = "timeout"
            for attempt in range(self._max_retries):
                attempt_timeout = min(
                    self._initial_timeout * (2**attempt),
                    64.0,
                    self._timeout,
                )
                try:
                    self._socket.settimeout(attempt_timeout)
                except OSError as exc:
                    raise NatPmpError(f"Socket error during NAT-PMP request: {exc}") from exc
                try:
                    self._socket.sendto(request, (self._gateway, NATPMP_PORT))
                except OSError as exc:
                    raise NatPmpError(f"Socket send error during NAT-PMP request: {exc}") from exc
                # Inner loop: retry recvfrom on same attempt for wrong-sender (H4)
                deadline = time.monotonic() + attempt_timeout
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        last_failure_reason = "timeout"
                        break
                    try:
                        self._socket.settimeout(remaining)
                    except OSError as exc:
                        raise NatPmpError(f"Socket error during NAT-PMP request: {exc}") from exc
                    try:
                        data, addr = self._socket.recvfrom(1024)
                    except OSError as exc:
                        if isinstance(exc, TimeoutError):
                            last_failure_reason = "timeout"
                            break
                        raise NatPmpError(
                            f"Socket receive error during NAT-PMP request: {exc}"
                        ) from exc
                    if addr[0] != self._gateway:
                        logger.warning(
                            "NAT-PMP response from unexpected source %s, expected %s",
                            addr[0],
                            self._gateway,
                        )
                        last_failure_reason = f"wrong sender ({addr[0]})"
                        continue
                    return data
                logger.debug(
                    "NAT-PMP attempt %d/%d failed (%s), retrying...",
                    attempt + 1,
                    self._max_retries,
                    last_failure_reason,
                )
            raise NatPmpTimeoutError(
                f"NAT-PMP request failed after {self._max_retries} attempts "
                f"(gateway={self._gateway}, last failure: {last_failure_reason})",
            )

    def get_external_address(self) -> ExternalAddressResponse:
        """Request the gateway's external IP address.

        Returns:
            An ``ExternalAddressResponse`` with the gateway's public IP.
        """
        request = _encode_external_address_request()
        data = self._send_and_receive(request)
        return _decode_external_address_response(data)

    def request_mapping(
        self,
        protocol: str | int,
        internal_port: int,
        external_port: int = 0,
        lifetime: int = 60,
    ) -> PortMappingResponse:
        """Request a port mapping from the gateway.

        Args:
            protocol: ``"TCP"``, ``"UDP"``, or a raw opcode int.
            internal_port: Local port to map (must be > 0).
            external_port: Requested external port (0 = let gateway choose).
            lifetime: Requested lease duration in seconds.

        Returns:
            A ``PortMappingResponse`` with the assigned mapping details.
        """
        if internal_port <= 0:
            raise ValueError(
                f"internal_port must be > 0 (got {internal_port}); "
                f"use delete_all_mappings() to remove all mappings for a protocol"
            )
        opcode = _resolve_opcode(protocol)
        request = _encode_mapping_request(opcode, internal_port, external_port, lifetime)
        data = self._send_and_receive(request)
        return _decode_mapping_response(data, expected_opcode=opcode)

    def delete_mapping(
        self,
        protocol: str | int,
        internal_port: int,
    ) -> PortMappingResponse:
        """Delete an existing port mapping.

        Sends a mapping request with ``lifetime=0`` and ``external_port=0``
        to signal deletion (RFC 6886 §3.4).

        Args:
            protocol: ``"TCP"``, ``"UDP"``, or a raw opcode int.
            internal_port: The internal port of the mapping to delete.

        Returns:
            A ``PortMappingResponse`` confirming deletion (lifetime=0).
        """
        return self.request_mapping(protocol, internal_port, external_port=0, lifetime=0)

    def delete_all_mappings(self, protocol: str | int) -> PortMappingResponse:
        """Delete ALL port mappings for a protocol.

        Sends a mapping request with ``internal_port=0``, ``external_port=0``,
        ``lifetime=0`` to signal deletion of all mappings for the given protocol
        (RFC 6886 Section 3.4).

        Args:
            protocol: ``"TCP"``, ``"UDP"``, or a raw opcode int.

        Returns:
            A ``PortMappingResponse`` confirming deletion.
        """
        opcode = _resolve_opcode(protocol)
        request = _encode_mapping_request(opcode, 0, 0, 0)
        data = self._send_and_receive(request)
        return _decode_mapping_response(data, expected_opcode=opcode)

    def port_mapping(
        self,
        protocol: str | int,
        internal_port: int,
        external_port: int = 0,
        lifetime: int = 60,
    ) -> PortMapping:
        """Create an auto-renewing port mapping context manager.

        Usage::

            with client.port_mapping("TCP", 8080) as pm:
                print(pm.external_port)
                # mapping is renewed automatically
            # mapping deleted on exit

        .. warning::

            For concurrent mappings, use separate ``NatPmpClient`` instances.
            See class-level docstring for details.

        Args:
            protocol: ``"TCP"``, ``"UDP"``, or a raw opcode int.
            internal_port: Local port to map.
            external_port: Requested external port (0 = gateway chooses).
            lifetime: Lease duration in seconds; renewed at ``lifetime / 2``.

        Returns:
            A ``PortMapping`` context manager.
        """
        return PortMapping(
            client=self,
            protocol=protocol,
            internal_port=internal_port,
            external_port=external_port,
            lifetime=lifetime,
        )


# ---------------------------------------------------------------------------
# PortMapping context manager
# ---------------------------------------------------------------------------


class PortMapping:
    """Auto-renewing NAT-PMP port mapping context manager.

    Performs the initial mapping on ``__enter__``, starts a background
    thread that renews at ``lifetime / 2``, and deletes the mapping on
    ``__exit__``.

    .. note::

        The renewal thread is a daemon thread. If the process exits while
        a ``PortMapping`` is active (without calling ``__exit__``), the
        thread will be killed and the port mapping will NOT be deleted
        from the gateway. The mapping will expire naturally after its
        lifetime elapses.
    """

    def __init__(
        self,
        client: NatPmpClient,
        protocol: str | int,
        internal_port: int,
        external_port: int = 0,
        lifetime: int = 60,
    ):
        self._client = client
        self._protocol = protocol
        self._internal_port = internal_port
        self._requested_external_port = external_port
        self._lifetime = lifetime
        self._response: PortMappingResponse | None = None
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_epoch: int | None = None

    def __repr__(self) -> str:
        with self._lock:
            ext_port = self._response.external_port if self._response else None
        return (
            f"PortMapping(protocol={self._protocol!r}, "
            f"internal_port={self._internal_port}, "
            f"external_port={ext_port})"
        )

    @property
    def external_port(self) -> int:
        """The externally assigned port (thread-safe)."""
        with self._lock:
            if self._response is None:
                raise RuntimeError("Port mapping not yet established; use as context manager")
            return self._response.external_port

    @property
    def lifetime(self) -> int:
        """The current lease lifetime in seconds."""
        with self._lock:
            if self._response is None:
                raise RuntimeError("Port mapping not yet established; use as context manager")
            return self._response.lifetime

    def __enter__(self) -> PortMapping:
        """Establish the initial mapping and start the renewal thread."""
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError(
                "PortMapping context is already active; " "call __exit__ before re-entering"
            )
        self._last_epoch = None  # Reset stale state from previous session
        response = self._client.request_mapping(
            self._protocol,
            self._internal_port,
            self._requested_external_port,
            self._lifetime,
        )
        with self._lock:
            self._response = response
            self._last_epoch = response.epoch
        logger.info(
            "NAT-PMP mapping established: internal=%d -> external=%d (lifetime=%ds)",
            response.internal_port,
            response.external_port,
            response.lifetime,
        )
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._renewal_loop,
            daemon=True,
            name="natpmp-renewal",
        )
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Stop the renewal thread and delete the mapping (best-effort)."""
        self._stop_event.set()
        if self._thread is not None:
            total_worst_case = sum(
                min(
                    self._client.initial_timeout * (2**i),
                    64.0,
                    self._client.timeout,
                )
                for i in range(self._client.max_retries)
            )
            self._thread.join(timeout=total_worst_case + 1.0)
            if self._thread.is_alive():
                logger.warning(
                    "NAT-PMP renewal thread did not stop within timeout; "
                    "skipping mapping deletion to avoid potential deadlock"
                )
                return
        try:
            self._client.delete_mapping(self._protocol, self._internal_port)
            logger.info("NAT-PMP mapping deleted: internal=%d", self._internal_port)
        except Exception as exc:
            logger.warning("Failed to delete NAT-PMP mapping: %s", exc)

    def _renewal_loop(self) -> None:
        """Background loop that renews the mapping at lifetime / 2."""
        consecutive_failures = 0
        while not self._stop_event.is_set():
            with self._lock:
                sleep_time = max(1, self._response.lifetime // 2) if self._response else 30
            if self._stop_event.wait(timeout=sleep_time):
                break
            # M1: Re-check stop event after waking from wait
            if self._stop_event.is_set():
                break
            try:
                response = self._client.request_mapping(
                    self._protocol,
                    self._internal_port,
                    self._requested_external_port,
                    self._lifetime,
                )
                # L1: Gateway returned lifetime=0, mapping refused
                if response.lifetime == 0:
                    logger.error(
                        "NAT-PMP gateway returned lifetime=0 during renewal; "
                        "mapping has been refused. Stopping renewal."
                    )
                    with self._lock:
                        self._response = response
                    break
                # L4: RFC 6886 Section 3.6 - detect gateway restart
                with self._lock:
                    if self._last_epoch is not None and response.epoch < self._last_epoch:
                        logger.warning(
                            "NAT-PMP gateway epoch decreased (%d -> %d); "
                            "gateway may have restarted. Previous mappings may be invalid.",
                            self._last_epoch,
                            response.epoch,
                        )
                    self._last_epoch = response.epoch
                    self._response = response
                consecutive_failures = 0
                logger.debug(
                    "NAT-PMP mapping renewed: external=%d (lifetime=%ds)",
                    response.external_port,
                    response.lifetime,
                )
            except Exception as exc:
                consecutive_failures += 1
                if consecutive_failures >= 3:
                    logger.error(
                        "NAT-PMP renewal failed %d consecutive times, "
                        "mapping may have expired: %s",
                        consecutive_failures,
                        exc,
                    )
                else:
                    logger.warning("NAT-PMP renewal failed: %s", exc)
