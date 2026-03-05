import socket
import struct
import threading
import time
from unittest.mock import MagicMock

import pytest
from wireguard_requests.exceptions import (
    NatPmpError,
    NatPmpTimeoutError,
    NatPmpUnsupportedError,
)
from wireguard_requests.natpmp import (
    NATPMP_PORT,
    NATPMP_VERSION,
    NatPmpClient,
    NatPmpOpcode,
    NatPmpResultCode,
    PortMapping,
    _decode_external_address_response,
    _decode_mapping_response,
    _encode_external_address_request,
    _encode_mapping_request,
    _raise_for_result_code,
    _resolve_opcode,
)

# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _make_address_response(epoch=99, ip="203.0.113.42", result_code=0):
    """Build a mock external address response."""
    ip_bytes = socket.inet_aton(ip)
    return struct.pack("!BBHI", 0, 128, result_code, epoch) + ip_bytes


def _make_mapping_response(
    opcode=1,
    epoch=100,
    internal_port=8080,
    external_port=9080,
    lifetime=60,
    result_code=0,
):
    """Build a mock mapping response."""
    return struct.pack(
        "!BBHIHHI",
        0,
        opcode + 128,
        result_code,
        epoch,
        internal_port,
        external_port,
        lifetime,
    )


def _make_delete_response(opcode=1, epoch=100, internal_port=8080):
    """Build a mock delete mapping response."""
    return _make_mapping_response(
        opcode=opcode,
        epoch=epoch,
        internal_port=internal_port,
        external_port=0,
        lifetime=0,
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_udp():
    """A mock WireGuardUdpSocket."""
    return MagicMock()


@pytest.fixture
def client(mock_udp):
    """A NatPmpClient with a mocked UDP socket and fast test-friendly backoff."""
    return NatPmpClient(
        mock_udp,
        gateway="10.2.0.1",
        timeout=1.0,
        max_retries=3,
        initial_timeout=0.01,
    )


@pytest.fixture
def fast_client(mock_udp):
    """A NatPmpClient with very fast timeouts for renewal tests."""
    return NatPmpClient(
        mock_udp,
        gateway="10.2.0.1",
        timeout=0.1,
        max_retries=2,
        initial_timeout=0.05,
    )


# ---------------------------------------------------------------------------
# Encode helpers
# ---------------------------------------------------------------------------


class TestEncodeExternalAddressRequest:
    def test_format(self):
        data = _encode_external_address_request()
        assert len(data) == 2
        ver, op = struct.unpack("!BB", data)
        assert ver == 0
        assert op == 0


class TestEncodeMappingRequest:
    def test_udp_format(self):
        data = _encode_mapping_request(
            opcode=NatPmpOpcode.MAP_UDP,
            internal_port=8080,
            external_port=0,
            lifetime=60,
        )
        assert len(data) == 12
        ver, op, reserved, iport, eport, lt = struct.unpack("!BBHHHI", data)
        assert ver == 0
        assert op == 1
        assert reserved == 0
        assert iport == 8080
        assert eport == 0
        assert lt == 60

    def test_tcp_format(self):
        data = _encode_mapping_request(
            opcode=NatPmpOpcode.MAP_TCP,
            internal_port=443,
            external_port=443,
            lifetime=120,
        )
        ver, op, _, iport, eport, lt = struct.unpack("!BBHHHI", data)
        assert op == 2
        assert iport == 443
        assert eport == 443
        assert lt == 120

    def test_max_port(self):
        data = _encode_mapping_request(NatPmpOpcode.MAP_UDP, 65535, 65535, 60)
        _, _, _, iport, eport, _ = struct.unpack("!BBHHHI", data)
        assert iport == 65535
        assert eport == 65535

    def test_port_overflow_raises(self):
        with pytest.raises(ValueError, match="internal_port must be 0-65535"):
            _encode_mapping_request(NatPmpOpcode.MAP_UDP, 70000, 0, 60)

    def test_external_port_overflow_raises(self):
        with pytest.raises(ValueError, match="external_port must be 0-65535"):
            _encode_mapping_request(NatPmpOpcode.MAP_UDP, 8080, 65536, 60)

    def test_lifetime_overflow_raises(self):
        with pytest.raises(ValueError, match="lifetime must fit in 32 bits"):
            _encode_mapping_request(NatPmpOpcode.MAP_UDP, 8080, 0, 2**32)

    def test_max_valid_lifetime(self):
        data = _encode_mapping_request(NatPmpOpcode.MAP_UDP, 8080, 0, 2**32 - 1)
        _, _, _, _, _, lt = struct.unpack("!BBHHHI", data)
        assert lt == 2**32 - 1

    def test_negative_lifetime_raises(self):
        with pytest.raises(ValueError, match="lifetime must be non-negative"):
            _encode_mapping_request(NatPmpOpcode.MAP_UDP, 8080, 0, -1)

    def test_negative_internal_port_raises(self):
        with pytest.raises(ValueError, match="internal_port must be 0-65535"):
            _encode_mapping_request(NatPmpOpcode.MAP_UDP, -1, 0, 60)


# ---------------------------------------------------------------------------
# Decode helpers
# ---------------------------------------------------------------------------


class TestDecodeExternalAddressResponse:
    def test_valid_response(self):
        ip_bytes = socket.inet_aton("203.0.113.42")
        data = struct.pack("!BBHI", 0, 128, 0, 12345) + ip_bytes
        resp = _decode_external_address_response(data)
        assert resp.epoch == 12345
        assert resp.external_ip == "203.0.113.42"

    def test_too_short(self):
        with pytest.raises(NatPmpError, match="too short"):
            _decode_external_address_response(b"\x00" * 8)

    def test_error_result_code(self):
        ip_bytes = socket.inet_aton("0.0.0.0")
        data = struct.pack("!BBHI", 0, 128, 2, 0) + ip_bytes
        with pytest.raises(NatPmpError) as exc_info:
            _decode_external_address_response(data)
        assert exc_info.value.result_code == 2

    def test_wrong_version_raises(self):
        ip_bytes = socket.inet_aton("1.2.3.4")
        data = struct.pack("!BBHI", 1, 128, 0, 100) + ip_bytes
        with pytest.raises(NatPmpError, match="version"):
            _decode_external_address_response(data)

    def test_wrong_opcode_raises(self):
        ip_bytes = socket.inet_aton("1.2.3.4")
        data = struct.pack("!BBHI", 0, 129, 0, 100) + ip_bytes
        with pytest.raises(NatPmpError, match="opcode"):
            _decode_external_address_response(data)

    def test_trailing_bytes_accepted(self):
        ip_bytes = socket.inet_aton("203.0.113.42")
        data = struct.pack("!BBHI", 0, 128, 0, 12345) + ip_bytes + b"\xff\xff"
        resp = _decode_external_address_response(data)
        assert resp.external_ip == "203.0.113.42"


class TestDecodeMappingResponse:
    def test_valid_response(self):
        data = struct.pack("!BBHIHHI", 0, 129, 0, 12345, 8080, 9080, 60)
        resp = _decode_mapping_response(data, expected_opcode=1)
        assert resp.epoch == 12345
        assert resp.internal_port == 8080
        assert resp.external_port == 9080
        assert resp.lifetime == 60

    def test_too_short(self):
        with pytest.raises(NatPmpError, match="too short"):
            _decode_mapping_response(b"\x00" * 12, expected_opcode=1)

    def test_error_result_code(self):
        data = struct.pack("!BBHIHHI", 0, 129, 3, 0, 0, 0, 0)
        with pytest.raises(NatPmpError) as exc_info:
            _decode_mapping_response(data, expected_opcode=1)
        assert exc_info.value.result_code == 3

    def test_not_authorized_result_code(self):
        data = struct.pack("!BBHIHHI", 0, 129, 2, 0, 0, 0, 0)
        with pytest.raises(NatPmpError) as exc_info:
            _decode_mapping_response(data, expected_opcode=1)
        assert exc_info.value.result_code == 2

    def test_out_of_resources_result_code(self):
        data = struct.pack("!BBHIHHI", 0, 129, 4, 0, 0, 0, 0)
        with pytest.raises(NatPmpError) as exc_info:
            _decode_mapping_response(data, expected_opcode=1)
        assert exc_info.value.result_code == 4

    def test_unknown_result_code(self):
        data = struct.pack("!BBHIHHI", 0, 129, 99, 0, 0, 0, 0)
        with pytest.raises(NatPmpError, match="UNKNOWN"):
            _decode_mapping_response(data, expected_opcode=1)

    def test_unsupported_version_result_code(self):
        data = struct.pack("!BBHIHHI", 0, 129, 1, 0, 0, 0, 0)
        with pytest.raises(NatPmpUnsupportedError) as exc_info:
            _decode_mapping_response(data, expected_opcode=1)
        assert exc_info.value.result_code == 1

    def test_unsupported_opcode_result_code(self):
        data = struct.pack("!BBHIHHI", 0, 129, 5, 0, 0, 0, 0)
        with pytest.raises(NatPmpUnsupportedError) as exc_info:
            _decode_mapping_response(data, expected_opcode=1)
        assert exc_info.value.result_code == 5

    def test_wrong_version_raises(self):
        data = struct.pack("!BBHIHHI", 1, 129, 0, 100, 8080, 9080, 60)
        with pytest.raises(NatPmpError, match="version"):
            _decode_mapping_response(data, expected_opcode=1)

    def test_wrong_opcode_raises(self):
        data = struct.pack("!BBHIHHI", 0, 130, 0, 100, 8080, 9080, 60)
        with pytest.raises(NatPmpError, match="opcode"):
            _decode_mapping_response(data, expected_opcode=1)

    def test_mismatched_opcode_always_checked(self):
        """expected_opcode is now required; mismatched opcode always raises."""
        data = struct.pack("!BBHIHHI", 0, 130, 0, 100, 8080, 9080, 60)
        with pytest.raises(NatPmpError, match="opcode"):
            _decode_mapping_response(data, expected_opcode=1)
        # Matching opcode should succeed
        resp = _decode_mapping_response(data, expected_opcode=2)
        assert resp.external_port == 9080

    def test_trailing_bytes_accepted(self):
        data = struct.pack("!BBHIHHI", 0, 129, 0, 12345, 8080, 9080, 60) + b"\xff\xff"
        resp = _decode_mapping_response(data, expected_opcode=1)
        assert resp.external_port == 9080


# ---------------------------------------------------------------------------
# NatPmpClient
# ---------------------------------------------------------------------------


class TestNatPmpClientGetExternalAddress:
    def test_success(self, client, mock_udp):
        ip_bytes = socket.inet_aton("203.0.113.42")
        resp_data = struct.pack("!BBHI", 0, 128, 0, 12345) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.get_external_address()
        assert resp.external_ip == "203.0.113.42"
        assert resp.epoch == 12345

        # Verify request bytes
        sent_data = mock_udp.sendto.call_args[0][0]
        assert sent_data == b"\x00\x00"
        assert mock_udp.sendto.call_args[0][1] == ("10.2.0.1", 5351)

    def test_error_code(self, client, mock_udp):
        ip_bytes = socket.inet_aton("0.0.0.0")
        resp_data = struct.pack("!BBHI", 0, 128, 2, 0) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        with pytest.raises(NatPmpError) as exc_info:
            client.get_external_address()
        assert exc_info.value.result_code == 2

    def test_timeout(self, client, mock_udp):
        mock_udp.recvfrom.side_effect = TimeoutError("timed out")

        with pytest.raises(NatPmpTimeoutError):
            client.get_external_address()
        assert mock_udp.sendto.call_count == 3

    def test_sends_to_correct_gateway(self, mock_udp):
        ip_bytes = socket.inet_aton("1.2.3.4")
        resp_data = struct.pack("!BBHI", 0, 128, 0, 99) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.99.0.1", 5351))

        c = NatPmpClient(mock_udp, gateway="10.99.0.1")
        c.get_external_address()
        mock_udp.sendto.assert_called_once()
        _, dest = mock_udp.sendto.call_args[0]
        assert dest == ("10.99.0.1", 5351)

    def test_uses_1024_buffer(self, client, mock_udp):
        ip_bytes = socket.inet_aton("1.2.3.4")
        resp_data = struct.pack("!BBHI", 0, 128, 0, 99) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        client.get_external_address()
        mock_udp.recvfrom.assert_called_with(1024)

    def test_rejects_wrong_sender(self, client, mock_udp):
        """Responses from unexpected addresses are discarded; correct sender accepted."""
        ip_bytes = socket.inet_aton("1.2.3.4")
        good_resp = struct.pack("!BBHI", 0, 128, 0, 99) + ip_bytes

        mock_udp.recvfrom.side_effect = [
            (good_resp, ("10.99.99.99", 5351)),  # wrong sender, retried in inner loop
            (good_resp, ("10.2.0.1", 5351)),  # correct sender, accepted
        ]

        resp = client.get_external_address()
        assert resp.external_ip == "1.2.3.4"

    def test_rejects_all_wrong_senders_timeout(self, client, mock_udp):
        """All responses from wrong senders eventually cause timeout."""
        ip_bytes = socket.inet_aton("1.2.3.4")
        good_resp = struct.pack("!BBHI", 0, 128, 0, 99) + ip_bytes

        # Each attempt: wrong sender then TimeoutError to move to next attempt
        side_effects = []
        for _ in range(3):  # Changed from 9 to match client fixture's max_retries=3
            side_effects.append((good_resp, ("10.99.99.99", 5351)))
            side_effects.append(TimeoutError("timed out"))
        mock_udp.recvfrom.side_effect = side_effects

        with pytest.raises(NatPmpTimeoutError):
            client.get_external_address()


class TestNatPmpClientRequestMapping:
    def test_udp_mapping(self, client, mock_udp):
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 60)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.request_mapping("UDP", internal_port=8080, lifetime=60)
        assert resp.internal_port == 8080
        assert resp.external_port == 9080
        assert resp.lifetime == 60

        # Verify full request format
        sent_data = mock_udp.sendto.call_args[0][0]
        assert len(sent_data) == 12
        ver, op, reserved, iport, eport, lt = struct.unpack("!BBHHHI", sent_data)
        assert ver == 0
        assert op == 1
        assert reserved == 0
        assert iport == 8080
        assert eport == 0
        assert lt == 60

    def test_tcp_mapping(self, client, mock_udp):
        resp_data = struct.pack("!BBHIHHI", 0, 130, 0, 100, 443, 443, 120)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.request_mapping("TCP", internal_port=443, external_port=443, lifetime=120)
        assert resp.internal_port == 443
        assert resp.external_port == 443

        sent_data = mock_udp.sendto.call_args[0][0]
        ver, op, _, iport, eport, lt = struct.unpack("!BBHHHI", sent_data)
        assert ver == 0
        assert op == 2
        assert iport == 443
        assert eport == 443
        assert lt == 120

    def test_delete_mapping(self, client, mock_udp):
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 0, 0)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.delete_mapping("UDP", internal_port=8080)
        assert resp.lifetime == 0
        assert resp.external_port == 0

        sent_data = mock_udp.sendto.call_args[0][0]
        _, _, _, _, eport, lt = struct.unpack("!BBHHHI", sent_data)
        assert eport == 0
        assert lt == 0

    def test_invalid_protocol(self, client):
        with pytest.raises(ValueError, match="Unknown protocol"):
            client.request_mapping("SCTP", internal_port=8080)

    def test_integer_opcode(self, client, mock_udp):
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 60)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.request_mapping(1, internal_port=8080)
        assert resp.external_port == 9080

        sent_data = mock_udp.sendto.call_args[0][0]
        _, op, _, _, _, _ = struct.unpack("!BBHHHI", sent_data)
        assert op == 1

    def test_case_insensitive_protocol(self, client, mock_udp):
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 60)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.request_mapping("udp", internal_port=8080)
        assert resp.external_port == 9080

    def test_mixed_case_protocol(self, client, mock_udp):
        resp_data = struct.pack("!BBHIHHI", 0, 130, 0, 100, 443, 443, 60)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.request_mapping("Tcp", internal_port=443)
        assert resp.external_port == 443

    def test_delete_all_mappings(self, client, mock_udp):
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 0, 0, 0)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        resp = client.delete_all_mappings("UDP")
        assert resp.lifetime == 0
        assert resp.external_port == 0

        sent_data = mock_udp.sendto.call_args[0][0]
        _, _, _, iport, eport, lt = struct.unpack("!BBHHHI", sent_data)
        assert iport == 0
        assert eport == 0
        assert lt == 0


class TestPortMappingContextManager:
    def test_enter_exit(self, client, mock_udp):
        # Initial mapping response
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 60)
        # Delete response
        del_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 0, 0)
        mock_udp.recvfrom.side_effect = [
            (resp_data, ("10.2.0.1", 5351)),
            (del_data, ("10.2.0.1", 5351)),
        ]

        pm = client.port_mapping("UDP", internal_port=8080, lifetime=60)
        with pm:
            assert pm.external_port == 9080
            assert pm.lifetime == 60
            assert pm._thread is not None
            assert not pm._stop_event.is_set()

        # After exit, thread should have stopped
        assert not pm._thread.is_alive()
        # Should have sent at least 2 requests: initial + delete
        assert mock_udp.sendto.call_count >= 2

    def test_properties_before_enter_raise(self, client):
        pm = PortMapping(client, "UDP", 8080)
        with pytest.raises(RuntimeError, match="not yet established"):
            _ = pm.external_port
        with pytest.raises(RuntimeError, match="not yet established"):
            _ = pm.lifetime

    def test_exit_suppresses_delete_error(self, client, mock_udp):
        """__exit__ should not raise when delete_mapping fails."""
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 60)
        mock_udp.recvfrom.side_effect = [
            (resp_data, ("10.2.0.1", 5351)),  # initial mapping
            TimeoutError("network down"),  # delete fails
        ]

        pm = client.port_mapping("UDP", internal_port=8080, lifetime=60)
        with pm:
            assert pm.external_port == 9080
        # Should not raise despite delete failure

    def test_double_enter_raises(self, client, mock_udp):
        """Calling __enter__ twice raises RuntimeError."""
        resp_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 60)
        del_data = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 0, 0)
        mock_udp.recvfrom.side_effect = [
            (resp_data, ("10.2.0.1", 5351)),
            (del_data, ("10.2.0.1", 5351)),
        ]

        pm = client.port_mapping("UDP", internal_port=8080, lifetime=60)
        pm.__enter__()
        try:
            with pytest.raises(RuntimeError, match="already active"):
                pm.__enter__()
        finally:
            pm.__exit__(None, None, None)

    def test_reentry_after_exit(self, client, mock_udp):
        """PortMapping can be re-entered after exiting, with fresh state."""
        resp1 = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 60)
        del1 = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 0, 0)
        resp2 = struct.pack("!BBHIHHI", 0, 129, 0, 200, 8080, 9081, 60)
        del2 = struct.pack("!BBHIHHI", 0, 129, 0, 200, 8080, 0, 0)

        mock_udp.recvfrom.side_effect = [
            (resp1, ("10.2.0.1", 5351)),
            (del1, ("10.2.0.1", 5351)),
            (resp2, ("10.2.0.1", 5351)),
            (del2, ("10.2.0.1", 5351)),
        ]

        pm = client.port_mapping("UDP", internal_port=8080, lifetime=60)

        # First entry
        with pm:
            assert pm.external_port == 9080

        # Second entry (should work, fresh state)
        with pm:
            assert pm.external_port == 9081

    def test_renewal_stops_on_lifetime_zero(self, client, mock_udp, caplog):
        """If gateway returns lifetime=0 during renewal, loop stops."""
        import logging

        initial_resp = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 2)
        zero_lt_resp = struct.pack("!BBHIHHI", 0, 129, 0, 101, 8080, 9080, 0)
        del_resp = struct.pack("!BBHIHHI", 0, 129, 0, 102, 8080, 0, 0)

        mock_udp.recvfrom.side_effect = [
            (initial_resp, ("10.2.0.1", 5351)),
            (zero_lt_resp, ("10.2.0.1", 5351)),
            (del_resp, ("10.2.0.1", 5351)),
        ]

        pm = client.port_mapping("UDP", internal_port=8080, lifetime=2)
        with caplog.at_level(logging.ERROR, logger="wireguard_requests.natpmp"):
            with pm:
                deadline = time.monotonic() + 5.0
                while mock_udp.sendto.call_count < 2 and time.monotonic() < deadline:
                    time.sleep(0.05)
                # Wait for thread to die after processing lifetime=0
                pm._thread.join(timeout=5.0)
                assert not pm._thread.is_alive(), "Renewal thread should stop on lifetime=0"

        assert any("lifetime=0" in r.message for r in caplog.records)

    def test_renewal_fires(self, client, mock_udp):
        """Verify the renewal thread actually sends renewal requests."""
        initial_resp = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 2)
        renewed_resp = struct.pack("!BBHIHHI", 0, 129, 0, 101, 8080, 9080, 2)
        del_resp = struct.pack("!BBHIHHI", 0, 129, 0, 102, 8080, 0, 0)

        mock_udp.recvfrom.side_effect = [
            (initial_resp, ("10.2.0.1", 5351)),
            (renewed_resp, ("10.2.0.1", 5351)),
            (del_resp, ("10.2.0.1", 5351)),
        ]

        pm = client.port_mapping("UDP", internal_port=8080, lifetime=2)
        with pm:
            # Poll for renewal instead of sleeping a fixed time
            deadline = time.monotonic() + 5.0
            while mock_udp.sendto.call_count < 2 and time.monotonic() < deadline:
                time.sleep(0.05)

        # Should have: initial + renewal + delete = at least 3 calls
        assert mock_udp.sendto.call_count >= 3

    def test_renewal_failure_does_not_crash_thread(self, fast_client, mock_udp):
        """Renewal failure should be logged but thread continues."""
        initial_resp = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 2)
        renewed_resp = struct.pack("!BBHIHHI", 0, 129, 0, 101, 8080, 9080, 2)
        del_resp = struct.pack("!BBHIHHI", 0, 129, 0, 102, 8080, 0, 0)

        mock_udp.recvfrom.side_effect = [
            (initial_resp, ("10.2.0.1", 5351)),  # initial mapping
            TimeoutError("renewal failed"),  # renewal attempt 1/2
            TimeoutError("renewal failed"),  # renewal attempt 2/2 -> fails
            (renewed_resp, ("10.2.0.1", 5351)),  # next renewal succeeds
            (del_resp, ("10.2.0.1", 5351)),  # delete
        ]

        pm = fast_client.port_mapping("UDP", internal_port=8080, lifetime=2)
        with pm:
            # Poll for renewal activity instead of sleeping a fixed time
            deadline = time.monotonic() + 5.0
            while mock_udp.sendto.call_count < 3 and time.monotonic() < deadline:
                time.sleep(0.05)
            assert pm._thread.is_alive()


class TestNatPmpErrorKeywordOnly:
    def test_result_code_keyword_only(self):
        """result_code must be passed as a keyword argument."""
        # This should work:
        err = NatPmpError("test", result_code=5)
        assert err.result_code == 5

        # Positional should fail:
        with pytest.raises(TypeError):
            NatPmpError("test", 5)

    def test_default_result_code(self):
        err = NatPmpError("test")
        assert err.result_code is None


# ---------------------------------------------------------------------------
# Constants and enums
# ---------------------------------------------------------------------------


class TestConstants:
    def test_natpmp_port(self):
        assert NATPMP_PORT == 5351

    def test_natpmp_version(self):
        assert NATPMP_VERSION == 0

    def test_opcodes(self):
        assert NatPmpOpcode.EXTERNAL_ADDRESS == 0
        assert NatPmpOpcode.MAP_UDP == 1
        assert NatPmpOpcode.MAP_TCP == 2

    def test_result_codes(self):
        assert NatPmpResultCode.SUCCESS == 0
        assert NatPmpResultCode.UNSUPPORTED_VERSION == 1
        assert NatPmpResultCode.NOT_AUTHORIZED == 2
        assert NatPmpResultCode.NETWORK_FAILURE == 3
        assert NatPmpResultCode.OUT_OF_RESOURCES == 4
        assert NatPmpResultCode.UNSUPPORTED_OPCODE == 5


# ---------------------------------------------------------------------------
# Private helper tests
# ---------------------------------------------------------------------------


class TestResolveOpcode:
    def test_udp_string(self):
        assert _resolve_opcode("UDP") == NatPmpOpcode.MAP_UDP

    def test_tcp_string(self):
        assert _resolve_opcode("TCP") == NatPmpOpcode.MAP_TCP

    def test_case_insensitive(self):
        assert _resolve_opcode("udp") == NatPmpOpcode.MAP_UDP
        assert _resolve_opcode("Tcp") == NatPmpOpcode.MAP_TCP

    def test_int_passthrough(self):
        assert _resolve_opcode(1) == 1
        assert _resolve_opcode(0) == 0

    def test_invalid_string(self):
        with pytest.raises(ValueError, match="Unknown protocol"):
            _resolve_opcode("SCTP")

    def test_int_out_of_range(self):
        with pytest.raises(ValueError, match="0-127"):
            _resolve_opcode(128)
        with pytest.raises(ValueError, match="0-127"):
            _resolve_opcode(-1)

    def test_boundary_values(self):
        assert _resolve_opcode(0) == 0
        assert _resolve_opcode(127) == 127


class TestRaiseForResultCode:
    def test_unsupported_version(self):
        with pytest.raises(NatPmpUnsupportedError) as exc_info:
            _raise_for_result_code(1)
        assert exc_info.value.result_code == 1

    def test_unsupported_opcode(self):
        with pytest.raises(NatPmpUnsupportedError) as exc_info:
            _raise_for_result_code(5)
        assert exc_info.value.result_code == 5

    def test_not_authorized(self):
        with pytest.raises(NatPmpError) as exc_info:
            _raise_for_result_code(2)
        assert exc_info.value.result_code == 2

    def test_network_failure(self):
        with pytest.raises(NatPmpError, match="NETWORK_FAILURE"):
            _raise_for_result_code(3)

    def test_out_of_resources(self):
        with pytest.raises(NatPmpError, match="OUT_OF_RESOURCES"):
            _raise_for_result_code(4)

    def test_unknown_code(self):
        with pytest.raises(NatPmpError, match="UNKNOWN"):
            _raise_for_result_code(99)


class TestNatPmpClientSocketConfig:
    def test_settimeout_called(self, mock_udp):
        """Client configures socket timeout before each attempt."""
        ip_bytes = socket.inet_aton("1.2.3.4")
        resp_data = struct.pack("!BBHI", 0, 128, 0, 99) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))

        client = NatPmpClient(mock_udp, gateway="10.2.0.1", initial_timeout=0.25)
        client.get_external_address()

        mock_udp.settimeout.assert_called()
        first_timeout = mock_udp.settimeout.call_args_list[0][0][0]
        assert first_timeout == pytest.approx(0.25, abs=0.01)


class TestPortValidation:
    def test_request_mapping_rejects_zero_port(self, client):
        with pytest.raises(ValueError, match="internal_port must be > 0"):
            client.request_mapping("UDP", internal_port=0)

    def test_delete_mapping_rejects_zero_port(self, client):
        with pytest.raises(ValueError, match="internal_port must be > 0"):
            client.delete_mapping("UDP", internal_port=0)

    def test_request_mapping_rejects_negative_port(self, client):
        with pytest.raises(ValueError):
            client.request_mapping("UDP", internal_port=-1)


class TestRenewalFailureEscalation:
    def test_error_logged_at_three_consecutive_failures(self, fast_client, mock_udp, caplog):
        """After 3 consecutive failures, an ERROR is logged."""
        import logging

        initial_resp = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 2)
        del_resp = struct.pack("!BBHIHHI", 0, 129, 0, 102, 8080, 0, 0)

        mock_udp.recvfrom.side_effect = [
            (initial_resp, ("10.2.0.1", 5351)),
            TimeoutError("fail 1"),
            TimeoutError("fail 2"),
            TimeoutError("fail 3"),
            TimeoutError("fail 4"),
            TimeoutError("fail 5"),
            TimeoutError("fail 6"),
            (del_resp, ("10.2.0.1", 5351)),
        ]

        pm = fast_client.port_mapping("UDP", internal_port=8080, lifetime=2)
        with caplog.at_level(logging.ERROR, logger="wireguard_requests.natpmp"):
            with pm:
                # Need 3 consecutive failures: initial(1) + 3 failures * 2 retries = 7 sends
                deadline = time.monotonic() + 10.0
                while mock_udp.sendto.call_count < 7 and time.monotonic() < deadline:
                    time.sleep(0.05)

        error_records = [
            r for r in caplog.records if "3 consecutive" in r.message and r.levelno >= logging.ERROR
        ]
        assert len(error_records) > 0

    def test_counter_resets_on_success(self, fast_client, mock_udp, caplog):
        """Consecutive failure counter resets after a successful renewal."""
        import logging

        initial_resp = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 2)
        renewed_resp = struct.pack("!BBHIHHI", 0, 129, 0, 101, 8080, 9080, 2)
        del_resp = struct.pack("!BBHIHHI", 0, 129, 0, 102, 8080, 0, 0)

        mock_udp.recvfrom.side_effect = [
            (initial_resp, ("10.2.0.1", 5351)),
            TimeoutError("fail 1"),
            TimeoutError("fail 2"),
            (renewed_resp, ("10.2.0.1", 5351)),
            TimeoutError("fail 1 again"),
            TimeoutError("fail 2 again"),
            (del_resp, ("10.2.0.1", 5351)),
        ]

        pm = fast_client.port_mapping("UDP", internal_port=8080, lifetime=2)
        with caplog.at_level(logging.ERROR, logger="wireguard_requests.natpmp"):
            with pm:
                deadline = time.monotonic() + 10.0
                while mock_udp.sendto.call_count < 5 and time.monotonic() < deadline:
                    time.sleep(0.05)

        error_records = [
            r for r in caplog.records if "consecutive" in r.message and r.levelno >= logging.ERROR
        ]
        assert len(error_records) == 0


class TestEpochMonitoring:
    def test_epoch_decrease_logged(self, fast_client, mock_udp, caplog):
        """Epoch decrease during renewal triggers a warning."""
        import logging

        initial_resp = struct.pack("!BBHIHHI", 0, 129, 0, 100, 8080, 9080, 2)
        # Epoch decreased from 100 to 50 (gateway restart)
        renewed_resp = struct.pack("!BBHIHHI", 0, 129, 0, 50, 8080, 9080, 2)
        del_resp = struct.pack("!BBHIHHI", 0, 129, 0, 51, 8080, 0, 0)

        mock_udp.recvfrom.side_effect = [
            (initial_resp, ("10.2.0.1", 5351)),
            (renewed_resp, ("10.2.0.1", 5351)),
            (del_resp, ("10.2.0.1", 5351)),
        ]

        pm = fast_client.port_mapping("UDP", internal_port=8080, lifetime=2)
        with caplog.at_level(logging.WARNING, logger="wireguard_requests.natpmp"):
            with pm:
                deadline = time.monotonic() + 5.0
                while mock_udp.sendto.call_count < 2 and time.monotonic() < deadline:
                    time.sleep(0.05)

        assert any("epoch decreased" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# OSError branch coverage (T-H1)
# ---------------------------------------------------------------------------


class TestSendAndReceiveOSErrors:
    def test_settimeout_oserror_raises_natpmp_error(self, client, mock_udp):
        """OSError from settimeout is wrapped in NatPmpError."""
        mock_udp.settimeout.side_effect = OSError("socket closed")
        with pytest.raises(NatPmpError, match="Socket error"):
            client.get_external_address()

    def test_sendto_oserror_raises_natpmp_error(self, client, mock_udp):
        """OSError from sendto is wrapped in NatPmpError."""
        mock_udp.sendto.side_effect = OSError("network unreachable")
        with pytest.raises(NatPmpError, match="Socket send error"):
            client.get_external_address()

    def test_recvfrom_non_timeout_oserror_raises_natpmp_error(self, client, mock_udp):
        """Non-TimeoutError OSError from recvfrom is wrapped in NatPmpError."""
        mock_udp.recvfrom.side_effect = OSError("connection reset")
        with pytest.raises(NatPmpError, match="Socket receive error"):
            client.get_external_address()

    def test_inner_settimeout_oserror_raises_natpmp_error(self, client, mock_udp):
        """OSError from inner settimeout (retry loop) is wrapped in NatPmpError."""
        call_count = 0

        def settimeout_side_effect(val):
            nonlocal call_count
            call_count += 1
            if call_count == 2:  # inner loop settimeout
                raise OSError("socket closed mid-receive")

        mock_udp.settimeout.side_effect = settimeout_side_effect
        mock_udp.sendto.return_value = 2

        with pytest.raises(NatPmpError, match="Socket error"):
            client.get_external_address()


# ---------------------------------------------------------------------------
# Concurrent access (T-H2)
# ---------------------------------------------------------------------------


class TestConcurrentAccess:
    def test_concurrent_requests_serialized(self, mock_udp):
        """Multiple threads calling the client are serialized by the lock."""
        ip_bytes = socket.inet_aton("1.2.3.4")
        resp_data = struct.pack("!BBHI", 0, 128, 0, 99) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))
        mock_udp.sendto.return_value = 2

        client = NatPmpClient(
            mock_udp,
            gateway="10.2.0.1",
            timeout=1.0,
            max_retries=2,
            initial_timeout=0.01,
        )

        errors = []

        def worker():
            try:
                client.get_external_address()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not errors, f"Threads raised errors: {errors}"
        assert mock_udp.sendto.call_count >= 3


# ---------------------------------------------------------------------------
# Malformed responses through client path (T-M4)
# ---------------------------------------------------------------------------


class TestMalformedResponses:
    """Test full client path with valid-length but semantically wrong responses."""

    def test_wrong_version_in_response(self, client, mock_udp):
        """12-byte response with version=1 (wrong) through client."""
        ip_bytes = socket.inet_aton("1.2.3.4")
        resp_data = struct.pack("!BBHI", 1, 128, 0, 99) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))
        with pytest.raises(NatPmpError, match="version"):
            client.get_external_address()

    def test_wrong_opcode_in_address_response(self, client, mock_udp):
        """Address response with wrong opcode through client."""
        ip_bytes = socket.inet_aton("1.2.3.4")
        resp_data = struct.pack("!BBHI", 0, 129, 0, 99) + ip_bytes
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))
        with pytest.raises(NatPmpError, match="opcode"):
            client.get_external_address()

    def test_error_result_code_in_mapping_response(self, client, mock_udp):
        """Mapping response with error result code through client."""
        resp_data = struct.pack("!BBHIHHI", 0, 129, 3, 0, 0, 0, 0)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))
        with pytest.raises(NatPmpError) as exc_info:
            client.request_mapping("UDP", internal_port=8080)
        assert exc_info.value.result_code == 3

    def test_mismatched_opcode_in_mapping_response(self, client, mock_udp):
        """UDP request gets TCP response opcode through client."""
        resp_data = struct.pack("!BBHIHHI", 0, 130, 0, 99, 8080, 9080, 60)
        mock_udp.recvfrom.return_value = (resp_data, ("10.2.0.1", 5351))
        with pytest.raises(NatPmpError, match="opcode"):
            client.request_mapping("UDP", internal_port=8080)
