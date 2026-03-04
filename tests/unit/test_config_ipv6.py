"""Unit tests for dual-stack IPv6 config parsing."""

import sys
from unittest.mock import MagicMock

import pytest
from wireguard_requests.config import Peer, WireGuardConfig

DUAL_STACK_CONF = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24, fd00::2/64

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""

IPV4_ONLY_CONF = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""

IPV6_WITHOUT_PREFIX_CONF = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24, fd00::2

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""

REVERSED_ORDER_CONF = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = fd00::2/64, 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""


@pytest.fixture
def mock_native():
    mock_mod = MagicMock()
    mock_mod.WgPeer = MagicMock()
    mock_mod.WgConfig = MagicMock()
    key = "wireguard_requests._native"
    old = sys.modules.get(key)
    sys.modules[key] = mock_mod
    yield mock_mod
    if old is None:
        sys.modules.pop(key, None)
    else:
        sys.modules[key] = old


class TestWireGuardConfigIPv6:
    def test_parse_dual_stack(self):
        config = WireGuardConfig.from_string(DUAL_STACK_CONF)
        assert config.address == "10.0.0.2"
        assert config.prefix_len == 24
        assert config.address_v6 == "fd00::2"
        assert config.prefix_len_v6 == 64

    def test_parse_ipv4_only(self):
        config = WireGuardConfig.from_string(IPV4_ONLY_CONF)
        assert config.address == "10.0.0.2"
        assert config.prefix_len == 24
        assert config.address_v6 is None
        assert config.prefix_len_v6 is None

    def test_parse_ipv6_without_prefix(self):
        config = WireGuardConfig.from_string(IPV6_WITHOUT_PREFIX_CONF)
        assert config.address == "10.0.0.2"
        assert config.address_v6 == "fd00::2"
        assert config.prefix_len_v6 is None

    def test_parse_reversed_order(self):
        config = WireGuardConfig.from_string(REVERSED_ORDER_CONF)
        assert config.address == "10.0.0.2"
        assert config.prefix_len == 24
        assert config.address_v6 == "fd00::2"
        assert config.prefix_len_v6 == 64

    def test_manual_dual_stack_construction(self):
        config = WireGuardConfig(
            private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            address="10.0.0.2",
            address_v6="fd00::2",
            prefix_len_v6=64,
            peers=[
                Peer(
                    public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    endpoint="203.0.113.1:51820",
                )
            ],
        )
        assert config.address_v6 == "fd00::2"
        assert config.prefix_len_v6 == 64

    def test_to_native_dual_stack(self, mock_native):
        config = WireGuardConfig(
            private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            address="10.0.0.2",
            address_v6="fd00::2",
            prefix_len_v6=64,
            peers=[
                Peer(
                    public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    endpoint="203.0.113.1:51820",
                )
            ],
        )
        config.to_native()
        call_args = mock_native.WgConfig.call_args
        kwargs = call_args[1]
        assert kwargs["address_v6"] == "fd00::2"
        assert kwargs["prefix_len_v6"] == 64
