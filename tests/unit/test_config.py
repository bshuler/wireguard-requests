"""Unit tests for WireGuard configuration parsing."""

import pytest
from wireguard_requests.config import Peer, WireGuardConfig

BASIC_CONF = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24
ListenPort = 51820
DNS = 1.1.1.1, 8.8.8.8
MTU = 1400

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""

MULTI_PEER_CONF = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.0.0.0/24

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2piVFBs2LR3PGk=
Endpoint = 203.0.113.2:51820
AllowedIPs = 10.0.1.0/24
PersistentKeepalive = 15
"""


class TestWireGuardConfig:
    def test_parse_basic(self):
        config = WireGuardConfig.from_string(BASIC_CONF)
        assert config.private_key == "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
        assert config.address == "10.0.0.2"
        assert config.prefix_len == 24
        assert config.listen_port == 51820
        assert config.mtu == 1400
        assert config.dns == ["1.1.1.1", "8.8.8.8"]

    def test_parse_peer(self):
        config = WireGuardConfig.from_string(BASIC_CONF)
        assert len(config.peers) == 1
        peer = config.peers[0]
        assert peer.public_key == "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="
        assert peer.endpoint == "203.0.113.1:51820"
        assert peer.allowed_ips == ["0.0.0.0/0"]
        assert peer.persistent_keepalive == 25

    def test_parse_multiple_peers(self):
        config = WireGuardConfig.from_string(MULTI_PEER_CONF)
        assert len(config.peers) == 2
        assert config.peers[0].endpoint == "203.0.113.1:51820"
        assert config.peers[1].endpoint == "203.0.113.2:51820"
        assert config.peers[1].persistent_keepalive == 15

    def test_parse_comments(self):
        conf = """\
# This is a comment
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
; Another comment
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""
        config = WireGuardConfig.from_string(conf)
        assert config.address == "10.0.0.2"

    def test_missing_private_key(self):
        conf = """\
[Interface]
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""
        with pytest.raises(ValueError, match="Missing PrivateKey"):
            WireGuardConfig.from_string(conf)

    def test_missing_address(self):
        conf = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""
        with pytest.raises(ValueError, match="Missing Address"):
            WireGuardConfig.from_string(conf)

    def test_missing_peers(self):
        conf = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24
"""
        with pytest.raises(ValueError, match="No .Peer. sections"):
            WireGuardConfig.from_string(conf)

    def test_defaults(self):
        conf = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""
        config = WireGuardConfig.from_string(conf)
        assert config.listen_port == 0
        assert config.mtu == 1420
        assert config.dns == []
        assert config.peers[0].persistent_keepalive is None

    def test_address_without_prefix(self):
        conf = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
"""
        config = WireGuardConfig.from_string(conf)
        assert config.address == "10.0.0.2"
        assert config.prefix_len == 24  # default

    def test_from_file(self, tmp_path):
        conf_file = tmp_path / "wg0.conf"
        conf_file.write_text(BASIC_CONF)
        config = WireGuardConfig.from_file(conf_file)
        assert config.address == "10.0.0.2"

    def test_from_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            WireGuardConfig.from_file("/nonexistent/wg0.conf")

    def test_manual_construction(self):
        config = WireGuardConfig(
            private_key="yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
            address="10.0.0.2",
            peers=[
                Peer(
                    public_key="xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
                    endpoint="203.0.113.1:51820",
                )
            ],
        )
        assert config.address == "10.0.0.2"
        assert len(config.peers) == 1

    def test_multiple_allowed_ips(self):
        conf = """\
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.0.0.2/24

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.1:51820
AllowedIPs = 10.0.0.0/24, 192.168.1.0/24, 172.16.0.0/12
"""
        config = WireGuardConfig.from_string(conf)
        assert config.peers[0].allowed_ips == [
            "10.0.0.0/24",
            "192.168.1.0/24",
            "172.16.0.0/12",
        ]
