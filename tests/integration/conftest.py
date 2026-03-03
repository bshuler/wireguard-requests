"""Fixtures for integration tests."""

import subprocess
import time
from pathlib import Path

import pytest
from wireguard_requests.config import WireGuardConfig

INTEGRATION_DIR = Path(__file__).parent
WG_CONFIG_DIR = INTEGRATION_DIR / "wg-config"


def is_docker_available():
    """Check if Docker is available."""
    try:
        subprocess.run(["docker", "info"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


@pytest.fixture(scope="session")
def wg_server():
    """Start a WireGuard server in Docker for integration tests.

    This fixture starts the docker-compose stack and waits for it
    to be ready. The stack includes a WireGuard server and an HTTP
    server accessible through the tunnel.
    """
    if not is_docker_available():
        pytest.skip("Docker not available")

    compose_file = INTEGRATION_DIR / "docker-compose.yml"

    # Start the stack.
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "up", "-d"],
        check=True,
    )

    # Wait for the WireGuard server to generate client configs.
    max_wait = 30
    config_path = WG_CONFIG_DIR / "peer_testclient" / "peer_testclient.conf"
    for _ in range(max_wait):
        if config_path.exists():
            break
        time.sleep(1)
    else:
        pytest.fail("WireGuard server did not generate client config in time")

    # Extra wait for services to stabilize.
    time.sleep(3)

    yield

    # Tear down.
    subprocess.run(
        ["docker", "compose", "-f", str(compose_file), "down", "-v"],
        check=True,
    )


@pytest.fixture
def wg_config(wg_server):
    """Load the auto-generated WireGuard client config."""
    config_path = WG_CONFIG_DIR / "peer_testclient" / "peer_testclient.conf"
    if not config_path.exists():
        pytest.skip("WireGuard client config not found")
    return WireGuardConfig.from_file(config_path)
