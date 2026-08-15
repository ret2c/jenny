from __future__ import annotations

import pytest

from tools.workflow_dashboard.dashboard import validate_remote_access


def test_loopback_is_the_default_safe_bind() -> None:
    assert validate_remote_access("127.0.0.1", False) == "127.0.0.1"


def test_remote_mode_accepts_only_a_concrete_tailscale_ipv4_address() -> None:
    assert validate_remote_access("100.64.0.1", True) == "100.64.0.1"

    for unsafe in ("0.0.0.0", "192.168.1.20", "8.8.8.8"):
        with pytest.raises(ValueError, match="concrete Tailscale IPv4"):
            validate_remote_access(unsafe, True)

    with pytest.raises(ValueError, match="requires explicit --allow-remote"):
        validate_remote_access("100.64.0.1", False)
