"""Unit tests for DiscordNotifier and Rich Embed generation."""

from unittest.mock import MagicMock, patch
import pytest

from src.config import DiscordConfig
from src.detector import AlertEvent
from src.discord_notifier import DiscordNotifier


def test_build_embed_violation():
    cfg = DiscordConfig(
        webhook_url="https://discord.com/api/webhooks/dummy/dummy",
        username="PVE Abuse Guard",
        avatar_url="https://example.com/icon.png",
    )
    notifier = DiscordNotifier(cfg)

    event = AlertEvent(
        vmid=101,
        name="ubuntu-miner",
        node="pve-node-01",
        vm_type="qemu",
        rule_name="cpu_mining",
        event_type="VIOLATION",
        severity="critical",
        current_cpu_percent=99.2,
        avg_cpu_percent=98.5,
        peak_cpu_percent=100.0,
        duration_seconds=1800.0,
        first_seen_at=1700000000.0,
        uptime_seconds=86400,
        mem_used_bytes=4294967296,
        mem_max_bytes=8589934592,
        alert_count=1,
    )

    embed = notifier.build_embed(event, ui_url="https://pve.example.com:8006/#v1:0:=qemu/101")
    assert "CRITICAL" in embed["title"]
    assert embed["color"] == 0xE74C3C  # Red
    field_names = [f["name"] for f in embed["fields"]]
    assert any("Máy ảo (VM)" in f for f in field_names)
    assert any("CPU Hiện tại" in f for f in field_names)
    assert any("Proxmox Web UI" in f for f in field_names)


def test_build_embed_resolved():
    cfg = DiscordConfig()
    notifier = DiscordNotifier(cfg)

    event = AlertEvent(
        vmid=101,
        name="ubuntu-miner",
        node="pve-node-01",
        vm_type="qemu",
        rule_name="cpu_mining",
        event_type="RESOLVED",
        severity="info",
        current_cpu_percent=12.5,
        avg_cpu_percent=12.5,
        peak_cpu_percent=12.5,
        duration_seconds=1800.0,
        first_seen_at=1700000000.0,
        uptime_seconds=86400,
        mem_used_bytes=4294967296,
        mem_max_bytes=8589934592,
        alert_count=1,
    )

    embed = notifier.build_embed(event)
    assert "ĐÃ HẾT VI PHẠM" in embed["title"]
    assert embed["color"] == 0x2ECC71  # Green


@patch("requests.post")
def test_send_alert_handles_429_retry(mock_post):
    cfg = DiscordConfig(
        webhook_url="https://discord.com/api/webhooks/dummy/dummy",
        max_retries=2,
    )
    notifier = DiscordNotifier(cfg)

    # 1st attempt: 429 Rate limited with retry_after = 0.01
    resp_429 = MagicMock()
    resp_429.status_code = 429
    resp_429.json.return_value = {"retry_after": 0.01}
    resp_429.headers = {}

    # 2nd attempt: 204 Success
    resp_204 = MagicMock()
    resp_204.status_code = 204

    mock_post.side_effect = [resp_429, resp_204]

    event = AlertEvent(
        vmid=101,
        name="ubuntu-miner",
        node="pve-node-01",
        vm_type="qemu",
        rule_name="cpu_mining",
        event_type="VIOLATION",
        severity="warning",
        current_cpu_percent=92.0,
        avg_cpu_percent=92.0,
        peak_cpu_percent=95.0,
        duration_seconds=1800.0,
        first_seen_at=1700000000.0,
        uptime_seconds=86400,
        mem_used_bytes=1000,
        mem_max_bytes=2000,
    )

    success = notifier.send_alert(event)
    assert success is True
    assert mock_post.call_count == 2
