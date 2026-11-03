"""Unit tests for ActionManager."""

from unittest.mock import MagicMock
from src.action_manager import ActionManager
from src.config import AutoActionConfig


def test_action_disabled_by_default():
    cfg = AutoActionConfig(enabled=False, dry_run=True)
    mock_pve = MagicMock()
    mgr = ActionManager(cfg, mock_pve)

    assert not mgr.should_take_action(vmid=101, alert_count=5)
    success, action, dry_run = mgr.execute_action("pve1", 101, alert_count=5)
    assert not success
    assert action is None


def test_action_whitelist_protection():
    cfg = AutoActionConfig(enabled=True, dry_run=False, whitelist_vmids=[100, 200])
    mock_pve = MagicMock()
    mgr = ActionManager(cfg, mock_pve)

    assert not mgr.should_take_action(vmid=100, alert_count=5)
    success, action, _ = mgr.execute_action("pve1", 100, alert_count=5)
    assert not success
    assert mock_pve.suspend_vm.call_count == 0


def test_dry_run_mode_does_not_call_pve():
    cfg = AutoActionConfig(
        enabled=True,
        dry_run=True,
        action="suspend",
        violations_before_action=2,
    )
    mock_pve = MagicMock()
    mgr = ActionManager(cfg, mock_pve)

    assert mgr.should_take_action(vmid=101, alert_count=2)
    success, action, is_dry = mgr.execute_action("pve1", 101, alert_count=2)
    assert success is True
    assert action == "suspend"
    assert is_dry is True
    # In dry-run, live suspend_vm must NOT be called
    assert mock_pve.suspend_vm.call_count == 0


def test_live_execution():
    cfg = AutoActionConfig(
        enabled=True,
        dry_run=False,
        action="suspend",
        violations_before_action=1,
    )
    mock_pve = MagicMock()
    mock_pve.suspend_vm.return_value = True
    mgr = ActionManager(cfg, mock_pve)

    success, action, is_dry = mgr.execute_action("pve1", 101, alert_count=1)
    assert success is True
    assert action == "suspend"
    assert is_dry is False
    mock_pve.suspend_vm.assert_called_once_with("pve1", 101, "qemu")
