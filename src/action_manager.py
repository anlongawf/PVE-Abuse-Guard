"""Automated action manager for suspending or stopping abusive VMs."""

import logging
from typing import Optional, Tuple

from src.config import AutoActionConfig
from src.pve_client import PVEClient

logger = logging.getLogger(__name__)


class ActionManager:
    """Handles automated mitigation (suspend, stop) with dry-run and whitelist checks."""

    def __init__(self, config: AutoActionConfig, pve_client: PVEClient):
        self.config = config
        self.pve_client = pve_client

    def should_take_action(self, vmid: int, alert_count: int) -> bool:
        """Determine if an automated mitigation action is warranted."""
        if not self.config.enabled:
            return False

        if vmid in self.config.whitelist_vmids:
            logger.info(f"VMID {vmid} is in auto_action whitelist. Skipping mitigation.")
            return False

        return alert_count >= self.config.violations_before_action

    def execute_action(
        self, node: str, vmid: int, vm_type: str = "qemu", alert_count: int = 1
    ) -> Tuple[bool, Optional[str], bool]:
        """
        Execute configured mitigation action.
        Returns: (success, action_name, is_dry_run)
        """
        if not self.should_take_action(vmid, alert_count):
            return False, None, self.config.dry_run

        action_name = self.config.action.lower()

        if self.config.dry_run:
            logger.warning(
                f"[DRY-RUN] Auto-mitigation triggered for VM {vmid} ({node}, type={vm_type}). "
                f"Action '{action_name}' was NOT executed (dry_run=True)."
            )
            return True, action_name, True

        # Live execution
        logger.warning(
            f"[LIVE-ACTION] Executing '{action_name}' on abusive VM {vmid} ({node}, type={vm_type})."
        )
        if action_name == "suspend":
            success = self.pve_client.suspend_vm(node, vmid, vm_type)
        elif action_name in ("stop", "shutdown"):
            success = self.pve_client.stop_vm(node, vmid, vm_type)
        else:
            logger.error(f"Unknown action '{action_name}' requested for VM {vmid}.")
            return False, action_name, False

        return success, action_name, False
