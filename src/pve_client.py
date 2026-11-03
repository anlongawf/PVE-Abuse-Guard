"""Proxmox VE REST API client using API Token authentication."""

import logging
from typing import Any, Dict, List, Optional
import requests
import urllib3

from src.config import ProxmoxConfig

logger = logging.getLogger(__name__)


class PVEClientError(Exception):
    """Base exception for Proxmox API errors."""
    pass


class PVEAuthError(PVEClientError):
    """Raised when authentication fails (401/403)."""
    pass


class PVEClient:
    """Client for interacting with Proxmox VE REST API."""

    def __init__(self, config: ProxmoxConfig):
        self.config = config
        self.session = requests.Session()

        if not self.config.verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            self.session.verify = False

        self._setup_auth()

    def _setup_auth(self) -> None:
        """Configure API Token header according to Proxmox VE format."""
        if not self.config.token_value:
            logger.warning("PVE API token value is empty. Requests will likely fail.")
            return

        # Header format: PVEAPIToken=USER@REALM!TOKENID=SECRET
        token_header = (
            f"PVEAPIToken={self.config.user}!{self.config.token_name}={self.config.token_value}"
        )
        self.session.headers.update({
            "Authorization": token_header,
            "Accept": "application/json",
            "User-Agent": "PVE-Abuse-Guard/1.0",
        })

    def _url(self, path: str) -> str:
        """Construct full API URL from path."""
        clean_path = path.lstrip("/")
        return f"{self.config.base_url}/api2/json/{clean_path}"

    def request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Send HTTP request to Proxmox API with error handling."""
        url = self._url(path)
        try:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                timeout=self.config.timeout_seconds,
            )
        except requests.exceptions.RequestException as e:
            raise PVEClientError(f"Failed to connect to Proxmox host {self.config.host}: {e}") from e

        if resp.status_code in (401, 403):
            raise PVEAuthError(
                f"Proxmox API Authentication/Permission error ({resp.status_code}): {resp.text}"
            )

        if not resp.ok:
            raise PVEClientError(
                f"Proxmox API error ({resp.status_code}) on {method} {path}: {resp.text}"
            )

        try:
            result = resp.json()
            return result.get("data")
        except ValueError as e:
            raise PVEClientError(f"Invalid JSON returned from Proxmox: {resp.text}") from e

    def test_connection(self) -> Dict[str, Any]:
        """Verify connectivity and API token validity."""
        version_data = self.request("GET", "version")
        logger.info(
            f"Connected to Proxmox VE (version: {version_data.get('version', 'unknown')}, "
            f"release: {version_data.get('release', 'unknown')})"
        )
        return version_data

    def get_cluster_vms(self, include_lxc: bool = True) -> List[Dict[str, Any]]:
        """
        Fetch all VMs and containers in the cluster in a single call.
        Normalizes CPU to percentage (0 - 100%).
        """
        resources = self.request("GET", "cluster/resources", params={"type": "vm"})
        if not isinstance(resources, list):
            return []

        vms: List[Dict[str, Any]] = []
        for r in resources:
            vm_type = r.get("type")  # "qemu" or "lxc"
            if not include_lxc and vm_type == "lxc":
                continue

            status = r.get("status", "")
            # Only track running VMs
            if status != "running":
                continue

            # In Proxmox cluster/resources, cpu is 0.0 to 1.0 (representing 0% to 100% of allocated vCPUs)
            raw_cpu = float(r.get("cpu", 0.0))
            cpu_percent = round(raw_cpu * 100.0, 2)

            vms.append({
                "vmid": int(r.get("vmid")),
                "name": str(r.get("name", f"vm-{r.get('vmid')}")),
                "node": str(r.get("node", "")),
                "type": vm_type,
                "status": status,
                "cpu_percent": cpu_percent,
                "maxcpu": int(r.get("maxcpu", 1)),
                "mem_bytes": int(r.get("mem", 0)),
                "maxmem_bytes": int(r.get("maxmem", 0)),
                "disk_bytes": int(r.get("disk", 0)),
                "maxdisk_bytes": int(r.get("maxdisk", 0)),
                "netin_bytes": int(r.get("netin", 0)),
                "netout_bytes": int(r.get("netout", 0)),
                "uptime_seconds": int(r.get("uptime", 0)),
            })

        return vms

    def suspend_vm(self, node: str, vmid: int, vm_type: str = "qemu") -> bool:
        """Suspend a VM (qemu). For LXC, Proxmox does not support suspend, so freeze/stop is used."""
        try:
            if vm_type == "qemu":
                path = f"nodes/{node}/qemu/{vmid}/status/suspend"
            else:
                path = f"nodes/{node}/lxc/{vmid}/status/stop"

            self.request("POST", path)
            logger.info(f"Successfully requested {path} for VMID {vmid}")
            return True
        except Exception as e:
            logger.error(f"Failed to execute suspend/stop on VM {vmid} ({node}): {e}")
            return False

    def stop_vm(self, node: str, vmid: int, vm_type: str = "qemu") -> bool:
        """Force stop a VM or LXC container."""
        try:
            path = f"nodes/{node}/{vm_type}/{vmid}/status/stop"
            self.request("POST", path)
            logger.info(f"Successfully requested stop for VMID {vmid}")
            return True
        except Exception as e:
            logger.error(f"Failed to stop VM {vmid} ({node}): {e}")
            return False

    def get_vm_web_ui_url(self, node: str, vmid: int, vm_type: str = "qemu") -> str:
        """Generate direct clickable URL to Proxmox VE Web UI for this VM."""
        base = self.config.web_ui_url or f"https://{self.config.host}:{self.config.port}"
        base = base.rstrip("/")
        return f"{base}/#v1:0:={vm_type}/{vmid}"
