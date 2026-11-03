"""In-memory tracking engine for VM metric samples, violation states, and cooldowns.

Zero-disk footprint: all data is stored purely in memory (RAM).
"""

import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class MetricSample:
    """Single point in time metric sample."""
    timestamp: float
    cpu_percent: float
    mem_bytes: int
    uptime_seconds: int


@dataclass
class ViolationState:
    """Tracks state of an active or resolved violation."""
    vmid: int
    node: str
    name: str
    status: str  # "ACTIVE" or "RESOLVED"
    first_seen_at: float
    last_seen_at: float
    last_alerted_at: float = 0.0
    alert_count: int = 0
    consecutive_normal_samples: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class InMemoryTracker:
    """Manages sliding window metric buffers and violation states entirely in RAM."""

    def __init__(self):
        # vmid -> deque of MetricSample
        self._samples: Dict[int, Deque[MetricSample]] = {}
        # vmid -> ViolationState
        self._violations: Dict[int, ViolationState] = {}
        # Track last update timestamp
        self._last_cleanup: float = time.time()

    def record_sample(
        self,
        vmid: int,
        node: str,
        name: str,
        cpu_percent: float,
        mem_bytes: int,
        uptime_seconds: int,
        current_time: float,
        max_window_seconds: float = 2700.0,  # 45 mins retention in RAM
    ) -> None:
        """Add a metric sample to the in-memory ring buffer and prune samples older than max_window."""
        if vmid not in self._samples:
            self._samples[vmid] = deque()

        buffer = self._samples[vmid]
        buffer.append(
            MetricSample(
                timestamp=current_time,
                cpu_percent=cpu_percent,
                mem_bytes=mem_bytes,
                uptime_seconds=uptime_seconds,
            )
        )

        # Evict samples older than max_window_seconds
        cutoff = current_time - max_window_seconds
        while buffer and buffer[0].timestamp < cutoff:
            buffer.popleft()

    def get_samples_in_window(
        self, vmid: int, window_seconds: float, current_time: float
    ) -> List[MetricSample]:
        """Retrieve all samples for a VM within the specified lookback window."""
        buffer = self._samples.get(vmid)
        if not buffer:
            return []

        cutoff = current_time - window_seconds
        return [s for s in buffer if s.timestamp >= cutoff]

    def get_violation(self, vmid: int) -> Optional[ViolationState]:
        """Get the current violation state for a VM."""
        return self._violations.get(vmid)

    def record_violation_active(
        self,
        vmid: int,
        node: str,
        name: str,
        current_time: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ViolationState:
        """Mark or update violation as ACTIVE in memory."""
        meta = metadata or {}
        viol = self._violations.get(vmid)

        if viol is None:
            viol = ViolationState(
                vmid=vmid,
                node=node,
                name=name,
                status="ACTIVE",
                first_seen_at=current_time,
                last_seen_at=current_time,
                last_alerted_at=0.0,
                alert_count=0,
                consecutive_normal_samples=0,
                metadata=meta,
            )
            self._violations[vmid] = viol
        else:
            if viol.status == "RESOLVED":
                # Re-triggered violation
                viol.status = "ACTIVE"
                viol.first_seen_at = current_time
                viol.last_seen_at = current_time
                viol.consecutive_normal_samples = 0
                viol.metadata = meta
                viol.node = node
                viol.name = name
            else:
                # Continuing active violation
                viol.last_seen_at = current_time
                viol.consecutive_normal_samples = 0
                viol.metadata = meta
                viol.node = node
                viol.name = name

        return viol

    def is_in_cooldown(self, vmid: int, cooldown_seconds: float, current_time: float) -> bool:
        """Check if VM has been alerted recently and is currently in cooldown."""
        viol = self._violations.get(vmid)
        if not viol or viol.last_alerted_at <= 0:
            return False
        return (current_time - viol.last_alerted_at) < cooldown_seconds

    def record_alert_sent(self, vmid: int, current_time: float) -> None:
        """Update last_alerted_at and increment alert counter."""
        viol = self._violations.get(vmid)
        if viol:
            viol.last_alerted_at = current_time
            viol.alert_count += 1

    def increment_normal_sample(self, vmid: int) -> int:
        """Increment consecutive normal samples count for active violation."""
        viol = self._violations.get(vmid)
        if viol and viol.status == "ACTIVE":
            viol.consecutive_normal_samples += 1
            return viol.consecutive_normal_samples
        return 0

    def mark_violation_resolved(self, vmid: int, current_time: float) -> None:
        """Mark violation as RESOLVED in memory."""
        viol = self._violations.get(vmid)
        if viol:
            viol.status = "RESOLVED"
            viol.last_seen_at = current_time
            viol.consecutive_normal_samples = 0

    def prune_stale_vms(self, running_vmids: List[int]) -> None:
        """Remove metrics and resolved states for VMs that are no longer running."""
        running_set = set(running_vmids)

        # Clean samples of VMs that stopped
        for vmid in list(self._samples.keys()):
            if vmid not in running_set:
                del self._samples[vmid]

        # Clean old resolved violations for VMs that stopped
        for vmid, viol in list(self._violations.items()):
            if vmid not in running_set and viol.status == "RESOLVED":
                del self._violations[vmid]
