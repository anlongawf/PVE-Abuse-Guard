"""CPU Crypto Mining Detection Engine using in-memory sliding window."""

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.config import MiningRuleConfig
from src.in_memory_tracker import InMemoryTracker

logger = logging.getLogger(__name__)


@dataclass
class AlertEvent:
    """Represents an alert event ready to be notified to Discord."""
    vmid: int
    name: str
    node: str
    vm_type: str
    rule_name: str
    event_type: str  # "VIOLATION" or "RESOLVED"
    severity: str    # "info", "warning", "critical"
    current_cpu_percent: float
    avg_cpu_percent: float
    peak_cpu_percent: float
    duration_seconds: float
    first_seen_at: float
    uptime_seconds: int
    mem_used_bytes: int
    mem_max_bytes: int
    alert_count: int = 1
    action_taken: Optional[str] = None
    dry_run: bool = False


class MiningDetector:
    """Detects sustained high CPU utilization indicative of crypto mining."""

    def __init__(self, config: MiningRuleConfig, tracker: InMemoryTracker):
        self.config = config
        self.tracker = tracker

    def evaluate_vm(
        self,
        vm_data: Dict[str, Any],
        current_time: Optional[float] = None,
        cooldown_seconds: float = 3600.0,
        resolved_stabilize_samples: int = 2,
    ) -> Optional[AlertEvent]:
        """
        Evaluate a single VM's metric sample against the mining rule.
        Returns an AlertEvent if an alert (violation or resolved) should be sent.
        """
        now = current_time if current_time is not None else time.time()
        vmid = vm_data["vmid"]
        node = vm_data.get("node", "unknown")
        name = vm_data.get("name", f"vm-{vmid}")
        vm_type = vm_data.get("type", "qemu")
        current_cpu = float(vm_data.get("cpu_percent", 0.0))
        mem_bytes = int(vm_data.get("mem_bytes", 0))
        maxmem_bytes = int(vm_data.get("maxmem_bytes", 0))
        uptime = int(vm_data.get("uptime_seconds", 0))

        # Check whitelist / exclusion
        if vmid in self.config.exclude_vmids:
            return None

        window_seconds = self.config.duration_minutes * 60.0
        # Retention in RAM buffer is 1.5x the duration window to ensure smooth calculations
        buffer_window = max(window_seconds * 1.5, window_seconds + 300)

        # 1. Record current sample into in-memory ring buffer
        self.tracker.record_sample(
            vmid=vmid,
            node=node,
            name=name,
            cpu_percent=current_cpu,
            mem_bytes=mem_bytes,
            uptime_seconds=uptime,
            current_time=now,
            max_window_seconds=buffer_window,
        )

        rule_name = "cpu_mining"
        is_high_cpu = current_cpu >= self.config.cpu_threshold_percent
        active_viol = self.tracker.get_violation(vmid)

        if is_high_cpu:
            # Query in-memory samples in the required duration window
            samples = self.tracker.get_samples_in_window(vmid, window_seconds, now)

            theoretical_samples = max(1, int(window_seconds / max(1, self.config.poll_interval_seconds)))
            min_required_samples = max(2, int(theoretical_samples * 0.7))
            time_span = (samples[-1].timestamp - samples[0].timestamp) if len(samples) >= 2 else 0.0

            # Condition: Sufficient samples collected AND time span spans almost the full window
            if len(samples) >= min_required_samples and time_span >= (window_seconds * 0.85):
                high_count = sum(1 for s in samples if s.cpu_percent >= self.config.cpu_threshold_percent)
                high_ratio = high_count / len(samples)

                if high_ratio >= self.config.min_samples_ratio:
                    avg_cpu = sum(s.cpu_percent for s in samples) / len(samples)
                    peak_cpu = max(s.cpu_percent for s in samples)

                    meta = {
                        "avg_cpu": round(avg_cpu, 2),
                        "peak_cpu": round(peak_cpu, 2),
                        "samples_count": len(samples),
                    }
                    viol = self.tracker.record_violation_active(
                        vmid=vmid,
                        node=node,
                        name=name,
                        current_time=now,
                        metadata=meta,
                    )

                    duration = now - viol.first_seen_at

                    # Check in-memory cooldown
                    in_cooldown = self.tracker.is_in_cooldown(vmid, cooldown_seconds, now)

                    if not in_cooldown:
                        severity = "critical" if current_cpu >= self.config.critical_cpu_percent else "warning"
                        alert_count = viol.alert_count + 1

                        return AlertEvent(
                            vmid=vmid,
                            name=name,
                            node=node,
                            vm_type=vm_type,
                            rule_name=rule_name,
                            event_type="VIOLATION",
                            severity=severity,
                            current_cpu_percent=round(current_cpu, 2),
                            avg_cpu_percent=round(avg_cpu, 2),
                            peak_cpu_percent=round(peak_cpu, 2),
                            duration_seconds=round(duration, 1),
                            first_seen_at=viol.first_seen_at,
                            uptime_seconds=uptime,
                            mem_used_bytes=mem_bytes,
                            mem_max_bytes=maxmem_bytes,
                            alert_count=alert_count,
                        )
        else:
            # CPU is currently below threshold
            if active_viol and active_viol.status == "ACTIVE":
                normal_count = self.tracker.increment_normal_sample(vmid)

                # Stabilize: must stay normal for required consecutive samples before resolving
                if normal_count >= resolved_stabilize_samples:
                    duration = now - active_viol.first_seen_at
                    self.tracker.mark_violation_resolved(vmid, now)

                    # Only notify resolved if an alert was previously sent
                    if active_viol.alert_count > 0:
                        return AlertEvent(
                            vmid=vmid,
                            name=name,
                            node=node,
                            vm_type=vm_type,
                            rule_name=rule_name,
                            event_type="RESOLVED",
                            severity="info",
                            current_cpu_percent=round(current_cpu, 2),
                            avg_cpu_percent=round(current_cpu, 2),
                            peak_cpu_percent=round(current_cpu, 2),
                            duration_seconds=round(duration, 1),
                            first_seen_at=active_viol.first_seen_at,
                            uptime_seconds=uptime,
                            mem_used_bytes=mem_bytes,
                            mem_max_bytes=maxmem_bytes,
                            alert_count=active_viol.alert_count,
                        )

        return None
