"""Unit tests for MiningDetector."""

from src.config import MiningRuleConfig
from src.detector import MiningDetector
from src.in_memory_tracker import InMemoryTracker


def create_detector(threshold: float = 90.0, duration_minutes: int = 30, poll_interval: int = 60):
    cfg = MiningRuleConfig(
        enabled=True,
        cpu_threshold_percent=threshold,
        duration_minutes=duration_minutes,
        poll_interval_seconds=poll_interval,
        min_samples_ratio=0.85,
        critical_cpu_percent=98.0,
        exclude_vmids=[999],
    )
    tracker = InMemoryTracker()
    return MiningDetector(cfg, tracker), tracker


def test_normal_cpu_no_alert():
    detector, _ = create_detector()
    now = 1000.0

    vm_data = {
        "vmid": 101,
        "name": "vps-normal",
        "node": "pve1",
        "type": "qemu",
        "cpu_percent": 15.0,
        "mem_bytes": 1000,
        "maxmem_bytes": 2000,
        "uptime_seconds": 3600,
    }

    event = detector.evaluate_vm(vm_data, current_time=now)
    assert event is None


def test_short_cpu_burst_no_alert():
    detector, _ = create_detector(duration_minutes=30, poll_interval=60)
    start_time = 1000.0

    # Simulate 5 minutes of 95% CPU (5 samples)
    for i in range(5):
        vm_data = {
            "vmid": 101,
            "name": "vps-burst",
            "node": "pve1",
            "type": "qemu",
            "cpu_percent": 95.0,
            "mem_bytes": 1000,
            "maxmem_bytes": 2000,
            "uptime_seconds": 3600 + (i * 60),
        }
        event = detector.evaluate_vm(vm_data, current_time=start_time + (i * 60.0))
        # Should not alert because duration is only 5 mins (< 30 mins)
        assert event is None


def test_sustained_high_cpu_triggers_violation_alert():
    detector, tracker = create_detector(threshold=90.0, duration_minutes=30, poll_interval=60)
    start_time = 1000.0
    last_event = None

    # Simulate 31 minutes of 95% CPU (31 samples at 60s interval)
    for i in range(31):
        now = start_time + (i * 60.0)
        vm_data = {
            "vmid": 101,
            "name": "vps-miner",
            "node": "pve1",
            "type": "qemu",
            "cpu_percent": 95.0,
            "mem_bytes": 1000,
            "maxmem_bytes": 2000,
            "uptime_seconds": 3600 + (i * 60),
        }
        event = detector.evaluate_vm(vm_data, current_time=now, cooldown_seconds=3600.0)
        if event:
            last_event = event

    assert last_event is not None
    assert last_event.event_type == "VIOLATION"
    assert last_event.vmid == 101
    assert last_event.severity == "warning"
    assert last_event.current_cpu_percent == 95.0
    assert last_event.avg_cpu_percent == 95.0


def test_critical_severity_when_above_98():
    detector, _ = create_detector(threshold=90.0, duration_minutes=5, poll_interval=60)
    start_time = 1000.0
    last_event = None

    for i in range(6):
        now = start_time + (i * 60.0)
        vm_data = {
            "vmid": 102,
            "name": "vps-heavy-miner",
            "node": "pve1",
            "type": "qemu",
            "cpu_percent": 99.5,
            "mem_bytes": 1000,
            "maxmem_bytes": 2000,
            "uptime_seconds": 3600 + (i * 60),
        }
        event = detector.evaluate_vm(vm_data, current_time=now, cooldown_seconds=3600.0)
        if event:
            last_event = event

    assert last_event is not None
    assert last_event.severity == "critical"


def test_cooldown_suppresses_duplicate_alerts():
    detector, tracker = create_detector(threshold=90.0, duration_minutes=5, poll_interval=60)
    start_time = 1000.0

    # 1. Trigger first alert at sample 5 (5 minutes)
    for i in range(6):
        now = start_time + (i * 60.0)
        vm_data = {
            "vmid": 101,
            "name": "vps-miner",
            "node": "pve1",
            "type": "qemu",
            "cpu_percent": 95.0,
            "mem_bytes": 1000,
            "maxmem_bytes": 2000,
            "uptime_seconds": 3600 + (i * 60),
        }
        event = detector.evaluate_vm(vm_data, current_time=now, cooldown_seconds=3600.0)
        if event:
            # Simulate daemon recording that alert was sent
            tracker.record_alert_sent(101, now)

    # 2. Next sample at minute 6 (still 95% CPU, but inside 3600s cooldown)
    now_min6 = start_time + (6 * 60.0)
    vm_data["cpu_percent"] = 96.0
    event_cooldown = detector.evaluate_vm(vm_data, current_time=now_min6, cooldown_seconds=3600.0)
    # Should be None due to cooldown
    assert event_cooldown is None


def test_resolved_alert_after_cpu_drops():
    detector, tracker = create_detector(threshold=90.0, duration_minutes=5, poll_interval=60)
    start_time = 1000.0

    # 1. Trigger violation
    for i in range(6):
        now = start_time + (i * 60.0)
        vm_data = {
            "vmid": 101,
            "name": "vps-miner",
            "node": "pve1",
            "type": "qemu",
            "cpu_percent": 95.0,
            "mem_bytes": 1000,
            "maxmem_bytes": 2000,
            "uptime_seconds": 3600 + (i * 60),
        }
        event = detector.evaluate_vm(vm_data, current_time=now, cooldown_seconds=3600.0)
        if event:
            tracker.record_alert_sent(101, now)

    # 2. CPU drops to 10% for sample 1 (needs 2 samples to stabilize)
    vm_data["cpu_percent"] = 10.0
    now_drop1 = start_time + (7 * 60.0)
    ev1 = detector.evaluate_vm(vm_data, current_time=now_drop1, resolved_stabilize_samples=2)
    assert ev1 is None  # Stabilizing sample 1

    # 3. CPU stays at 10% for sample 2
    now_drop2 = start_time + (8 * 60.0)
    ev2 = detector.evaluate_vm(vm_data, current_time=now_drop2, resolved_stabilize_samples=2)
    assert ev2 is not None
    assert ev2.event_type == "RESOLVED"
    assert ev2.vmid == 101
    assert ev2.current_cpu_percent == 10.0


def test_excluded_vm_is_ignored():
    detector, _ = create_detector(threshold=90.0, duration_minutes=5, poll_interval=60)
    vm_data = {
        "vmid": 999,  # In exclude_vmids
        "name": "backup-server",
        "node": "pve1",
        "type": "qemu",
        "cpu_percent": 100.0,
        "mem_bytes": 1000,
        "maxmem_bytes": 2000,
        "uptime_seconds": 3600,
    }
    event = detector.evaluate_vm(vm_data, current_time=1000.0)
    assert event is None
