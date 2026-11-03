"""Unit tests for InMemoryTracker."""

import time
from src.in_memory_tracker import InMemoryTracker


def test_record_sample_and_window_retrieval():
    tracker = InMemoryTracker()
    now = 1000.0

    # Add 5 samples, 60 seconds apart
    for i in range(5):
        ts = now + (i * 60.0)
        tracker.record_sample(
            vmid=101,
            node="pve1",
            name="vps-test",
            cpu_percent=95.0,
            mem_bytes=2147483648,
            uptime_seconds=3600,
            current_time=ts,
            max_window_seconds=600.0,
        )

    # Window of 150 seconds lookback from last timestamp (now + 240)
    samples = tracker.get_samples_in_window(vmid=101, window_seconds=150.0, current_time=now + 240.0)
    # Samples at ts = 1240, 1180, 1120 are within [1240 - 150 = 1090]
    assert len(samples) == 3
    assert all(s.cpu_percent == 95.0 for s in samples)


def test_eviction_of_old_samples():
    tracker = InMemoryTracker()
    now = 1000.0

    # Add sample at ts=1000 with max_window = 100
    tracker.record_sample(101, "pve1", "vps-test", 50.0, 1000, 100, now, max_window_seconds=100.0)
    # Add sample at ts=1200 (200s later)
    tracker.record_sample(101, "pve1", "vps-test", 80.0, 1000, 300, now + 200.0, max_window_seconds=100.0)

    # Sample at ts=1000 should be evicted because cutoff is 1200 - 100 = 1100
    samples = tracker.get_samples_in_window(101, window_seconds=500.0, current_time=now + 200.0)
    assert len(samples) == 1
    assert samples[0].cpu_percent == 80.0


def test_violation_state_and_cooldown():
    tracker = InMemoryTracker()
    now = 5000.0

    # Initially no violation
    assert tracker.get_violation(101) is None
    assert not tracker.is_in_cooldown(101, cooldown_seconds=3600.0, current_time=now)

    # Record active violation
    viol = tracker.record_violation_active(101, "pve1", "vps-test", now, {"avg_cpu": 96.0})
    assert viol.status == "ACTIVE"
    assert viol.first_seen_at == now
    assert viol.last_alerted_at == 0.0

    # Still not in cooldown because no alert sent yet
    assert not tracker.is_in_cooldown(101, cooldown_seconds=3600.0, current_time=now)

    # Record alert sent
    tracker.record_alert_sent(101, now)
    viol = tracker.get_violation(101)
    assert viol.alert_count == 1
    assert viol.last_alerted_at == now

    # Now in cooldown for 3600s
    assert tracker.is_in_cooldown(101, cooldown_seconds=3600.0, current_time=now + 1800.0)
    # Cooldown expires after 3601s
    assert not tracker.is_in_cooldown(101, cooldown_seconds=3600.0, current_time=now + 3601.0)


def test_increment_normal_sample_and_resolve():
    tracker = InMemoryTracker()
    now = 5000.0

    tracker.record_violation_active(101, "pve1", "vps-test", now)
    assert tracker.increment_normal_sample(101) == 1
    assert tracker.increment_normal_sample(101) == 2

    tracker.mark_violation_resolved(101, now + 120.0)
    viol = tracker.get_violation(101)
    assert viol.status == "RESOLVED"
    assert viol.consecutive_normal_samples == 0


def test_prune_stale_vms():
    tracker = InMemoryTracker()
    now = 1000.0

    tracker.record_sample(101, "pve1", "vm-101", 10.0, 1000, 100, now)
    tracker.record_sample(102, "pve1", "vm-102", 10.0, 1000, 100, now)
    tracker.record_violation_active(102, "pve1", "vm-102", now)
    tracker.mark_violation_resolved(102, now + 10)

    # Only VM 101 is running now, 102 was stopped
    tracker.prune_stale_vms(running_vmids=[101])

    assert len(tracker.get_samples_in_window(101, 500, now)) == 1
    assert len(tracker.get_samples_in_window(102, 500, now)) == 0
    assert tracker.get_violation(102) is None
