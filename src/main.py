"""Main Entrypoint and Daemon Engine for PVE Abuse Guard.

Zero-disk footprint, in-memory CPU crypto mining detector for Proxmox VE.
"""

import argparse
import logging
import os
import signal
import sys
import time
from typing import List

from src import __version__
from src.action_manager import ActionManager
from src.config import AppConfig, load_config
from src.detector import MiningDetector
from src.discord_notifier import DiscordNotifier
from src.in_memory_tracker import InMemoryTracker
from src.pve_client import PVEClient, PVEClientError

logger = logging.getLogger("pve_abuse_guard")


def setup_logging(level_name: str, log_file: str = None) -> None:
    """Configure structured logging."""
    level = getattr(logging, level_name.upper(), logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        handlers.append(file_handler)

    logging.basicConfig(level=level, handlers=handlers, force=True)


class PVEAbuseDaemon:
    """Daemon running periodic polling loop and dispatching Discord alerts."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.running = True

        self.pve_client = PVEClient(config.proxmox)
        self.tracker = InMemoryTracker()
        self.detector = MiningDetector(config.mining_rule, self.tracker)
        self.discord = DiscordNotifier(config.discord, web_ui_base_url=config.proxmox.base_url)
        self.action_manager = ActionManager(config.auto_action, self.pve_client)

        self._setup_signals()

    def _setup_signals(self) -> None:
        """Register graceful termination signals."""
        signal.signal(signal.SIGINT, self._handle_exit)
        signal.signal(signal.SIGTERM, self._handle_exit)

    def _handle_exit(self, signum: int, frame) -> None:
        sig_name = signal.Signals(signum).name
        logger.info(f"Received shutdown signal {sig_name}. Stopping daemon gracefully...")
        self.running = False

    def poll_once(self) -> int:
        """
        Execute a single polling and evaluation cycle across all VMs.
        Returns the count of alerts dispatched.
        """
        now = time.time()
        try:
            vms = self.pve_client.get_cluster_vms(include_lxc=self.config.mining_rule.include_lxc)
        except PVEClientError as e:
            logger.error(f"Error fetching VM list from Proxmox API: {e}")
            return 0

        logger.debug(f"Polled {len(vms)} running VMs/LXCs from Proxmox cluster.")

        running_vmids: List[int] = []
        alerts_sent = 0
        cooldown_sec = self.config.discord.cooldown_minutes * 60.0
        stabilize_samples = self.config.discord.resolved_stabilize_samples

        for vm in vms:
            vmid = vm["vmid"]
            running_vmids.append(vmid)

            event = self.detector.evaluate_vm(
                vm_data=vm,
                current_time=now,
                cooldown_seconds=cooldown_sec,
                resolved_stabilize_samples=stabilize_samples,
            )

            if event:
                ui_url = self.pve_client.get_vm_web_ui_url(event.node, event.vmid, event.vm_type)

                if event.event_type == "VIOLATION":
                    logger.warning(
                        f"🚨 Mining violation detected on VM {event.vmid} ({event.name}) "
                        f"on node {event.node}: CPU={event.current_cpu_percent}%, "
                        f"Avg={event.avg_cpu_percent}%, Duration={event.duration_seconds}s"
                    )

                    # Check automated mitigation
                    took_action, action_name, is_dry_run = self.action_manager.execute_action(
                        node=event.node,
                        vmid=event.vmid,
                        vm_type=event.vm_type,
                        alert_count=event.alert_count,
                    )
                    if took_action:
                        event.action_taken = action_name
                        event.dry_run = is_dry_run

                    # Send Discord Alert
                    sent = self.discord.send_alert(event, ui_url=ui_url)
                    if sent:
                        self.tracker.record_alert_sent(event.vmid, now)
                        alerts_sent += 1

                elif event.event_type == "RESOLVED":
                    logger.info(
                        f"✅ Mining violation resolved on VM {event.vmid} ({event.name}): "
                        f"CPU returned to {event.current_cpu_percent}%."
                    )
                    if self.config.discord.notify_on_resolved:
                        sent = self.discord.send_alert(event, ui_url=ui_url)
                        if sent:
                            alerts_sent += 1

        # Prune memory for VMs that are no longer running to keep RAM clean
        self.tracker.prune_stale_vms(running_vmids)

        return alerts_sent

    def run(self) -> None:
        """Run continuous daemon polling loop."""
        interval = max(5, self.config.mining_rule.poll_interval_seconds)
        logger.info(
            f"Starting PVE Abuse Guard Daemon v{__version__} "
            f"(Target PVE: {self.config.proxmox.base_url}, Interval: {interval}s, Zero-Disk: Active)"
        )

        try:
            self.pve_client.test_connection()
        except Exception as e:
            logger.warning(
                f"Proxmox initial connection check warning: {e}. Daemon will still run and retry."
            )

        while self.running:
            start_poll = time.time()
            try:
                self.poll_once()
            except Exception as e:
                logger.exception(f"Unexpected error during polling cycle: {e}")

            elapsed = time.time() - start_poll
            sleep_time = max(1.0, interval - elapsed)

            # Responsive sleep so daemon shuts down immediately on signal
            step = 1.0
            slept = 0.0
            while self.running and slept < sleep_time:
                time.sleep(min(step, sleep_time - slept))
                slept += step

        logger.info("PVE Abuse Guard Daemon stopped cleanly.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PVE Abuse Guard: Zero-disk in-memory CPU crypto mining detector for Proxmox VE."
    )
    parser.add_argument(
        "-c", "--config", help="Path to YAML configuration file (default: config.yaml)"
    )
    parser.add_argument(
        "--test-webhook", action="store_true", help="Send a test notification to Discord and exit"
    )
    parser.add_argument(
        "--test-pve",
        action="store_true",
        help="Test connection to Proxmox VE API and list running VMs, then exit",
    )
    parser.add_argument(
        "--once", action="store_true", help="Execute one polling check and exit"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Force dry-run mode for auto-mitigation actions"
    )
    parser.add_argument(
        "--debug-sim",
        action="store_true",
        help="Run an in-memory simulation of a VM mining coin and resolving, with debug logs",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"pve-abuse-guard {__version__}"
    )

    args = parser.parse_args()

    config = load_config(args.config)
    if args.dry_run:
        config.auto_action.dry_run = True

    if args.debug_sim:
        config.logging.level = "DEBUG"

    setup_logging(config.logging.level, config.logging.file)

    if args.debug_sim:
        from src.in_memory_tracker import InMemoryTracker
        import json

        logger.info("========== BẮT ĐẦU CHẾ ĐỘ MÔ PHỎNG DEBUG (DEBUG SIMULATION) ==========")
        logger.info("Quy tắc: CPU >= 90% liên tục 30 phút, chu kỳ 60s, Cooldown 60 phút.")
        tracker = InMemoryTracker()
        detector = MiningDetector(config.mining_rule, tracker)
        discord = DiscordNotifier(config.discord)

        vmid = 101
        vm_name = "ubuntu-vps-client"
        sim_time = 1700000000.0

        # Phase 1: 5 minutes normal (15% CPU)
        logger.info("--- Giai đoạn 1: 5 phút đầu máy hoạt động bình thường (CPU ~15%) ---")
        for m in range(5):
            sim_time += 60.0
            data = {"vmid": vmid, "name": vm_name, "node": "pve1", "type": "qemu", "cpu_percent": 15.0, "uptime_seconds": 3600 + (m * 60), "mem_bytes": 1024**3, "maxmem_bytes": 2 * 1024**3}
            ev = detector.evaluate_vm(data, current_time=sim_time)
            logger.debug(f"[Phút {m+1}] CPU: 15% -> Kết quả: {ev}")

        # Phase 2: 32 minutes mining (95% CPU)
        logger.info("--- Giai đoạn 2: Bắt đầu đào coin liên tục (CPU 95%) kéo dài 32 phút ---")
        for m in range(5, 37):
            sim_time += 60.0
            data = {"vmid": vmid, "name": vm_name, "node": "pve1", "type": "qemu", "cpu_percent": 95.0, "uptime_seconds": 3600 + (m * 60), "mem_bytes": 1024**3, "maxmem_bytes": 2 * 1024**3}
            ev = detector.evaluate_vm(data, current_time=sim_time, cooldown_seconds=config.discord.cooldown_minutes * 60.0)
            if ev:
                logger.warning(f"🚨 [Phút {m+1}] VIOLATION PHÁT HIỆN! Đạt điều kiện vi phạm!")
                embed = discord.build_embed(ev, ui_url=f"https://pve1:8006/#v1:0:=qemu/{vmid}")
                logger.info(f"Embed gửi Discord:\n{json.dumps(embed, indent=2, ensure_ascii=False)}")
                tracker.record_alert_sent(vmid, sim_time)
            else:
                samples = tracker.get_samples_in_window(vmid, 30 * 60.0, sim_time)
                logger.debug(f"[Phút {m+1}] CPU: 95% -> Tích luỹ mẫu: {len(samples)}/30 mẫu, chưa đủ 30 phút hoặc đang trong Cooldown")

        # Phase 3: CPU drops to 10% (miner stopped)
        logger.info("--- Giai đoạn 3: Khách tắt tool đào coin, CPU hạ nhiệt về 10% ---")
        for m in range(37, 40):
            sim_time += 60.0
            data = {"vmid": vmid, "name": vm_name, "node": "pve1", "type": "qemu", "cpu_percent": 10.0, "uptime_seconds": 3600 + (m * 60), "mem_bytes": 1024**3, "maxmem_bytes": 2 * 1024**3}
            ev = detector.evaluate_vm(data, current_time=sim_time, resolved_stabilize_samples=config.discord.resolved_stabilize_samples)
            if ev and ev.event_type == "RESOLVED":
                logger.info(f"✅ [Phút {m+1}] RESOLVED PHÁT HIỆN! Đã xác nhận máy ảo hạ nhiệt!")
                embed = discord.build_embed(ev, ui_url=f"https://pve1:8006/#v1:0:=qemu/{vmid}")
                logger.info(f"Embed giải phóng gửi Discord:\n{json.dumps(embed, indent=2, ensure_ascii=False)}")
            else:
                logger.debug(f"[Phút {m+1}] CPU: 10% -> Đang theo dõi ổn định...")

        logger.info("========== KẾT THÚC MÔ PHỎNG DEBUG: TOÀN BỘ LOGIC HOẠT ĐỘNG CHÍNH XÁC ==========")
        sys.exit(0)

    if args.test_webhook:
        notifier = DiscordNotifier(config.discord, web_ui_base_url=config.proxmox.base_url)
        print("Sending test embed to Discord Webhook...")
        success = notifier.send_test_message()
        if success:
            print("Test message sent successfully!")
            sys.exit(0)
        else:
            print("Failed to send test message. Check your DISCORD_WEBHOOK_URL.")
            sys.exit(1)

    if args.test_pve:
        client = PVEClient(config.proxmox)
        print(f"Connecting to Proxmox VE at {config.proxmox.base_url}...")
        try:
            ver = client.test_connection()
            print(f"Connection OK! Proxmox VE version: {ver.get('version')} (release: {ver.get('release')})")
            vms = client.get_cluster_vms(include_lxc=config.mining_rule.include_lxc)
            print(f"Found {len(vms)} running VMs/LXCs:")
            for vm in vms:
                print(
                    f"  - [{vm['type'].upper()}] ID: {vm['vmid']:<5} Name: {vm['name']:<20} "
                    f"Node: {vm['node']:<10} CPU: {vm['cpu_percent']:>5.1f}%"
                )
            sys.exit(0)
        except Exception as e:
            print(f"Proxmox connection test failed: {e}")
            sys.exit(1)

    daemon = PVEAbuseDaemon(config)

    if args.once:
        logger.info("Executing single poll check (--once)...")
        alerts = daemon.poll_once()
        logger.info(f"Single check complete. Alerts dispatched: {alerts}")
        sys.exit(0)

    daemon.run()


if __name__ == "__main__":
    main()
