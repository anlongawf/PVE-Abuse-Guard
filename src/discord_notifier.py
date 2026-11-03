"""Discord Webhook Notifier with Rich Embeds, 429 Rate-Limit handling, and mentions."""

import datetime
import logging
import time
from typing import Any, Dict, Optional
import requests

from src.config import DiscordConfig
from src.detector import AlertEvent

logger = logging.getLogger(__name__)


def _format_bytes(num_bytes: int) -> str:
    """Format bytes to human readable string (MB/GB)."""
    if num_bytes <= 0:
        return "N/A"
    gb = num_bytes / (1024 ** 3)
    if gb >= 1.0:
        return f"{gb:.2f} GB"
    mb = num_bytes / (1024 ** 2)
    return f"{mb:.1f} MB"


def _format_uptime(seconds: int) -> str:
    """Format seconds into days, hours, minutes."""
    if seconds <= 0:
        return "N/A"
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    mins, _ = divmod(rem, 60)
    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    parts.append(f"{mins}m")
    return " ".join(parts)


def _format_duration(seconds: float) -> str:
    """Format duration seconds to readable string."""
    mins = int(seconds // 60)
    secs = int(seconds % 60)
    if mins > 0:
        return f"{mins} phút {secs} giây"
    return f"{secs} giây"


class DiscordNotifier:
    """Sends structured alerts and resolution notices via Discord Webhook."""

    def __init__(self, config: DiscordConfig, web_ui_base_url: str = ""):
        self.config = config
        self.web_ui_base_url = web_ui_base_url

    def build_embed(self, event: AlertEvent, ui_url: str = "") -> Dict[str, Any]:
        """Build Discord Rich Embed dictionary according to Discord API spec."""
        iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        start_dt = datetime.datetime.fromtimestamp(event.first_seen_at).strftime("%Y-%m-%d %H:%M:%S")

        if event.event_type == "RESOLVED":
            title = f"✅ [ĐÃ HẾT VI PHẠM] VM {event.vmid} ({event.name}) đã hạ nhiệt"
            color = 0x2ECC71  # Green
            description = (
                f"Chỉ số CPU của máy ảo **{event.name}** (VMID: `{event.vmid}`) "
                f"đã hạ xuống mức bình thường ({event.current_cpu_percent}%). "
                f"Trạng thái cảnh báo đã được giải phóng."
            )
        elif event.action_taken:
            title = f"🛑 [CAN THIỆP TỰ ĐỘNG] VM {event.vmid} ({event.name}) đã bị {event.action_taken.upper()}"
            color = 0x9B59B6  # Purple
            description = (
                f"Máy ảo **{event.name}** (VMID: `{event.vmid}`) liên tục vi phạm "
                f"đào coin kéo dài. Hệ thống đã tự động thực thi hành động: **{event.action_taken.upper()}**."
            )
        elif event.severity == "critical":
            title = f"🚨 [CRITICAL] Phát hiện nghi vấn đào tiền ảo trên VM {event.vmid}"
            color = 0xE74C3C  # Red
            description = (
                f"Máy ảo **{event.name}** (VMID: `{event.vmid}`) đang duy trì mức CPU cực cao "
                f"liên tục trong thời gian dài. Nghi vấn đang chạy tiến trình đào coin (crypto mining)."
            )
        else:
            title = f"⚠️ [WARNING] Phát hiện CPU cao bất thường trên VM {event.vmid}"
            color = 0xE67E22  # Orange
            description = (
                f"Máy ảo **{event.name}** (VMID: `{event.vmid}`) có mức sử dụng CPU vượt ngưỡng "
                f"cho phép liên tục trong {self.config.cooldown_minutes} phút."
            )

        fields = [
            {"name": "🖥️ Máy ảo (VM)", "value": f"**{event.name}** (ID: `{event.vmid}`)", "inline": True},
            {"name": "🌐 Node Proxmox", "value": f"`{event.node}`", "inline": True},
            {"name": "⚡ CPU Hiện tại", "value": f"**{event.current_cpu_percent}%**", "inline": True},
            {
                "name": "📊 Thống kê CPU cửa sổ",
                "value": f"Trung bình: **{event.avg_cpu_percent}%**\nĐỉnh: **{event.peak_cpu_percent}%**",
                "inline": True,
            },
            {
                "name": "⏱️ Thời gian vi phạm",
                "value": f"{_format_duration(event.duration_seconds)}\n*(Bắt đầu: {start_dt})*",
                "inline": True,
            },
            {
                "name": "💾 RAM / Uptime",
                "value": f"RAM: {_format_bytes(event.mem_used_bytes)} / {_format_bytes(event.mem_max_bytes)}\nUptime: {_format_uptime(event.uptime_seconds)}",
                "inline": True,
            },
        ]

        if event.dry_run and event.action_taken:
            fields.append({
                "name": "🛡️ Trạng thái can thiệp",
                "value": f"`[DRY-RUN]` Dự kiến thực thi: **{event.action_taken}** (Chưa áp dụng thật)",
                "inline": False,
            })

        if ui_url:
            fields.append({
                "name": "🔗 Proxmox Web UI",
                "value": f"[Bấm vào đây để mở VM trên Proxmox Web UI]({ui_url})",
                "inline": False,
            })

        embed = {
            "title": title,
            "description": description,
            "color": color,
            "fields": fields,
            "timestamp": iso_now,
            "footer": {
                "text": "PVE Abuse Guard • In-Memory Proxmox Monitor",
                "icon_url": self.config.avatar_url,
            },
        }

        return embed

    def send_alert(self, event: AlertEvent, ui_url: str = "") -> bool:
        """Send formatted alert event to Discord webhook with 429 rate limit handling."""
        if not self.config.webhook_url:
            logger.warning("Discord webhook_url is empty. Skipping notification.")
            return False

        embed = self.build_embed(event, ui_url=ui_url)

        # Build content mentions if critical
        content_parts = []
        if event.severity == "critical" and event.event_type != "RESOLVED":
            if self.config.mention_role_id:
                content_parts.append(f"<@&{self.config.mention_role_id}>")
            if self.config.mention_user_id:
                content_parts.append(f"<@{self.config.mention_user_id}>")

        payload: Dict[str, Any] = {
            "username": self.config.username,
            "avatar_url": self.config.avatar_url,
            "embeds": [embed],
        }
        if content_parts:
            payload["content"] = " ".join(content_parts)

        return self._post_webhook(payload)

    def send_test_message(self) -> bool:
        """Send a test message to verify Discord Webhook configuration."""
        if not self.config.webhook_url:
            logger.error("Cannot test: Discord webhook_url is empty.")
            return False

        iso_now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        embed = {
            "title": "🧪 [TEST] PVE Abuse Guard Webhook Kết Nối Thành Công",
            "description": (
                "Hệ thống giám sát lạm dụng Proxmox VE (In-Memory CPU Mining Detector) "
                "đã kết nối thành công tới kênh Discord này!\n"
                "Khi phát hiện máy ảo đào coin liên tục >= 90%, cảnh báo sẽ gửi về đây."
            ),
            "color": 0x3498DB,  # Blue
            "fields": [
                {"name": "Trạng thái", "value": "🟢 Hoạt động tốt", "inline": True},
                {"name": "Chế độ lưu trữ", "value": "🧠 In-Memory (Zero Disk)", "inline": True},
            ],
            "timestamp": iso_now,
            "footer": {"text": "PVE Abuse Guard Verification"},
        }

        payload = {
            "username": self.config.username,
            "avatar_url": self.config.avatar_url,
            "embeds": [embed],
        }
        return self._post_webhook(payload)

    def _post_webhook(self, payload: Dict[str, Any]) -> bool:
        """Post payload with retry and 429 Rate Limit backoff."""
        max_retries = max(1, self.config.max_retries)

        for attempt in range(1, max_retries + 1):
            try:
                resp = requests.post(
                    self.config.webhook_url,
                    json=payload,
                    timeout=10,
                    headers={"Content-Type": "application/json"},
                )

                # Discord success returns 200 or 204
                if resp.status_code in (200, 204):
                    logger.info("Successfully dispatched Discord webhook notification.")
                    return True

                if resp.status_code == 429:
                    # Rate limited: check retry_after
                    retry_after = 2.0
                    try:
                        err_json = resp.json()
                        retry_after = float(err_json.get("retry_after", 2.0))
                    except Exception:
                        if "Retry-After" in resp.headers:
                            retry_after = float(resp.headers["Retry-After"])

                    logger.warning(
                        f"Discord 429 Rate Limit hit. Backing off for {retry_after:.2f}s "
                        f"(attempt {attempt}/{max_retries})..."
                    )
                    time.sleep(retry_after + 0.2)
                    continue

                logger.error(
                    f"Discord Webhook failed with HTTP {resp.status_code}: {resp.text}"
                )
                return False

            except requests.exceptions.RequestException as e:
                logger.error(f"Network error sending Discord webhook (attempt {attempt}): {e}")
                time.sleep(1.5)

        logger.error(f"Failed to deliver Discord notification after {max_retries} attempts.")
        return False
