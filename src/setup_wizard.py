"""Interactive Setup Wizard for PVE Abuse Guard.

Guides user step-by-step to generate config.yaml, asking for Proxmox API, Discord Webhook,
and specifically prompting whether to enable Anti-Spam & Cooldown (default: False).
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict
import yaml


def _prompt_str(prompt_text: str, default: str = "") -> str:
    """Prompt for a string with default."""
    if default:
        res = input(f"{prompt_text} [{default}]: ").strip()
        return res if res else default
    res = input(f"{prompt_text}: ").strip()
    return res


def _prompt_int(prompt_text: str, default: int) -> int:
    """Prompt for an integer with default."""
    while True:
        res = input(f"{prompt_text} [{default}]: ").strip()
        if not res:
            return default
        try:
            return int(res)
        except ValueError:
            print("  ⚠️ Vui lòng nhập số nguyên hợp lệ!")


def _prompt_float(prompt_text: str, default: float) -> float:
    """Prompt for a float with default."""
    while True:
        res = input(f"{prompt_text} [{default}]: ").strip()
        if not res:
            return default
        try:
            return float(res)
        except ValueError:
            print("  ⚠️ Vui lòng nhập số thực hợp lệ!")


def _prompt_bool(prompt_text: str, default: bool = False) -> bool:
    """Prompt for a boolean with clear indication of default."""
    suffix = "[Y/n]" if default else "[y/N]"
    default_str = "True" if default else "False"
    res = input(f"{prompt_text} {suffix} (mặc định: {default_str}): ").strip().lower()
    if not res:
        return default
    return res in ("y", "yes", "true", "1")


def run_setup(output_path: str = "config.yaml") -> None:
    """Run interactive configuration setup."""
    print("=" * 72)
    print(" 🛡️  PVE ABUSE GUARD - TRÌNH THIẾT LẬP CẤU HÌNH TƯƠNG TÁC (SETUP WIZARD)")
    print("=" * 72)
    print("Nhấn Enter để chọn giá trị mặc định trong ngoặc vuông [ ].\n")

    # 1. Proxmox VE
    print("-" * 72)
    print("📡 [1/6] CẤU HÌNH KẾT NỐI PROXMOX VE")
    print("-" * 72)
    pve_host = _prompt_str("Địa chỉ IP hoặc Hostname của Proxmox VE", "127.0.0.1")
    pve_port = _prompt_int("Cổng Port Proxmox API", 8006)
    pve_user = _prompt_str("User Proxmox", "abuse-monitor@pam")
    pve_token_name = _prompt_str("Tên Token", "pve-guard")
    pve_token_value = _prompt_str("Giá trị bí mật Token Secret (UUID)", "")
    if not pve_token_value:
        print("  ⚠️ Bạn chưa nhập Token Secret. Hãy nhớ cập nhật lại vào config.yaml sau!")
    pve_verify_ssl = _prompt_bool("Xác thực chứng chỉ SSL (True nếu có SSL xịn, False nếu self-signed)?", False)
    pve_web_ui = _prompt_str("URL Web UI Proxmox để gắn link Discord (để trống nếu tự động)", "")

    # 2. Discord Webhook
    print("\n" + "-" * 72)
    print("💬 [2/6] CẤU HÌNH DISCORD WEBHOOK")
    print("-" * 72)
    discord_webhook = _prompt_str("Discord Webhook URL", "")
    if not discord_webhook:
        print("  ⚠️ Bạn chưa nhập Webhook URL. Hệ thống sẽ không thể gửi cảnh báo nếu thiếu URL này!")
    discord_username = _prompt_str("Tên hiển thị bot Discord", "PVE Abuse Guard")

    # 3. Chống spam & Cooldown (Yêu cầu đặc biệt: hỏi true/false, mặc định là false)
    print("\n" + "-" * 72)
    print("⏱️ [3/6] CẤU HÌNH CHỐNG SPAM & COOLDOWN")
    print("-" * 72)
    print("Mô tả: Tự động khóa cảnh báo lặp lại cho cùng 1 VM trong thời gian Cooldown.")
    cooldown_enabled = _prompt_bool(
        "👉 Bạn có muốn BẬT tính năng Chống spam & Cooldown không?",
        default=False,  # Mặc định là False theo yêu cầu
    )

    cooldown_minutes = 60
    if cooldown_enabled:
        print("  🟢 Đã BẬT Chống spam & Cooldown.")
        cooldown_minutes = _prompt_int("  Thời gian Cooldown khóa lặp lại (phút)", 60)
    else:
        print("  ⚪ Đã TẮT Chống spam & Cooldown (mỗi chu kỳ vi phạm sẽ gửi cảnh báo).")

    notify_resolved = _prompt_bool("Gửi thông báo 'Đã hết vi phạm' (Resolved) khi CPU VM hạ nhiệt?", True)

    # 4. Mining Rule
    print("\n" + "-" * 72)
    print("⚙️ [4/6] QUY TẮC PHÁT HIỆN ĐÀO COIN (CPU MINING RULE)")
    print("-" * 72)
    cpu_threshold = _prompt_float("Ngưỡng CPU cảnh báo (%)", 90.0)
    duration_min = _prompt_int("Thời gian CPU duy trì liên tục tối thiểu (phút)", 30)
    poll_interval = _prompt_int("Chu kỳ quét Proxmox API (giây)", 60)
    include_lxc = _prompt_bool("Giám sát cả LXC Container kèm theo VM?", True)

    # 5. Auto Action
    print("\n" + "-" * 72)
    print("🛑 [5/6] CAN THIỆP TỰ ĐỘNG (AUTO ACTION - TÙY CHỌN)")
    print("-" * 72)
    auto_action_enabled = _prompt_bool("Bật can thiệp tự động đình chỉ VM khi vi phạm kéo dài?", False)
    auto_dry_run = True
    action_type = "suspend"
    if auto_action_enabled:
        auto_dry_run = _prompt_bool("  Chạy ở chế độ Thử nghiệm (Dry-run, chỉ log, không tắt thật)?", True)
        action_type = _prompt_str("  Hành động thực thi (suspend hoặc stop)", "suspend")

    # Build config structure
    config_dict = {
        "proxmox": {
            "host": pve_host,
            "port": pve_port,
            "user": pve_user,
            "token_name": pve_token_name,
            "token_value": pve_token_value,
            "verify_ssl": pve_verify_ssl,
            "timeout_seconds": 15,
            "web_ui_url": pve_web_ui,
        },
        "mining_rule": {
            "enabled": True,
            "cpu_threshold_percent": cpu_threshold,
            "duration_minutes": duration_min,
            "poll_interval_seconds": poll_interval,
            "min_samples_ratio": 0.85,
            "critical_cpu_percent": 98.0,
            "include_lxc": include_lxc,
            "exclude_vmids": [9999],
        },
        "discord": {
            "webhook_url": discord_webhook,
            "username": discord_username,
            "avatar_url": "https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/proxmox.png",
            "cooldown_enabled": cooldown_enabled,  # Giá trị người dùng chọn
            "cooldown_minutes": cooldown_minutes,
            "notify_on_resolved": notify_resolved,
            "resolved_stabilize_samples": 2,
            "mention_role_id": "",
            "mention_user_id": "",
            "max_retries": 3,
        },
        "auto_action": {
            "enabled": auto_action_enabled,
            "dry_run": auto_dry_run,
            "action": action_type,
            "violations_before_action": 2,
            "whitelist_vmids": [100, 200],
        },
        "logging": {
            "level": "INFO",
        },
    }

    # 6. Save
    print("\n" + "-" * 72)
    print("💾 [6/6] LƯU FILE CẤU HÌNH")
    print("-" * 72)
    confirm_save = _prompt_bool(f"Xác nhận ghi file cấu hình vào '{output_path}'?", True)

    if confirm_save:
        with open(output_path, "w", encoding="utf-8") as f:
            yaml.dump(config_dict, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"🎉 Đã lưu thành công cấu hình vào: {output_path}")

        # Optional quick tests
        if discord_webhook:
            test_dc = _prompt_bool("\nBạn có muốn gửi thử một tin nhắn Test tới Discord Webhook ngay bây giờ không?", True)
            if test_dc:
                from src.config import DiscordConfig
                from src.discord_notifier import DiscordNotifier
                dc_cfg = DiscordConfig(webhook_url=discord_webhook, username=discord_username)
                notifier = DiscordNotifier(dc_cfg)
                print("Đang gửi test...")
                if notifier.send_test_message():
                    print("✅ Gửi tin nhắn Discord thành công! Hãy kiểm tra kênh chat.")
                else:
                    print("❌ Gửi tin nhắn Discord thất bại. Vui lòng kiểm tra lại Webhook URL.")

        print("\nHoàn tất cài đặt! Bạn có thể khởi động dịch vụ bằng lệnh:")
        print(f"  .venv/bin/python3 -m src.main -c {output_path}")
        print("Hoặc kích hoạt qua Systemd:")
        print("  systemctl enable --now pve-abuse-guard.service\n")
    else:
        print("Đã hủy lưu cấu hình.")


if __name__ == "__main__":
    run_setup()
