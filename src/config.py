"""Configuration loader with YAML support and environment variable overrides."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml


def _env_to_bool(val: Optional[str], default: bool = False) -> bool:
    if val is None:
        return default
    return str(val).strip().lower() in ("true", "1", "yes", "on")


def _env_to_float(val: Optional[str], default: float) -> float:
    if val is None:
        return default
    try:
        return float(val)
    except ValueError:
        return default


def _env_to_int(val: Optional[str], default: int) -> int:
    if val is None:
        return default
    try:
        return int(val)
    except ValueError:
        return default


@dataclass
class ProxmoxConfig:
    host: str = "127.0.0.1"
    port: int = 8006
    user: str = "root@pam"
    token_name: str = "abuse-monitor"
    token_value: str = ""
    verify_ssl: bool = False
    timeout_seconds: int = 15
    web_ui_url: str = ""  # Base URL for Proxmox UI link (e.g. https://pve.example.com:8006)

    @property
    def base_url(self) -> str:
        if self.web_ui_url:
            return self.web_ui_url.rstrip("/")
        return f"https://{self.host}:{self.port}"


@dataclass
class MiningRuleConfig:
    enabled: bool = True
    cpu_threshold_percent: float = 90.0
    duration_minutes: int = 30
    poll_interval_seconds: int = 60
    min_samples_ratio: float = 0.85  # At least 85% of samples in window must exceed threshold
    critical_cpu_percent: float = 98.0  # Mark severity as critical if at/above this
    include_lxc: bool = True
    exclude_vmids: List[int] = field(default_factory=list)


@dataclass
class DiscordConfig:
    webhook_url: str = ""
    username: str = "PVE Abuse Guard"
    avatar_url: str = "https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/proxmox.png"
    cooldown_enabled: bool = False  # Tự động khóa cảnh báo lặp lại cho cùng 1 VM (Mặc định: False)
    cooldown_minutes: int = 60
    notify_on_resolved: bool = True
    resolved_stabilize_samples: int = 2  # Needs 2 consecutive normal samples before marking resolved
    mention_role_id: str = ""
    mention_user_id: str = ""
    max_retries: int = 3


@dataclass
class AutoActionConfig:
    enabled: bool = False
    dry_run: bool = True
    action: str = "suspend"  # "suspend", "stop", or "shutdown"
    violations_before_action: int = 2  # Action taken after N consecutive violation alert cycles
    whitelist_vmids: List[int] = field(default_factory=list)


@dataclass
class LoggingConfig:
    level: str = "INFO"
    file: Optional[str] = None


@dataclass
class AppConfig:
    proxmox: ProxmoxConfig = field(default_factory=ProxmoxConfig)
    mining_rule: MiningRuleConfig = field(default_factory=MiningRuleConfig)
    discord: DiscordConfig = field(default_factory=DiscordConfig)
    auto_action: AutoActionConfig = field(default_factory=AutoActionConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def _expand_env_vars(data: Any) -> Any:
    """Recursively expand ${VAR:default} or $VAR in strings."""
    if isinstance(data, dict):
        return {k: _expand_env_vars(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [_expand_env_vars(item) for item in data]
    elif isinstance(data, str):
        pattern = re.compile(r"\$\{([A-Za-z0-9_]+)(?::-?([^}]*))?\}")

        def repl(match):
            var_name = match.group(1)
            default_val = match.group(2) if match.group(2) is not None else ""
            return os.getenv(var_name, default_val)

        return pattern.sub(repl, data)
    return data


def load_config(config_path: Optional[str] = None) -> AppConfig:
    """Load configuration from YAML file and apply environment variable overrides."""
    raw_data: Dict[str, Any] = {}

    candidate_paths = [
        config_path,
        os.getenv("CONFIG_PATH"),
        "config.yaml",
        "/etc/pve-abuse-guard/config.yaml",
    ]
    resolved_path = None
    for p in candidate_paths:
        if p and Path(p).is_file():
            resolved_path = p
            break

    if resolved_path:
        with open(resolved_path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if loaded and isinstance(loaded, dict):
                raw_data = _expand_env_vars(loaded)

    # 1. Proxmox config
    pve_raw = raw_data.get("proxmox", {})
    pve_cfg = ProxmoxConfig(
        host=os.getenv("PVE_HOST", pve_raw.get("host", "127.0.0.1")),
        port=_env_to_int(os.getenv("PVE_PORT"), pve_raw.get("port", 8006)),
        user=os.getenv("PVE_USER", pve_raw.get("user", "root@pam")),
        token_name=os.getenv("PVE_TOKEN_NAME", pve_raw.get("token_name", "abuse-monitor")),
        token_value=os.getenv("PVE_TOKEN_VALUE", pve_raw.get("token_value", "")),
        verify_ssl=_env_to_bool(os.getenv("PVE_VERIFY_SSL"), pve_raw.get("verify_ssl", False)),
        timeout_seconds=_env_to_int(os.getenv("PVE_TIMEOUT"), pve_raw.get("timeout_seconds", 15)),
        web_ui_url=os.getenv("PVE_WEB_UI_URL", pve_raw.get("web_ui_url", "")),
    )

    # 2. Mining Rule config
    rule_raw = raw_data.get("mining_rule", {})
    exclude_vmids_env = os.getenv("EXCLUDE_VMIDS")
    exclude_vmids = (
        [int(x.strip()) for x in exclude_vmids_env.split(",") if x.strip().isdigit()]
        if exclude_vmids_env
        else rule_raw.get("exclude_vmids", [])
    )
    rule_cfg = MiningRuleConfig(
        enabled=_env_to_bool(os.getenv("MINING_RULE_ENABLED"), rule_raw.get("enabled", True)),
        cpu_threshold_percent=_env_to_float(
            os.getenv("CPU_THRESHOLD_PERCENT"), rule_raw.get("cpu_threshold_percent", 90.0)
        ),
        duration_minutes=_env_to_int(
            os.getenv("DURATION_MINUTES"), rule_raw.get("duration_minutes", 30)
        ),
        poll_interval_seconds=_env_to_int(
            os.getenv("POLL_INTERVAL_SECONDS"), rule_raw.get("poll_interval_seconds", 60)
        ),
        min_samples_ratio=_env_to_float(
            os.getenv("MIN_SAMPLES_RATIO"), rule_raw.get("min_samples_ratio", 0.85)
        ),
        critical_cpu_percent=_env_to_float(
            os.getenv("CRITICAL_CPU_PERCENT"), rule_raw.get("critical_cpu_percent", 98.0)
        ),
        include_lxc=_env_to_bool(os.getenv("INCLUDE_LXC"), rule_raw.get("include_lxc", True)),
        exclude_vmids=exclude_vmids,
    )

    # 3. Discord config
    dc_raw = raw_data.get("discord", {})
    dc_cfg = DiscordConfig(
        webhook_url=os.getenv("DISCORD_WEBHOOK_URL", dc_raw.get("webhook_url", "")),
        username=os.getenv("DISCORD_USERNAME", dc_raw.get("username", "PVE Abuse Guard")),
        avatar_url=os.getenv(
            "DISCORD_AVATAR_URL",
            dc_raw.get(
                "avatar_url",
                "https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/proxmox.png",
            ),
        ),
        cooldown_enabled=_env_to_bool(
            os.getenv("COOLDOWN_ENABLED"), dc_raw.get("cooldown_enabled", False)
        ),
        cooldown_minutes=_env_to_int(
            os.getenv("COOLDOWN_MINUTES"), dc_raw.get("cooldown_minutes", 60)
        ),
        notify_on_resolved=_env_to_bool(
            os.getenv("NOTIFY_ON_RESOLVED"), dc_raw.get("notify_on_resolved", True)
        ),
        resolved_stabilize_samples=_env_to_int(
            os.getenv("RESOLVED_STABILIZE_SAMPLES"),
            dc_raw.get("resolved_stabilize_samples", 2),
        ),
        mention_role_id=os.getenv("DISCORD_MENTION_ROLE_ID", dc_raw.get("mention_role_id", "")),
        mention_user_id=os.getenv("DISCORD_MENTION_USER_ID", dc_raw.get("mention_user_id", "")),
        max_retries=_env_to_int(os.getenv("DISCORD_MAX_RETRIES"), dc_raw.get("max_retries", 3)),
    )

    # 4. Auto Action config
    action_raw = raw_data.get("auto_action", {})
    whitelist_vmids_env = os.getenv("AUTO_ACTION_WHITELIST_VMIDS")
    whitelist_vmids = (
        [int(x.strip()) for x in whitelist_vmids_env.split(",") if x.strip().isdigit()]
        if whitelist_vmids_env
        else action_raw.get("whitelist_vmids", [])
    )
    action_cfg = AutoActionConfig(
        enabled=_env_to_bool(os.getenv("AUTO_ACTION_ENABLED"), action_raw.get("enabled", False)),
        dry_run=_env_to_bool(os.getenv("AUTO_ACTION_DRY_RUN"), action_raw.get("dry_run", True)),
        action=os.getenv("AUTO_ACTION_TYPE", action_raw.get("action", "suspend")),
        violations_before_action=_env_to_int(
            os.getenv("AUTO_ACTION_VIOLATIONS_COUNT"),
            action_raw.get("violations_before_action", 2),
        ),
        whitelist_vmids=whitelist_vmids,
    )

    # 5. Logging config
    log_raw = raw_data.get("logging", {})
    log_cfg = LoggingConfig(
        level=os.getenv("LOG_LEVEL", log_raw.get("level", "INFO")).upper(),
        file=os.getenv("LOG_FILE", log_raw.get("file")),
    )

    return AppConfig(
        proxmox=pve_cfg,
        mining_rule=rule_cfg,
        discord=dc_cfg,
        auto_action=action_cfg,
        logging=log_cfg,
    )
