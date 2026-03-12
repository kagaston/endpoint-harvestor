from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    SYSTEM_INFO = "system_info"
    PROCESS = "process"
    NETWORK_CONNECTION = "network_connection"
    DNS_ENTRY = "dns_entry"
    ARP_ENTRY = "arp_entry"
    USER_ACCOUNT = "user_account"
    LOGIN_EVENT = "login_event"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    STARTUP_ITEM = "startup_item"
    CRON_JOB = "cron_job"
    FILE_ENTRY = "file_entry"
    LOG_ENTRY = "log_entry"
    BROWSER_HISTORY = "browser_history"
    BROWSER_DOWNLOAD = "browser_download"
    SHELL_COMMAND = "shell_command"
    USB_DEVICE = "usb_device"
    INSTALLED_SOFTWARE = "installed_software"
    KERNEL_MODULE = "kernel_module"
    FIREWALL_RULE = "firewall_rule"
    ENVIRONMENT_VAR = "environment_var"
    CLIPBOARD_CONTENT = "clipboard_content"
    CERTIFICATE = "certificate"


class Artifact(BaseModel):
    artifact_type: ArtifactType
    source: str = ""
    timestamp: str = ""
    data: dict[str, Any] = Field(default_factory=dict)


class CollectorResult(BaseModel):
    collector_name: str
    platform: str
    timestamp: str
    artifacts: list[Artifact] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    duration_ms: float = 0.0
