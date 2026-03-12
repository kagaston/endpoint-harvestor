from collectors.system_info import SystemInfoCollector
from collectors.processes import ProcessCollector
from collectors.network import NetworkCollector
from collectors.users import UserCollector
from collectors.persistence import PersistenceCollector
from collectors.filesystem import FilesystemCollector
from collectors.logs import LogCollector
from collectors.browser import BrowserCollector
from collectors.shell_history import ShellHistoryCollector
from collectors.usb_devices import USBDeviceCollector
from collectors.installed_software import InstalledSoftwareCollector
from collectors.kernel_modules import KernelModuleCollector
from collectors.firewall import FirewallCollector
from collectors.environment import EnvironmentCollector
from collectors.clipboard import ClipboardCollector
from collectors.certificates import CertificateCollector
from collectors.protocol import Collector


COLLECTOR_REGISTRY: dict[str, type] = {
    "system_info": SystemInfoCollector,
    "processes": ProcessCollector,
    "network": NetworkCollector,
    "users": UserCollector,
    "persistence": PersistenceCollector,
    "filesystem": FilesystemCollector,
    "logs": LogCollector,
    "browser": BrowserCollector,
    "shell_history": ShellHistoryCollector,
    "usb_devices": USBDeviceCollector,
    "installed_software": InstalledSoftwareCollector,
    "kernel_modules": KernelModuleCollector,
    "firewall": FirewallCollector,
    "environment": EnvironmentCollector,
    "clipboard": ClipboardCollector,
    "certificates": CertificateCollector,
}


def get_collector(name: str, **kwargs) -> Collector:
    cls = COLLECTOR_REGISTRY.get(name)
    if cls is None:
        raise KeyError(f"Unknown collector: {name!r}. Available: {list(COLLECTOR_REGISTRY)}")
    return cls(**kwargs)


def list_collectors() -> list[str]:
    return list(COLLECTOR_REGISTRY.keys())
