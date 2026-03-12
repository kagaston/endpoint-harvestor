import os

VERSION = "0.1.0"

# --- Collection Limits ---
MAX_FILE_HASH_SIZE = 100 * 1024 * 1024  # 100 MB
BROWSER_HISTORY_DAYS = 30
LOG_COLLECTION_DAYS = 7
TEMP_DIR_SCAN_DEPTH = 3

# --- Network Anomaly Detection ---
SUSPICIOUS_PORTS = [4444, 5555, 8888, 1337, 31337, 6666, 6667, 9001, 9050, 9150]

# --- Defaults ---
DEFAULT_PROFILE = "standard"
OUTPUT_DIR = os.getenv("II_OUTPUT_DIR", "./output")
CASE_ID = os.getenv("II_CASE_ID", "")
EXAMINER = os.getenv("II_EXAMINER", "")

# --- LOLBins (Living-off-the-Land Binaries) ---
LOLBINS_WINDOWS = [
    "certutil.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe",
    "wscript.exe", "cscript.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msxsl.exe", "odbcconf.exe",
    "ieexec.exe", "cmstp.exe", "presentationhost.exe", "bash.exe",
    "forfiles.exe", "scriptrunner.exe", "syncappvpublishingserver.exe",
    "hh.exe", "infdefaultinstall.exe", "msconfig.exe", "msdeploy.exe",
    "msdt.exe", "msiexec.exe", "pcalua.exe", "pcwrun.exe",
    "desktopimgdownldr.dll", "eudcedit.exe", "finger.exe",
    "gpscript.exe", "imewdbld.exe", "ie4uinit.exe",
    "mavinject.exe", "microsoft.workflow.compiler.exe",
    "mmc.exe", "msconfig.exe", "msdeploy.exe", "pktmon.exe",
    "powershell.exe", "pwsh.exe", "bitsadmin.exe",
    "wmic.exe", "control.exe", "explorer.exe",
]

LOLBINS_LINUX = [
    "curl", "wget", "python", "python3", "perl", "ruby", "php",
    "nc", "ncat", "netcat", "socat", "bash", "sh", "dash", "zsh",
    "awk", "gawk", "nawk", "sed", "openssl", "base64", "xxd",
    "xterm", "nohup", "screen", "tmux", "at", "busybox", "env",
    "find", "ftp", "gcc", "gdb", "git", "lua", "make", "man",
    "nice", "node", "rsync", "scp", "sftp", "ssh", "strace",
    "tar", "taskset", "tclsh", "telnet", "vim", "xargs",
]

LOLBINS_MACOS = [
    "curl", "wget", "python3", "perl", "ruby", "php",
    "nc", "ncat", "bash", "sh", "zsh", "osascript",
    "open", "say", "screencapture", "sqlite3", "tclsh",
    "awk", "sed", "openssl", "base64", "pbcopy", "pbpaste",
    "security", "dscl", "defaults", "launchctl", "plutil",
    "xattr", "mdls", "mdfind", "sips", "qlmanage",
]

# --- Suspicious Parent-Child Relationships ---
SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "certutil.exe", "mshta.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "certutil.exe", "mshta.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"],
    "explorer.exe": ["powershell.exe", "pwsh.exe", "cmd.exe"],
    "svchost.exe": ["cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe"],
    "wmiprvse.exe": ["cmd.exe", "powershell.exe", "pwsh.exe"],
    "services.exe": ["cmd.exe", "powershell.exe"],
    "spoolsv.exe": ["cmd.exe", "powershell.exe", "net.exe", "whoami.exe"],
    "w3wp.exe": ["cmd.exe", "powershell.exe", "whoami.exe"],
}

# --- Suspicious Environment Variables ---
SUSPICIOUS_ENV_VARS = [
    "http_proxy", "https_proxy", "socks_proxy", "all_proxy",
    "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH", "PYTHONSTARTUP", "PERL5OPT",
    "RUBYOPT", "NODE_OPTIONS", "CLASSPATH",
    "COMSPEC", "PROMPT",
]
