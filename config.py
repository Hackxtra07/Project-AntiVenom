import os
from pathlib import Path

# Base directory
BASE_DIR = Path(__file__).resolve().parent

# Scan settings
MONITOR_PATHS = [
    Path.home() / "Downloads",
    Path("/tmp"),
]

WHITELIST_PATHS = [
    Path("/usr/lib"),
    Path("/opt/trusted_apps"),
]

# Quarantine settings
QUARANTINE_DIR = BASE_DIR / "quarantine"
QUARANTINE_DIR.mkdir(exist_ok=True)

# Database settings
DB_PATH = BASE_DIR / "database" / "antivenom.db"

# API settings
API_HOST = "127.0.0.1"
API_PORT = 8000

# YARA settings
YARA_RULES_DIR = BASE_DIR / "rules"
YARA_RULES_FILE = YARA_RULES_DIR / "default.yar"

# Logging
LOG_FILE = BASE_DIR / "antivenom.log"

# Level 6: System Control
GAME_MODE = False  # Suppresses notifications and throttles scanning
SILENT_MODE = False # Suppresses UI alerts completely
