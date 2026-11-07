from pathlib import Path

# ==========================================
# PROJECT PATHS
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = PROJECT_ROOT / "config"

SIGNATURE_DB_PATH = CONFIG_DIR / "signatures.json"

CORE_DIR = PROJECT_ROOT / "core"

UTILS_DIR = PROJECT_ROOT / "utils"

TESTS_DIR = PROJECT_ROOT / "tests"

REPORTS_DIR = Path.cwd() / "reports"

EXTRACTED_DIR = Path.cwd() / "extracted"


# ==========================================
# SCANNER CONFIGURATION
# ==========================================

# Number of bytes read in each chunk
CHUNK_SIZE = 4096

# Number of bytes analyzed in each entropy window
ENTROPY_WINDOW_SIZE = 4096

# High entropy triage threshold (0 to 8)
ENTROPY_THRESHOLD = 7.2


# ==========================================
# SIGNATURE DATABASE CONFIGURATION
# ==========================================

# Maximum permitted signature database size
MAX_SIGNATURE_DB_SIZE = 2 * 1024 * 1024  # 2 MB


# ==========================================
# EXTRACTION CONFIGURATION
# ==========================================

# Maximum size allowed for a single extracted candidate
MAX_EXTRACTION_SIZE = 50 * 1024 * 1024  # 50 MB


# ==========================================
# APPLICATION INFORMATION
# ==========================================

APP_NAME = "FILEX"

APP_VERSION = "1.0.0"

LOG_LEVEL = "INFO"
# Maximum aggregate bytes written by one SafeExtractor instance
MAX_TOTAL_EXTRACTION_SIZE = 200 * 1024 * 1024  # 200 MB

# Maximum time allowed for a YARA match call (seconds)
YARA_TIMEOUT_SECONDS = 30
