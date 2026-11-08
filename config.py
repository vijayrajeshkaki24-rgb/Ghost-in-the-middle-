"""Central configuration, read from environment / .env."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv optional
    pass

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    PORT = int(os.getenv("FLASK_PORT", "5000"))
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")]

    # Email OTP
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    OTP_VALIDITY_SECONDS = int(os.getenv("OTP_VALIDITY_SECONDS", "120"))
    OTP_MAX_ATTEMPTS = 5

    # Ollama
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")
    OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3")
    OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "60"))

    # Scanner
    SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", "10"))
    PROXY_TIMING_THRESHOLD_MS = float(os.getenv("PROXY_TIMING_THRESHOLD_MS", "100"))
    ENTROPY_THRESHOLD = float(os.getenv("ENTROPY_THRESHOLD", "3.5"))
    VERIFY_TLS = os.getenv("VERIFY_TLS", "1") == "1"
    TIMING_SAMPLES = int(os.getenv("TIMING_SAMPLES", "5"))

    # Storage
    DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
    REPORT_DIR = Path(os.getenv("REPORT_DIR", BASE_DIR / "reports"))
