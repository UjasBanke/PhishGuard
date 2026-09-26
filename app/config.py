"""Project-wide paths and settings."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "demo_urls.csv"
MODEL_PATH = ROOT / "models" / "phishguard_rf.pkl"
METRICS_PATH = ROOT / "models" / "metrics.json"
APP_VERSION = "1.0.0"
