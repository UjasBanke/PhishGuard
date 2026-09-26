"""Helpers for the Streamlit dashboard: batch handling and safe CSV export."""
from __future__ import annotations

import io
from typing import Any

import pandas as pd

MAX_BATCH_ROWS = 5000
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def sanitize_cell(value: Any) -> Any:
    """Neutralise spreadsheet formula injection (a URL like '=HYPERLINK(...)')."""
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def sanitize_frame(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    for col in out.select_dtypes(include=["object", "string"]).columns:
        out[col] = out[col].map(sanitize_cell)
    return out


def to_csv_bytes(df: pd.DataFrame) -> bytes:
    return sanitize_frame(df).to_csv(index=False).encode("utf-8")


def read_urls_from_csv(file_like: Any) -> list[str]:
    """Read URLs from an uploaded CSV.

    Uses the column headed ``url`` (case-insensitive) if there is one, otherwise the
    first column. A header row such as ``url`` / ``link`` is skipped automatically.
    """
    raw = file_like.read() if hasattr(file_like, "read") else file_like
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8-sig", errors="replace")
    if not str(raw).strip():
        return []
    df = pd.read_csv(io.StringIO(raw), dtype=str, keep_default_na=False, header=None,
                     on_bad_lines="skip", engine="python")
    if df.empty:
        return []
    header = [str(c).strip().lower() for c in df.iloc[0]]
    col, skip = 0, 0
    for name in ("url", "urls"):
        if name in header:
            col, skip = header.index(name), 1
            break
    else:
        if header[0] in {"link", "links", "website", "address", "domain"}:
            skip = 1
    return [str(u).strip() for u in df.iloc[skip:, col].tolist() if str(u).strip()]


def results_to_frame(urls: list[str], results: list[dict[str, Any] | None], include_features: bool = False) -> pd.DataFrame:
    rows = []
    for url, res in zip(urls, results):
        if res is None:
            rows.append({"url": url, "verdict": "INVALID", "risk_score": None, "ml_prediction": None,
                         "ml_confidence_pct": None, "rule_score": None, "indicators": "Invalid or unsupported URL"})
            continue
        row = {
            "url": url, "verdict": res["verdict"], "risk_score": res["risk_score"], "ml_prediction": res["ml_prediction"],
            "ml_confidence_pct": round(res["ml_confidence"] * 100, 1), "rule_score": res["rule_score"],
            "indicators": "; ".join(res["reasons"]) or "none",
        }
        if include_features:
            row.update(res["features"])
        rows.append(row)
    return pd.DataFrame(rows)
