"""Hybrid phishing analysis: ML probability + rule engine -> 0-100 risk score.

Only the URL *string* is analysed. Nothing here opens a connection to the
submitted URL, resolves its DNS name, downloads content or executes anything.
"""
from __future__ import annotations

import logging
import threading
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
import sklearn
from sklearn.exceptions import InconsistentVersionWarning

from app.config import APP_VERSION, DATA_PATH, MODEL_PATH
from app.rules import evaluate_rules
from feature_engineering.extractor import (ExtractionResult, InvalidURLError, extract,
                                           feature_names, load_config, to_frame)

log = logging.getLogger("phishguard")

NOTE = "URL string analysed only - no request was made to the submitted URL."
VERDICT_LOW, VERDICT_SUS, VERDICT_HIGH = "LOW RISK", "SUSPICIOUS", "HIGH RISK"


def load_bundle(path: Path = MODEL_PATH) -> dict[str, Any]:
    """Load the model bundle; retrain automatically if it is missing or was
    pickled with an incompatible scikit-learn version."""
    path = Path(path)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", InconsistentVersionWarning)
            bundle = joblib.load(path)
        if bundle.get("feature_names") != feature_names():
            raise RuntimeError("feature_order in feature_config.json no longer matches the trained model")
        bundle["model"].n_jobs = 1
        return bundle
    except Exception as exc:  # noqa: BLE001 - any load problem -> rebuild
        log.warning("Model at %s unusable (%s); retraining from %s", path, exc, DATA_PATH)
        from app.training import train_and_save
        try:
            return train_and_save(DATA_PATH, path, verbose=False)
        except OSError:  # read-only file system: train in memory only
            return train_and_save(DATA_PATH, Path("/tmp/phishguard_rf.pkl"), None, verbose=False)


def verdict_for(score: int) -> str:
    s = load_config()["scoring"]
    if score >= s["high_min"]:
        return VERDICT_HIGH
    if score >= s["suspicious_min"]:
        return VERDICT_SUS
    return VERDICT_LOW


def build_explanation(verdict: str, score: int, reasons: list[str]) -> str:
    lines = [f"{verdict} \u2014 {score}/100", ""]
    if reasons:
        lines.append("Reasons:")
        lines += [f"- {r}" for r in reasons]
    else:
        lines.append("No suspicious indicators detected in the URL structure.")
    return "\n".join(lines)


class PhishGuardAnalyzer:
    def __init__(self, model_path: Path = MODEL_PATH):
        self.bundle = load_bundle(model_path)
        self.model = self.bundle["model"]
        self.cfg = load_config()
        self.phish_idx = list(self.model.classes_).index(1)
        self.meta = self.bundle.get("meta", {})
        self.metrics = self.bundle.get("metrics", {})
        self.baseline = self.bundle.get("legit_baseline", {})
        self.importances = self.bundle.get("feature_importances", {})

    # ---- ML helpers -----------------------------------------------------
    def _phish_proba(self, frame: pd.DataFrame) -> list[float]:
        return [float(p) for p in self.model.predict_proba(frame)[:, self.phish_idx]]

    def _ml_drivers(self, features: dict[str, float], base_p: float, top: int = 5) -> list[dict[str, Any]]:
        """Occlusion-style local explanation: swap one feature at a time for the
        typical-legitimate value and measure how the phishing probability moves."""
        names = feature_names()
        rows = []
        for n in names:
            alt = dict(features)
            alt[n] = self.baseline.get(n, 0.0)
            rows.append(alt)
        probs = self._phish_proba(to_frame(rows))
        drivers = []
        for n, p_alt in zip(names, probs):
            impact = base_p - p_alt
            if abs(impact) >= 0.005:
                drivers.append({"feature": n, "value": features[n],
                                "baseline": round(self.baseline.get(n, 0.0), 3),
                                "impact": round(impact * 100, 1)})
        drivers.sort(key=lambda d: abs(d["impact"]), reverse=True)
        return drivers[:top]

    # ---- result assembly ------------------------------------------------
    def _assemble(self, ex: ExtractionResult, p_phish: float, explain: bool) -> dict[str, Any]:
        sc = self.cfg["scoring"]
        rule_score, indicators = evaluate_rules(ex)
        ml_score = p_phish * 100
        risk = int(round(min(100.0, max(0.0, sc["ml_weight"] * ml_score + sc["rule_weight"] * rule_score))))
        verdict = verdict_for(risk)
        reasons = [i.reason for i in indicators]
        is_phish = p_phish >= 0.5
        return {
            "url": ex.parsed.raw.strip(),
            "normalized_url": ex.parsed.normalized,
            "risk_score": risk,
            "verdict": verdict,
            "ml_prediction": "PHISHING" if is_phish else "LEGITIMATE",
            "ml_confidence": round(p_phish if is_phish else 1 - p_phish, 4),
            "ml_phishing_probability": round(p_phish, 4),
            "rule_score": rule_score,
            "score_breakdown": {
                "ml_score": round(ml_score, 1), "rule_score": rule_score,
                "ml_weight": sc["ml_weight"], "rule_weight": sc["rule_weight"],
                "suspicious_min": sc["suspicious_min"], "high_min": sc["high_min"],
            },
            "indicators": [i.to_dict() for i in indicators],
            "reasons": reasons,
            "explanation": build_explanation(verdict, risk, reasons),
            "features": ex.features,
            "ml_drivers": self._ml_drivers(ex.features, p_phish) if explain else [],
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "note": NOTE,
        }

    # ---- public API -----------------------------------------------------
    def analyze(self, url: str, explain: bool = True) -> dict[str, Any]:
        """Analyse one URL string. Raises :class:`InvalidURLError` for unusable input."""
        ex = extract(url)
        p = self._phish_proba(to_frame([ex.features]))[0]
        return self._assemble(ex, p, explain)

    def analyze_many(self, urls: list[str]) -> list[dict[str, Any] | None]:
        """Vectorised batch analysis. Invalid entries yield ``None`` at their position."""
        extracted: list[ExtractionResult | None] = []
        for u in urls:
            try:
                extracted.append(extract(u))
            except (InvalidURLError, ValueError):
                extracted.append(None)
        valid = [e for e in extracted if e is not None]
        probs = self._phish_proba(to_frame([e.features for e in valid])) if valid else []
        it = iter(probs)
        return [None if e is None else self._assemble(e, next(it), explain=False) for e in extracted]

    def model_info(self) -> dict[str, Any]:
        return {"meta": self.meta, "metrics": self.metrics, "feature_importances": self.importances,
                "version": APP_VERSION, "sklearn_runtime": sklearn.__version__}


_lock = threading.Lock()
_instance: PhishGuardAnalyzer | None = None


def get_analyzer() -> PhishGuardAnalyzer:
    """Process-wide lazily created analyzer."""
    global _instance
    if _instance is None:
        with _lock:
            if _instance is None:
                _instance = PhishGuardAnalyzer()
    return _instance
