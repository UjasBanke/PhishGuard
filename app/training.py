"""Model training utilities (RandomForest on URL-derived features)."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,
                             precision_score, recall_score, roc_auc_score)
from sklearn.model_selection import cross_val_score, train_test_split

from app.config import DATA_PATH, METRICS_PATH, MODEL_PATH, ROOT
from feature_engineering.extractor import feature_names, extract_features, to_frame


def load_dataset(path: Path = DATA_PATH) -> pd.DataFrame:
    path = Path(path)
    if not path.exists():
        from data.generate_demo_dataset import main as generate
        generate(["--out", str(path)])
    df = pd.read_csv(path)
    if not {"url", "label"} <= set(df.columns):
        raise ValueError("Dataset needs 'url' and 'label' columns (label: 1 = phishing, 0 = legitimate).")
    return df.dropna(subset=["url", "label"]).drop_duplicates("url").reset_index(drop=True)


def build_feature_matrix(urls: list[str]) -> tuple[pd.DataFrame, list[int]]:
    """Extract features, skipping strings that are not valid URLs. Returns (X, kept_indices)."""
    rows, kept = [], []
    for i, u in enumerate(urls):
        try:
            rows.append(extract_features(str(u)))
            kept.append(i)
        except ValueError:
            continue
    return to_frame(rows), kept


def train_and_save(
    data_path: Path = DATA_PATH,
    model_path: Path = MODEL_PATH,
    metrics_path: Path | None = METRICS_PATH,
    n_estimators: int = 300,
    seed: int = 42,
    cv_folds: int = 5,
    verbose: bool = True,
) -> dict:
    """Train the RandomForest, evaluate on a hold-out split and persist the bundle."""
    t0 = time.time()
    df = load_dataset(data_path)
    X, kept = build_feature_matrix(df["url"].tolist())
    y = df["label"].astype(int).iloc[kept].reset_index(drop=True)
    is_synthetic = bool(df.get("source", pd.Series(["unknown"])).astype(str).eq("synthetic").all())

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, stratify=y, random_state=seed)
    model = RandomForestClassifier(
        n_estimators=n_estimators, min_samples_leaf=2, max_features="sqrt",
        class_weight="balanced", n_jobs=-1, random_state=seed,
    )
    model.fit(X_tr, y_tr)

    proba = model.predict_proba(X_te)[:, list(model.classes_).index(1)]
    pred = (proba >= 0.5).astype(int)
    metrics = {
        "accuracy": round(float(accuracy_score(y_te, pred)), 4),
        "precision": round(float(precision_score(y_te, pred)), 4),
        "recall": round(float(recall_score(y_te, pred)), 4),
        "f1": round(float(f1_score(y_te, pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_te, proba)), 4),
        "confusion_matrix": confusion_matrix(y_te, pred).tolist(),
    }
    if cv_folds and cv_folds > 1:
        scores = cross_val_score(
            RandomForestClassifier(n_estimators=max(50, n_estimators // 3), min_samples_leaf=2,
                                   class_weight="balanced", n_jobs=-1, random_state=seed),
            X, y, cv=cv_folds, scoring="f1")
        metrics["cv_f1_mean"] = round(float(scores.mean()), 4)
        metrics["cv_f1_std"] = round(float(scores.std()), 4)

    # Refit on all data for the shipped model; keep hold-out metrics for reporting.
    final = RandomForestClassifier(
        n_estimators=n_estimators, min_samples_leaf=2, max_features="sqrt",
        class_weight="balanced", n_jobs=-1, random_state=seed).fit(X, y)
    final.n_jobs = 1  # single-row inference is faster without process fan-out

    importances = dict(sorted(zip(feature_names(), map(float, final.feature_importances_)),
                              key=lambda kv: kv[1], reverse=True))
    baseline = X[y == 0].median(numeric_only=True).to_dict()  # "typical legitimate URL"

    meta = {
        "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sklearn_version": sklearn.__version__,
        "numpy_version": np.__version__,
        "n_samples": int(len(X)),
        "n_train": int(len(X_tr)),
        "n_test": int(len(X_te)),
        "n_estimators": n_estimators,
        "dataset_is_synthetic": is_synthetic,
        "dataset_path": str(Path(data_path).relative_to(ROOT)) if Path(data_path).is_relative_to(ROOT) else str(data_path),
    }
    bundle = {
        "model": final,
        "feature_names": feature_names(),
        "feature_importances": importances,
        "legit_baseline": {k: float(v) for k, v in baseline.items()},
        "metrics": metrics,
        "meta": meta,
        "sklearn_version": sklearn.__version__,
    }
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, model_path, compress=3)
    if metrics_path:
        Path(metrics_path).write_text(
            json.dumps({"metrics": metrics, "meta": meta, "feature_importances": importances}, indent=2),
            encoding="utf-8")

    if verbose:
        print(f"[train] samples={meta['n_samples']} (synthetic={is_synthetic}) "
              f"train={meta['n_train']} test={meta['n_test']}")
        print("[train] hold-out metrics: " + ", ".join(
            f"{k}={v}" for k, v in metrics.items() if k != "confusion_matrix"))
        print(f"[train] confusion matrix [[TN FP][FN TP]]: {metrics['confusion_matrix']}")
        print("[train] top features: " + ", ".join(f"{k} ({v:.3f})" for k, v in list(importances.items())[:6]))
        print(f"[train] saved model -> {model_path} ({time.time() - t0:.1f}s)")
    return bundle
