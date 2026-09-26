"""Train the PhishGuard RandomForest model.

    python train.py                       # uses data/demo_urls.csv (generated if missing)
    python train.py --regenerate          # rebuild the SYNTHETIC demo dataset first
    python train.py --data my_urls.csv    # your own CSV with columns: url,label (1=phishing)
"""
from __future__ import annotations

import argparse
from pathlib import Path

from app.config import DATA_PATH, METRICS_PATH, MODEL_PATH
from app.training import train_and_save


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, default=DATA_PATH)
    ap.add_argument("--out", type=Path, default=MODEL_PATH)
    ap.add_argument("--metrics", type=Path, default=METRICS_PATH)
    ap.add_argument("--n-estimators", type=int, default=300)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--regenerate", action="store_true", help="regenerate the synthetic demo dataset first")
    args = ap.parse_args()

    if args.regenerate or not args.data.exists():
        from data.generate_demo_dataset import main as generate
        generate(["--out", str(args.data)])
    train_and_save(args.data, args.out, args.metrics, n_estimators=args.n_estimators, seed=args.seed)


if __name__ == "__main__":
    main()
