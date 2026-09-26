# PhishGuard architecture

```
            URL string (never fetched)
                      │
        feature_engineering/extractor.py
   normalise → parse (urllib + offline tldextract) → 28 numeric features + signals
                 │                                   │
        RandomForest (models/*.pkl)           app/rules.py (~20 rules)
        P(phishing) 0-1                       indicators + rule score 0-100
                 └───────────────┬───────────────────┘
                     app/analyzer.py  (hybrid)
      risk = 0.6·ML(0-100) + 0.4·rules  → LOW <35 ≤ SUSPICIOUS <65 ≤ HIGH
                 ┌───────────────┴────────────────┐
        app/main.py (FastAPI)          dashboard/streamlit_app.py
        GET /health, POST /analyze     scanner · batch · history · system
```

## Components
| Path | Role |
|---|---|
| `feature_engineering/feature_config.json` | Keywords, TLDs, brands, weights, thresholds, feature order |
| `feature_engineering/extractor.py` | Validation, parsing, feature + signal extraction |
| `app/rules.py` | Explainable rule engine; each rule yields title, detail, points |
| `app/analyzer.py` | Loads the model (auto-retrains on version mismatch), blends scores, builds explanation and per-feature "occlusion" drivers |
| `app/training.py`, `train.py` | Train/evaluate RandomForest, save bundle (model, feature order, metrics, legit baseline) |
| `data/generate_demo_dataset.py` | **Synthetic** dataset generator (seeded) |
| `dashboard/` | Themed Streamlit UI; `theme.py` CSS/HTML, `charts.py` Plotly, `utils.py` CSV safety |

## Design decisions
* **String-only analysis.** No HTTP, DNS or content fetch; `tldextract` uses its bundled suffix snapshot. A test blocks sockets and still analyses a URL.
* **Hybrid scoring.** ML generalises to combinations of weak signals; rules give transparent reasons and catch strong single signals. Weights/thresholds are configurable.
* **Explainability.** Rule indicators list exactly what fired. ML drivers show how much the phishing probability drops when one feature is replaced by a typical-legitimate value.
* **Untrusted output.** All URLs are HTML-escaped and never rendered as links; CSV exports neutralise formula injection (`=`, `+`, `-`, `@`).

## Limitations
* Trained on synthetic data: metrics are not real-world accuracy.
* Lexical only: no WHOIS age, certificates, page content, or reputation feeds.
* Brand list is finite; legitimate regional brand domains not listed may be flagged.
* Scheme-less input is assumed `https`.
