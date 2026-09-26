# PhishGuard demo dataset — SYNTHETIC

`demo_urls.csv` (8,000 rows: 4,000 legitimate + 4,000 phishing-style) is **synthetic**.
It is produced by `data/generate_demo_dataset.py` from rule-based templates with a fixed seed (42),
so the project runs offline and contains **no real phishing links**.

| column | meaning |
|--------|---------|
| `url` | fabricated URL string |
| `label` | `1` = phishing-style, `0` = legitimate-style |
| `source` | always `synthetic` |

## What it is good for
* Demonstrating the full pipeline (feature extraction → training → scoring → API/dashboard).
* Running tests and demos without downloading data.

## What it is NOT
* A benchmark. The model scores ~99 % on a hold-out split of this data because the generator's patterns
  are easy to learn — that says **nothing** about accuracy on real traffic.
* A source of ground truth. Legitimate URLs mimic common patterns (including `login`/`account` paths on
  well-known brands) and phishing URLs mimic common tactics (brand-in-subdomain, IP hosts, `@` tricks,
  abused TLDs, shorteners, punycode, keyword stuffing), but real attackers adapt.

## Using real data
Replace `data/demo_urls.csv` with a CSV that has `url` and `label` columns
(for example PhishTank / OpenPhish for label 1 and Tranco top sites for label 0),
then run `python train.py`. Use a time-based split and check for domain overlap between train/test.
