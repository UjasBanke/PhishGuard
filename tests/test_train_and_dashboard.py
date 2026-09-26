from pathlib import Path

import pandas as pd
from streamlit.testing.v1 import AppTest

from app.training import train_and_save
from dashboard.utils import read_urls_from_csv, results_to_frame, sanitize_cell, to_csv_bytes

ROOT = Path(__file__).resolve().parents[1]


def test_training_small_subset(tmp_path):
    df = pd.read_csv(ROOT / "data" / "demo_urls.csv").sample(600, random_state=1)
    csv = tmp_path / "d.csv"
    df.to_csv(csv, index=False)
    b = train_and_save(csv, tmp_path / "m.pkl", None, n_estimators=25, cv_folds=0, verbose=False)
    assert (tmp_path / "m.pkl").exists() and b["metrics"]["accuracy"] > 0.85


def test_csv_helpers():
    assert read_urls_from_csv(b"url,label\nhttps://a.com,0\nhttp://b.tk,1\n") == ["https://a.com", "http://b.tk"]
    assert sanitize_cell("=HYPERLINK(1)").startswith("'")
    df = results_to_frame(["=x", "bad"], [None, None])
    assert b"'=x" in to_csv_bytes(df)


def test_streamlit_app_scan():
    at = AppTest.from_file(str(ROOT / "dashboard" / "streamlit_app.py"), default_timeout=60).run()
    assert not at.exception
    at.text_input(key="url_input").set_value("http://paypal.secure-verify.tk/login")
    at.button[0].click().run()
    assert not at.exception and at.session_state["result"]["verdict"] == "HIGH RISK"
