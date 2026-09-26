"""PhishGuard - threat detection console (Streamlit).

Run from the project root:  streamlit run dashboard/streamlit_app.py

2-page flow:
  Page 1 (page == "scan")   — URL input + history
  Page 2 (page == "results") — Full scan results

The dashboard imports the analysis engine directly (same code the FastAPI service
uses), so it works without the API running. Only URL *strings* are analysed;
nothing is ever fetched, opened or rendered as a link.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from app.analyzer import get_analyzer  # noqa: E402
from app.config import APP_VERSION  # noqa: E402
from dashboard import charts, theme  # noqa: E402
from dashboard.utils import MAX_BATCH_ROWS, read_urls_from_csv, results_to_frame, to_csv_bytes  # noqa: E402
from feature_engineering.extractor import InvalidURLError, load_config  # noqa: E402

st.set_page_config(
    page_title="PhishGuard // Threat Detection System",
    page_icon="\U0001F6E1\uFE0F",
    layout="wide",
    initial_sidebar_state="collapsed",
)

DEMO_TARGETS = {
    "SAMPLE // SAFE": "https://www.wikipedia.org/wiki/Computer_security",
    "SAMPLE // SUSPICIOUS": "http://bit.ly/3xYzAb9",
    "SAMPLE // PHISHING": "http://paypal.secure-verify.account-update.tk/login.php?session=8f3a2c",
}
SAMPLE_CSV = ROOT / "data" / "sample_batch.csv"

st.markdown(theme.CSS, unsafe_allow_html=True)


@st.cache_resource(show_spinner="Loading threat engine...")
def load_engine():
    return get_analyzer()


# ---- session state ----------------------------------------------------------
st.session_state.setdefault("page", "scan")        # "scan" | "results"
st.session_state.setdefault("history", [])
st.session_state.setdefault("result", None)
st.session_state.setdefault("error", None)
st.session_state.setdefault("url_input", "")
st.session_state.setdefault("batch", None)


def _load_demo(url: str) -> None:
    st.session_state["url_input"] = url
    st.session_state["pending_scan"] = True


def _scan(url: str) -> None:
    engine = load_engine()
    try:
        res = engine.analyze(url)
    except InvalidURLError as exc:
        st.session_state["error"] = str(exc)
        st.session_state["result"] = None
        st.session_state["page"] = "scan"
        return
    st.session_state["error"] = None
    st.session_state["result"] = res
    st.session_state["history"].insert(0, {
        "time": datetime.now().strftime("%H:%M:%S"),
        "url": res["url"],
        "verdict": res["verdict"],
        "risk_score": res["risk_score"],
        "ml_confidence_pct": round(res["ml_confidence"] * 100, 1),
        "rule_score": res["rule_score"],
    })
    del st.session_state["history"][200:]
    st.session_state["page"] = "results"


def show_chart(fig, key: str) -> None:
    st.plotly_chart(fig, theme=None, key=key, config={"displayModeBar": False})


# ---- load engine once -------------------------------------------------------
try:
    engine = load_engine()
    model_ready = True
except Exception as exc:  # noqa: BLE001
    engine, model_ready = None, False
    st.markdown(theme.alert(f"Threat engine failed to start: {exc}"), unsafe_allow_html=True)



# =============================================================================
# PAGE 1 — SCAN
# =============================================================================
if st.session_state["page"] == "scan":
    st.markdown(theme.hero(), unsafe_allow_html=True)

    tab_scan, tab_batch, tab_hist, tab_sys = st.tabs(
        ["SCANNER", "BATCH SCANNER", "SCAN HISTORY", "SYSTEM"]
    )

    # ---- SCANNER ------------------------------------------------------------
    with tab_scan:
        _, mid, _ = st.columns([1, 4, 1])
        with mid:
            st.markdown('<div class="pg-prompt">[ ENTER URL ]</div>', unsafe_allow_html=True)
            with st.form("scan_form", border=False):
                st.text_input(
                    "Target URL",
                    key="url_input",
                    placeholder="https://example.com/login",
                    label_visibility="collapsed",
                )
                submitted = st.form_submit_button("[ SCAN URL ]", disabled=not model_ready)

            st.markdown(
                '<div class="pg-hint">demo targets &mdash; fabricated strings, analysed as text and never visited</div>',
                unsafe_allow_html=True,
            )
            with st.container(key="chips"):
                for col, (label, url) in zip(st.columns(3), DEMO_TARGETS.items()):
                    col.button(
                        label,
                        key=f"demo_{label}",
                        on_click=_load_demo,
                        args=(url,),
                        disabled=not model_ready,
                    )

        if model_ready and (submitted or st.session_state.pop("pending_scan", False)):
            with st.spinner("SCANNING TARGET..."):
                _scan(st.session_state["url_input"])
            st.rerun()

        err = st.session_state["error"]
        if err:
            st.markdown(theme.alert(f"Scan aborted: {err}"), unsafe_allow_html=True)
        else:
            st.markdown(
                theme.empty_state("AWAITING TARGET  //  ENTER A URL TO BEGIN SCAN"),
                unsafe_allow_html=True,
            )

        # ---- recent history preview on scan page ----------------------------
        hist = st.session_state["history"]
        if hist:
            st.markdown(theme.section("RECENT SCANS"), unsafe_allow_html=True)
            recent = hist[:5]
            st.dataframe(
                pd.DataFrame(recent),
                hide_index=True,
                height=min(220, 50 + 35 * len(recent)),
                column_config={
                    "risk_score": st.column_config.ProgressColumn(
                        "risk_score", min_value=0, max_value=100, format="%d"
                    ),
                    "url": st.column_config.TextColumn("url", width="large"),
                },
            )

    # ---- BATCH --------------------------------------------------------------
    with tab_batch:
        st.markdown(theme.section("BATCH SCANNER"), unsafe_allow_html=True)
        st.markdown(
            theme.note(
                f"Upload a CSV with a <b>url</b> column (or one URL per line). "
                f"Up to {MAX_BATCH_ROWS:,} rows are analysed as text only &mdash; no URL is visited."
            ),
            unsafe_allow_html=True,
        )
        st.write("")
        left, right = st.columns([3, 1], gap="medium")
        with left:
            upload = st.file_uploader(
                "CSV file", type=["csv", "txt"], label_visibility="collapsed", key="batch_file"
            )
        with right:
            if SAMPLE_CSV.exists():
                st.download_button(
                    "SAMPLE CSV",
                    data=SAMPLE_CSV.read_bytes(),
                    file_name="sample_batch.csv",
                    mime="text/csv",
                    key="dl_sample",
                )
        if upload is not None and model_ready:
            if st.button("[ RUN BATCH SCAN ]", key="run_batch"):
                try:
                    urls = read_urls_from_csv(upload)[:MAX_BATCH_ROWS]
                except Exception as exc:  # noqa: BLE001
                    urls = []
                    st.markdown(theme.alert(f"Could not read the file: {exc}"), unsafe_allow_html=True)
                if urls:
                    bar = st.progress(0.0, text="SCANNING...")
                    results: list = []
                    chunk = 250
                    for i in range(0, len(urls), chunk):
                        results += engine.analyze_many(urls[i : i + chunk])
                        bar.progress(
                            min(1.0, (i + chunk) / len(urls)),
                            text=f"SCANNING... {min(i + chunk, len(urls))}/{len(urls)}",
                        )
                    bar.empty()
                    st.session_state["batch"] = {
                        "summary": results_to_frame(urls, results),
                        "full": results_to_frame(urls, results, include_features=True),
                    }
                elif upload is not None:
                    st.markdown(
                        theme.alert("No URLs found in the uploaded file."), unsafe_allow_html=True
                    )

        batch = st.session_state["batch"]
        if batch is None:
            st.markdown(
                theme.empty_state("NO BATCH LOADED  //  UPLOAD A CSV TO SCAN MANY TARGETS"),
                unsafe_allow_html=True,
            )
        else:
            df = batch["summary"]
            counts = df["verdict"].value_counts()
            st.markdown(theme.section("BATCH RESULTS  //  SCAN COMPLETE"), unsafe_allow_html=True)
            st.markdown(
                theme.stat_tiles([
                    ("TARGETS", len(df), ""),
                    ("HIGH RISK", int(counts.get("HIGH RISK", 0)), "lvl-high"),
                    ("SUSPICIOUS", int(counts.get("SUSPICIOUS", 0)), "lvl-sus"),
                    ("LOW RISK", int(counts.get("LOW RISK", 0)), "lvl-low"),
                    ("INVALID", int(counts.get("INVALID", 0)), ""),
                ]),
                unsafe_allow_html=True,
            )
            scored = df[df["verdict"] != "INVALID"]
            if not scored.empty:
                st.write("")
                b1, b2 = st.columns(2, gap="medium")
                with b1:
                    show_chart(charts.verdict_donut(scored), "batch_donut")
                with b2:
                    show_chart(charts.score_histogram(scored), "batch_hist")
            st.dataframe(
                df,
                hide_index=True,
                height=360,
                column_config={
                    "risk_score": st.column_config.ProgressColumn(
                        "risk_score", min_value=0, max_value=100, format="%d"
                    ),
                    "ml_confidence_pct": st.column_config.NumberColumn("ml_conf %", format="%.1f"),
                    "url": st.column_config.TextColumn("url", width="large"),
                    "indicators": st.column_config.TextColumn("indicators", width="large"),
                },
            )
            d1, d2, _ = st.columns([1.3, 1.5, 1.2])
            d1.download_button(
                "DOWNLOAD RESULTS",
                data=to_csv_bytes(batch["summary"]),
                file_name="phishguard_results.csv",
                mime="text/csv",
                key="dl_batch",
            )
            d2.download_button(
                "RESULTS + FEATURES",
                data=to_csv_bytes(batch["full"]),
                file_name="phishguard_results_features.csv",
                mime="text/csv",
                key="dl_batch_full",
            )

    # ---- HISTORY ------------------------------------------------------------
    with tab_hist:
        st.markdown(theme.section("SCAN HISTORY"), unsafe_allow_html=True)
        hist = st.session_state["history"]
        if not hist:
            st.markdown(
                theme.empty_state("NO SCANS RECORDED THIS SESSION"), unsafe_allow_html=True
            )
        else:
            show_chart(charts.history_trend(hist), "history_trend")
            st.dataframe(
                pd.DataFrame(hist),
                hide_index=True,
                height=320,
                column_config={
                    "risk_score": st.column_config.ProgressColumn(
                        "risk_score", min_value=0, max_value=100, format="%d"
                    ),
                    "url": st.column_config.TextColumn("url", width="large"),
                },
            )
            h1, h2, _ = st.columns([1.3, 1.1, 1.6])
            h1.download_button(
                "DOWNLOAD HISTORY",
                data=to_csv_bytes(pd.DataFrame(hist)),
                file_name="phishguard_history.csv",
                mime="text/csv",
                key="dl_hist",
            )
            if h2.button("CLEAR HISTORY", key="clear_hist"):
                st.session_state["history"] = []
                st.rerun()
            st.caption("History lives in this browser session only and is cleared when the page is reloaded.")

    # ---- SYSTEM -------------------------------------------------------------
    with tab_sys:
        st.markdown(theme.section("THREAT ENGINE"), unsafe_allow_html=True)
        if engine is not None:
            info = engine.model_info()
            m, meta = info["metrics"], info["meta"]
            sc = load_config()["scoring"]
            st.markdown(
                theme.stat_tiles([
                    ("ALGORITHM", "RF", ""),
                    ("RANDOM FOREST TREES", meta.get("n_estimators", "-"), ""),
                    ("TRAIN SAMPLES", f'{meta.get("n_samples", 0):,}', ""),
                    ("HOLD-OUT F1", m.get("f1", "-"), ""),
                    ("ROC AUC", m.get("roc_auc", "-"), ""),
                ]),
                unsafe_allow_html=True,
            )
            st.write("")
            if meta.get("dataset_is_synthetic", True):
                st.markdown(
                    theme.note(
                        "<b>SYNTHETIC DEMO DATASET.</b> The bundled model was trained on machine-generated URLs (see "
                        "<code>data/DATASET_README.md</code>). The near-perfect metrics above measure how well it learned the "
                        "generator's patterns, <b>not</b> real-world phishing detection. Retrain with a real labelled corpus "
                        "before relying on it."
                    ),
                    unsafe_allow_html=True,
                )
            st.markdown(theme.section("HYBRID SCORING"), unsafe_allow_html=True)
            st.markdown(
                theme.note(
                    f"<b>RISK SCORE</b> = {sc['ml_weight']:.2f} &times; ML phishing probability (0&ndash;100) + "
                    f"{sc['rule_weight']:.2f} &times; rule score (0&ndash;100). &nbsp; "
                    f"<b>LOW RISK</b> &lt; {sc['suspicious_min']} &nbsp;|&nbsp; "
                    f"<b>SUSPICIOUS</b> {sc['suspicious_min']}&ndash;{sc['high_min'] - 1} "
                    f"&nbsp;|&nbsp; <b>HIGH RISK</b> &ge; {sc['high_min']}."
                ),
                unsafe_allow_html=True,
            )
            st.write("")
            show_chart(charts.feature_importance(info["feature_importances"]), "importance")
    

# =============================================================================
# PAGE 2 — RESULTS
# =============================================================================
else:
    res = st.session_state.get("result")

    # ---- back button (top) --------------------------------------------------
    st.markdown(
        """
        <style>
        .pg-back-bar{
            display:flex; align-items:center; gap:18px;
            padding:10px 0 6px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )

    # Minimal header on results page
    st.markdown(
        '<div style="text-align:center;padding:24px 0 10px;">'
        '<span style="font-family:var(--display);font-size:clamp(22px,3.5vw,34px);'
        'font-weight:700;letter-spacing:.22em;color:var(--neon);'
        'text-shadow:0 0 10px rgba(61,255,138,.65),0 0 34px rgba(61,255,138,.30);">'
        'PHISHGUARD</span>'
        '<div style="font-size:12px;letter-spacing:.35em;color:var(--dim);margin-top:6px;">'
        'THREAT DETECTION SYSTEM  //  SCAN RESULTS'
        '</div></div>',
        unsafe_allow_html=True,
    )

    if st.button("◀  SCAN ANOTHER URL", key="back_top"):
        st.session_state["page"] = "scan"
        st.session_state["result"] = None
        st.session_state["error"] = None
        st.rerun()

    if res is None:
        st.markdown(
            theme.empty_state("NO RESULT AVAILABLE  //  PLEASE SCAN A URL FIRST"),
            unsafe_allow_html=True,
        )
    else:
        # ---- threat meter ---------------------------------------------------
        _, meter_col, _ = st.columns([1, 3, 1])
        with meter_col:
            st.markdown(theme.threat_meter(res), unsafe_allow_html=True)

        # ---- target analysis ------------------------------------------------
        st.markdown(theme.section("TARGET ANALYSIS"), unsafe_allow_html=True)
        st.markdown(theme.target_analysis(res), unsafe_allow_html=True)

        # ---- detected threats -----------------------------------------------
        n = len(res["indicators"])
        st.markdown(
            theme.section(f"DETECTED THREATS  [{n}]" if n else "DETECTED THREATS"),
            unsafe_allow_html=True,
        )
        st.markdown(theme.threat_cards(res), unsafe_allow_html=True)

        # ---- score breakdown + ML panel -------------------------------------
        st.markdown(theme.section("THREAT SCORE  //  ML PREDICTION"), unsafe_allow_html=True)
        c1, c2 = st.columns(2, gap="medium")
        with c1:
            show_chart(charts.score_breakdown(res), "score_breakdown")
        with c2:
            st.markdown(theme.ml_panel(res), unsafe_allow_html=True)

        # ---- security indicators --------------------------------------------
        st.markdown(theme.section("SECURITY INDICATORS"), unsafe_allow_html=True)
        c3, c4 = st.columns(2, gap="medium")
        with c3:
            show_chart(charts.indicator_points(res), "indicator_points")
        with c4:
            show_chart(charts.threat_radar(res), "threat_radar")

        # ---- feature analysis -----------------------------------------------
        st.markdown(theme.section("URL FEATURE ANALYSIS"), unsafe_allow_html=True)
        st.markdown(
            theme.feature_table(res["features"], load_config()["feature_descriptions"]),
            unsafe_allow_html=True,
        )

        # ---- export + back button -------------------------------------------
        col_dl, col_back, _ = st.columns([1.4, 1.6, 1])
        col_dl.download_button(
            "EXPORT REPORT (JSON)",
            data=json.dumps(res, indent=2),
            file_name="phishguard_report.json",
            mime="application/json",
            key="dl_report",
        )
        if col_back.button("◀  SCAN ANOTHER URL", key="back_bottom"):
            st.session_state["page"] = "scan"
            st.session_state["result"] = None
            st.session_state["error"] = None
            st.rerun()

    st.markdown(theme.footer(APP_VERSION), unsafe_allow_html=True)
