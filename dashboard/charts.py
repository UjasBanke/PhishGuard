"""Plotly figures styled for the PhishGuard dark-green console theme."""
from __future__ import annotations

from typing import Any

import pandas as pd
import plotly.graph_objects as go

from dashboard.theme import (AMBER, CARD, DEEP, DIM, LEVEL_COLORS, LINE, LINE_HI, MUTED, NEON, NEON_DIM, RED, TEXT)
from feature_engineering.extractor import load_config

FONT = "JetBrains Mono, Cascadia Mono, Consolas, monospace"
GRID = "#13281c"
SEV_COLORS = {"low": NEON, "medium": AMBER, "high": RED}


def _style(fig: go.Figure, title: str = "", height: int = 300, legend: bool = False) -> go.Figure:
    fig.update_layout(
        title=dict(text=title, x=0.01, xanchor="left", font=dict(family=FONT, size=12, color=NEON)),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", height=height,
        font=dict(family=FONT, color=TEXT, size=12), showlegend=legend,
        margin=dict(l=12, r=34, t=44, b=14),
        hoverlabel=dict(bgcolor=CARD, bordercolor=NEON, font=dict(family=FONT, color=TEXT, size=12)),
        legend=dict(font=dict(color=DIM, size=11), bgcolor="rgba(0,0,0,0)"),
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=LINE_HI, linecolor=LINE, tickfont=dict(color=DIM, size=11))
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=LINE_HI, linecolor=LINE, tickfont=dict(color=DIM, size=11), automargin=True)
    fig.update_xaxes(automargin=True)
    return fig


def _glow_bar(**kw: Any) -> go.Bar:
    kw.setdefault("marker_line_width", 1)
    return go.Bar(**kw)


def score_breakdown(res: dict[str, Any]) -> go.Figure:
    sb = res["score_breakdown"]
    color = LEVEL_COLORS[res["verdict"]]
    labels = ["FINAL RISK", "RULE ENGINE", "ML MODEL"]
    values = [res["risk_score"], sb["rule_score"], sb["ml_score"]]
    fig = go.Figure(_glow_bar(
        x=values, y=labels, orientation="h", marker=dict(color=[color, MUTED, NEON_DIM], line=dict(color=[color, NEON_DIM, NEON], width=1)),
        text=[f"{v:.0f}" for v in values], textposition="outside", textfont=dict(color=TEXT, family=FONT),
        hovertemplate="%{y}: %{x:.1f}/100<extra></extra>"))
    for x, lab in ((sb["suspicious_min"], "SUSPICIOUS"), (sb["high_min"], "HIGH")):
        fig.add_vline(x=x, line=dict(color=LINE_HI, width=1, dash="dot"), annotation_text=lab,
                      annotation_font=dict(color=DIM, size=10), annotation_position="top")
    _style(fig, "THREAT SCORE BREAKDOWN", 290)
    fig.update_xaxes(range=[0, 112], title=None)
    fig.update_yaxes(autorange="reversed")
    return fig


def indicator_points(res: dict[str, Any]) -> go.Figure:
    inds = res["indicators"]
    fig = go.Figure()
    if inds:
        inds = sorted(inds, key=lambda i: i["points"])
        fig.add_trace(_glow_bar(
            x=[i["points"] for i in inds], y=[i["title"] for i in inds], orientation="h",
            marker=dict(color=[SEV_COLORS[i["severity"]] for i in inds], opacity=0.9),
            text=[f'+{i["points"]}' for i in inds], textposition="outside", textfont=dict(color=TEXT, family=FONT),
            hovertext=[i["detail"] for i in inds], hovertemplate="%{y}<br>%{hovertext}<extra></extra>"))
        fig.update_xaxes(range=[0, max(i["points"] for i in inds) * 1.25])
    else:
        fig.add_annotation(text="NO INDICATORS TRIGGERED", showarrow=False, font=dict(color=NEON_DIM, size=14, family=FONT))
        fig.update_xaxes(visible=False)
        fig.update_yaxes(visible=False)
    _style(fig, "SECURITY INDICATORS  //  RULE POINTS", max(260, 70 + 34 * max(len(inds), 1)))
    fig.update_layout(bargap=0.45)
    return fig


def threat_radar(res: dict[str, Any]) -> go.Figure:
    caps = load_config()["radar_caps"]
    f = res["features"]
    axes = list(caps)
    vals = [min(f[a] / caps[a], 1.0) for a in axes]
    labels = [a.replace("num_", "").replace("_", " ") for a in axes]
    color = LEVEL_COLORS[res["verdict"]]
    fig = go.Figure(go.Scatterpolar(
        r=vals + vals[:1], theta=labels + labels[:1], fill="toself", line=dict(color=color, width=2),
        fillcolor="rgba(61,255,138,0.14)" if color == NEON else ("rgba(240,180,41,0.14)" if color == AMBER else "rgba(255,77,94,0.16)"),
        hovertemplate="%{theta}: %{r:.0%} of alert level<extra></extra>"))
    fig.update_layout(polar=dict(
        bgcolor="rgba(0,0,0,0)",
        radialaxis=dict(range=[0, 1], showticklabels=False, gridcolor=GRID, linecolor=LINE),
        angularaxis=dict(gridcolor=GRID, linecolor=LINE, tickfont=dict(color=DIM, size=10, family=FONT))))
    return _style(fig, "URL FEATURE PROFILE  //  % OF ALERT LEVEL", 340)


def feature_importance(importances: dict[str, float], top: int = 12) -> go.Figure:
    items = sorted(importances.items(), key=lambda kv: kv[1])[-top:]
    fig = go.Figure(_glow_bar(
        x=[v for _, v in items], y=[k for k, _ in items], orientation="h",
        marker=dict(color=NEON_DIM, line=dict(color=NEON, width=1)),
        hovertemplate="%{y}: %{x:.3f}<extra></extra>"))
    return _style(fig, "RANDOM FOREST  //  GLOBAL FEATURE IMPORTANCE", 380)


def verdict_donut(df: pd.DataFrame) -> go.Figure:
    order = ["LOW RISK", "SUSPICIOUS", "HIGH RISK"]
    counts = [int((df["verdict"] == v).sum()) for v in order]
    fig = go.Figure(go.Pie(
        labels=order, values=counts, hole=0.62, sort=False, marker=dict(colors=[NEON, AMBER, RED], line=dict(color="#050a07", width=3)),
        textinfo="value", textfont=dict(color="#050a07", family=FONT, size=13),
        hovertemplate="%{label}: %{value} (%{percent})<extra></extra>"))
    fig.add_annotation(text=f"{sum(counts)}<br><span style='font-size:10px;color:{DIM}'>TARGETS</span>", showarrow=False,
                       font=dict(size=22, color=TEXT, family=FONT))
    return _style(fig, "VERDICT DISTRIBUTION", 320, legend=True)


def score_histogram(df: pd.DataFrame) -> go.Figure:
    scores = df["risk_score"].dropna()
    fig = go.Figure(go.Histogram(x=scores, xbins=dict(start=0, end=100, size=5),
                                 marker=dict(color=NEON_DIM, line=dict(color=NEON, width=1)),
                                 hovertemplate="score %{x}: %{y} URLs<extra></extra>"))
    cfg = load_config()["scoring"]
    for x in (cfg["suspicious_min"], cfg["high_min"]):
        fig.add_vline(x=x, line=dict(color=LINE_HI, width=1, dash="dot"))
    _style(fig, "RISK SCORE DISTRIBUTION", 320)
    fig.update_xaxes(range=[0, 100])
    return fig


def history_trend(history: list[dict[str, Any]]) -> go.Figure:
    df = pd.DataFrame(history).iloc[::-1].reset_index(drop=True)
    fig = go.Figure(go.Scatter(
        x=list(range(1, len(df) + 1)), y=df["risk_score"], mode="lines+markers",
        line=dict(color=MUTED, width=2), marker=dict(size=11, color=[LEVEL_COLORS[v] for v in df["verdict"]], line=dict(color="#050a07", width=2)),
        text=df["url"], hovertemplate="scan #%{x}: %{y}/100<br>%{text}<extra></extra>"))
    cfg = load_config()["scoring"]
    for y in (cfg["suspicious_min"], cfg["high_min"]):
        fig.add_hline(y=y, line=dict(color=LINE_HI, width=1, dash="dot"))
    _style(fig, "RISK SCORE PER SCAN", 300)
    fig.update_yaxes(range=[0, 105])
    fig.update_xaxes(title=None, dtick=1)
    return fig
