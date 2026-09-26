"""PhishGuard console theme: CSS + small HTML component builders.

All dynamic text is passed through ``html.escape`` - submitted URLs are
untrusted strings and must never be rendered as live markup or links.
"""
from __future__ import annotations

from html import escape
from typing import Any

# ---- palette (shared with charts.py) ---------------------------------------
BG = "#050a07"
CARD = "#0b1510"
LINE = "#1b3a29"
LINE_HI = "#2a5a3e"
NEON = "#3dff8a"
NEON_DIM = "#2fbf6a"
MUTED = "#2c7a4d"
DEEP = "#164a2e"
TEXT = "#dbe6df"
DIM = "#8aa294"
AMBER = "#f0b429"
RED = "#ff4d5e"

LEVEL_COLORS = {"LOW RISK": NEON, "SUSPICIOUS": AMBER, "HIGH RISK": RED}
LEVEL_CLASS = {"LOW RISK": "lvl-low", "SUSPICIOUS": "lvl-sus", "HIGH RISK": "lvl-high"}
SEVERITY_CLASS = {"low": "lvl-low", "medium": "lvl-sus", "high": "lvl-high"}

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Chakra+Petch:wght@500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap');

:root{
  --bg:#050a07; --bg2:#08110c; --card:#0b1510; --card2:#0f1c15;
  --line:#1b3a29; --line2:#2a5a3e; --neon:#3dff8a; --neon-dim:#2fbf6a;
  --muted:#2c7a4d; --deep:#164a2e; --text:#dbe6df; --dim:#8aa294;
  --amber:#f0b429; --red:#ff4d5e;
  --mono:'JetBrains Mono','Cascadia Mono',Consolas,'Courier New',monospace;
  --display:'Chakra Petch','Rajdhani','Segoe UI',system-ui,sans-serif;
}

/* ---------- app shell ---------- */
html, body, .stApp{ background:var(--bg); color:var(--text); font-family:var(--mono); }
.stApp{
  background:
    radial-gradient(1100px 520px at 50% -8%, rgba(61,255,138,.10), transparent 62%),
    radial-gradient(800px 500px at 100% 100%, rgba(44,122,77,.10), transparent 60%),
    linear-gradient(rgba(61,255,138,.035) 1px, transparent 1px),
    linear-gradient(90deg, rgba(61,255,138,.035) 1px, transparent 1px),
    var(--bg);
  background-size:auto, auto, 44px 44px, 44px 44px, auto;
  background-attachment:fixed;
}
.stApp::before{ /* faint CRT scanlines */
  content:''; position:fixed; inset:0; pointer-events:none; z-index:0;
  background:repeating-linear-gradient(0deg, rgba(0,0,0,.16) 0, rgba(0,0,0,.16) 1px, transparent 1px, transparent 3px);
  opacity:.35;
}
header[data-testid="stHeader"]{ background:transparent; }
[data-testid="stToolbar"], [data-testid="stDecoration"], #MainMenu, footer{ display:none !important; }
.block-container{ max-width:1140px; padding-top:1.4rem; padding-bottom:3rem; position:relative; z-index:1; }
::selection{ background:rgba(61,255,138,.28); color:#fff; }
h1,h2,h3,h4{ font-family:var(--display); color:var(--text); }
p, li, span, label, div{ font-family:var(--mono); }
a{ color:var(--neon); }
hr{ border-color:var(--line); }
* { scrollbar-width:thin; scrollbar-color:var(--line2) var(--bg); }

/* ---------- status strip ---------- */
.pg-status{ display:flex; flex-wrap:wrap; gap:8px 28px; justify-content:center; padding:10px 14px;
  border:1px solid var(--line); background:rgba(11,21,16,.7); font-size:11.5px; letter-spacing:.08em; color:var(--dim); }
.pg-status b{ color:var(--neon); font-weight:700; letter-spacing:.1em; }
.pg-status b.off{ color:var(--red); }
.pg-dot{ display:inline-block; width:7px; height:7px; border-radius:50%; margin-right:8px; vertical-align:middle;
  background:var(--neon); box-shadow:0 0 6px var(--neon), 0 0 14px rgba(61,255,138,.55); animation:pgPulse 2.4s ease-in-out infinite; }
.pg-dot.off{ background:var(--red); box-shadow:0 0 6px var(--red); animation:none; }
@keyframes pgPulse{ 0%,100%{ opacity:1 } 50%{ opacity:.35 } }

/* ---------- hero ---------- */
.pg-hero{ text-align:center; padding:56px 0 26px; }
.pg-hero .pg-title{ font-family:var(--display); font-weight:700; font-size:clamp(38px,6.6vw,68px); letter-spacing:.22em;
  margin:0; padding-left:.22em; color:var(--neon) !important; line-height:1;
  text-shadow:0 0 10px rgba(61,255,138,.65), 0 0 34px rgba(61,255,138,.30), 0 0 80px rgba(61,255,138,.18);
  animation:pgBoot 1.3s steps(1,end) 1; }
@keyframes pgBoot{ 0%{opacity:0} 8%{opacity:1} 14%{opacity:.25} 22%{opacity:1} 30%{opacity:.6} 38%{opacity:1} 100%{opacity:1} }
.pg-sub{ display:flex; align-items:center; justify-content:center; gap:16px; margin-top:16px;
  font-size:13px; letter-spacing:.42em; color:var(--dim); padding-left:.42em; }
.pg-sub::before, .pg-sub::after{ content:''; height:1px; width:min(90px,14vw); background:linear-gradient(90deg,transparent,var(--muted)); }
.pg-sub::after{ transform:scaleX(-1); }
.pg-prompt{ text-align:center; font-size:13px; letter-spacing:.3em; color:var(--neon-dim); margin:18px 0 10px; }
.pg-prompt::after{ content:'_'; margin-left:4px; animation:pgBlink 1.1s steps(1,end) infinite; color:var(--neon); }
@keyframes pgBlink{ 0%,50%{opacity:1} 51%,100%{opacity:0} }
.pg-hint{ text-align:center; font-size:11.5px; color:var(--dim); margin:14px 0 6px; letter-spacing:.04em; }

/* ---------- inputs ---------- */
[data-testid="stTextInputRootElement"], div[data-testid="stTextInput"] div[data-baseweb="input"], div[data-testid="stTextInput"] div[data-baseweb="base-input"]{
  background:#040806 !important; border-radius:2px !important; }
[data-testid="stTextInputRootElement"], div[data-testid="stTextInput"] div[data-baseweb="input"]{
  border:1px solid var(--line2) !important; transition:border-color .2s ease, box-shadow .2s ease; }
[data-testid="stTextInputRootElement"]:focus-within, div[data-testid="stTextInput"] div[data-baseweb="input"]:focus-within{
  border-color:var(--neon) !important; box-shadow:0 0 0 1px rgba(61,255,138,.35), 0 0 22px rgba(61,255,138,.22) !important; }
[data-testid="stTextInputField"], div[data-testid="stTextInput"] input{ font-family:var(--mono) !important; font-size:15px !important;
  color:var(--neon) !important; caret-color:var(--neon); padding:15px 16px !important; letter-spacing:.02em; background:transparent !important; }
[data-testid="stTextInputField"]::placeholder, div[data-testid="stTextInput"] input::placeholder{ color:#4c6a58 !important; opacity:1; }
[data-testid="InputInstructions"]{ display:none !important; }
[data-testid="stForm"]{ border:none !important; padding:0 !important; background:transparent !important; }

/* ---------- buttons ---------- */
.stButton > button, [data-testid="stFormSubmitButton"] > button, [data-testid="stDownloadButton"] > button{
  font-family:var(--mono) !important; font-weight:700 !important; letter-spacing:.2em; text-transform:uppercase;
  color:var(--neon) !important; background:rgba(61,255,138,.05) !important; border:1px solid var(--neon-dim) !important;
  border-radius:2px !important; padding:.7rem 2.2rem !important; transition:all .18s ease; box-shadow:0 0 0 rgba(61,255,138,0); }
.stButton > button:hover, [data-testid="stFormSubmitButton"] > button:hover, [data-testid="stDownloadButton"] > button:hover{
  background:var(--neon) !important; color:#03150a !important; border-color:var(--neon) !important;
  box-shadow:0 0 22px rgba(61,255,138,.55), 0 0 50px rgba(61,255,138,.2); transform:translateY(-1px); }
.stButton > button:active, [data-testid="stFormSubmitButton"] > button:active{ transform:translateY(0); }
.stButton > button:focus-visible, [data-testid="stFormSubmitButton"] > button:focus-visible{ outline:2px solid var(--neon); outline-offset:2px; }
[data-testid="stElementContainer"]:has([data-testid="stFormSubmitButton"]), .element-container:has([data-testid="stFormSubmitButton"]){ width:100% !important; }
[data-testid="stFormSubmitButton"]{ display:flex; justify-content:center; width:100%; }
.stButton > button p, [data-testid="stFormSubmitButton"] button p, [data-testid="stDownloadButton"] button p{ font-size:13px; }
/* small "demo target" chips */
.st-key-chips [data-testid="stElementContainer"], .st-key-chips .element-container, .st-key-chips [data-testid="stButton"], .st-key-chips .stButton{ width:100% !important; }
.st-key-chips .stButton > button, .st-key-chips [data-testid="stButton"] > button{ font-size:11px !important; letter-spacing:.12em; padding:.4rem .4rem !important; color:var(--dim) !important;
  background:transparent !important; border-color:var(--line2) !important; width:100%; white-space:nowrap; }
.st-key-chips .stButton > button:hover{ color:#03150a !important; }

/* ---------- tabs ---------- */
[data-baseweb="tab-list"]{ gap:6px; border-bottom:1px solid var(--line); }
button[data-baseweb="tab"]{ font-family:var(--mono) !important; letter-spacing:.18em; color:var(--dim) !important; background:transparent !important;
  padding:12px 18px !important; transition:color .15s ease, text-shadow .15s ease; }
button[data-baseweb="tab"]:hover{ color:var(--neon) !important; }
button[data-baseweb="tab"][aria-selected="true"]{ color:var(--neon) !important; text-shadow:0 0 12px rgba(61,255,138,.6); }
button[data-baseweb="tab"] p{ font-size:12.5px; font-weight:700; color:inherit !important; }
[data-baseweb="tab-highlight"]{ background:var(--neon) !important; height:2px !important; box-shadow:0 0 12px var(--neon); }
[data-baseweb="tab-border"]{ background:transparent !important; }

/* ---------- section heading ---------- */
.pg-h{ display:flex; align-items:center; gap:14px; margin:34px 0 14px; font-family:var(--display); font-weight:600;
  font-size:14px; letter-spacing:.28em; color:var(--neon); text-shadow:0 0 10px rgba(61,255,138,.35); }
.pg-h::before{ content:''; width:8px; height:8px; background:var(--neon); box-shadow:0 0 10px var(--neon); }
.pg-h::after{ content:''; flex:1; height:1px; background:linear-gradient(90deg,var(--line2),transparent); }

/* ---------- cards ---------- */
.pg-card{ position:relative; background:linear-gradient(180deg,var(--card),var(--bg2)); border:1px solid var(--line);
  border-radius:2px; padding:18px 20px; box-shadow:0 0 0 1px rgba(61,255,138,.02), 0 0 26px rgba(61,255,138,.05);
  transition:border-color .2s ease, box-shadow .2s ease; }
.pg-card::before, .pg-card::after{ content:''; position:absolute; width:11px; height:11px; pointer-events:none; }
.pg-card::before{ top:-1px; left:-1px; border-top:2px solid var(--neon); border-left:2px solid var(--neon); }
.pg-card::after{ bottom:-1px; right:-1px; border-bottom:2px solid var(--neon); border-right:2px solid var(--neon); }
.pg-card:hover{ border-color:var(--line2); box-shadow:0 0 0 1px rgba(61,255,138,.08), 0 0 34px rgba(61,255,138,.11); }
.pg-label{ font-size:10.5px; letter-spacing:.24em; color:var(--dim); margin-bottom:6px; }
.pg-value{ font-family:var(--display); font-size:28px; font-weight:700; color:var(--text); line-height:1.15; }
.pg-value small{ font-size:15px; color:var(--dim); font-weight:500; }
.pg-grid{ display:grid; gap:16px; }
.pg-g4{ grid-template-columns:repeat(4,minmax(0,1fr)); }
.pg-g3{ grid-template-columns:repeat(3,minmax(0,1fr)); }
.pg-g2{ grid-template-columns:repeat(2,minmax(0,1fr)); }
.pg-g5{ grid-template-columns:repeat(5,minmax(0,1fr)); }
@media (max-width:820px){ .pg-g4,.pg-g3,.pg-g5{ grid-template-columns:repeat(2,minmax(0,1fr)); } .pg-g2{ grid-template-columns:1fr; } }
.pg-url{ font-family:var(--mono); font-size:14.5px; color:var(--neon); word-break:break-all; padding:12px 14px; margin:2px 0 18px;
  background:#040806; border:1px solid var(--line); border-left:3px solid var(--neon); text-shadow:0 0 8px rgba(61,255,138,.25); }

/* threat level colours */
.lvl-low{ --lvl:var(--neon); } .lvl-sus{ --lvl:var(--amber); } .lvl-high{ --lvl:var(--red); }
.pg-pill{ display:inline-flex; align-items:center; gap:8px; font-weight:700; letter-spacing:.14em; font-size:13px; color:var(--lvl);
  text-shadow:0 0 10px color-mix(in srgb, var(--lvl) 60%, transparent); }
.pg-pill::before{ content:''; width:9px; height:9px; border-radius:50%; background:var(--lvl);
  box-shadow:0 0 8px var(--lvl), 0 0 18px color-mix(in srgb, var(--lvl) 55%, transparent); }
.pg-value.lvl-text{ color:var(--lvl); text-shadow:0 0 14px color-mix(in srgb, var(--lvl) 45%, transparent); }

/* ---------- threat meter ---------- */
.pg-meter{ position:relative; overflow:hidden; text-align:center; padding:26px 26px 22px; margin:8px 0 6px;
  background:linear-gradient(180deg,#0c1812,#070e0a); border:1px solid color-mix(in srgb, var(--lvl) 55%, var(--line));
  box-shadow:0 0 0 1px color-mix(in srgb, var(--lvl) 12%, transparent), 0 0 44px color-mix(in srgb, var(--lvl) 20%, transparent), inset 0 0 60px rgba(0,0,0,.45); }
.pg-meter::before{ content:''; position:absolute; left:0; right:0; height:70px; top:-70px; pointer-events:none;
  background:linear-gradient(180deg,transparent,color-mix(in srgb, var(--lvl) 22%, transparent),transparent); animation:pgSweep 1.5s ease-out 1 forwards; }
@keyframes pgSweep{ to{ top:105%; } }
.pg-meter-title{ font-size:11.5px; letter-spacing:.5em; color:var(--dim); padding-left:.5em; }
.pg-meter-score{ font-family:var(--display); font-weight:700; font-size:clamp(84px,14vw,132px); line-height:1.02; margin:6px 0 0;
  color:var(--lvl); text-shadow:0 0 16px color-mix(in srgb, var(--lvl) 70%, transparent), 0 0 60px color-mix(in srgb, var(--lvl) 30%, transparent); }
.pg-meter-verdict{ font-family:var(--display); font-weight:700; letter-spacing:.34em; padding-left:.34em; font-size:22px; color:var(--lvl); margin-bottom:22px; }
.pg-bar{ display:grid; grid-template-columns:repeat(25,1fr); gap:4px; max-width:560px; margin:0 auto; }
.pg-seg{ height:16px; background:#0e2217; border:1px solid #143024; }
.pg-seg.on{ background:var(--lvl); border-color:var(--lvl); box-shadow:0 0 9px color-mix(in srgb, var(--lvl) 75%, transparent);
  animation:pgSeg .35s ease-out both; }
@keyframes pgSeg{ from{ opacity:0; transform:scaleY(.2); } to{ opacity:1; transform:scaleY(1); } }
.pg-scale{ display:flex; max-width:560px; margin:8px auto 0; font-size:10px; letter-spacing:.16em; color:var(--dim); }
.pg-scale span{ text-align:center; }
.pg-meter-foot{ margin-top:20px; font-size:11.5px; letter-spacing:.2em; color:var(--dim); display:flex; justify-content:center; flex-wrap:wrap; gap:8px 26px; }
.pg-meter-foot i{ font-style:normal; color:var(--lvl); }
.pg-banner{ text-align:center; font-family:var(--display); font-weight:700; letter-spacing:.32em; padding-left:.32em; font-size:15px; margin:22px 0 4px; color:var(--lvl);
  text-shadow:0 0 12px color-mix(in srgb, var(--lvl) 55%, transparent); }

/* ---------- threat cards ---------- */
.pg-threats{ display:grid; grid-template-columns:repeat(auto-fit,minmax(310px,1fr)); gap:14px; }
.pg-threat{ position:relative; display:flex; gap:14px; align-items:flex-start; padding:15px 16px; background:linear-gradient(180deg,var(--card),var(--bg2));
  border:1px solid var(--line); border-left:3px solid var(--lvl); border-radius:2px; transition:all .18s ease; }
.pg-threat:hover{ border-color:color-mix(in srgb, var(--lvl) 65%, var(--line)); border-left-color:var(--lvl);
  box-shadow:0 0 22px color-mix(in srgb, var(--lvl) 18%, transparent); transform:translateX(2px); }
.pg-threat .ico{ color:var(--lvl); font-size:19px; line-height:1.1; text-shadow:0 0 10px var(--lvl); }
.pg-threat .ttl{ font-weight:700; letter-spacing:.12em; font-size:12.5px; color:var(--lvl); text-transform:uppercase; }
.pg-threat .dsc{ color:var(--text); font-size:13px; margin-top:5px; word-break:break-word; }
.pg-threat .pts{ margin-left:auto; font-size:11.5px; color:var(--dim); border:1px solid var(--line2); padding:2px 8px; white-space:nowrap; align-self:flex-start; }

/* ---------- terminal report ---------- */
.pg-term{ font-family:var(--mono); font-size:13.5px; line-height:1.7; color:var(--text); background:#040806; border:1px solid var(--line);
  padding:16px 18px; white-space:normal; margin:0; }
.pg-term .hd{ color:var(--lvl) !important; font-weight:700; text-shadow:0 0 10px color-mix(in srgb, var(--lvl) 45%, transparent); }
.pg-term .pr{ color:var(--neon-dim) !important; }

/* ---------- tables ---------- */
.pg-table{ width:100%; border-collapse:collapse; font-size:12.5px; }
.pg-table th{ text-align:left; font-weight:500; font-size:10.5px; letter-spacing:.2em; color:var(--dim); padding:6px 10px 10px; border-bottom:1px solid var(--line2); }
.pg-table td{ padding:8px 10px; border-bottom:1px solid #12261b; vertical-align:top; }
.pg-table tr:hover td{ background:rgba(61,255,138,.045); }
.pg-table td.k{ color:var(--text); white-space:nowrap; }
.pg-table td.v{ color:var(--neon); text-align:right; font-weight:700; white-space:nowrap; }
.pg-table td.v.flag{ color:var(--amber); text-shadow:0 0 8px rgba(240,180,41,.4); }
.pg-table td.d{ color:var(--dim); font-size:11.5px; }
.pg-table-wrap{ overflow-x:auto; }

/* ---------- ML drivers ---------- */
.pg-drv{ display:grid; grid-template-columns:200px 1fr 56px; gap:10px; align-items:center; font-size:12px; padding:5px 0; }
.pg-drv .n{ color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
.pg-drv .b{ height:8px; background:#0e2217; position:relative; }
.pg-drv .b > i{ position:absolute; left:0; top:0; bottom:0; background:var(--c); box-shadow:0 0 8px var(--c); }
.pg-drv .p{ text-align:right; color:var(--c); font-weight:700; }

/* ---------- stat tiles, notices ---------- */
.pg-stat .pg-value{ font-size:32px; }
.pg-alert{ border:1px solid var(--red); border-left-width:3px; background:rgba(255,77,94,.07); color:#ffd6da; padding:12px 16px; font-size:13px; margin:14px 0; }
.pg-note{ border:1px dashed var(--line2); background:rgba(61,255,138,.03); color:var(--dim); padding:12px 16px; font-size:12px; line-height:1.6; }
.pg-note b{ color:var(--neon); }
.pg-empty{ text-align:center; color:var(--dim); font-size:12.5px; letter-spacing:.14em; padding:42px 0 30px; border:1px dashed var(--line); margin-top:26px; }
.pg-foot{ margin-top:54px; padding-top:16px; border-top:1px solid var(--line); text-align:center; color:#5d7767; font-size:11px; letter-spacing:.14em; }

/* ---------- streamlit widget polish ---------- */
[data-testid="stFileUploaderDropzone"]{ background:rgba(11,21,16,.8) !important; border:1px dashed var(--muted) !important; border-radius:2px !important; transition:all .2s ease; }
[data-testid="stFileUploaderDropzone"]:hover{ border-color:var(--neon) !important; box-shadow:0 0 22px rgba(61,255,138,.14); }
[data-testid="stFileUploaderDropzone"] button{ border-radius:2px !important; }
[data-testid="stDataFrame"]{ border:1px solid var(--line); border-radius:2px; }
[data-testid="stPlotlyChart"]{ border:1px solid var(--line); background:linear-gradient(180deg,var(--card),var(--bg2)); padding:6px 8px; border-radius:2px;
  transition:border-color .2s ease, box-shadow .2s ease; }
[data-testid="stPlotlyChart"]:hover{ border-color:var(--line2); box-shadow:0 0 28px rgba(61,255,138,.09); }
[data-testid="stCaptionContainer"], .stCaption{ color:var(--dim) !important; font-size:11.5px !important; }
[data-testid="stAlert"]{ border-radius:2px; }
label, [data-testid="stWidgetLabel"] p{ color:var(--dim) !important; font-size:12px !important; letter-spacing:.06em; }

@media (prefers-reduced-motion: reduce){ *{ animation:none !important; transition:none !important; } }
</style>
"""


def h(markup: str) -> str:
    """Collapse indentation/newlines so Markdown never treats the HTML as a code block."""
    return "".join(line.strip() for line in markup.strip().splitlines())


def esc(value: Any) -> str:
    return escape(str(value), quote=True)


def level_class(verdict: str) -> str:
    return LEVEL_CLASS.get(verdict, "lvl-low")


# ---- components ------------------------------------------------------------



def hero() -> str:
    return h("""
    <div class="pg-hero">
      <div class="pg-title">PHISHGUARD</div>
      <div class="pg-sub">THREAT DETECTION SYSTEM</div>
    </div>""")


def section(title: str) -> str:
    return f'<div class="pg-h">{esc(title)}</div>'


def threat_meter(res: dict[str, Any]) -> str:
    score, verdict = int(res["risk_score"]), res["verdict"]
    lit = round(score / 100 * 25)
    segs = "".join(
        f'<div class="pg-seg{" on" if i < lit else ""}" style="animation-delay:{0.25 + i * 0.045:.2f}s"></div>' for i in range(25))
    sb = res["score_breakdown"]
    lo, mid, hi = sb["suspicious_min"], sb["high_min"] - sb["suspicious_min"], 100 - sb["high_min"]
    banner = "SYSTEM SECURE" if verdict == "LOW RISK" else "THREAT DETECTED"
    return h(f"""
    <div class="pg-banner {level_class(verdict)}">{banner}</div>
    <div class="pg-meter {level_class(verdict)}">
      <div class="pg-meter-title">THREAT LEVEL</div>
      <div class="pg-meter-score">{score}</div>
      <div class="pg-meter-verdict">{esc(verdict)}</div>
      <div class="pg-bar">{segs}</div>
      <div class="pg-scale"><span style="width:{lo}%">LOW</span><span style="width:{mid}%">SUSPICIOUS</span><span style="width:{hi}%">HIGH</span></div>
      <div class="pg-meter-foot"><span><i>&#9679;</i> SCAN COMPLETE</span><span><i>&#9679;</i> TARGET ANALYZED</span></div>
    </div>""")


def target_analysis(res: dict[str, Any]) -> str:
    v = res["verdict"]
    conf = f'{res["ml_confidence"] * 100:.1f}<small>%</small>'
    term = terminal_report(res)
    return h(f"""
    <div class="pg-card {level_class(v)}">
      <div class="pg-label">URL</div>
      <div class="pg-url">{esc(res["url"])}</div>
      <div class="pg-grid pg-g4">
        <div><div class="pg-label">STATUS</div><div class="pg-pill">{esc(v)}</div></div>
        <div><div class="pg-label">RISK SCORE</div><div class="pg-value lvl-text">{res["risk_score"]} <small>/ 100</small></div></div>
        <div><div class="pg-label">ML CONFIDENCE</div><div class="pg-value">{conf}</div></div>
        <div><div class="pg-label">RULE SCORE</div><div class="pg-value">{res["rule_score"]} <small>/ 100</small></div></div>
      </div>
      <div class="pg-label" style="margin-top:22px">ANALYST REPORT</div>
      {term}
    </div>""")


def terminal_report(res: dict[str, Any]) -> str:
    head = f'{esc(res["verdict"])} \u2014 {res["risk_score"]}/100'
    if res["reasons"]:
        body = "<br>".join(f'<span class="pr">-</span> {esc(r)}' for r in res["reasons"])
        text = f'<span class="hd">{head}</span><br><br>Reasons:<br>{body}'
    else:
        text = f'<span class="hd">{head}</span><br><br>No suspicious indicators detected in the URL structure.'
    return f'<div class="pg-term {level_class(res["verdict"])}">{text}</div>'


def threat_cards(res: dict[str, Any]) -> str:
    if not res["indicators"]:
        return h("""<div class="pg-threats"><div class="pg-threat lvl-low"><div class="ico">&#10003;</div>
        <div><div class="ttl">No threat indicators</div><div class="dsc">The URL structure shows none of the monitored phishing signals.</div></div></div></div>""")
    cards = "".join(
        f'<div class="pg-threat {SEVERITY_CLASS[i["severity"]]}"><div class="ico">&#9888;</div>'
        f'<div><div class="ttl">{esc(i["title"])}</div><div class="dsc">{esc(i["detail"])}</div></div>'
        f'<div class="pts">+{i["points"]}</div></div>' for i in res["indicators"])
    return f'<div class="pg-threats">{cards}</div>'


def ml_panel(res: dict[str, Any]) -> str:
    pred = res["ml_prediction"]
    cls = "lvl-high" if pred == "PHISHING" else "lvl-low"
    drivers = res.get("ml_drivers", [])
    top = max((abs(d["impact"]) for d in drivers), default=1) or 1
    rows = ""
    for d in drivers:
        raises = d["impact"] > 0
        color = "var(--red)" if raises else "var(--neon)"
        val = d["value"]
        val = int(val) if float(val).is_integer() else round(val, 2)
        rows += (f'<div class="pg-drv" style="--c:{color}"><div class="n" title="{esc(d["feature"])}">{esc(d["feature"])} = {esc(val)}</div>'
                 f'<div class="b"><i style="width:{abs(d["impact"]) / top * 100:.0f}%"></i></div>'
                 f'<div class="p">{d["impact"]:+.1f}</div></div>')
    if not rows:
        rows = '<div style="color:var(--dim);font-size:12px">No single feature moves the model output noticeably.</div>'
    return h(f"""
    <div class="pg-card {cls}">
      <div class="pg-grid pg-g3" style="margin-bottom:18px">
        <div><div class="pg-label">ML PREDICTION</div><div class="pg-value lvl-text" style="font-size:18px;white-space:nowrap;padding-top:6px">{pred}</div></div>
        <div><div class="pg-label">CONFIDENCE</div><div class="pg-value">{res["ml_confidence"] * 100:.1f}<small>%</small></div></div>
        <div><div class="pg-label">P(PHISHING)</div><div class="pg-value">{res["ml_phishing_probability"] * 100:.1f}<small>%</small></div></div>
      </div>
      <div class="pg-label">WHAT MOVED THE MODEL (POINTS OF PHISHING PROBABILITY)</div>
      {rows}
    </div>""")


_FLAG_FEATURES = {"has_ip_domain", "has_at_symbol", "suspicious_tld", "is_shortener", "has_punycode", "has_port",
                  "double_slash_in_path", "brand_in_host", "brand_in_path"}


def feature_table(features: dict[str, float], descriptions: dict[str, str]) -> str:
    def fmt(v: float) -> str:
        return str(int(v)) if float(v).is_integer() else f"{v:.3f}".rstrip("0").rstrip(".")

    def flagged(k: str, v: float) -> bool:
        return (k in _FLAG_FEATURES and v) or (k == "has_https" and not v) or (k == "num_suspicious_keywords" and v)

    items = list(features.items())
    half = (len(items) + 1) // 2

    def table(chunk: list[tuple[str, float]]) -> str:
        rows = "".join(
            f'<tr><td class="k">{esc(k)}</td><td class="v{" flag" if flagged(k, v) else ""}">{esc(fmt(v))}</td>'
            f'<td class="d">{esc(descriptions.get(k, ""))}</td></tr>' for k, v in chunk)
        return (f'<div class="pg-card pg-table-wrap"><table class="pg-table"><thead><tr><th>FEATURE</th><th style="text-align:right">VALUE</th>'
                f'<th>MEANING</th></tr></thead><tbody>{rows}</tbody></table></div>')

    return f'<div class="pg-grid pg-g2">{table(items[:half])}{table(items[half:])}</div>'


def stat_tiles(stats: list[tuple[str, Any, str]]) -> str:
    """stats: (label, value, level_class or '')."""
    n = len(stats)
    cells = "".join(
        f'<div class="pg-card pg-stat {cls}"><div class="pg-label">{esc(lbl)}</div>'
        f'<div class="pg-value{" lvl-text" if cls else ""}">{esc(val)}</div></div>' for lbl, val, cls in stats)
    return f'<div class="pg-grid pg-g{min(n, 5)}">{cells}</div>'


def alert(message: str) -> str:
    return f'<div class="pg-alert">&#9888; {esc(message)}</div>'


def note(markup_safe: str) -> str:
    """``markup_safe`` must already be escaped / trusted static HTML."""
    return f'<div class="pg-note">{markup_safe}</div>'


def empty_state(text: str) -> str:
    return f'<div class="pg-empty">{esc(text)}</div>'


def footer(version: str) -> str:
    return (f'<div class="pg-foot">PHISHGUARD v{esc(version)} &nbsp;//&nbsp; URL STRING ANALYSIS ONLY '
            f'&nbsp;//&nbsp; NO REQUEST IS EVER MADE TO A SUBMITTED URL</div>')
