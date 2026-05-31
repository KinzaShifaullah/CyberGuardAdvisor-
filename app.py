# ============================================================
# app.py  –  CyberGuard Advisor  (Final Version)
# Rule-Based Cybersecurity Expert System
# BS-CS Artificial Intelligence Term Project · 2026
# ============================================================
import streamlit as st
import sys, os, base64, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inference_engine import (
    extract_password_facts, extract_url_facts,
    extract_message_facts, extract_scam_facts,
    extract_hygiene_facts, run_inference, resolve_conflicts,
)
from confidence_engine   import build_score_report
from explanation_engine  import generate_explanation, format_full_report
from recommendation_engine import get_recommendations
from certainty_factor    import build_cf_report
from backward_chaining   import run_backward_chaining
from test_scenarios      import TEST_SCENARIOS
from knowledge_base      import RULES

# ── Page config ─────────────────────────────────────────────
st.set_page_config(
    page_title="CyberGuard Advisor",
    page_icon="assets/hero1.jpeg" if os.path.exists("assets/hero1.jpeg") else "🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

def img_b64(path):
    try:
        with open(path,"rb") as f: return base64.b64encode(f.read()).decode()
    except: return None

import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) if "__file__" in dir() else os.getcwd()
HERO_IMG = img_b64(os.path.join(BASE_DIR, "assets", "hero2.jpeg"))

# ── CSS ─────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

html,body,[class*="css"]{ font-family:'Inter',sans-serif!important; background:#0d1b2a!important; color:#e2e8f0; }
.main .block-container{ padding:0 2rem 2rem 2rem; max-width:1300px; }

/* Sidebar */
section[data-testid="stSidebar"]{ background:linear-gradient(180deg,#0a1628,#0d1b2a)!important; border-right:1px solid #1e3a5f; }
div[role="radiogroup"] label{ display:flex;align-items:center;padding:.48rem 1rem;border-radius:7px;margin:2px 0;color:#7fa8c9!important;font-size:.88rem;font-weight:500;transition:all .15s;cursor:pointer; }
div[role="radiogroup"] label:hover{ background:rgba(59,130,246,.12);color:#e2e8f0!important; }

/* Buttons */
.stButton>button{ background:linear-gradient(135deg,#1d4ed8,#2563eb)!important;color:#fff!important;border:none!important;border-radius:8px!important;font-weight:600!important;font-family:'Inter',sans-serif!important;padding:.55rem 1.4rem!important;box-shadow:0 4px 14px rgba(37,99,235,.3)!important;transition:all .2s!important; }
.stButton>button:hover{ background:linear-gradient(135deg,#2563eb,#3b82f6)!important;transform:translateY(-1px)!important; }

/* Inputs */
.stTextInput input,.stTextArea textarea{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:8px!important;color:#e2e8f0!important;font-family:'Inter',sans-serif!important; }
.stTextInput input:focus,.stTextArea textarea:focus{ border-color:#3b82f6!important;box-shadow:0 0 0 3px rgba(59,130,246,.15)!important; }
div[data-baseweb="select"]>div{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:8px!important;color:#e2e8f0!important; }
div[data-baseweb="select"] *{ color:#e2e8f0!important; }
div[data-baseweb="popover"]{ background:#0f2236!important;border:1px solid #1e3a5f!important; }
li[role="option"]{ background:#0f2236!important;color:#e2e8f0!important; }
li[role="option"]:hover{ background:#1e3a5f!important; }

/* Slider */
.stSlider>div>div>div>div{ background:#3b82f6!important; }
.stSlider [data-testid="stThumbValue"]{ color:#60a5fa!important; }

/* Checkbox */
.stCheckbox label{ color:#94a3b8!important;font-size:.88rem!important; }

/* Radio */
.stRadio label{ color:#94a3b8!important;font-size:.88rem!important; }
.stRadio [data-testid="stMarkdownContainer"] p{ color:#94a3b8!important; }

/* Metrics */
[data-testid="stMetric"]{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:10px!important;padding:1rem!important; }
[data-testid="stMetricLabel"]{ color:#7fa8c9!important;font-size:.75rem!important;text-transform:uppercase;letter-spacing:.06em; }
[data-testid="stMetricValue"]{ color:#e2e8f0!important;font-weight:700!important;font-size:1.5rem!important; }

/* Progress */
.stProgress>div>div{ background:#3b82f6!important; }

/* Hide form container border/background */
[data-testid="stForm"]{ background:transparent!important;border:none!important;padding:0!important; }

/* Tabs */
.stTabs [data-baseweb="tab-list"]{ background:#0f2236!important;border-radius:10px;padding:4px;border:1px solid #1e3a5f; }
.stTabs [data-baseweb="tab"]{ color:#7fa8c9!important;border-radius:7px!important;font-weight:500; }
.stTabs [aria-selected="true"]{ background:#1d4ed8!important;color:#fff!important; }
.stTabs [data-baseweb="tab-panel"]{ padding-top:1rem!important; }

/* Expander */
.streamlit-expanderHeader{ background:#0f2236!important;border:1px solid #1e3a5f!important;border-radius:8px!important;color:#94a3b8!important; }
.streamlit-expanderContent{ background:#0a1628!important;border:1px solid #1e3a5f!important;border-top:none!important; }

#MainMenu,footer{ visibility:hidden; }
header[data-testid="stHeader"]{ background:transparent; }
[data-testid="stToolbar"]{ display:none!important; }
.stDeployButton{ display:none!important; }
button[kind="header"]{ display:none!important; }

/* ── Custom components ── */
.result-banner{ border-radius:12px;padding:1.2rem 1.8rem;margin:1rem 0;display:flex;align-items:center;gap:1rem;font-weight:700;font-size:1.05rem; }
.banner-CRITICAL{ background:linear-gradient(135deg,rgba(239,68,68,.12),rgba(239,68,68,.04));border:1px solid rgba(239,68,68,.35);color:#ef4444; }
.banner-HIGH    { background:linear-gradient(135deg,rgba(245,158,11,.12),rgba(245,158,11,.04));border:1px solid rgba(245,158,11,.35);color:#f59e0b; }
.banner-MEDIUM  { background:linear-gradient(135deg,rgba(234,179,8,.1),rgba(234,179,8,.04)); border:1px solid rgba(234,179,8,.35); color:#eab308; }
.banner-LOW     { background:linear-gradient(135deg,rgba(34,197,94,.1),rgba(34,197,94,.04)); border:1px solid rgba(34,197,94,.35); color:#22c55e; }
.banner-SAFE    { background:linear-gradient(135deg,rgba(34,197,94,.1),rgba(34,197,94,.04)); border:1px solid rgba(34,197,94,.35); color:#22c55e; }

.info-card{ background:#0f2236;border:1px solid #1e3a5f;border-radius:12px;padding:1.2rem 1.5rem;margin:4px 0;transition:border-color .2s; }
.info-card:hover{ border-color:#3b82f6; }
.stack-card{ background:#0f2236;border:1px solid #1e3a5f;border-radius:12px;padding:1.3rem 1.5rem; }
.stack-card .lbl{ font-size:.7rem;color:#7fa8c9;text-transform:uppercase;letter-spacing:.1em;margin-bottom:.35rem; }
.stack-card .val{ font-size:1.05rem;font-weight:700;color:#e2e8f0; }

.step-card{ background:#0f2236;border:1px solid #1e3a5f;border-radius:12px;padding:1.5rem;margin-bottom:1rem; }
.step-title{ font-size:1rem;font-weight:700;color:#e2e8f0;margin-bottom:.2rem; }
.step-sub{ font-size:.82rem;color:#7fa8c9;margin-bottom:1rem; }

.rule-item{ display:flex;align-items:center;gap:10px;padding:.48rem 1rem;margin:3px 0;background:#0f2236;border-radius:8px;border-left:3px solid #1e3a5f; }
.rule-item.CRITICAL{ border-left-color:#ef4444; }
.rule-item.HIGH    { border-left-color:#f59e0b; }
.rule-item.MEDIUM  { border-left-color:#eab308; }
.rule-item.LOW     { border-left-color:#22c55e; }
.r-id  { font-family:'JetBrains Mono',monospace;color:#60a5fa;font-size:.8rem;font-weight:600;min-width:40px; }
.r-desc{ flex:1;color:#94a3b8;font-size:.84rem; }
.r-sev { font-family:'JetBrains Mono',monospace;font-weight:700;font-size:.75rem;white-space:nowrap; }

.score-row{ display:flex;align-items:center;gap:1rem;padding:.65rem 1rem;background:#0f2236;border-radius:8px;margin:3px 0;border:1px solid #1e3a5f; }
.s-lbl{ min-width:145px;font-weight:600;font-size:.85rem;color:#94a3b8; }
.s-pill{ padding:3px 10px;border-radius:6px;font-weight:700;font-size:.75rem;min-width:100px;text-align:center;font-family:'JetBrains Mono',monospace; }

.rec-s{ background:#0f2236;border:1px solid #1e3a5f;border-left:3px solid #3b82f6;border-radius:8px;padding:.65rem 1.1rem;margin:3px 0;font-size:.85rem;color:#94a3b8;position:relative;padding-left:1.6rem; }
.rec-s::before{ content:"";position:absolute;left:.75rem;top:50%;transform:translateY(-50%);width:6px;height:6px;background:#3b82f6;border-radius:50%; }
.rec-g{ background:#0a1628;border:1px solid #1e2d3d;border-left:3px solid #1e3a5f;border-radius:8px;padding:.65rem 1.1rem;margin:3px 0;font-size:.85rem;color:#7fa8c9;position:relative;padding-left:1.6rem; }
.rec-g::before{ content:"";position:absolute;left:.75rem;top:50%;transform:translateY(-50%);width:6px;height:6px;background:#1e3a5f;border-radius:50%; }

.disclaimer{ background:rgba(59,130,246,.08);border:1px solid rgba(59,130,246,.22);border-radius:10px;padding:.9rem 1.3rem;color:#7fa8c9;font-size:.83rem;margin:1rem 0; }

.sec-lbl{ font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.14em;color:#3b82f6;margin:1.5rem 0 .6rem 0;padding-bottom:.35rem;border-bottom:1px solid #1e3a5f; }

.mono-rpt{ font-family:'JetBrains Mono',monospace;font-size:.78rem;background:#0a1628;border:1px solid #1e3a5f;border-radius:10px;padding:1.3rem;white-space:pre-wrap;color:#94a3b8;max-height:500px;overflow-y:auto;line-height:1.7; }

.kb-row{ display:flex;gap:.8rem;padding:.42rem .9rem;border-bottom:1px solid rgba(30,58,95,.4);font-size:.82rem; }
.kb-row:hover{ background:#0f2236; }

.sb-logo{ background:linear-gradient(135deg,#1d4ed8,#1e3a8a);border-radius:10px;padding:1rem 1.2rem;margin-bottom:1rem;text-align:center; }
.sb-title{ font-size:1.05rem;font-weight:800;color:#fff;letter-spacing:.02em; }
.sb-sub  { font-size:.7rem;color:rgba(255,255,255,.55);margin-top:3px; }

.pass-lbl{ color:#22c55e;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:.8rem; }
.fail-lbl{ color:#ef4444;font-weight:700;font-family:'JetBrains Mono',monospace;font-size:.8rem; }
</style>
""", unsafe_allow_html=True)

# ── Session state ────────────────────────────────────────────
for k,v in {"page":"Dashboard","msg_step":1,"hyg_step":1,"hyg_data":{},
            "last_triggered":[],"last_scores":{},"last_cf":{},
            "last_explanation":{},"last_recs":{},"last_source":"","last_facts":{},
            "accumulated_facts":{}}.items():
    if k not in st.session_state: st.session_state[k]=v

# ── Constants ────────────────────────────────────────────────
SC = {"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}

def run_analysis(facts, source):
    t = run_inference(facts)
    s = build_score_report(t)
    # Accumulate facts across all analyses in the session
    st.session_state["accumulated_facts"].update(facts)
    st.session_state.update({
        "last_triggered":t,"last_scores":s,"last_cf":build_cf_report(t),
        "last_explanation":generate_explanation(t,s),"last_recs":get_recommendations(t),
        "last_source":source,"last_facts":facts,
    })
    st.session_state.page="Results"; st.rerun()

def sec(t): st.markdown(f'<div class="sec-lbl">{t}</div>',unsafe_allow_html=True)

def rbanner(label,score,source=""):
    icons={"CRITICAL":"[CRITICAL]","HIGH":"[HIGH]","MEDIUM":"[MEDIUM]","LOW":"[LOW]","SAFE":"[SAFE]"}
    s2=f" &nbsp;·&nbsp; <span style='font-weight:400;font-size:.85rem;color:#94a3b8'>{source}</span>" if source else ""
    st.markdown(f'<div class="result-banner banner-{label}"><span style="font-family:JetBrains Mono,monospace">{icons.get(label,label)}</span><div><div>{label} THREAT LEVEL</div><div style="font-weight:400;font-size:.83rem;margin-top:2px">Threat Score: {score:.0f}%{s2}</div></div></div>',unsafe_allow_html=True)

def srow(name,label,score):
    c=SC.get(label,"#7fa8c9")
    st.markdown(f'<div class="score-row"><span class="s-lbl">{name}</span><div style="flex:1;background:#1e3a5f;border-radius:5px;height:9px;overflow:hidden"><div style="width:{score:.0f}%;height:100%;background:{c};border-radius:5px;transition:width .5s"></div></div><span class="s-pill" style="background:{c}18;color:{c};border:1px solid {c}33">{label} &nbsp; {score:.0f}%</span></div>',unsafe_allow_html=True)

def rcard(rule,show_cond=False,facts=None):
    c=SC.get(rule["severity"],"#7fa8c9")
    st.markdown(f'<div class="rule-item {rule["severity"]}"><span class="r-id">{rule["id"]}</span><span class="r-desc">{rule["desc"]}</span><span class="r-sev" style="color:{c}">{rule["severity"]} {rule["confidence"]}%</span></div>',unsafe_allow_html=True)
    if show_cond and facts:
        html="".join(f'<span style="font-family:JetBrains Mono,monospace;font-size:.72rem;color:{"#22c55e" if facts.get(cond) else "#ef4444"};margin-right:.9rem">{"+" if facts.get(cond) else "-"} {cond}</span>' for cond in rule["conditions"])
        st.markdown(f'<div style="padding:.2rem 1rem .45rem 3.5rem">{html}</div>',unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sb-logo"><div class="sb-title">CyberGuard Advisor</div><div class="sb-sub">Rule-Based Expert System</div></div>',unsafe_allow_html=True)
    PAGES=["Dashboard","Password Analyzer","URL Scanner","Message Detector",
           "Cyber Hygiene","Results","Recommendations","Explanation Engine",
           "Knowledge Base","Test Scenarios"]
    LABELS=["  Dashboard","  Password Analyzer","  URL Scanner","  Message Detector",
            "  Cyber Hygiene","  Threat Results","  Recommendations","  Explanation Engine",
            "  Knowledge Base","  Test Scenarios"]
    cur=PAGES.index(st.session_state.page) if st.session_state.page in PAGES else 0
    sel=st.radio("nav",LABELS,index=cur,label_visibility="collapsed")
    st.session_state.page=PAGES[LABELS.index(sel)]
    if st.session_state.last_scores:
        st.markdown("---")
        ov=st.session_state.last_scores.get("overall",{})
        lbl=ov.get("label","SAFE"); sc=ov.get("score",0); c=SC.get(lbl,"#7fa8c9")
        st.markdown(f'<div style="background:#0f2236;border:1px solid #1e3a5f;border-radius:8px;padding:.8rem 1rem"><div style="font-size:.67rem;color:#7fa8c9;text-transform:uppercase;letter-spacing:.08em;margin-bottom:.3rem">Last Analysis</div><div style="color:{c};font-weight:700;font-size:.95rem">{lbl}</div><div style="color:#7fa8c9;font-size:.73rem;margin-top:2px">{sc:.0f}% &nbsp;·&nbsp; {len(st.session_state.last_triggered)} rules fired</div></div>',unsafe_allow_html=True)
    st.markdown('<div style="position:fixed;bottom:.8rem;left:1rem;color:#1e3a5f;font-size:.68rem">BS-CS AI Project · 2026</div>',unsafe_allow_html=True)

page=st.session_state.page

# ════════════════════════════════════════════════════════════
# DASHBOARD
# ════════════════════════════════════════════════════════════
if page=="Dashboard":
    if HERO_IMG:
        st.markdown(f'<div style="border-radius:14px;overflow:hidden;margin-bottom:.5rem;max-height:360px"><img src="data:image/jpeg;base64,{HERO_IMG}" style="width:100%;object-fit:cover;object-position:center 35%;max-height:360px;display:block"></div>',unsafe_allow_html=True)
    st.markdown('<div style="padding:1.2rem 0 .4rem 0"><h1 style="font-size:1.9rem;font-weight:800;color:#e2e8f0;margin:0">CyberGuard Advisor</h1><p style="color:#7fa8c9;font-size:.9rem;margin:.3rem 0 0 0">A rule-based cybersecurity expert system using forward chaining inference, MYCIN certainty factors, and explainable decision support.</p></div>',unsafe_allow_html=True)


    sec("SYSTEM OVERVIEW")
    c1,c2,c3,c4=st.columns(4)
    for col,lbl,val in [(c1,"Knowledge Base","80 Rules"),(c2,"Inference Engine","Forward Chaining"),(c3,"Reasoning Type","Explainable"),(c4,"Advanced Feature","Certainty Factor")]:
        with col: st.markdown(f'<div class="stack-card"><div class="lbl">{lbl}</div><div class="val">{val}</div></div>',unsafe_allow_html=True)

    sec("PROJECT STACK")
    p1,p2,p3,p4=st.columns(4)
    for col,lbl,val in [(p1,"Language","Python"),(p2,"Interface","Streamlit"),(p3,"IDE","PyCharm"),(p4,"Chaining","Forward + Backward")]:
        with col: st.markdown(f'<div class="stack-card"><div class="lbl">{lbl}</div><div class="val">{val}</div></div>',unsafe_allow_html=True)

    sec("DOMAIN COVERAGE")
    d1,d2,d3,d4,d5=st.columns(5)
    for col,name,rng,cnt in [(d1,"Password Security","R01-R18","18 rules"),(d2,"URL Safety","R19-R34","15 rules"),(d3,"Phishing Detection","R35-R50","15 rules"),(d4,"Scam Detection","R51-R66","14 rules"),(d5,"Cyber Hygiene","R67-R80","10 rules")]:
        with col:
            st.markdown(f'<div class="info-card" style="text-align:center"><div style="font-weight:700;font-size:.9rem;color:#e2e8f0;margin-bottom:.3rem">{name}</div><div style="font-family:JetBrains Mono,monospace;color:#3b82f6;font-size:.75rem">{rng}</div><div style="color:#7fa8c9;font-size:.76rem">{cnt}</div></div>',unsafe_allow_html=True)



# ════════════════════════════════════════════════════════════
# PASSWORD ANALYZER
# ════════════════════════════════════════════════════════════
elif page=="Password Analyzer":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Password Analyzer</h2><p style="color:#7fa8c9;font-size:.88rem">Evaluates password strength using 18 expert rules with certainty factor scoring.</p>',unsafe_allow_html=True)

    st.markdown('<div style="background:#0f2236;border:1px solid #1e3a5f;border-radius:10px;padding:1rem 1.4rem;margin-bottom:1rem"><div style="font-size:.82rem;color:#7fa8c9">The expert system evaluates 18 rules including length, complexity, keyboard patterns, and known compromised password lists.</div></div>',unsafe_allow_html=True)

    # Quick examples
    sec("QUICK TEST CASES")
    st.markdown('<div style="color:#7fa8c9;font-size:.78rem;margin-bottom:.5rem">Select an example to test the system.</div>',unsafe_allow_html=True)
    e1,e2,e3,e4=st.columns(4)
    for col,ex,lbl in [(e1,"123456","Very Weak"),(e2,"Hello2024","Moderate"),(e3,"qwerty","Keyboard Pattern"),(e4,"P@ssw0rd!XY99#","Strong")]:
        with col:
            if st.button(lbl,use_container_width=True,key=f"pe_{lbl}"):
                st.session_state["_pex"]=ex; st.rerun()

    # Password input form
    prefill=st.session_state.pop("_pex","")
    with st.form(key="pwd_form",clear_on_submit=False):
        c1f,c2f=st.columns([3,1])
        with c1f:
            username=st.text_input("Username or Email (optional)",placeholder="e.g. john@example.com",key="uname_f")
            pwd=st.text_input("Password",value=prefill,placeholder="Enter password to analyse",type="password",key="pwd_f")
        with c2f:
            st.markdown("<br>",unsafe_allow_html=True)
            show_pw=st.checkbox("Show as text",key="show_pw_f")
        if pwd:
            has_u=any(c.isupper() for c in pwd); has_d=any(c.isdigit() for c in pwd)
            has_s=any(c in "!@#$%^&*()_+-=[]{}|;:',.<>?/`~" for c in pwd)
            sv=min(len(pwd)/16,.9)*0.8+sum([has_u,has_d,has_s])*0.067; sv=min(sv,1.0)
            lt,lc=(("VERY STRONG","#22c55e") if sv>=.85 else ("STRONG","#22c55e") if sv>=.65 else ("MODERATE","#eab308") if sv>=.45 else ("WEAK","#f59e0b") if sv>=.25 else ("VERY WEAK","#ef4444"))
            st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-weight:700;font-size:.82rem;color:{lc};margin:.4rem 0">STRENGTH: {lt}</div>',unsafe_allow_html=True)
            st.progress(sv)
            m1,m2,m3,m4=st.columns(4)
            with m1: st.metric("Length",len(pwd))
            with m2: st.metric("Uppercase","Yes" if has_u else "No")
            with m3: st.metric("Digits","Yes" if has_d else "No")
            with m4: st.metric("Specials","Yes" if has_s else "No")
            if show_pw: st.code(pwd,language=None)
        submitted_pwd=st.form_submit_button("Run Password Analysis",use_container_width=True)
    if submitted_pwd:
        if not pwd: st.warning("Please enter a password.")
        else:
            st.session_state.last_scores={}
            run_analysis(extract_password_facts(pwd,username),"Password Analysis")

    # Show last result with direct link
    if st.session_state.last_scores and "Password" in st.session_state.get("last_source",""):
        ov=st.session_state.last_scores.get("overall",{})
        lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
        c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
        st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem;display:flex;align-items:center;gap:1.5rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
        if st.button("View Threat Results",key="view_res_pwd",use_container_width=False):
            st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# URL SCANNER
# ════════════════════════════════════════════════════════════
elif page=="URL Scanner":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">URL Scanner</h2><p style="color:#7fa8c9;font-size:.88rem">Detects phishing URLs, typosquatting, IP masking, and suspicious domain patterns using 15 rules.</p>',unsafe_allow_html=True)
    st.markdown('<div style="background:#0f2236;border:1px solid #1e3a5f;border-radius:10px;padding:1rem 1.4rem;margin-bottom:1rem"><div style="font-size:.82rem;color:#7fa8c9;margin-bottom:.7rem">Enter the full URL including protocol (http:// or https://). The system checks 15 rules for phishing indicators, suspicious domains, IP masking, and encoding tricks.</div></div>',unsafe_allow_html=True)
    url=st.text_input("URL",placeholder="https://www.example.com",label_visibility="collapsed")

    if st.session_state.last_scores and "URL" in st.session_state.last_source:
        ov=st.session_state.last_scores.get("overall",{})
        c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(ov.get("label","SAFE"),"#7fa8c9")
        st.markdown(f'<div style="background:{c}18;border:1px solid {c}44;border-radius:8px;padding:.7rem 1.2rem;margin:.5rem 0"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace">Last result: {ov.get("label","")} {ov.get("score",0):.0f}%</span></div>',unsafe_allow_html=True)
        if st.button("View Last Threat Results",use_container_width=False,key="view_results_url"):
            st.session_state.page="Results"; st.rerun()

    sec("QUICK TEST CASES")
    u1,u2,u3,u4=st.columns(4)
    for col,ex,lbl in [(u1,"https://www.google.com","Safe URL"),(u2,"http://paypa1-login.xyz/verify","Typosquatting"),(u3,"http://192.168.1.1/paypal/login","IP Address"),(u4,"http://trusted.com@evil.com/path","@ Symbol Trick")]:
        with col:
            if st.button(lbl,use_container_width=True,key=f"ue_{lbl}"):
                st.session_state["_uex"]=ex; st.rerun()
    if "_uex" in st.session_state:
        url=st.session_state["_uex"]; st.code(url,language=None)

    st.markdown("<br>",unsafe_allow_html=True)
    if st.button("Scan URL",use_container_width=True,key="url_go"):
        tgt=url or st.session_state.get("_uex","")
        if not tgt: st.warning("Please enter a URL.")
        else:
            st.session_state.last_scores={}
            run_analysis(extract_url_facts(tgt),f"URL: {tgt[:55]}{'...' if len(tgt)>55 else ''}")

    if st.session_state.last_scores and "URL" in st.session_state.get("last_source",""):
        ov=st.session_state.last_scores.get("overall",{})
        lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
        c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
        st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
        if st.button("View Threat Results",key="view_res_url"):
            st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# MESSAGE DETECTOR  — 2-step
# ════════════════════════════════════════════════════════════
elif page=="Message Detector":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Message Detector</h2><p style="color:#7fa8c9;font-size:.88rem">Detects phishing, scam messages, and social engineering using 29 rules across 2 domains.</p>',unsafe_allow_html=True)
    step=st.session_state.get("msg_step",1)
    st.markdown(f'<div style="font-size:.8rem;color:#7fa8c9;margin:1rem 0 .4rem 0">Step {step} of 2: {"Message Type" if step==1 else "Message Content"}</div>',unsafe_allow_html=True)
    st.progress(step/2)

    SAMPLES={"OTP Phishing":"Dear Customer, Your account has been suspended. Please verify your OTP immediately to avoid account closure. Click: http://bit.ly/verify",
             "Prize Scam":"CONGRATULATIONS! You have won Rs.50,00,000 cash prize! Send Rs.500 processing fee via Easypaisa to claim today only!",
             "Nigerian Prince":"Dear Friend, I am Prince Emmanuel of Nigeria. I have $45 million to transfer. Please send advance fee of $500 via Western Union.",
             "Investment Fraud":"Earn 100% profit guaranteed! Double your money in 7 days with our crypto investment. Risk free, respond within 24 hours!",
             "Legitimate Email":"Hi John, the meeting is confirmed for Monday at 10 AM. Please review the attached agenda. Best regards, Sarah."}

    if step==1:
        st.markdown('<div class="step-card"><div class="step-title">Select Message Type</div><div class="step-sub">What type of message do you want to analyse?</div>',unsafe_allow_html=True)
        st.selectbox("Message Type",["Email","SMS / WhatsApp","Chat Message","Other"],label_visibility="collapsed",key="_mtype")
        st.markdown('</div>',unsafe_allow_html=True)
        sec("LOAD SAMPLE MESSAGE")
        cols=st.columns(5)
        for col,(lbl,txt) in zip(cols,SAMPLES.items()):
            with col:
                if st.button(lbl,use_container_width=True,key=f"ms_{lbl}"):
                    st.session_state["_msample"]=txt; st.session_state["msg_step"]=2; st.rerun()
        if st.button("Next: Enter Message",use_container_width=True):
            st.session_state["msg_step"]=2; st.rerun()
    else:
        st.markdown('<div class="step-card"><div class="step-title">Paste Message Content</div><div class="step-sub">Enter the complete message text to be analysed by the expert system.</div>',unsafe_allow_html=True)
        msg=st.text_area("Message",value=st.session_state.get("_msample",""),height=140,placeholder="Paste full message text here...",label_visibility="collapsed")
        st.markdown('</div>',unsafe_allow_html=True)
        b1,b2=st.columns([1,4])
        with b1:
            if st.button("Back",key="mb"): st.session_state["msg_step"]=1; st.session_state["_msample"]=""; st.rerun()
        with b2:
            if st.button("Analyse Message",use_container_width=True,key="mg"):
                if not msg.strip(): st.warning("Please paste a message.")
                else:
                    st.session_state.last_scores={}
                    run_analysis({**extract_message_facts(msg),**extract_scam_facts(msg)},"Message Analysis")

        if st.session_state.last_scores and "Message" in st.session_state.get("last_source",""):
            ov=st.session_state.last_scores.get("overall",{})
            lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
            c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
            st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
            if st.button("View Threat Results",key="view_res_msg"):
                st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# CYBER HYGIENE  — 3-step, statement-style Yes/No dropdowns
# ════════════════════════════════════════════════════════════
elif page=="Cyber Hygiene":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Cyber Hygiene Assessment</h2><p style="color:#7fa8c9;font-size:.88rem">Evaluates your cybersecurity habits using 10 expert rules. Answer each statement honestly.</p>',unsafe_allow_html=True)
    hs=st.session_state.get("hyg_step",1)
    steps_h=["Password & Account Security","Device & Network Security","Online Behaviour"]
    st.markdown(f'<div style="font-size:.8rem;color:#7fa8c9;margin:1rem 0 .4rem 0">Step {hs} of {len(steps_h)}: {steps_h[hs-1]}</div>',unsafe_allow_html=True)
    st.progress(hs/len(steps_h))
    d=st.session_state.get("hyg_data",{})

    YN  = ["No","Yes"]
    FRQ = ["Never","Rarely","Sometimes","Often","Always"]

    def yn_box(label, key, default="No"):
        stored = d.get(key, default)
        idx = YN.index(stored) if stored in YN else YN.index(default)
        return st.selectbox(label, YN, index=idx, key=f"hq_{key}")

    def frq_box(label, key, default="Never"):
        stored = d.get(key, default)
        val = stored if stored in FRQ else default
        return st.select_slider(label, options=FRQ, value=val, key=f"hq_{key}")

    if hs==1:
        st.markdown('<div class="step-card"><div class="step-title">Password & Account Security</div><div class="step-sub">Select the option that best describes your current practice.</div>',unsafe_allow_html=True)
        c1,c2 = st.columns(2)
        with c1:
            r1 = frq_box("I use the same password for different accounts","pw_reuse","Never")
            r2 = yn_box("I do not use two-factor authentication (2FA) on my accounts","no_2fa","No")
        with c2:
            r3 = frq_box("I share my passwords with friends, family, or colleagues","pw_share","Never")
            r4 = yn_box("My passwords are short (less than 8 characters)","short_pwd","No")
        st.markdown('</div>',unsafe_allow_html=True)

        d["pw_reuse"]=r1; d["no_2fa_val"]=r2; d["pw_share"]=r3; d["short_pwd_val"]=r4
        d["password_reuse"]   = r1 in ["Often","Always"]
        d["no_2fa"]           = r2 == "Yes"
        d["shares_passwords"] = r3 in ["Often","Always"]
        st.session_state["hyg_data"]=d
        if st.button("Next: Device & Network Security",use_container_width=True,key="hn1"):
            st.session_state["hyg_step"]=2; st.rerun()

    elif hs==2:
        st.markdown('<div class="step-card"><div class="step-title">Device & Network Security</div><div class="step-sub">Select the option that best describes your current practice.</div>',unsafe_allow_html=True)
        c1,c2 = st.columns(2)
        with c1:
            r5 = yn_box("I do not have antivirus or security software installed","no_av","No")
            r6 = yn_box("I rarely or never update my OS or applications","no_upd","No")
        with c2:
            r7 = frq_box("I connect to public Wi-Fi without using a VPN","pub_wifi","Never")
            r8 = yn_box("I use the same Wi-Fi password for years without changing","old_wifi","No")
        st.markdown('</div>',unsafe_allow_html=True)

        d["no_av_val"]=r5; d["no_upd_val"]=r6; d["pub_wifi"]=r7; d["old_wifi_val"]=r8
        d["no_antivirus"] = r5 == "Yes"
        d["no_updates"]   = r6 == "Yes"
        d["public_wifi"]  = r7 in ["Often","Always"]
        st.session_state["hyg_data"]=d
        b1,b2=st.columns([1,4])
        with b1:
            if st.button("Back",key="hb1"): st.session_state["hyg_step"]=1; st.rerun()
        with b2:
            if st.button("Next: Online Behaviour",use_container_width=True,key="hn2"):
                st.session_state["hyg_step"]=3; st.rerun()

    else:
        st.markdown('<div class="step-card"><div class="step-title">Online Behaviour</div><div class="step-sub">Select the option that best describes your current practice.</div>',unsafe_allow_html=True)
        c1,c2 = st.columns(2)
        with c1:
            r9  = yn_box("I open email attachments from unknown or unverified senders","open_att","No")
            r10 = yn_box("I click on links in emails without checking the sender","click_links","No")
        with c2:
            r11 = frq_box("I download software or apps from unofficial sources","dl_unoff","Never")
            r12 = yn_box("I ignore browser security warnings when visiting websites","ignore_warn","No")
        st.markdown('</div>',unsafe_allow_html=True)

        d["open_att_val"]=r9; d["click_links_val"]=r10; d["dl_unoff"]=r11; d["ignore_warn_val"]=r12
        d["opens_attachments"] = r9 == "Yes"
        st.session_state["hyg_data"]=d

        risks = sum([
            d.get("password_reuse",False), d.get("shares_passwords",False),
            d.get("no_2fa",False),         d.get("no_updates",False),
            d.get("no_antivirus",False),   d.get("public_wifi",False),
            d.get("opens_attachments",False),
        ])
        if risks > 0:
            st.markdown(f'<div style="background:rgba(245,158,11,.08);border:1px solid rgba(245,158,11,.25);border-radius:8px;padding:.7rem 1rem;color:#f59e0b;font-size:.84rem;margin:.5rem 0">{risks} risk factor(s) identified — run assessment to see detailed analysis</div>',unsafe_allow_html=True)

        b1,b2=st.columns([1,4])
        with b1:
            if st.button("Back",key="hb2"): st.session_state["hyg_step"]=2; st.rerun()
        with b2:
            if st.button("Run Assessment",use_container_width=True,key="hgo"):
                st.session_state.last_scores={}
                run_analysis(extract_hygiene_facts(st.session_state["hyg_data"]),"Cyber Hygiene Assessment")
                st.session_state["hyg_step"]=1

        if st.session_state.last_scores and "Hygiene" in st.session_state.get("last_source",""):
            ov=st.session_state.last_scores.get("overall",{})
            lbl=ov.get("label","SAFE"); sc2=ov.get("score",0)
            c={"CRITICAL":"#ef4444","HIGH":"#f59e0b","MEDIUM":"#eab308","LOW":"#22c55e","SAFE":"#22c55e"}.get(lbl,"#7fa8c9")
            st.markdown(f'<div style="background:{c}15;border:1px solid {c}40;border-radius:8px;padding:.65rem 1.2rem;margin-top:.8rem"><span style="color:{c};font-weight:700;font-family:JetBrains Mono,monospace;font-size:.85rem">Last Analysis: {lbl} — {sc2:.0f}% threat score</span></div>',unsafe_allow_html=True)
            if st.button("View Threat Results",key="view_res_hyg"):
                st.session_state.page="Results"; st.rerun()

# ════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════
elif page=="Results":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Threat Results</h2>',unsafe_allow_html=True)
    if not st.session_state.last_scores:
        st.info("No analysis run yet. Use any module from the sidebar.")
    else:
        sc=st.session_state.last_scores; cf=st.session_state.last_cf
        tr=st.session_state.last_triggered; src=st.session_state.last_source
        ov=sc.get("overall",{"score":0,"label":"SAFE"}); cfo=cf.get("overall",{"cf_score":0,"label":"SAFE"})
        rbanner(ov["label"],ov["score"],src)
        m1,m2,m3,m4,m5=st.columns(5)
        with m1: st.metric("Threat Level",ov["label"])
        with m2: st.metric("Threat Score",f"{ov['score']:.0f}%")
        with m3: st.metric("CF Score",f"{cfo['cf_score']:.0f}%")
        with m4: st.metric("Rules Fired",len(tr))
        with m5: st.metric("Critical Rules",sum(1 for r in tr if r["severity"]=="CRITICAL"))
        page_map={"Password Analysis":"Password Analyzer","URL":"URL Scanner","Message":"Message Detector","Cyber Hygiene":"Cyber Hygiene"}
        back_page=next((v for k,v in page_map.items() if k in src),"Password Analyzer")
        ba,bb=st.columns([1,5])
        with ba:
            if st.button("Run New Analysis",key="new_ana",use_container_width=True):
                st.session_state.last_scores={}; st.session_state.last_triggered=[]
                st.session_state.last_explanation={}; st.session_state.last_recs={}
                st.session_state.page=back_page; st.rerun()

        t1,t2=st.tabs(["Score Breakdown","Triggered Rules"])
        with t1:
            sec("CATEGORY THREAT SCORES")
            cats=[("password","Password"),("url","URL"),("phishing","Phishing"),("scam","Scam"),("hygiene","Hygiene")]
            shown=False
            for k,n in cats:
                s=sc.get(k,{"score":0,"label":"SAFE"})
                if s["score"]>0: srow(n,s["label"],s["score"]); shown=True
            if not shown: st.markdown('<div style="color:#22c55e;padding:.8rem;font-size:.88rem">All categories: No threats detected</div>',unsafe_allow_html=True)

            sec("CERTAINTY FACTOR SCORES — MYCIN CF Algebra")
            st.markdown('<div style="color:#7fa8c9;font-size:.78rem;margin-bottom:.5rem">CF scores are combined using MYCIN algebra: CF(A,B) = CF(A) + CF(B)×(1-CF(A)). This prevents dilution of CRITICAL findings by lower-severity rules.</div>',unsafe_allow_html=True)
            for k,n in cats:
                s=cf.get(k,{"cf_score":0,"label":"SAFE"})
                if s["cf_score"]>0: srow(f"{n} (CF)",s["label"],s["cf_score"])

            sec("CONFLICT RESOLUTION")
            st.markdown('<div style="color:#7fa8c9;font-size:.78rem;margin-bottom:.5rem">When multiple rules fire in the same domain, the highest-severity rule takes precedence: CRITICAL > HIGH > MEDIUM > LOW.</div>',unsafe_allow_html=True)
            res=resolve_conflicts(tr)
            if res:
                for cat,rule in res.items():
                    c=SC.get(rule["severity"],"#7fa8c9")
                    st.markdown(f'<div class="info-card" style="border-left:3px solid {c}"><span style="color:#7fa8c9;font-size:.77rem">{cat.upper()}: </span><span style="color:#60a5fa;font-family:JetBrains Mono,monospace;font-weight:600">{rule["id"]}</span><span style="color:#94a3b8;font-size:.83rem"> — {rule["desc"]}</span><span style="float:right;color:{c};font-weight:700;font-size:.77rem;font-family:JetBrains Mono,monospace">{rule["severity"]}</span></div>',unsafe_allow_html=True)
        with t2:
            sec(f"ALL TRIGGERED RULES  ({len(tr)} fired)")
            if tr:
                for rule in tr: rcard(rule)
            else:
                st.markdown('<div style="color:#22c55e;padding:.8rem;font-size:.88rem">No rules triggered — no threats found.</div>',unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════
# RECOMMENDATIONS
# ════════════════════════════════════════════════════════════
elif page=="Recommendations":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Recommendations</h2><p style="color:#7fa8c9;font-size:.88rem">Actionable security guidance generated from triggered rules.</p>',unsafe_allow_html=True)
    if not st.session_state.last_recs:
        st.info("Run an analysis first.")
    else:
        r=st.session_state.last_recs
        if r.get("specific"):
            sec(f"SPECIFIC RECOMMENDATIONS  ({len(r['specific'])} items)")
            for x in r["specific"]: st.markdown(f'<div class="rec-s">{x.strip()}</div>',unsafe_allow_html=True)
        sec("GENERAL SECURITY GUIDELINES")
        for x in r.get("general",[]): st.markdown(f'<div class="rec-g">{x.strip()}</div>',unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════
# EXPLANATION ENGINE
# ════════════════════════════════════════════════════════════
elif page=="Explanation Engine":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Explanation Engine</h2><p style="color:#7fa8c9;font-size:.88rem">Full reasoning trace — which rules fired, why conditions were true, and backward chaining verification.</p>',unsafe_allow_html=True)
    if not st.session_state.last_explanation:
        st.info("Run an analysis first.")
    else:
        exp=st.session_state.last_explanation; sc=st.session_state.last_scores; facts=st.session_state.last_facts
        rbanner(exp.get("overall_label","SAFE"),exp.get("overall_score",0))
        t1,t2,t3=st.tabs(["Forward Chaining Trace","Backward Chaining","Full Report"])

        with t1:
            sec("FORWARD CHAINING — HOW INFERENCE WORKS")
            st.markdown('<div style="color:#7fa8c9;font-size:.82rem;margin-bottom:.8rem">The inference engine iterates all 80 rules. Each rule fires if and only if ALL its conditions are TRUE in the current fact base (AND logic). Fired rules add conclusions to working memory. This continues until no more rules fire (fixed-point).</div>',unsafe_allow_html=True)
            for cat,info in exp.get("by_category",{}).items():
                with st.expander(f"{info['label']}  —  {info['level']}  ({info['score']:.0f}%)"):
                    st.markdown(f'<div style="color:#94a3b8;font-size:.84rem;line-height:1.7;margin-bottom:.7rem">{info["narrative"]}</div>',unsafe_allow_html=True)
                    sec("FIRED RULES — CONDITION TRUTH VALUES")
                    for rule in info.get("rules",[]):
                        rcard(rule,show_cond=True,facts=facts)

        with t2:
            sec("BACKWARD CHAINING — GOAL-DRIVEN PROOF")
            st.markdown('<div style="color:#7fa8c9;font-size:.82rem;margin-bottom:.8rem">Backward chaining starts from a goal hypothesis and works backwards to find supporting rules and evidence. This is the goal-driven complement to forward chaining.</div>',unsafe_allow_html=True)
            # Check if multiple domains have been analysed
            acc_facts = st.session_state.get("accumulated_facts", {})
            if len(acc_facts) > len(facts):
                st.markdown('<div style="background:#1e3a5f22;border:1px solid #1e3a5f;border-radius:8px;padding:.65rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:#7fa8c9">Backward chaining uses <b style="color:#22c55e">all analyses from this session</b> (Password, URL, Message, and Hygiene facts are combined). You can verify goals across any domain you have analysed.</div>',unsafe_allow_html=True)
            else:
                st.markdown('<div style="background:#1e3a5f22;border:1px solid #1e3a5f;border-radius:8px;padding:.65rem 1rem;margin-bottom:.8rem;font-size:.8rem;color:#7fa8c9">Backward chaining uses the fact base from all analyses run in this session. For richer results, run multiple analysers (Password, URL, Message, Hygiene) before verifying goals here.</div>',unsafe_allow_html=True)
            # Auto-select domain based on last analysis
            src=st.session_state.get("last_source","")
            domain_hint=("password" if "Password" in src else "url" if "URL" in src else "phishing" if "Message" in src else "hygiene" if "Hygiene" in src else "password")
            dom_options=["password","url","phishing","scam","hygiene"]
            dom=st.selectbox("Select domain to verify",dom_options,index=dom_options.index(domain_hint))
            if st.button("Run Backward Chaining",key="bcb"):
                # Use accumulated facts so all prior analyses are included
                bc_facts = st.session_state.get("accumulated_facts", facts)
                bc=run_backward_chaining(bc_facts,dom)
                proved=bc.get(dom,[])
                if proved:
                    for pg in proved:
                        c=SC.get("HIGH","#f59e0b")
                        st.markdown(f'<div class="info-card" style="border-left:3px solid {c}"><b style="color:#e2e8f0">Goal proved:</b> <code style="color:#60a5fa">{pg["goal"]}</code> &nbsp; CF: {pg["confidence"]}%</div>',unsafe_allow_html=True)
                        with st.expander("Step-by-step reasoning trace"):
                            for line in pg["trace"]:
                                col="#22c55e" if "PROVED" in line and "NOT" not in line else "#ef4444" if "NOT proved" in line else "#94a3b8"
                                st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-size:.75rem;color:{col};line-height:1.6">{line}</div>',unsafe_allow_html=True)
                else:
                    st.markdown('<div style="color:#7fa8c9;padding:.8rem;font-size:.85rem">No goals proved for this domain with current facts.</div>',unsafe_allow_html=True)

        with t3:
            sec("COMPLETE ANALYSIS REPORT")
            rpt=format_full_report(exp,sc)
            st.markdown(f'<div class="mono-rpt">{rpt}</div>',unsafe_allow_html=True)
            st.download_button("Download Report (.txt)",data=rpt,file_name="cyberguard_report.txt",mime="text/plain")

# ════════════════════════════════════════════════════════════
# KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════
elif page=="Knowledge Base":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Knowledge Base</h2><p style="color:#7fa8c9;font-size:.88rem">All 72 production rules with conditions, certainty factors, and knowledge acquisition sources.</p>',unsafe_allow_html=True)

    sec("KNOWLEDGE ACQUISITION METHODOLOGY")
    st.markdown("""<div class="info-card">
      <div style="font-size:.84rem;color:#94a3b8;line-height:1.9">
        Rules were derived from five authoritative expert sources:<br>
        <b style="color:#e2e8f0">1. OWASP Top 10 (2023)</b> — Password complexity, URL phishing patterns, injection attack signatures<br>
        <b style="color:#e2e8f0">2. NIST SP 800-63B</b> — Password entropy standards, common password blacklists, minimum length requirements<br>
        <b style="color:#e2e8f0">3. Anti-Phishing Working Group (APWG)</b> — Real phishing URL and message patterns from quarterly eCrime reports<br>
        <b style="color:#e2e8f0">4. FTC Consumer Sentinel Network</b> — Scam detection patterns from fraud reports database<br>
        <b style="color:#e2e8f0">5. CIS Controls v8 / SANS Awareness</b> — Cyber hygiene rules based on critical security controls baseline<br>
        Certainty factors (0-100%) represent empirical precision rates from published cybersecurity research.
      </div></div>""",unsafe_allow_html=True)

    sec("HOW RULES WERE DERIVED")
    st.markdown("""<div class="info-card">
      <div style="font-size:.84rem;color:#94a3b8;line-height:1.9">
        <b style="color:#e2e8f0">Step 1 — Domain Selection:</b> Five cybersecurity domains were identified based on the MITRE ATT&CK framework attack surface.<br>
        <b style="color:#e2e8f0">Step 2 — Pattern Extraction:</b> Known attack patterns, IOCs (Indicators of Compromise), and security checklists were collected from OWASP, NIST, APWG.<br>
        <b style="color:#e2e8f0">Step 3 — Rule Encoding:</b> Each pattern was encoded as IF (conditions) THEN (conclusion) with severity reflecting real-world impact.<br>
        <b style="color:#e2e8f0">Step 4 — CF Assignment:</b> Certainty factors were assigned based on precision rates in threat detection literature.<br>
        <b style="color:#e2e8f0">Step 5 — Conflict Resolution:</b> Conflicting rules in the same domain are resolved by severity priority (CRITICAL > HIGH > MEDIUM > LOW).
      </div></div>""",unsafe_allow_html=True)

    sec("RULE BROWSER")
    fc1,fc2=st.columns(2)
    with fc1: cf=st.selectbox("Filter Domain",["All","password","url","phishing","scam","hygiene"])
    with fc2: sf=st.selectbox("Filter Severity",["All","CRITICAL","HIGH","MEDIUM","LOW"])
    filtered=[r for r in RULES if (cf=="All" or r["category"]==cf) and (sf=="All" or r["severity"]==sf)]
    st.markdown(f'<div style="color:#7fa8c9;font-size:.76rem;margin:.4rem 0">{len(filtered)} rules shown</div>',unsafe_allow_html=True)
    st.markdown('<div class="kb-row" style="border-bottom:2px solid #1e3a5f;font-weight:700;color:#3b82f6;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em"><span style="min-width:42px">ID</span><span style="min-width:85px">Domain</span><span style="flex:1">Description</span><span style="min-width:80px">Severity</span><span style="min-width:42px">CF%</span></div>',unsafe_allow_html=True)
    for rule in filtered:
        c=SC.get(rule["severity"],"#7fa8c9")
        st.markdown(f'<div class="kb-row"><span style="min-width:42px;color:#60a5fa;font-family:JetBrains Mono,monospace;font-weight:600;font-size:.8rem">{rule["id"]}</span><span style="min-width:85px;color:#7fa8c9;font-size:.76rem">{rule["category"]}</span><span style="flex:1;color:#94a3b8;font-size:.82rem">{rule["desc"]}</span><span style="min-width:80px;color:{c};font-weight:700;font-size:.75rem;font-family:JetBrains Mono,monospace">{rule["severity"]}</span><span style="min-width:42px;color:#7fa8c9;font-family:JetBrains Mono,monospace;font-size:.75rem">{rule["confidence"]}</span></div>',unsafe_allow_html=True)
        if st.session_state.get(f"show_rat_{rule['id']}"):
            if rule.get("rationale"):
                st.markdown(f'<div style="padding:.3rem 1rem .4rem 3.5rem;font-size:.76rem;color:#7fa8c9;font-style:italic">{rule["rationale"]}</div>',unsafe_allow_html=True)

    with st.expander("View Rule Structure Example"):
        st.code("""{
  "id":         "R01",
  "desc":       "Very short password with no special characters",
  "category":   "password",
  "conditions": ["pwd_length_very_short", "no_special_char"],
  "conclusion": "password_risk_critical",
  "severity":   "CRITICAL",
  "confidence": 95,
  "rationale":  "NIST 800-63B: passwords < 6 chars have near-zero entropy"
}
# Inference: IF pwd_length_very_short=TRUE AND no_special_char=TRUE
#            THEN conclusion=password_risk_critical  (CF=95%)""",language="python")

# ════════════════════════════════════════════════════════════
# TEST SCENARIOS
# ════════════════════════════════════════════════════════════
elif page=="Test Scenarios":
    st.markdown('<h2 style="color:#e2e8f0;font-weight:700;padding-top:1.5rem">Test Scenarios</h2><p style="color:#7fa8c9;font-size:.88rem">14 predefined test cases across all 5 domains. Validates system accuracy and rule correctness.</p>',unsafe_allow_html=True)
    if st.button("Run All 14 Test Scenarios",use_container_width=True):
        results=[]; prog=st.progress(0); status=st.empty()
        for i,tc in enumerate(TEST_SCENARIOS):
            status.markdown(f'<div style="color:#7fa8c9;font-size:.8rem">Running {tc["id"]}: {tc["name"]}...</div>',unsafe_allow_html=True)
            prog.progress((i+1)/len(TEST_SCENARIOS))
            if tc["input_type"]=="password": f=extract_password_facts(tc["input"]["password"],tc["input"].get("username",""))
            elif tc["input_type"]=="url": f=extract_url_facts(tc["input"]["url"])
            elif tc["input_type"]=="message": f={**extract_message_facts(tc["input"]["message"]),**extract_scam_facts(tc["input"]["message"])}
            else: f=extract_hygiene_facts(tc["input"])
            tr=run_inference(f); s=build_score_report(tr)
            ov=s.get("overall",{"label":"SAFE","score":0}); fired=[r["id"] for r in tr]
            ef=any(e in fired for e in tc["expected_rules"])
            so=(ov["label"]==tc["expected_severity"] or
                (tc["expected_severity"] in ["LOW","SAFE"] and ov["label"] in ["LOW","SAFE"]) or
                (tc["expected_severity"]=="CRITICAL" and ov["label"] in ["CRITICAL","HIGH"]))
            ok=ef and so
            results.append({**tc,"passed":ok,"actual_label":ov["label"],"actual_score":ov["score"],"fired_ids":fired})
            time.sleep(0.03)
        status.empty(); prog.empty()
        pc=sum(1 for r in results if r["passed"]); acc=pc/len(results)*100
        rbanner("LOW" if pc==len(results) else "MEDIUM",acc,f"{pc}/{len(results)} test cases passed")
        m1,m2,m3=st.columns(3)
        with m1: st.metric("Tests Passed",f"{pc}/{len(results)}")
        with m2: st.metric("Accuracy",f"{acc:.1f}%")
        with m3: st.metric("Failed",len(results)-pc)
        sec("DETAILED RESULTS")
        for r in results:
            ec=SC.get(r["actual_label"],"#7fa8c9")
            with st.expander(f"{r['id']} — {r['name']}"):
                st.markdown(f'<div style="display:flex;gap:2rem;align-items:center;margin-bottom:.7rem"><span class="{"pass-lbl" if r["passed"] else "fail-lbl"}">{"PASS" if r["passed"] else "FAIL"}</span><span style="font-size:.82rem;color:#7fa8c9">Expected: <b style="color:#e2e8f0">{r["expected_severity"]}</b></span><span style="font-size:.82rem;color:#7fa8c9">Actual: <b style="color:{ec}">{r["actual_label"]} ({r["actual_score"]:.0f}%)</b></span></div>',unsafe_allow_html=True)
                st.markdown(f'<div style="font-size:.83rem;color:#94a3b8;margin-bottom:.3rem"><b style="color:#e2e8f0">Description:</b> {r["description"]}</div>',unsafe_allow_html=True)
                st.markdown(f'<div style="font-size:.83rem;color:#94a3b8;margin-bottom:.5rem"><b style="color:#e2e8f0">Rationale:</b> {r["rationale"]}</div>',unsafe_allow_html=True)
                st.markdown(f'<div style="font-family:JetBrains Mono,monospace;font-size:.74rem;color:#7fa8c9">Expected rules: <span style="color:#60a5fa">{", ".join(r["expected_rules"])}</span><br>Rules fired: <span style="color:#94a3b8">{", ".join(r["fired_ids"][:10])}</span></div>',unsafe_allow_html=True)
    else:
        sec("TEST CASES OVERVIEW")
        st.markdown('<div class="kb-row" style="border-bottom:2px solid #1e3a5f;font-weight:700;color:#3b82f6;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em"><span style="min-width:42px">ID</span><span style="min-width:90px">Domain</span><span style="flex:1">Scenario Name</span><span style="min-width:90px">Expected</span></div>',unsafe_allow_html=True)
        for tc in TEST_SCENARIOS:
            c=SC.get(tc["expected_severity"],"#7fa8c9")
            st.markdown(f'<div class="kb-row"><span style="min-width:42px;color:#60a5fa;font-family:JetBrains Mono,monospace;font-weight:600;font-size:.8rem">{tc["id"]}</span><span style="min-width:90px;color:#7fa8c9;font-size:.77rem">{tc["domain"]}</span><span style="flex:1;color:#94a3b8;font-size:.83rem">{tc["name"]}</span><span style="min-width:90px;color:{c};font-weight:700;font-size:.75rem;font-family:JetBrains Mono,monospace">{tc["expected_severity"]}</span></div>',unsafe_allow_html=True)
