"""
app.py - Smart Contract Auditor - Main Streamlit Application
Run with: streamlit run app.py
"""

import json
import streamlit as st
from auditor import audit_contract, SEVERITY_ORDER
from contracts.examples import (
    REENTRANCY_CONTRACT,
    INTEGER_OVERFLOW_CONTRACT,
    ACCESS_CONTROL_CONTRACT,
)

# ---------------------------------------------------------------------------
# Page Config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="Smart Contract Auditor",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------------
# Custom CSS - Dark terminal aesthetic fitting the security/Web3 audience
# ---------------------------------------------------------------------------

st.markdown("""
<style>
  /* ── Base ── */
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600;700&display=swap');

  html, body, [data-testid="stAppViewContainer"] {
      background-color: #0d0f14;
      color: #e2e8f0;
  }
  [data-testid="stSidebar"] {
      background-color: #111318;
      border-right: 1px solid #1e2130;
  }
  [data-testid="stSidebar"] * { color: #e2e8f0 !important; }

  /* ── Typography ── */
  h1, h2, h3 { font-family: 'Inter', sans-serif; }
  code, pre, textarea { font-family: 'JetBrains Mono', monospace !important; }

  /* ── Header banner ── */
  .audit-header {
      background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
      border: 1px solid #312e81;
      border-radius: 12px;
      padding: 28px 32px;
      margin-bottom: 24px;
  }
  .audit-header h1 {
      font-size: 2rem;
      font-weight: 700;
      color: #a5b4fc;
      margin: 0 0 4px 0;
      letter-spacing: -0.5px;
  }
  .audit-header p {
      color: #94a3b8;
      margin: 0;
      font-size: 0.95rem;
  }

  /* ── Risk score card ── */
  .risk-card {
      border-radius: 10px;
      padding: 20px 24px;
      text-align: center;
      margin-bottom: 16px;
  }
  .risk-safe     { background: #052e16; border: 1px solid #16a34a; }
  .risk-low      { background: #1a2e05; border: 1px solid #65a30d; }
  .risk-medium   { background: #2d1b05; border: 1px solid #d97706; }
  .risk-high     { background: #2d0a0a; border: 1px solid #dc2626; }
  .risk-critical { background: #1a0020; border: 2px solid #c026d3; }
  .risk-score    { font-size: 3rem; font-weight: 700; font-family: 'JetBrains Mono'; }
  .risk-label    { font-size: 0.85rem; letter-spacing: 2px; text-transform: uppercase; font-weight: 600; margin-top: 4px; }

  /* ── Severity badges ── */
  .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 99px;
      font-size: 0.72rem;
      font-weight: 700;
      font-family: 'JetBrains Mono';
      letter-spacing: 0.5px;
  }
  .badge-CRITICAL { background: #581c87; color: #e879f9; border: 1px solid #a855f7; }
  .badge-HIGH     { background: #7f1d1d; color: #fca5a5; border: 1px solid #ef4444; }
  .badge-MEDIUM   { background: #78350f; color: #fcd34d; border: 1px solid #f59e0b; }
  .badge-LOW      { background: #14532d; color: #86efac; border: 1px solid #22c55e; }
  .badge-INFO     { background: #1e3a5f; color: #93c5fd; border: 1px solid #3b82f6; }

  /* ── Finding card ── */
  .finding-card {
      background: #111827;
      border: 1px solid #1f2937;
      border-radius: 8px;
      padding: 16px 20px;
      margin-bottom: 12px;
  }
  .finding-card:hover { border-color: #374151; }
  .finding-title { font-weight: 600; font-size: 0.95rem; margin-bottom: 8px; color: #f1f5f9; }
  .finding-section-label {
      font-size: 0.7rem;
      letter-spacing: 1.5px;
      text-transform: uppercase;
      color: #6b7280;
      font-family: 'JetBrains Mono';
      margin-top: 10px;
      margin-bottom: 2px;
  }
  .finding-text { font-size: 0.875rem; color: #d1d5db; line-height: 1.55; }
  .finding-rec  { font-size: 0.875rem; color: #86efac; line-height: 1.55; }
  .line-ref     { font-family: 'JetBrains Mono'; font-size: 0.8rem; color: #818cf8; }

  /* ── Summary box ── */
  .summary-box {
      background: #0f172a;
      border-left: 3px solid #6366f1;
      border-radius: 0 8px 8px 0;
      padding: 14px 18px;
      margin-bottom: 20px;
      font-size: 0.9rem;
      color: #cbd5e1;
      line-height: 1.6;
  }

  /* ── Stat pill ── */
  .stat-pill {
      display: inline-block;
      background: #1f2937;
      border-radius: 8px;
      padding: 10px 16px;
      text-align: center;
      min-width: 80px;
  }
  .stat-num  { font-size: 1.5rem; font-weight: 700; font-family: 'JetBrains Mono'; }
  .stat-lbl  { font-size: 0.7rem; color: #6b7280; text-transform: uppercase; letter-spacing: 1px; }

  /* ── Code textarea ── */
  .stTextArea textarea {
      background-color: #0a0c12 !important;
      color: #c9d1d9 !important;
      border: 1px solid #21262d !important;
      border-radius: 8px !important;
      font-family: 'JetBrains Mono', monospace !important;
      font-size: 0.82rem !important;
  }

  /* ── Buttons ── */
  .stButton > button {
      background: linear-gradient(135deg, #4f46e5, #7c3aed) !important;
      color: white !important;
      border: none !important;
      border-radius: 8px !important;
      font-weight: 600 !important;
      font-size: 0.9rem !important;
      padding: 0.5rem 1.5rem !important;
      width: 100%;
  }
  .stButton > button:hover {
      background: linear-gradient(135deg, #4338ca, #6d28d9) !important;
      transform: translateY(-1px);
  }

  /* ── Divider ── */
  hr { border-color: #1e2130 !important; }

  /* ── Error box ── */
  .error-box {
      background: #1c0a0a;
      border: 1px solid #dc2626;
      border-radius: 8px;
      padding: 16px 20px;
      color: #fca5a5;
      font-size: 0.9rem;
  }

  /* ── Expander ── */
  .streamlit-expanderHeader {
      background: #111827 !important;
      border-radius: 8px !important;
  }

  /* Hide Streamlit branding */
  #MainMenu, footer, header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("### 🔐 Smart Contract Auditor")
    st.markdown("---")

    st.markdown("**Load Example Contract**")
    example_choice = st.selectbox(
        "Choose a vulnerable example:",
        ["— Select —", "Reentrancy Attack", "Integer Overflow", "Broken Access Control"],
        label_visibility="collapsed"
    )

    st.markdown("---")
    st.markdown("**About**")
    st.markdown("""
Powered by **Google Gemini 2.0 Flash** (free tier).

Detects:
- Reentrancy vulnerabilities
- Integer overflow/underflow  
- Access control flaws
- Unprotected selfdestruct
- tx.origin misuse
- And more...
    """)

    st.markdown("---")
    st.markdown("**Free Tier Limits**")
    st.markdown("1,500 requests/day · 1M tokens/day")
    st.markdown("[Get API Key →](https://aistudio.google.com/app/apikey)")

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("""
<div class="audit-header">
  <h1>🔐 Smart Contract Auditor</h1>
  <p>AI-powered Solidity vulnerability detection using Google Gemini 2.0 Flash</p>
</div>
""", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

if "report" not in st.session_state:
    st.session_state.report = None
if "contract_code" not in st.session_state:
    st.session_state.contract_code = ""

# Load example if selected
if example_choice == "Reentrancy Attack":
    st.session_state.contract_code = REENTRANCY_CONTRACT
elif example_choice == "Integer Overflow":
    st.session_state.contract_code = INTEGER_OVERFLOW_CONTRACT
elif example_choice == "Broken Access Control":
    st.session_state.contract_code = ACCESS_CONTROL_CONTRACT

# ---------------------------------------------------------------------------
# Input Panel
# ---------------------------------------------------------------------------

col_input, col_results = st.columns([1, 1], gap="large")

with col_input:
    st.markdown("#### Paste Solidity Contract")

    contract_input = st.text_area(
        label="contract_code",
        value=st.session_state.contract_code,
        height=460,
        placeholder="// SPDX-License-Identifier: MIT\npragma solidity ^0.8.0;\n\ncontract MyContract {\n    // Paste your Solidity code here...\n}",
        label_visibility="collapsed",
    )

    char_count = len(contract_input)
    line_count = contract_input.count("\n") + 1 if contract_input.strip() else 0
    st.caption(f"📄 {line_count} lines · {char_count:,} characters")

    audit_clicked = st.button("🔍 Run Security Audit", use_container_width=True)

    if audit_clicked:
       if not contract_input.strip():
           st.error("Please paste a Solidity contract or load an example from the sidebar.")
       elif len(contract_input.strip()) < 50:
            st.error("Contract seems too short. Please paste a complete Solidity file.")
       elif st.session_state.get("last_audited") != contract_input:
           st.session_state.contract_code = contract_input
           st.session_state.last_audited = contract_input
           with st.spinner("🤖 Gemini is analyzing your contract..."):
              st.session_state.report = audit_contract(contract_input)

# ---------------------------------------------------------------------------
# Results Panel
# ---------------------------------------------------------------------------

with col_results:
    st.markdown("#### Audit Report")

    report = st.session_state.report

    if report is None:
        st.markdown("""
        <div style="background:#111827; border:1px dashed #374151; border-radius:10px;
                    padding:48px 24px; text-align:center; color:#4b5563;">
            <div style="font-size:2.5rem; margin-bottom:12px;">🛡️</div>
            <div style="font-size:1rem; font-weight:600; color:#6b7280;">No audit yet</div>
            <div style="font-size:0.85rem; margin-top:6px;">
                Paste a Solidity contract or load an example, then click <strong>Run Security Audit</strong>
            </div>
        </div>
        """, unsafe_allow_html=True)

    elif report.error:
        st.markdown(f"""
        <div class="error-box">
            <strong>⚠️ Audit Failed</strong><br><br>
            {report.error.replace(chr(10), '<br>')}
        </div>
        """, unsafe_allow_html=True)

    else:
        # ── Risk Score Card ──
        score = report.overall_risk_score
        label = report.overall_risk_label

        if score == 0:
            card_class = "risk-safe"
            score_color = "#4ade80"
        elif score < 25:
            card_class = "risk-low"
            score_color = "#a3e635"
        elif score < 45:
            card_class = "risk-medium"
            score_color = "#fbbf24"
        elif score < 70:
            card_class = "risk-high"
            score_color = "#f87171"
        else:
            card_class = "risk-critical"
            score_color = "#e879f9"

        st.markdown(f"""
        <div class="risk-card {card_class}">
            <div class="risk-score" style="color:{score_color}">{score}</div>
            <div class="risk-label" style="color:{score_color}">{label}</div>
            <div style="color:#94a3b8; font-size:0.78rem; margin-top:6px;">
                Contract: <code style="color:#a5b4fc">{report.contract_name}</code>
                · Audited: {report.audit_timestamp}
            </div>
        </div>
        """, unsafe_allow_html=True)

        # ── Severity Breakdown ──
        counts = report.severity_counts()
        sev_colors = {
            "CRITICAL": "#e879f9",
            "HIGH": "#f87171",
            "MEDIUM": "#fbbf24",
            "LOW": "#4ade80",
            "INFO": "#60a5fa",
        }

        cols = st.columns(5)
        for i, sev in enumerate(SEVERITY_ORDER):
            with cols[i]:
                color = sev_colors[sev]
                st.markdown(f"""
                <div class="stat-pill" style="border-top: 3px solid {color};">
                    <div class="stat-num" style="color:{color}">{counts[sev]}</div>
                    <div class="stat-lbl">{sev}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)

        # ── Summary ──
        if report.summary:
            st.markdown(f"""
            <div class="summary-box">
                <strong style="color:#818cf8; font-size:0.75rem; letter-spacing:1.5px; 
                               text-transform:uppercase;">Executive Summary</strong><br><br>
                {report.summary}
            </div>
            """, unsafe_allow_html=True)

        # ── Findings ──
        total = len(report.findings)
        if total == 0:
            st.success("✅ No vulnerabilities detected. This contract appears safe.")
        else:
            st.markdown(f"**{total} Finding{'s' if total != 1 else ''} Detected**")

            for i, finding in enumerate(report.findings):
                sev = finding.severity.upper()
                badge_class = f"badge-{sev}"

                st.markdown(f"""
                <div class="finding-card">
                    <div class="finding-title">
                        <span class="badge {badge_class}">{sev}</span>
                        &nbsp; {finding.vulnerability_name}
                    </div>
                    <div class="line-ref">📍 {finding.line_reference}</div>

                    <div class="finding-section-label">Explanation</div>
                    <div class="finding-text">{finding.explanation}</div>

                    <div class="finding-section-label">Recommendation</div>
                    <div class="finding-rec">✅ {finding.recommendation}</div>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("---")

        # ── Download Report ──
        report_dict = report.to_dict()
        report_json = json.dumps(report_dict, indent=2)

        st.download_button(
            label="⬇️ Download Report as JSON",
            data=report_json,
            file_name=f"audit_{report.contract_name}_{report.audit_timestamp.replace(' ', '_').replace(':', '-')}.json",
            mime="application/json",
            use_container_width=True,
        )
