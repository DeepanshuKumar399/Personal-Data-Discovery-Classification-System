import streamlit as st
import pandas as pd
import plotly.express as px
import tempfile
import os

from src.scanner import scan_file
from src.classifier import summarize
from src.masking import mask_findings
from src.report_generator import generate_json, generate_csv, generate_excel
from src.database import save_scan, get_history, get_findings_by_scan

st.set_page_config(page_title="PII Scanner", page_icon="🔍", layout="wide")

st.markdown("""
<style>
/* ── Global ── */
[data-testid="stAppViewContainer"] {
    background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
    color: #f0f0f0;
}
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #1a1a2e 0%, #16213e 100%);
    border-right: 1px solid #ffffff18;
}
[data-testid="stSidebar"] * { color: #e0e0e0 !important; }

/* ── Sidebar title ── */
[data-testid="stSidebar"] h1 {
    font-size: 1.4rem;
    font-weight: 800;
    letter-spacing: 1px;
    color: #a78bfa !important;
    padding-bottom: 8px;
    border-bottom: 1px solid #ffffff22;
}

/* ── Page title ── */
h1 { color: #a78bfa !important; font-weight: 800; letter-spacing: 1px; }
h2, h3 { color: #c4b5fd !important; }

/* ── Metric cards ── */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #1e1b4b, #312e81);
    border: 1px solid #4f46e5;
    border-radius: 12px;
    padding: 16px 20px;
    box-shadow: 0 4px 20px #4f46e540;
    transition: transform 0.2s;
}
[data-testid="stMetric"]:hover { transform: translateY(-3px); }
[data-testid="stMetricLabel"] { color: #a5b4fc !important; font-size: 0.85rem; }
[data-testid="stMetricValue"] { color: #ffffff !important; font-size: 2rem; font-weight: 800; }

/* ── File uploader ── */
[data-testid="stFileUploader"] {
    background: #1e1b4b;
    border: 2px dashed #6d28d9;
    border-radius: 12px;
    padding: 20px;
}

/* ── Download buttons ── */
.stDownloadButton > button {
    background: linear-gradient(135deg, #6d28d9, #4f46e5) !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    padding: 10px 20px !important;
    font-weight: 600 !important;
    width: 100% !important;
    transition: opacity 0.2s !important;
}
.stDownloadButton > button:hover { opacity: 0.85 !important; }

/* ── Radio buttons ── */
[data-testid="stRadio"] label {
    background: #1e1b4b;
    border-radius: 8px;
    padding: 6px 12px;
    margin: 4px 0;
    display: block;
    cursor: pointer;
    transition: background 0.2s;
}
[data-testid="stRadio"] label:hover { background: #312e81; }

/* ── Toggle ── */
[data-testid="stToggle"] span { color: #a78bfa !important; }

/* ── Dataframe ── */
[data-testid="stDataFrame"] {
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid #4f46e5;
}

/* ── Spinner ── */
[data-testid="stSpinner"] { color: #a78bfa !important; }

/* ── Selectbox ── */
[data-testid="stSelectbox"] > div > div {
    background: #1e1b4b !important;
    border: 1px solid #6d28d9 !important;
    border-radius: 8px !important;
    color: #f0f0f0 !important;
}

/* ── Success / Info alerts ── */
[data-testid="stAlert"] {
    border-radius: 10px;
    border-left: 4px solid #6d28d9;
    background: #1e1b4b !important;
}

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #1a1a2e; }
::-webkit-scrollbar-thumb { background: #6d28d9; border-radius: 10px; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.title("🔍 PII Scanner")
st.sidebar.markdown("---")
page = st.sidebar.radio("Navigate", ["Scan File", "Scan History"])
st.sidebar.markdown("---")
mask_enabled = st.sidebar.toggle("🎭 Mask PII Values", value=False)
st.sidebar.markdown("---")
st.sidebar.markdown("<small style='color:#6d28d9'>Personal Data Discovery<br>& Classification System</small>", unsafe_allow_html=True)

SEVERITY_COLORS = {"Critical": "#FF4C4C", "High": "#FFA500", "Medium": "#FFD700", "Low": "#90EE90"}

# ── Page: Scan File ───────────────────────────────────────────────────────────
if page == "Scan File":
    st.title("📂 Upload & Scan File")
    uploaded = st.file_uploader("Upload a file to scan", type=["csv", "txt", "json", "log", "xml"])

    if uploaded:
        # Save to temp file
        suffix = os.path.splitext(uploaded.name)[1]
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(uploaded.read())
            tmp_path = tmp.name

        with st.spinner("Scanning for PII..."):
            findings = scan_file(tmp_path)
            for f in findings:
                f["source"] = uploaded.name

        if mask_enabled:
            findings = mask_findings(findings)

        summary = summarize(findings)
        scan_id = save_scan(uploaded.name, findings, summary)
        os.unlink(tmp_path)

        # ── Metric Cards ──
        st.subheader("📊 Scan Summary")
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Findings", summary["total"])
        c2.metric("🔴 Critical", summary["by_sensitivity"].get("Critical", 0))
        c3.metric("🟠 High", summary["by_sensitivity"].get("High", 0))
        c4.metric("🟡 Medium", summary["by_sensitivity"].get("Medium", 0))
        c5.metric("🟢 Low", summary["by_sensitivity"].get("Low", 0))

        if findings:
            col1, col2 = st.columns(2)

            # Pie chart by sensitivity
            with col1:
                fig1 = px.pie(
                    names=list(summary["by_sensitivity"].keys()),
                    values=list(summary["by_sensitivity"].values()),
                    title="By Sensitivity",
                    color=list(summary["by_sensitivity"].keys()),
                    color_discrete_map=SEVERITY_COLORS,
                )
                st.plotly_chart(fig1, use_container_width=True)

            # Bar chart by PII type
            with col2:
                fig2 = px.bar(
                    x=list(summary["by_type"].keys()),
                    y=list(summary["by_type"].values()),
                    title="By PII Type",
                    labels={"x": "PII Type", "y": "Count"},
                    color=list(summary["by_type"].keys()),
                )
                st.plotly_chart(fig2, use_container_width=True)

            # Findings table
            st.subheader("📋 Findings")
            df = pd.DataFrame(findings)
            display_cols = ["type", "masked_value" if mask_enabled else "value", "sensitivity", "source", "line"]
            display_cols = [c for c in display_cols if c in df.columns]

            def highlight_row(row):
                color = SEVERITY_COLORS.get(row["sensitivity"], "#FFFFFF") + "55"
                return [f"background-color: {color}"] * len(row)

            st.dataframe(df[display_cols].style.apply(highlight_row, axis=1), use_container_width=True)

            # ── Export ──
            st.subheader("📥 Export Report")
            e1, e2, e3 = st.columns(3)

            with e1:
                json_path = generate_json(findings, summary)
                with open(json_path, "rb") as f:
                    st.download_button("⬇ Download JSON", f, file_name=os.path.basename(json_path), mime="application/json")

            with e2:
                csv_path = generate_csv(findings)
                with open(csv_path, "rb") as f:
                    st.download_button("⬇ Download CSV", f, file_name=os.path.basename(csv_path), mime="text/csv")

            with e3:
                xlsx_path = generate_excel(findings, summary)
                with open(xlsx_path, "rb") as f:
                    st.download_button("⬇ Download Excel", f, file_name=os.path.basename(xlsx_path), mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        else:
            st.success("✅ No PII found in this file.")

# ── Page: Scan History ────────────────────────────────────────────────────────
elif page == "Scan History":
    st.title("🕓 Scan History")
    history = get_history()

    if not history:
        st.info("No scans yet. Go to 'Scan File' to run your first scan.")
    else:
        df_hist = pd.DataFrame([{
            "ID": h["id"],
            "Scanned At": h["scanned_at"],
            "File": h["target"],
            "Total Findings": h["total_findings"],
            "Critical": h["summary"]["by_sensitivity"].get("Critical", 0),
            "High": h["summary"]["by_sensitivity"].get("High", 0),
            "Medium": h["summary"]["by_sensitivity"].get("Medium", 0),
            "Low": h["summary"]["by_sensitivity"].get("Low", 0),
        } for h in history])

        st.dataframe(df_hist, use_container_width=True)

        # Drill down into a specific scan
        st.subheader("🔎 View Findings for a Scan")
        scan_ids = [h["id"] for h in history]
        selected_id = st.selectbox("Select Scan ID", scan_ids)

        if selected_id:
            findings = get_findings_by_scan(selected_id)
            if findings:
                df_f = pd.DataFrame(findings)
                st.dataframe(df_f, use_container_width=True)

                xlsx_path = generate_excel(findings, summarize(findings))
                with open(xlsx_path, "rb") as f:
                    st.download_button("⬇ Export as Excel", f, file_name=os.path.basename(xlsx_path))
            else:
                st.info("No findings stored for this scan.")
