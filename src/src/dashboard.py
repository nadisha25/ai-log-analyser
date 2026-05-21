import streamlit as st
import sqlite3
import pandas as pd
import os
import matplotlib.pyplot as plt

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.path.join(BASE_DIR, "logs.db")

st.set_page_config(page_title="AI Audit Log Analyzer", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
.risk-high { color: #FF6B9D; font-weight: bold; }
.risk-medium { color: #FFD93D; font-weight: bold; }
.risk-low { color: #00F5D4; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

@st.cache_data
def load_data():
    if not os.path.exists(DB_PATH):
        return None, None, None
    conn = sqlite3.connect(DB_PATH)
    logs_df = pd.read_sql_query("SELECT * FROM logs", conn)
    try:
        suspicious_df = pd.read_sql_query("SELECT * FROM suspicious_events", conn)
    except:
        suspicious_df = pd.DataFrame()
    try:
        ai_df = pd.read_sql_query("SELECT * FROM ai_analysis", conn)
    except:
        ai_df = pd.DataFrame()
    conn.close()
    return logs_df, suspicious_df, ai_df

logs_df, suspicious_df, ai_df = load_data()

st.title("🛡️ AI Audit Log Analyzer")
st.markdown("**Real-time security intelligence powered by AI** | Built with Python, SQLite & Groq")
st.divider()

if logs_df is None:
    st.error("Database not found. Please run ingest.py first.")
    st.stop()

col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric(label="📋 Total Log Entries", value=len(logs_df))
with col2:
    st.metric(label="🚨 Suspicious Events", value=len(suspicious_df) if not suspicious_df.empty else 0)
with col3:
    st.metric(label="🤖 AI Analyses", value=len(ai_df) if not ai_df.empty else 0)
with col4:
    high_count = len(suspicious_df[suspicious_df['risk_level'] == 'High']) if not suspicious_df.empty else 0
    st.metric(label="🔴 High Risk Events", value=high_count, delta=f"{high_count} need attention" if high_count > 0 else "All clear")

st.divider()

left_col, right_col = st.columns([1, 1])

with left_col:
    st.subheader("📊 Risk Type Breakdown")
    if not suspicious_df.empty and 'risk_type' in suspicious_df.columns:
        risk_counts = suspicious_df['risk_type'].value_counts()
        fig, ax = plt.subplots(figsize=(5, 3.5))
        fig.patch.set_facecolor('#1e1e3c')
        ax.set_facecolor('#1e1e3c')
        colors = ['#FF6B9D', '#9B5DE5', '#00BBF9', '#FFD93D', '#00F5D4']
        bars = ax.barh(risk_counts.index, risk_counts.values, color=colors[:len(risk_counts)], height=0.5)
        ax.set_xlabel('Count', color='white', fontsize=9)
        ax.tick_params(colors='white', labelsize=8)
        for spine in ax.spines.values():
            spine.set_edgecolor('#444')
        for bar, val in zip(bars, risk_counts.values):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, str(val), va='center', color='white', fontsize=9)
        plt.tight_layout()
        st.pyplot(fig)
    else:
        st.info("No suspicious events data available.")

with right_col:
    st.subheader("🕐 Activity Timeline")
    if not logs_df.empty and 'timestamp' in logs_df.columns:
        logs_df['timestamp'] = pd.to_datetime(logs_df['timestamp'])
        logs_df['hour'] = logs_df['timestamp'].dt.hour
        hourly = logs_df.groupby('hour').size().reset_index(name='count')
        fig2, ax2 = plt.subplots(figsize=(5, 3.5))
        fig2.patch.set_facecolor('#1e1e3c')
        ax2.set_facecolor('#1e1e3c')
        ax2.fill_between(hourly['hour'], hourly['count'], color='#9B5DE5', alpha=0.6)
        ax2.plot(hourly['hour'], hourly['count'], color='#9B5DE5', linewidth=2)
        ax2.axvspan(0, 6, alpha=0.15, color='#FF6B9D', label='High risk hours')
        ax2.set_xlabel('Hour of Day', color='white', fontsize=9)
        ax2.set_ylabel('Events', color='white', fontsize=9)
        ax2.tick_params(colors='white', labelsize=8)
        for spine in ax2.spines.values():
            spine.set_edgecolor('#444')
        ax2.legend(fontsize=8, facecolor='#2d2d5e', labelcolor='white')
        plt.tight_layout()
        st.pyplot(fig2)
    else:
        st.info("No timeline data available.")

st.divider()
st.subheader("🚨 All Suspicious Events")

if not suspicious_df.empty:
    display_df = suspicious_df[['timestamp', 'user', 'ip_address', 'action', 'risk_type', 'risk_level']].copy()
    display_df.columns = ['Timestamp', 'User', 'IP Address', 'Action', 'Risk Type', 'Risk Level']
    st.dataframe(display_df, use_container_width=True, height=300)
else:
    st.info("No suspicious events found.")

st.divider()
st.subheader("🤖 AI Risk Analysis Results")

if not ai_df.empty:
    for _, row in ai_df.iterrows():
        level = str(row.get('ai_risk_level', 'Unknown'))
        score = row.get('ai_risk_score', 0)
        user = row.get('user', 'unknown')
        action = row.get('action', 'unknown')
        summary = row.get('ai_summary', '')
        recommendation = row.get('ai_recommended_action', '')
        risk_type = row.get('risk_type', '')

        if level.lower() == 'high':
            icon = "🔴"
        elif level.lower() == 'medium':
            icon = "🟡"
        else:
            icon = "🟢"

        with st.expander(f"{icon} {user} — {action} | Risk: {level} | Score: {score}/10"):
            col_a, col_b = st.columns(2)
            with col_a:
                st.markdown(f"**Risk Type:** {risk_type}")
                st.markdown(f"**Timestamp:** {row.get('timestamp', 'N/A')}")
                st.markdown(f"**IP Address:** {row.get('ip_address', 'N/A')}")
            with col_b:
                st.markdown(f"**AI Summary:** {summary}")
            if recommendation:
                st.warning(f"**Recommended Action:** {recommendation}")
else:
    st.info("No AI analysis results found. Run ingest.py first.")

st.divider()
st.markdown("<div style='text-align:center;color:#555;font-size:0.8rem'>AI Audit Log Analyzer | Built with Python, Streamlit, SQLite & Groq AI</div>", unsafe_allow_html=True)