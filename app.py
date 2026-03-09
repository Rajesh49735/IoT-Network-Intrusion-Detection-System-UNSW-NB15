"""
live_dashboard.py  –  Add this as a new PAGE / TAB inside your app.py
=====================================================================
This module provides a "Live Hardware Monitor" section that reads from
live_predictions.json (written by receiver.py) and auto-refreshes.

HOW TO INTEGRATE INTO YOUR EXISTING app.py
───────────────────────────────────────────
Option A – Add as a Streamlit page (multi-page app):
  1. Create folder:  pages/
  2. Save this file: pages/3_Live_Monitor.py

Option B – Add as a sidebar tab in existing app.py:
  1. At the top of app.py, add:
       from live_dashboard import show_live_dashboard
  2. In your sidebar/tab section, add:
       if selected == "Live Hardware Monitor":
           show_live_dashboard()

You can also just run this file standalone:
  streamlit run live_dashboard.py
"""

import streamlit as st
import json
import os
import pandas as pd
import time
from datetime import datetime

LIVE_LOG_PATH = "live_predictions.json"
RECEIVER_URL  = "http://localhost:5050"

# ──────────────────────────────────────────────────────────────
def load_live_data() -> list:
    if not os.path.exists(LIVE_LOG_PATH):
        return []
    try:
        with open(LIVE_LOG_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        return []


def show_live_dashboard():
    """Main function – call this from your app.py"""
    st.markdown("""
    <style>
      @keyframes pulse-red {
        0%   { box-shadow: 0 0 0 0   rgba(255,50,50,0.7); }
        70%  { box-shadow: 0 0 0 14px rgba(255,50,50,0); }
        100% { box-shadow: 0 0 0 0   rgba(255,50,50,0); }
      }
      @keyframes pulse-green {
        0%   { box-shadow: 0 0 0 0   rgba(50,255,100,0.5); }
        70%  { box-shadow: 0 0 0 14px rgba(50,255,100,0); }
        100% { box-shadow: 0 0 0 0   rgba(50,255,100,0); }
      }
      .card-intrusion {
        background: rgba(255,50,50,0.12);
        border: 1.5px solid rgba(255,80,80,0.6);
        border-radius: 12px;
        padding: 18px 22px;
        animation: pulse-red 1.5s infinite;
        text-align: center;
      }
      .card-normal {
        background: rgba(40,220,100,0.10);
        border: 1.5px solid rgba(40,220,100,0.5);
        border-radius: 12px;
        padding: 18px 22px;
        animation: pulse-green 2s infinite;
        text-align: center;
      }
      .card-idle {
        background: rgba(120,120,120,0.10);
        border: 1.5px solid rgba(150,150,150,0.4);
        border-radius: 12px;
        padding: 18px 22px;
        text-align: center;
      }
      .big-status { font-size: 2.2rem; font-weight: 800; margin: 0; }
      .sub-status { font-size: 1rem; opacity: 0.75; margin-top: 4px; }
    </style>
    """, unsafe_allow_html=True)

    # ── Header ─────────────────────────────────────────────────
    st.markdown("## 📡 Live Hardware Monitor")
    st.caption("Real-time traffic from Arduino / ESP8266 → ML prediction")

    # ── Controls ───────────────────────────────────────────────
    col_a, col_b, col_c = st.columns([2, 1, 1])
    with col_a:
        refresh_rate = st.slider("Auto-refresh (seconds)", 2, 30, 5)
    with col_b:
        auto_refresh = st.toggle("Auto Refresh", value=True)
    with col_c:
        if st.button("🗑️ Clear Log"):
            import requests
            try:
                requests.get(f"{RECEIVER_URL}/clear", timeout=2)
                st.success("Log cleared!")
            except:
                # Clear locally if receiver not reachable
                with open(LIVE_LOG_PATH, "w") as f:
                    json.dump([], f)
                st.success("Local log cleared!")

    st.divider()

    # ── Load data ──────────────────────────────────────────────
    entries = load_live_data()

    # ── Status card for latest prediction ─────────────────────
    if entries:
        latest = entries[-1]
        label     = latest.get("label", -1)
        status    = latest.get("status", "Unknown")
        conf      = latest.get("confidence", 0)
        device    = latest.get("device_id", "Unknown")
        ts        = latest.get("timestamp", "")

        if label == 1:
            card_class = "card-intrusion"
            icon = "🚨"
        elif label == 0:
            card_class = "card-normal"
            icon = "✅"
        else:
            card_class = "card-idle"
            icon = "❓"

        st.markdown(f"""
        <div class="{card_class}">
          <p class="big-status">{icon} {status}</p>
          <p class="sub-status">
            Confidence: <b>{conf:.1f}%</b> &nbsp;|&nbsp;
            Device: <b>{device}</b> &nbsp;|&nbsp;
            {ts}
          </p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="card-idle">
          <p class="big-status">⏳ Waiting for hardware data…</p>
          <p class="sub-status">Make sure receiver.py is running and your Arduino/ESP8266 is sending packets</p>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # ── KPI Metrics ────────────────────────────────────────────
    if entries:
        total      = len(entries)
        intrusions = sum(1 for e in entries if e.get("label") == 1)
        normals    = total - intrusions
        avg_conf   = sum(e.get("confidence", 0) for e in entries) / total if total else 0
        pct_attack = (intrusions / total * 100) if total else 0

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("📦 Total Packets", total)
        m2.metric("✅ Normal",     normals,    delta=None)
        m3.metric("🚨 Intrusions", intrusions, delta=f"{pct_attack:.1f}%" if intrusions else None,
                  delta_color="inverse")
        m4.metric("🎯 Avg Confidence", f"{avg_conf:.1f}%")

        st.markdown("---")

        # ── Timeline chart ─────────────────────────────────────
        st.subheader("📈 Traffic Timeline")
        df = pd.DataFrame(entries)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["label_text"] = df["label"].map({0: "Normal", 1: "Intrusion"})

        # Rolling window: last 50 entries
        df_tail = df.tail(50).copy()
        df_tail["color_val"] = df_tail["label"].astype(int)

        import altair as alt
        chart = alt.Chart(df_tail).mark_point(size=80, filled=True).encode(
            x=alt.X("timestamp:T", title="Time", axis=alt.Axis(format="%H:%M:%S")),
            y=alt.Y("confidence:Q", title="Confidence (%)", scale=alt.Scale(domain=[0, 100])),
            color=alt.Color("label_text:N",
                scale=alt.Scale(domain=["Normal", "Intrusion"],
                                range=["#2ecc71", "#e74c3c"]),
                legend=alt.Legend(title="Detection")),
            tooltip=["timestamp:T", "label_text:N", "confidence:Q",
                     "device_id:N", alt.Tooltip("rate:Q", format=".1f")]
        ).properties(height=280)

        st.altair_chart(chart, use_container_width=True)

        # ── Feature heatmap for last packet ───────────────────
        st.subheader("🔍 Latest Packet Features")
        feats = latest.get("features", {})
        if feats:
            feat_df = pd.DataFrame({
                "Feature": list(feats.keys()),
                "Value":   [round(v, 3) for v in feats.values()]
            })
            st.dataframe(feat_df, use_container_width=True, hide_index=True,
                         column_config={
                             "Value": st.column_config.ProgressColumn(
                                 "Value", format="%.3f", min_value=0, max_value=float(max(feats.values()) or 1)
                             )
                         })

        # ── Raw log table ──────────────────────────────────────
        with st.expander("📋 Full Prediction Log (last 50)"):
            log_df = df[["timestamp", "device_id", "label_text",
                         "confidence"]].tail(50).iloc[::-1]
            log_df.columns = ["Timestamp", "Device", "Status", "Confidence (%)"]
            st.dataframe(log_df, use_container_width=True, hide_index=True)

    # ── Receiver health ────────────────────────────────────────
    with st.expander("⚙️ Receiver Status"):
        try:
            import requests
            r = requests.get(f"{RECEIVER_URL}/status", timeout=2)
            info = r.json()
            st.success(f"✅ receiver.py running | Model: `{info.get('model')}` | "
                       f"Log entries: {info.get('log_entries')}")
        except:
            st.warning("⚠️ receiver.py is not reachable at localhost:5050 — "
                       "start it with `python receiver.py`")

    # ── Auto-refresh ───────────────────────────────────────────
    if auto_refresh:
        time.sleep(refresh_rate)
        st.rerun()


# ── Standalone run ─────────────────────────────────────────────
if __name__ == "__main__":
    st.set_page_config(
        page_title="IoT IDS – Live Monitor",
        page_icon="📡",
        layout="wide"
    )
    show_live_dashboard()
