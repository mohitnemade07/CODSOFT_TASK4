
import pandas as pd
import streamlit as st

from nids_engine import get_events

st.set_page_config(
    page_title="Network Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Network Intrusion Detection System")
st.caption("Suspicious network activity and security alerts")

events = get_events()
df = pd.DataFrame(events)

if df.empty:
    st.info(
        "No alerts recorded yet. Run test_nids.py or start the "
        "packet monitor to generate detection events."
    )
    high_count = medium_count = low_count = 0
else:
    high_count = int((df["severity"] == "High").sum())
    medium_count = int((df["severity"] == "Medium").sum())
    low_count = int((df["severity"] == "Low").sum())

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Alerts", len(events))
col2.metric("High Severity", high_count)
col3.metric("Medium Severity", medium_count)
col4.metric("Low Severity", low_count)

if not df.empty:
    st.subheader("Alerts by Severity")
    severity_counts = (
        df["severity"]
        .value_counts()
        .reindex(["High", "Medium", "Low"], fill_value=0)
    )
    st.bar_chart(severity_counts)

    st.subheader("Recent Security Events")
    st.dataframe(
        df.sort_values("timestamp", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

    st.download_button(
        "Download Alert Log (CSV)",
        data=df.to_csv(index=False).encode("utf-8"),
        file_name="nids_alerts.csv",
        mime="text/csv",
    )

if st.button("Refresh alerts"):
    st.rerun()

st.divider()
st.caption(
    "Educational prototype. Alerts indicate suspicious patterns, "
    "not confirmed attacks. Only monitor networks you are authorized to inspect."
)

# Automatic refresh
from streamlit_autorefresh import st_autorefresh
st_autorefresh(interval=5000, key="nids_refresh")
