"""Pattern analysis page — trending attack categories."""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from detector.storage.sqlite_store import AnalysisStore
from detector.config import settings

st.header("Pattern Analysis")

store = AnalysisStore(settings.db_path)
stats = store.get_stats()

st.subheader("Attack Category Distribution")
if stats["top_categories"]:
    import pandas as pd

    cat_df = pd.DataFrame(
        list(stats["top_categories"].items()),
        columns=["Category", "Count"],
    ).sort_values("Count", ascending=False)

    st.bar_chart(cat_df.set_index("Category"))

    st.markdown("### Category Details")
    for cat, count in stats["top_categories"].items():
        st.markdown(f"- **{cat}**: {count} detections")
else:
    st.info("No attack patterns detected yet.")

st.markdown("---")
st.subheader("Detection Volume Over Time")

timeseries = store.get_verdict_timeseries(days=30)
if timeseries:
    import pandas as pd

    ts_df = pd.DataFrame(timeseries)
    pivot = ts_df.pivot_table(index="date", columns="verdict", values="count", fill_value=0)
    st.line_chart(pivot)
else:
    st.info("Not enough data for time series analysis.")
