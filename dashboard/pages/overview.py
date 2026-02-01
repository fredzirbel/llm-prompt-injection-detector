"""Overview dashboard page — detection stats and volume."""

import sys
from pathlib import Path

import streamlit as st

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from detector.storage.sqlite_store import AnalysisStore
from detector.config import settings

st.header("Detection Overview")

store = AnalysisStore(settings.db_path)
stats = store.get_stats()

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Analyzed", stats["total_analyzed"])
col2.metric("Clean", stats["total_clean"])
col3.metric("Suspicious", stats["total_suspicious"])
col4.metric("Malicious", stats["total_malicious"])

st.markdown("---")

st.subheader("Verdict Breakdown")
if stats["total_analyzed"] > 0:
    import pandas as pd

    verdict_data = pd.DataFrame({
        "Verdict": ["CLEAN", "SUSPICIOUS", "MALICIOUS"],
        "Count": [stats["total_clean"], stats["total_suspicious"], stats["total_malicious"]],
    })
    st.bar_chart(verdict_data.set_index("Verdict"))

st.subheader("Top Attack Categories")
if stats["top_categories"]:
    cat_data = pd.DataFrame(
        list(stats["top_categories"].items()),
        columns=["Category", "Count"],
    )
    st.bar_chart(cat_data.set_index("Category"))
else:
    st.info("No attack categories detected yet.")
