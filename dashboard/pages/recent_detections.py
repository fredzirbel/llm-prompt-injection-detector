"""Recent detections page — table of recent flagged prompts."""

import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from detector.storage.sqlite_store import AnalysisStore
from detector.config import settings

st.header("Recent Detections")

store = AnalysisStore(settings.db_path)

filter_verdict = st.selectbox(
    "Filter by verdict",
    ["All", "MALICIOUS", "SUSPICIOUS", "CLEAN"],
)

recent = store.get_recent(limit=100)

if filter_verdict != "All":
    recent = [r for r in recent if r["verdict"] == filter_verdict]

if recent:
    import pandas as pd

    df = pd.DataFrame(recent)
    display_cols = [
        "timestamp", "verdict", "confidence", "primary_category",
        "triggered_detectors", "prompt_length", "latency_ms",
    ]
    available_cols = [c for c in display_cols if c in df.columns]
    st.dataframe(df[available_cols], use_container_width=True)
else:
    st.info("No detections recorded yet. Send prompts to the /analyze endpoint.")
