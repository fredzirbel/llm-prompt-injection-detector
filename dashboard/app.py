"""Streamlit dashboard entry point."""

import streamlit as st

st.set_page_config(
    page_title="Prompt Injection Detector — Dashboard",
    page_icon="🛡",  # noqa
    layout="wide",
)

st.title("Prompt Injection Detector")
st.markdown("Real-time monitoring dashboard for LLM prompt injection detection.")
st.markdown("---")
st.markdown("Select a page from the sidebar to view detection analytics.")
