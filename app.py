"""Streamlit analyst dashboard for the LLM-assisted SOC prototype."""
import json
import os

import pandas as pd
import streamlit as st

st.set_page_config(page_title="LLM-assisted SOC", layout="wide")

if not (os.path.exists("models/rf_model.joblib") and os.path.exists("data/test_alerts.csv")):
    st.error("Model not found. Run `python -m src.train` first, then restart the app.")
    st.stop()

from src.pipeline import SocPipeline  # noqa: E402


@st.cache_resource
def load_pipeline():
    return SocPipeline()


@st.cache_data
def load_queue():
    df = pd.read_csv("data/test_alerts.csv")
    return df


pipe = load_pipeline()
alerts = load_queue()
queue = pipe.detect_all(alerts)
metrics = json.load(open("models/metrics.json"))

st.session_state.setdefault("decisions", {})
st.session_state.setdefault("analysis", {})

st.title("LLM-assisted SOC")
st.caption("Alert triage with ML detection, MITRE ATT&CK retrieval and LLM explanations. "
           "Every recommendation needs analyst approval.")

with st.sidebar:
    st.header("System")
    st.metric("Classifier accuracy", f"{metrics['accuracy'] * 100:.1f}%")
    st.write(f"F1 (weighted): {metrics['f1']:.3f}")
    st.write(f"Test alerts: {metrics['n_test']}")
    st.write(f"Retrieval: {pipe.retriever.backend}")
    has_key = bool(os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY"))
    st.write("LLM: Gemini" if has_key else "LLM: offline fallback (set GEMINI_API_KEY)")
    st.divider()
    sev_filter = st.multiselect("Severity", ["Critical", "Non-critical", "False positive"],
                                default=["Critical", "Non-critical", "False positive"])
    with st.expander("Confusion matrix"):
        cm = pd.DataFrame(metrics["confusion_matrix"], index=metrics["labels"], columns=metrics["labels"])
        st.dataframe(cm)

counts = queue["severity"].value_counts()
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total alerts", len(queue))
c2.metric("Critical", int(counts.get("Critical", 0)))
c3.metric("Non-critical", int(counts.get("Non-critical", 0)))
c4.metric("False positive", int(counts.get("False positive", 0)))

view = queue[queue["severity"].isin(sev_filter)].copy()
view["decision"] = view["alert_id"].map(st.session_state["decisions"]).fillna("pending")

left, right = st.columns([1.2, 1])
with left:
    st.subheader("Alert queue")
    st.dataframe(view, use_container_width=True, height=420, hide_index=True)

with right:
    st.subheader("Alert details")
    if view.empty:
        st.info("No alerts match the selected severity filter.")
        st.stop()
    alert_id = st.selectbox("Select an alert", view["alert_id"].tolist())
    row = alerts[alerts["alert_id"] == alert_id].iloc[0]
    if alert_id not in st.session_state["analysis"]:
        with st.spinner("Analyzing alert..."):
            st.session_state["analysis"][alert_id] = pipe.analyze(row)
    res = st.session_state["analysis"][alert_id]

    st.write(f"**Predicted:** {res['label']} (confidence {res['confidence']:.2f})")
    st.write(f"**Severity:** {res['severity']}")
    st.write("**ATT&CK context:** " + ", ".join(f"{t['id']} {t['name']}" for t in res["context"]))
    st.markdown("**Explanation and recommendation**")
    st.write(res["explanation"])
    st.caption(f"Source: {res['llm_source']}")

    b1, b2 = st.columns(2)
    decision = None
    if b1.button("Approve", use_container_width=True):
        decision = "approved"
    if b2.button("Reject", use_container_width=True):
        decision = "rejected"
    if decision:
        st.session_state["decisions"][alert_id] = decision
        log = pd.DataFrame([{"alert_id": alert_id, "predicted": res["label"],
                             "severity": res["severity"], "decision": decision,
                             "time": pd.Timestamp.now().isoformat(timespec="seconds")}])
        log.to_csv("data/decisions.csv", mode="a", header=not os.path.exists("data/decisions.csv"),
                   index=False)
        st.success(f"{alert_id} {decision}")
        st.rerun()
    current = st.session_state["decisions"].get(alert_id)
    if current:
        st.info(f"Current decision: {current}")
