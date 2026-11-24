"""End-to-end pipeline: detect -> triage -> retrieve -> explain."""
import joblib
from src.generate_data import FEATURES
from src.llm import explain
from src.retrieval import Retriever
from src.triage import triage

QUERY_HINT = {
    "benign": "benign normal traffic false positive routine",
    "brute_force": "brute force repeated failed logins credential guessing",
    "dos": "denial of service flood high packet rate",
    "port_scan": "port scan service discovery many ports reconnaissance",
    "web_attack": "web attack exploit public-facing application http errors",
}


class SocPipeline:
    def __init__(self, model_path="models/rf_model.joblib", kb_path="data/attack_kb.json"):
        self.model = joblib.load(model_path)
        self.retriever = Retriever(kb_path)

    def detect(self, row):
        x = row[FEATURES].to_frame().T.astype(float)
        probs = self.model.predict_proba(x)[0]
        i = probs.argmax()
        label = str(self.model.classes_[i])
        conf = float(probs[i])
        return label, conf, triage(label, conf)

    def detect_all(self, df):
        probs = self.model.predict_proba(df[FEATURES].astype(float))
        idx = probs.argmax(axis=1)
        out = df[["alert_id", "src_ip", "dst_port"]].copy()
        out["predicted"] = [str(self.model.classes_[i]) for i in idx]
        out["confidence"] = probs.max(axis=1).round(2)
        out["severity"] = [triage(l, c) for l, c in zip(out["predicted"], out["confidence"])]
        return out

    def analyze(self, row):
        label, conf, severity = self.detect(row)
        query = (f"{QUERY_HINT[label]} port {row['dst_port']} failed logins {row['failed_logins']} "
                 f"request rate {row['request_rate']:.0f} unique ports {row['unique_ports']}")
        context = self.retriever.search(query, k=3)
        text, source = explain(row, label, conf, severity, context)
        return {"label": label, "confidence": conf, "severity": severity,
                "context": context, "explanation": text, "llm_source": source}
