"""Command-line demo: analyze a few alerts without the dashboard."""
import pandas as pd
from src.pipeline import SocPipeline

pipe = SocPipeline()
print("Retrieval backend:", pipe.retriever.backend)
df = pd.read_csv("data/test_alerts.csv")
for _, row in df.groupby("label").head(1).iterrows():
    r = pipe.analyze(row)
    print("\n" + "=" * 70)
    print(f"{row['alert_id']} true={row['label']} -> predicted={r['label']} "
          f"({r['confidence']:.2f}) severity={r['severity']}")
    print("Context:", ", ".join(f"{t['id']} {t['name']}" for t in r["context"]))
    print(f"[{r['llm_source']}]")
    print(r["explanation"])
