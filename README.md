# LLM-assisted SOC

A prototype Security Operations Center (SOC) assistant that triages security alerts, links each one to MITRE ATT&CK techniques, and writes a plain-language explanation and recommended response for a human analyst to approve.

B.Tech major project (Phase-II prototype), School of Computer Science and Engineering, IILM University, Greater Noida, 2026-27.

**Live portfolio:** https://mohammad-ashif-hussain-llm-assisted-soc-cd-d89fab3615.netlify.app

## How it works

```
Alert -> Random Forest detection -> Severity triage -> Chroma retrieval (MITRE ATT&CK) -> Gemini explanation -> Analyst approve / reject
```

1. **Data:** simulated SIEM-style alerts based on the CICIDS2017 attack categories (benign, brute force, DoS, port scan, web attack).
2. **Detection:** a Random Forest predicts the alert type and a confidence score.
3. **Triage:** simple rules map the result to critical, non-critical or false positive.
4. **Retrieval (RAG):** Chroma finds the closest MITRE ATT&CK techniques in a small local knowledge base. If Chroma can't load, it falls back to TF-IDF.
5. **Explanation:** Gemini writes why the alert was flagged and what to do next. Without an API key, or if the API is unavailable, the app uses an offline fallback built from the knowledge base.
6. **Review:** a Streamlit dashboard lets the analyst approve or reject each recommendation. Decisions are saved to `data/decisions.csv`.

## Results

Measured on 750 held-out simulated alerts (25% of 3,000):

| Class | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| benign | 0.98 | 0.99 | 0.99 | 296 |
| brute_force | 0.96 | 0.95 | 0.95 | 116 |
| dos | 0.96 | 0.95 | 0.96 | 110 |
| port_scan | 0.98 | 0.96 | 0.97 | 112 |
| web_attack | 0.96 | 0.96 | 0.96 | 116 |

Overall accuracy: **0.9707**. The data is simulated, so these numbers are indicative and are not a measure of real-world performance.

## Setup

Requires Python 3.10 or newer.

```
python -m venv .venv
.venv\Scripts\Activate.ps1      # Windows PowerShell
source .venv/bin/activate       # macOS / Linux
pip install -r requirements.txt
```

## Run

```
python -m src.train             # generate data, train the model, print metrics
python run_demo.py              # optional command-line check
streamlit run app.py            # dashboard at http://localhost:8501
```

## Gemini setup (optional)

Create a free key in Google AI Studio and set it in the same terminal where you run the app. Never put the key in a file or commit it.

```
$env:GEMINI_API_KEY = Read-Host "Paste your Gemini key"    # Windows PowerShell
export GEMINI_API_KEY=your_key                             # macOS / Linux
```

Optional settings:

- `GEMINI_MODEL`: the main model (default `gemini-3.8-flash`).
- `GEMINI_BACKUP_MODELS`: comma-separated backup models, used if the main model is overloaded, for example `gemini-3.6-flash,gemini-3.1-flash-lite`.

Model names change over time. List the ones your key can use with:

```
python -c "from google import genai; import os; c=genai.Client(api_key=os.environ['GEMINI_API_KEY']); print([m.name for m in c.models.list() if 'gemini' in m.name])"
```

## Project layout

```
app.py                 Streamlit dashboard
run_demo.py            Command-line demo
src/generate_data.py   Simulated alert generator
src/train.py           Random Forest training and metrics
src/triage.py          Severity rules
src/retrieval.py       Chroma / TF-IDF retrieval over ATT&CK data
src/llm.py             Gemini prompt, retries and offline fallback
src/pipeline.py        End-to-end flow
data/attack_kb.json    MITRE ATT&CK knowledge base (9 entries)
```

## Limitations

- Alerts are simulated; validation on the real CICIDS2017 dataset is future work.
- The ATT&CK knowledge base has only 9 entries.
- LLM output depends on the Gemini service. LLM recommendations have not yet been scored in a formal manual review.

## Team

Aditya Raj, Raj Aryan, Mohammad Ashif Hussain, Nayandeep Prakash. Guide: Dr. Ashish Sharma.
