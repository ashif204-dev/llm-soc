"""Explanation and recommendation generator (Gemini, with an offline fallback)."""
import os
import time

# Main model, plus optional backups (comma-separated), e.g. set GEMINI_BACKUP_MODELS
MODEL = os.environ.get("GEMINI_MODEL", "gemini-3.8-flash")
BACKUPS = [m.strip() for m in os.environ.get("GEMINI_BACKUP_MODELS", "").split(",") if m.strip()]


def build_prompt(alert, label, confidence, severity, context):
    ctx = "\n".join(f"- {t['id']} {t['name']} ({t['tactic']}): {t['description']}" for t in context)
    return f"""You are a SOC assistant helping a security analyst.

Alert {alert['alert_id']} from {alert['src_ip']}:
- predicted type: {label} (confidence {confidence:.2f}), severity: {severity}
- protocol code {alert['protocol']}, destination port {alert['dst_port']}
- duration {alert['duration']:.1f}s, packets {alert['packets']:.0f}, bytes {alert['bytes']:.0f}
- failed logins {alert['failed_logins']}, request rate {alert['request_rate']:.1f}/s
- unique ports {alert['unique_ports']}, SYN ratio {alert['syn_ratio']:.2f}, HTTP error ratio {alert['http_error_ratio']:.2f}

Relevant MITRE ATT&CK context:
{ctx}

Write two short parts, in plain language:
EXPLANATION: 2-3 sentences on why this alert was flagged, using the numbers above.
RECOMMENDED ACTION: 2-3 concrete steps for the analyst.
Use only the information above. Do not invent facts."""


def fallback(label, severity, context):
    top = context[0]
    return (f"EXPLANATION: The classifier labels this alert as '{label}' ({severity}). "
            f"This pattern matches MITRE ATT&CK {top['id']} {top['name']}: {top['description']}\n\n"
            f"RECOMMENDED ACTION: {top['mitigation']}")


def explain(alert, label, confidence, severity, context):
    """Returns (text, source) where source is 'gemini' or 'fallback'."""
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not key:
        return fallback(label, severity, context), "fallback (no API key)"
    try:
        from google import genai
        client = genai.Client(api_key=key)
    except Exception as e:
        return fallback(label, severity, context), f"fallback ({type(e).__name__})"
    prompt = build_prompt(alert, label, confidence, severity, context)
    last_error = "unknown"
    for model in [MODEL] + BACKUPS:
        for attempt in range(3):  # retry temporary overloads
            try:
                resp = client.models.generate_content(model=model, contents=prompt)
                return resp.text.strip(), f"gemini ({model})"
            except Exception as e:
                last_error = f"{type(e).__name__}: {str(e)[:200]}"
                if "503" in str(e) or "UNAVAILABLE" in str(e) or "429" in str(e):
                    time.sleep(2 * (attempt + 1))
                    continue
                break  # other errors won't fix themselves on retry
    return fallback(label, severity, context), f"fallback ({last_error})"