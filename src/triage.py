"""Rule-based mapping from classifier output to a severity category."""
CRITICAL_TYPES = {"brute_force", "dos", "web_attack"}


def triage(label: str, confidence: float) -> str:
    if label == "benign":
        return "False positive"
    if label in CRITICAL_TYPES and confidence >= 0.80:
        return "Critical"
    return "Non-critical"
