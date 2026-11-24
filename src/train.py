"""Train the Random Forest detector and save metrics + held-out test alerts."""
import json
import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (accuracy_score, classification_report,
                             confusion_matrix, precision_recall_fscore_support)
from sklearn.model_selection import train_test_split

from src.generate_data import FEATURES, LABELS, generate


def main():
    os.makedirs("models", exist_ok=True)
    os.makedirs("data", exist_ok=True)
    df = generate()
    df.to_csv("data/alerts.csv", index=False)
    train, test = train_test_split(df, test_size=0.25, random_state=42, stratify=df.label)
    model = RandomForestClassifier(n_estimators=200, random_state=42, n_jobs=-1)
    model.fit(train[FEATURES], train.label)
    pred = model.predict(test[FEATURES])
    acc = accuracy_score(test.label, pred)
    p, r, f1, _ = precision_recall_fscore_support(test.label, pred, average="weighted", zero_division=0)
    cm = confusion_matrix(test.label, pred, labels=LABELS)
    print(classification_report(test.label, pred, zero_division=0))
    print("Confusion matrix (rows=true, cols=pred):", LABELS)
    print(cm)
    print(f"Accuracy: {acc:.4f}")
    joblib.dump(model, "models/rf_model.joblib")
    test.to_csv("data/test_alerts.csv", index=False)
    json.dump({"accuracy": acc, "precision": p, "recall": r, "f1": f1,
               "labels": LABELS, "confusion_matrix": cm.tolist(), "n_test": len(test)},
              open("models/metrics.json", "w"), indent=2)
    print("Saved models/rf_model.joblib, models/metrics.json, data/test_alerts.csv")


if __name__ == "__main__":
    main()
