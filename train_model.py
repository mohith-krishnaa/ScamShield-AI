"""Train ScamShield's baseline TF-IDF + Logistic Regression classifier."""
from pathlib import Path
import json
import re
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data" / "messages.csv"
MODEL_DIR = ROOT / "models"

def main() -> None:
    df = pd.read_csv(DATA).dropna(subset=["text", "label"]).copy()
    df["text"] = df["text"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.lower().str.strip()
    df = df[df["label"].isin(["scam", "legitimate"]) & df["text"].ne("")]
    df["normalized_text"] = df["text"].map(lambda s: re.sub(r"\s+", " ", s.lower()).strip())
    if (df.groupby("normalized_text")["label"].nunique() > 1).any():
        raise ValueError("Conflicting labels for duplicate normalized messages. Fix data/messages.csv first.")
    df = df.drop_duplicates("normalized_text")
    if len(df) < 20 or df["label"].nunique() != 2 or df["label"].value_counts().min() < 4:
        raise ValueError("Dataset needs at least 20 unique rows and at least 4 samples per label.")
    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.25, random_state=42, stratify=df["label"]
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), lowercase=True, strip_accents="unicode",
                                  max_features=12000, sublinear_tf=True)),
        ("classifier", LogisticRegression(max_iter=1500, class_weight="balanced", random_state=42)),
    ])
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    report = classification_report(y_test, pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, pred, labels=["legitimate", "scam"])
    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_DIR / "scamshield_model.joblib")
    payload = {
        "dataset_type": "small hand-written illustrative starter dataset",
        "dataset_rows_after_deduplication": int(len(df)),
        "train_rows": int(len(X_train)), "test_rows": int(len(X_test)),
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "confusion_matrix_labels_legitimate_scam": cm.tolist(),
        "classification_report": report,
        "caution": "Not a real-world benchmark; small synthetic examples may be easy to separate.",
    }
    (MODEL_DIR / "evaluation.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print("Held-out split evaluation — illustrative starter data only:")
    print(classification_report(y_test, pred, zero_division=0))
    print("Confusion matrix [[TN, FP], [FN, TP]]:", cm.tolist())
    print(f"Saved model to {MODEL_DIR / 'scamshield_model.joblib'}")

if __name__ == "__main__":
    main()
