from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parents[1]
DATASET_PATH = BASE_DIR / "data" / "security_logs.csv"
MODEL_PATH = Path(__file__).resolve().parent / "security_model.joblib"
FEATURE_COLUMNS = [
    "port",
    "failed_logins",
    "bytes",
    "request_count",
    "login_success",
    "packet_count",
    "session_duration",
    "unique_ports",
    "connection_rate",
    "payload_size",
]


def load_dataset(path: Path = DATASET_PATH) -> pd.DataFrame:
    """Load and validate the generated security dataset."""
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}. Run dataset_builder.py first."
        )

    df = pd.read_csv(path)
    required = {
        "source_ip",
        "destination_ip",
        "protocol",
        "port",
        "failed_logins",
        "bytes",
        "request_count",
        "login_success",
        "packet_count",
        "session_duration",
        "unique_ports",
        "connection_rate",
        "payload_size",
        "label",
    }

    missing = required - set(df.columns)
    if missing:
        raise ValueError(f"Dataset missing required columns: {sorted(missing)}")

    if df.empty:
        raise ValueError("Dataset contains no training rows.")

    if df["label"].isna().any():
        raise ValueError("Dataset contains missing labels.")

    labels = pd.to_numeric(df["label"], errors="coerce")
    if labels.isna().any() or not set(labels.unique()).issubset({0, 1}):
        raise ValueError("Labels must contain only binary values 0 and 1.")

    for column in FEATURE_COLUMNS:
        values = pd.to_numeric(df[column], errors="coerce")
        if values.notna().sum() == 0:
            raise ValueError(f"Feature column '{column}' contains no numeric values.")

    if labels.value_counts().min() < 2:
        raise ValueError("Each label class must contain at least two rows for stratified training.")

    return df


def build_training_features(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    """Prepare numeric features and target for supervised learning."""
    X = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
    y = pd.to_numeric(df["label"], errors="raise").astype(int)

    return X, y


def train_model(
    dataset_path: Path = DATASET_PATH,
    model_path: Path = MODEL_PATH,
    test_size: float = 0.2,
    random_state: int = 42,
) -> Dict[str, Any]:
    """Train, evaluate, and save the classifier using the selected dataset."""
    if not 0 < test_size < 1:
        raise ValueError("test_size must be greater than 0 and less than 1.")

    df = load_dataset(dataset_path)
    X, y = build_training_features(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=test_size,
        random_state=random_state,
        stratify=y,
    )

    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        (
            "model",
            RandomForestClassifier(
                n_estimators=300,
                max_depth=None,
                min_samples_leaf=2,
                random_state=random_state,
            ),
        ),
    ])

    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)

    metrics = {
        "accuracy": float(accuracy_score(y_test, predictions)),
        "f1_score": float(f1_score(y_test, predictions, zero_division=0)),
        "classification_report": classification_report(
            y_test,
            predictions,
            output_dict=True,
            zero_division=0,
        ),
    }

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, model_path)

    return {
        "model_path": str(model_path.resolve()),
        "dataset_path": str(dataset_path.resolve()),
        "samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "features": FEATURE_COLUMNS,
        "metrics": metrics,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train the SOC security-log classifier.")
    parser.add_argument("--dataset", type=Path, default=DATASET_PATH)
    parser.add_argument("--model-output", type=Path, default=MODEL_PATH)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--random-state", type=int, default=42)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    result = train_model(
        dataset_path=args.dataset,
        model_path=args.model_output,
        test_size=args.test_size,
        random_state=args.random_state,
    )
    print(json.dumps(result, indent=2))