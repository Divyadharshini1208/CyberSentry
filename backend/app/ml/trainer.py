"""SentinelX ML Trainer & Model Evaluation Pipeline
Provides reproducible train/validation/test evaluation and performance metrics.
"""

from typing import Dict, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split
from backend.app.ml.feature_extractor import URLFeatureExtractor
from backend.app.ml.model import BENIGN_SAMPLES, MALICIOUS_SAMPLES


def evaluate_model() -> Dict[str, Any]:
    """Evaluates the classifier using train/test separation and computes classification metrics."""
    X = []
    y = []

    for u in BENIGN_SAMPLES:
        X.append(URLFeatureExtractor.to_vector(u))
        y.append(0)

    for u in MALICIOUS_SAMPLES:
        X.append(URLFeatureExtractor.to_vector(u))
        y.append(1)

    X = np.array(X)
    y = np.array(y)

    # 70% train, 30% test with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(n_estimators=30, max_depth=5, random_state=42)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    return {
        "samplesTotal": len(X),
        "trainCount": len(X_train),
        "testCount": len(X_test),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "confusionMatrix": cm,
        "featureCount": X.shape[1]
    }
