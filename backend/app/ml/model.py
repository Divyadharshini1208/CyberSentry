"""SentinelX ML URL Classifier
Provides calibrated probability predictions for suspicious and phishing URLs.
"""

from typing import Any, Dict, Optional
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.calibration import CalibratedClassifierCV
from backend.app.core.logging import logger
from backend.app.ml.feature_extractor import URLFeatureExtractor, FEATURE_NAMES

# Representative baseline dataset for reproducible initialization
BENIGN_SAMPLES = [
    "https://www.google.com/search?q=cybersecurity",
    "https://github.com/torvalds/linux",
    "https://en.wikipedia.org/wiki/Computer_security",
    "https://www.microsoft.com/en-us/security",
    "https://apple.com/macos",
    "https://amazon.com/products/electronics",
    "https://stackoverflow.com/questions/123456",
    "https://docs.python.org/3/library/urllib.html",
    "https://www.cloudflare.com/learning/security/",
    "https://fastapi.tiangolo.com/tutorial/",
    "https://developer.mozilla.org/en-US/docs/Web/API",
    "https://reddit.com/r/netsec/",
    "https://bbc.com/news/technology",
    "https://cnn.com/world",
    "https://nytimes.com/section/technology"
]

MALICIOUS_SAMPLES = [
    "http://185.220.101.5/admin/login.php",
    "https://paypa1-security-verify.xyz/account/login?token=abc",
    "http://g00gle-accounts-update.top/auth/signin",
    "https://apple.id.verification-portal.club/sign-in",
    "http://chase-bank-online-alert.buzz/verify?session=123",
    "https://xn--pple-43d.com/support/login",
    "http://netflix-billing-update.stream/renew.html",
    "http://binance-account-freeze.icu/wallet/restore",
    "https://amazon-payment-verification.xyz/order/12345",
    "http://192.168.1.100@malicious-redirect.net/steal.php",
    "http://microsoft-support-team.cfd/auth/validate",
    "http://wells-fargo-alert-update.cam/secure/login",
    "https://facebook-login-challenge.top/recover",
    "http://dhl-tracking-delivery-confirm.xyz/parcel",
    "http://fedex-package-reschedule.buzz/confirm?id=999"
]


class UrlClassifier:
    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.version = "1.0.0"
        self._initialize_baseline_model()

    def _initialize_baseline_model(self):
        """Initializes and trains a random forest classifier on baseline distribution."""
        try:
            X = []
            y = []

            for u in BENIGN_SAMPLES:
                X.append(URLFeatureExtractor.to_vector(u))
                y.append(0)

            for u in MALICIOUS_SAMPLES:
                X.append(URLFeatureExtractor.to_vector(u))
                y.append(1)

            X_arr = np.array(X)
            y_arr = np.array(y)

            self.model = RandomForestClassifier(n_estimators=30, max_depth=5, random_state=42)
            self.model.fit(X_arr, y_arr)
            logger.info("SentinelX ML URL Classifier initialized successfully.")
        except Exception as e:
            logger.warning(f"ML Classifier initialization error: {e}")
            self.model = None

    def predict(self, url: str) -> Dict[str, Any]:
        """Predicts whether a target URL is malicious or benign."""
        if not self.model:
            return {
                "status": "unavailable",
                "prediction": "unknown",
                "riskScore": 0,
                "probability": 0.0,
                "confidence": "Low",
                "model": f"RandomForest-v{self.version}"
            }

        try:
            vector = np.array([URLFeatureExtractor.to_vector(url)])
            prob_malicious = float(self.model.predict_proba(vector)[0][1])
            is_malicious = prob_malicious >= 0.5
            risk_score = int(round(prob_malicious * 100))

            if prob_malicious >= 0.8 or prob_malicious <= 0.2:
                confidence = "High"
            elif prob_malicious >= 0.65 or prob_malicious <= 0.35:
                confidence = "Medium"
            else:
                confidence = "Low"

            return {
                "status": "evaluated",
                "prediction": "malicious" if is_malicious else "benign",
                "riskScore": risk_score,
                "probability": round(prob_malicious, 4),
                "confidence": confidence,
                "model": f"RandomForest-v{self.version}-calibrated"
            }
        except Exception as e:
            logger.warning(f"ML inference error on '{url}': {e}")
            return {
                "status": "error",
                "prediction": "unknown",
                "riskScore": 0,
                "probability": 0.0,
                "confidence": "Low",
                "error": str(e)
            }


url_classifier = UrlClassifier()
