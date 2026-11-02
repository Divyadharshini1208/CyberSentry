"""Tests for SentinelX ML Pipeline and Feature Extractor."""

import pytest
from backend.app.ml.feature_extractor import URLFeatureExtractor, FEATURE_NAMES, shannon_entropy
from backend.app.ml.model import UrlClassifier, url_classifier
from backend.app.ml.trainer import evaluate_model


def test_feature_extractor_keys_and_values():
    url = "https://sub.secure-example.xyz/login?session=abc#test"
    features = URLFeatureExtractor.extract_features(url)
    
    for key in FEATURE_NAMES:
        assert key in features, f"Missing feature: {key}"
        assert isinstance(features[key], (int, float))

    assert features["is_https"] == 1.0
    assert features["has_suspicious_tld"] == 1.0
    assert features["has_auth_path"] == 1.0
    assert features["subdomain_count"] >= 1.0


def test_feature_extractor_ip_address():
    ip_url = "http://192.168.1.100/index.php"
    features = URLFeatureExtractor.extract_features(ip_url)
    assert features["is_ip_address"] == 1.0
    assert features["is_https"] == 0.0


def test_shannon_entropy():
    assert shannon_entropy("") == 0.0
    assert shannon_entropy("aaaaaa") == 0.0
    assert shannon_entropy("abcdef") > 2.0


def test_feature_vector_dimension():
    vector = URLFeatureExtractor.to_vector("https://test.com")
    assert len(vector) == len(FEATURE_NAMES)
    assert len(vector) == 17


def test_url_classifier_benign():
    result = url_classifier.predict("https://docs.python.org/3/library/urllib.html")
    assert result["status"] == "evaluated"
    assert result["prediction"] == "benign"
    assert result["riskScore"] < 50
    assert "probability" in result
    assert "confidence" in result


def test_url_classifier_malicious():
    result = url_classifier.predict("http://paypa1-security-verify.xyz/account/login?token=abc")
    assert result["status"] == "evaluated"
    assert result["prediction"] == "malicious"
    assert result["riskScore"] >= 50


def test_evaluate_model():
    metrics = evaluate_model()
    assert metrics["samplesTotal"] >= 30
    assert metrics["trainCount"] > 0
    assert metrics["testCount"] > 0
    assert metrics["featureCount"] == 17
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert 0.0 <= metrics["precision"] <= 1.0
    assert 0.0 <= metrics["recall"] <= 1.0
    assert 0.0 <= metrics["f1"] <= 1.0
    assert len(metrics["confusionMatrix"]) == 2

