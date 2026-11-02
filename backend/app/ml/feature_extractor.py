"""SentinelX ML Feature Extractor
Extracts lexical, statistical, and structural features from URLs for machine learning classification.
"""

import math
import re
from typing import Dict, List
from urllib.parse import urlparse

FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "dot_count",
    "hyphen_count",
    "at_symbol_count",
    "slash_count",
    "digit_count_host",
    "digit_ratio_host",
    "hostname_entropy",
    "is_ip_address",
    "is_https",
    "subdomain_count",
    "has_brand_keyword",
    "has_suspicious_tld",
    "has_auth_path"
]

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "buzz", "club", "work",
    "click", "link", "stream", "icu", "cam", "monster", "sbs", "cfd"
}

KNOWN_BRANDS = [
    "google", "microsoft", "apple", "paypal", "amazon", "netflix", "facebook",
    "instagram", "linkedin", "twitter", "chase", "bofa", "wellsfargo"
]


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


class URLFeatureExtractor:
    @staticmethod
    def extract_features(url: str) -> Dict[str, float]:
        """Extracts a normalized feature map from a target URL."""
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

        is_ip = 1.0 if re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname) else 0.0
        is_https = 1.0 if parsed.scheme.lower() == "https" else 0.0

        parts = hostname.split(".")
        tld = parts[-1] if parts else ""
        subdomain_count = float(max(0, len(parts) - 2))

        digit_count = sum(c.isdigit() for c in hostname)
        digit_ratio = (digit_count / len(hostname)) if len(hostname) > 0 else 0.0

        has_brand = 1.0 if any(b in hostname for b in KNOWN_BRANDS) else 0.0
        has_tld = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
        has_auth = 1.0 if any(k in path.lower() for k in ["login", "signin", "auth", "verify", "webscr"]) else 0.0

        features = {
            "url_length": float(len(url)),
            "hostname_length": float(len(hostname)),
            "path_length": float(len(path)),
            "query_length": float(len(query)),
            "dot_count": float(url.count(".")),
            "hyphen_count": float(url.count("-")),
            "at_symbol_count": float(url.count("@")),
            "slash_count": float(url.count("/")),
            "digit_count_host": float(digit_count),
            "digit_ratio_host": float(round(digit_ratio, 4)),
            "hostname_entropy": float(round(shannon_entropy(hostname), 4)),
            "is_ip_address": is_ip,
            "is_https": is_https,
            "subdomain_count": subdomain_count,
            "has_brand_keyword": has_brand,
            "has_suspicious_tld": has_tld,
            "has_auth_path": has_auth
        }

        return features

    @classmethod
    def to_vector(cls, url: str) -> List[float]:
        feat = cls.extract_features(url)
        return [feat[name] for name in FEATURE_NAMES]
