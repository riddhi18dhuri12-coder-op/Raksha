"""
RAKSHA -- URL Analyzer endpoint.

Ported from the standalone "secure-url-analyzer" project (FastAPI backend +
trained logistic-regression model on the PhiUSIIL phishing-URL dataset).
Same detection logic, folded into RAKSHA's backend so it shows up as a page
in the same dashboard instead of a separate app:

  - feature_extractor: lexical URL features (length, entropy, suspicious
    keywords, IP-literal host, etc.)
  - ML model: trained LogisticRegression classifier -> phishing / legitimate
  - WHOIS / SSL / DNS lookups: live checks against the real domain
  - threat_engine: combines all of the above into a single risk score

WHOIS/SSL/DNS all make real outbound network calls and are wrapped in
try/except (as in the original project) so a lookup failure degrades
gracefully instead of failing the whole scan.
"""

import math
import re
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import joblib
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/api/url-analyzer", tags=["url-analyzer"])

_MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "url_analyzer_model.pkl"
_MODEL = joblib.load(_MODEL_PATH)

SUSPICIOUS_WORDS = [
    "login", "verify", "secure", "update", "bank", "wallet", "paypal",
    "signin", "account", "free", "gift", "bonus", "confirm",
]


class UrlScanRequest(BaseModel):
    url: str


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    entropy = 0.0
    for c in set(text):
        p = text.count(c) / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 2)


def _extract_features(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    host = parsed.hostname or ""
    return {
        "url_length": len(url),
        "hostname_length": len(host),
        "path_length": len(parsed.path),
        "dot_count": host.count("."),
        "hyphen_count": host.count("-"),
        "digit_count": len(re.findall(r"\d", url)),
        "special_symbol_count": len(re.findall(r"[@?=&_%]", url)),
        "uses_https": url.startswith("https://"),
        "contains_ip": bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", host)),
        "subdomain_depth": max(0, host.count(".") - 1),
        "entropy": _shannon_entropy(url),
        "suspicious_keywords": [w for w in SUSPICIOUS_WORDS if w in url.lower()],
    }


def _predict_url(url: str) -> dict:
    features = _extract_features(url)
    x = [[
        features["url_length"],
        features["hostname_length"],
        features["path_length"],
        features["dot_count"],
        features["hyphen_count"],
        features["digit_count"],
        features["special_symbol_count"],
        int(features["uses_https"]),
        int(features["contains_ip"]),
        features["subdomain_depth"],
        features["entropy"],
        len(features["suspicious_keywords"]),
    ]]
    prediction = int(_MODEL.predict(x)[0])
    probabilities = _MODEL.predict_proba(x)[0]
    return {
        "prediction": prediction,
        "verdict": "Legitimate" if prediction == 1 else "Phishing",
        "legitimate_probability": float(round(probabilities[1] * 100, 2)),
        "phishing_probability": float(round(probabilities[0] * 100, 2)),
        "features": features,
    }


def _get_whois_info(domain: str) -> dict:
    try:
        import whois  # python-whois; imported lazily so a missing dep only breaks this lookup
        data = whois.whois(domain)
        creation = data.creation_date
        expiration = data.expiration_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(expiration, list):
            expiration = expiration[0]
        age_days = None
        if creation:
            if hasattr(creation, "tzinfo") and creation.tzinfo is not None:
                creation = creation.replace(tzinfo=None)
            age_days = (datetime.now() - creation).days
        return {
            "registrar": data.registrar,
            "creation_date": str(creation),
            "expiration_date": str(expiration),
            "domain_age_days": age_days,
        }
    except Exception as e:  # noqa: BLE001 -- intentionally broad, mirrors upstream
        return {"error": str(e)}


def _get_ssl_info(hostname: str) -> dict:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert["issuer"])
                expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.now(timezone.utc).replace(tzinfo=None)).days
                return {
                    "valid": True,
                    "issuer": issuer.get("organizationName"),
                    "expires": str(expiry),
                    "days_remaining": days_left,
                    "protocol": ssock.version(),
                }
    except socket.timeout:
        return {"valid": False, "reason": "Connection timed out"}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "reason": "Certificate verification failed"}
    except socket.gaierror:
        return {"valid": False, "reason": "Hostname could not be resolved"}
    except Exception as e:  # noqa: BLE001
        return {"valid": False, "reason": str(e)}


def _get_dns_info(domain: str) -> dict:
    try:
        import dns.resolver  # dnspython; imported lazily
        result = {}
        for record_type, key, extract in (
            ("A", "A", lambda r: r.to_text()),
            ("MX", "MX", lambda r: r.exchange.to_text()),
            ("NS", "NS", lambda r: r.to_text()),
            ("TXT", "TXT", lambda r: r.to_text()),
        ):
            try:
                answers = dns.resolver.resolve(domain, record_type)
                result[key] = [extract(r) for r in answers]
            except Exception:  # noqa: BLE001
                result[key] = []
        return result
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}


def _calculate_risk(prediction: dict, whois: dict, ssl_info: dict, dns_info: dict) -> dict:
    score = 0
    reasons = []

    if prediction["prediction"] == 0:
        score += 40
        reasons.append("Machine learning model classified this URL as phishing.")

    age = whois.get("domain_age_days")
    if age is not None and age < 30:
        score += 25
        reasons.append("Domain was registered less than 30 days ago.")

    if ssl_info.get("valid") is False:
        score += 15
        reasons.append("SSL certificate is invalid or unavailable.")

    if len(dns_info.get("MX", [])) == 0:
        score += 10
        reasons.append("No MX records found.")
    if len(dns_info.get("NS", [])) == 0:
        score += 10
        reasons.append("No Name Server records found.")

    if len(prediction["features"]["suspicious_keywords"]) > 0:
        score += 15
        reasons.append(
            "Suspicious keyword(s): " + ", ".join(prediction["features"]["suspicious_keywords"])
        )

    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"

    return {"risk_score": score, "risk_level": level, "reasons": reasons}


@router.post("/scan")
def scan_url(request: UrlScanRequest):
    prediction = _predict_url(request.url)

    url = request.url
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    hostname = urlparse(url).hostname or ""

    whois_info = _get_whois_info(hostname)
    ssl_info = _get_ssl_info(hostname)
    dns_info = _get_dns_info(hostname)
    threat = _calculate_risk(prediction, whois_info, ssl_info, dns_info)

    return {
        "prediction": prediction,
        "whois": whois_info,
        "ssl": ssl_info,
        "dns": dns_info,
        "threat_analysis": threat,
    }
