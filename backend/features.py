from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import urlparse

FEATURE_NAMES: List[str] = [
    "url_length",
    "hostname_length",
    "dot_count",
    "hyphen_count",
    "has_ip_address",
    "has_https",
    "subdomain_count",
    "suspicious_keyword_count",
    "has_punycode",
    "is_shortener",
]

SUSPICIOUS_KEYWORDS: Tuple[str, ...] = (
    "login",
    "signin",
    "verify",
    "account",
    "secure",
    "update",
    "confirm",
    "bank",
    "banking",
    "paypal",
    "password",
    "wallet",
    "credential",
    "suspended",
    "urgent",
    "recover",
    "auth",
    "billing",
    "invoice",
    "reward",
    "claim",
    "bonus",
    "kyc",
    "otp",
)

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "rebrand.ly",
}

BRAND_TOKENS: Tuple[str, ...] = (
    "paypal",
    "amazon",
    "apple",
    "microsoft",
    "google",
    "netflix",
    "chase",
    "wellsfargo",
    "citibank",
    "hdfc",
    "icici",
    "sbi",
    "metamask",
    "coinbase",
    "binance",
    "dropbox",
    "instagram",
    "whatsapp",
)


def validate_http_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if not url:
        raise ValueError("URL cannot be empty.")
    if re.search(r"\s", url):
        raise ValueError("URL cannot contain whitespace.")

    parsed = urlparse(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// URLs are permitted.")
    if not parsed.hostname:
        raise ValueError("URL must include a valid hostname.")
    return url


def _is_ip_address(hostname: str) -> bool:
    clean = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean)
        return True
    except ValueError:
        return False


def extract_features_dict(url: str) -> Dict[str, Any]:
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()
    is_ip = _is_ip_address(hostname)
    labels = [lbl for lbl in hostname.split(".") if lbl]
    subdomain_count = 0 if is_ip else max(0, len(labels) - 2)

    lower_url = url.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_url]
    bare_host = hostname[4:] if hostname.startswith("www.") else hostname

    return {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "dot_count": url.count("."),
        "hyphen_count": hostname.count("-"),
        "has_ip_address": 1 if is_ip else 0,
        "has_https": 1 if parsed.scheme.lower() == "https" else 0,
        "subdomain_count": subdomain_count,
        "suspicious_keyword_count": len(matched_keywords),
        "has_punycode": 1 if "xn--" in hostname else 0,
        "is_shortener": 1 if (bare_host in URL_SHORTENERS or hostname in URL_SHORTENERS) else 0,
        "_hostname": hostname,
        "_matched_keywords": matched_keywords,
        "_has_at_symbol": "@" in url,
    }


def extract_feature_vector(url: str) -> List[int]:
    feats = extract_features_dict(url)
    return [int(feats[name]) for name in FEATURE_NAMES]


def explain_url_indicators(url: str, feats: Dict[str, Any]) -> Tuple[List[str], List[Dict[str, str]], int]:
    indicators: List[str] = []
    details: List[Dict[str, str]] = []
    heuristic_adj = 0
    hostname: str = feats["_hostname"]
    matched_keywords: List[str] = feats["_matched_keywords"]

    if feats["has_https"]:
        label = "HTTPS is enabled"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "info",
            "explanation": "The URL uses encrypted HTTPS transport. Phishing sites can also use HTTPS, so this does not prove legitimacy.",
        })
    else:
        heuristic_adj += 16
        label = "HTTP connection without HTTPS"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "warning",
            "explanation": "Traffic is not encrypted with HTTPS. Never enter passwords or payment details on unencrypted pages.",
        })

    if feats["has_ip_address"]:
        heuristic_adj += 28
        label = "IP-based hostname detected"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "danger",
            "explanation": "Serving login or account workflows directly from a raw IP address is a common phishing indicator.",
        })

    if feats["has_punycode"]:
        heuristic_adj += 24
        label = "Punycode / IDN homograph pattern (xn--)"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "danger",
            "explanation": "Punycode domains can be used to visually mimic trusted brands with lookalike characters.",
        })

    if matched_keywords:
        heuristic_adj += min(22, len(matched_keywords) * 8)
        label = f"Suspicious credential/action keywords ({', '.join(matched_keywords[:4])})"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "danger" if len(matched_keywords) >= 2 else "warning",
            "explanation": "Phishing URLs commonly include urgent or authentication keywords like login, verify, bank, or account.",
        })

    matched_brands = [
        brand for brand in BRAND_TOKENS
        if brand in hostname and hostname != f"{brand}.com" and not hostname.endswith(f".{brand}.com")
    ]
    if matched_brands:
        heuristic_adj += 22
        label = f"Possible brand impersonation token ({', '.join(matched_brands)})"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "danger",
            "explanation": "A recognizable brand token appears inside a non-canonical domain structure.",
        })

    if feats["hyphen_count"] >= 2 or feats["subdomain_count"] >= 2:
        heuristic_adj += 12
        label = "Unusual domain structure (multiple hyphens or deep subdomains)"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "warning",
            "explanation": f"Detected {feats['hyphen_count']} hyphen(s) and {feats['subdomain_count']} subdomain level(s).",
        })

    if feats["is_shortener"]:
        heuristic_adj += 16
        label = "Known URL shortener hostname"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "warning",
            "explanation": "URL shorteners mask the final destination domain from lexical inspection.",
        })

    if feats["url_length"] > 75:
        heuristic_adj += 8
        label = f"Extended URL length ({feats['url_length']} characters)"
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "warning",
            "explanation": "Unusually long URLs can obscure suspicious paths or encoded payloads.",
        })

    if feats["_has_at_symbol"]:
        heuristic_adj += 20
        label = 'Embedded "@" userinfo symbol in URL'
        indicators.append(label)
        details.append({
            "label": label,
            "severity": "danger",
            "explanation": "Text before '@' in a URL authority is ignored as userinfo, which can disguise the real host.",
        })

    return indicators, details, heuristic_adj
