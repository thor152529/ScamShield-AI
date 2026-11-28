"""Evaluation and benchmark harness for ScamShield AI Python FastAPI backend."""
from __future__ import annotations

import time
from typing import List, Tuple

import numpy as np
from fastapi.testclient import TestClient
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_validate

from features import FEATURE_NAMES, explain_url_indicators, extract_feature_vector, extract_features_dict, validate_http_url
import main as api_main


def build_benchmark_corpus() -> Tuple[List[str], List[int]]:
    benign = [
        "https://example.com",
        "https://github.com/features/security",
        "https://docs.python.org/3/library/",
        "https://developer.mozilla.org/en-US/docs/Web/Security",
        "https://arxiv.org/abs/2301.00001",
        "https://scholar.google.com/",
        "https://www.wikipedia.org/wiki/Phishing",
        "https://numpy.org/doc/stable/",
        "https://scikit-learn.org/stable/",
        "https://nodejs.org/en/learn",
        "https://react.dev/reference/react",
        "https://www.python.org/downloads/",
        "https://fastapi.tiangolo.com/",
        "https://www.postgresql.org/docs/",
        "https://www.cloudflare.com/learning/",
        "https://www.kernel.org/doc/html/latest/",
        "https://pytorch.org/docs/stable/index.html",
        "https://www.tensorflow.org/tutorials",
        "https://kubernetes.io/docs/home/",
        "https://go.dev/doc/",
        "https://rust-lang.org/learn",
        "https://www.debian.org/doc/",
        "https://sqlite.org/docs.html",
        "https://redis.io/docs/",
        "https://www.gnu.org/software/bash/manual/",
        "https://httpd.apache.org/docs/",
        "https://nginx.org/en/docs/",
        "https://www.w3.org/TR/",
        "https://ietf.org/standards/",
        "https://openai.com/research",
    ]
    malicious = [
        "http://192.168.1.1/login",
        "http://10.0.0.5/verify/account",
        "http://172.16.0.9/bank/signin",
        "http://secure-login-verify-example.com",
        "http://secure-bank-login-example.com",
        "https://paypal-security-verify-account.com/login",
        "https://xn--pypal-4ve.com/verify",
        "https://xn--googl-fsa.example.com/auth",
        "http://account-update-verify-billing.example.com/signin",
        "https://apple-id-verify-support.example.net/auth",
        "http://microsoft-password-reset-urgent.example.com/otp",
        "https://amazon-billing-suspended-confirm.example.org/login",
        "http://chase-banking-kyc-update.example.com/signin",
        "https://metamask-wallet-recover-seed.example.xyz/claim",
        "http://coinbase-wallet-auth-urgent.example.top/verify",
        "http://paypal-billing-invoice-confirm.example.click/login",
        "https://hdfc-kyc-update-reward.example.info/otp",
        "http://icici-banking-suspended-verify.example.net/auth",
        "http://sbi-otp-verify-account-urgent.example.com/login",
        "https://binance-bonus-claim-wallet.example.biz/signin",
        "http://bit.ly/verify-bank-login",
        "https://tinyurl.com/urgent-kyc-update",
        "http://login-verify-account.sub1.sub2.example.com/auth/confirm",
        "http://203.0.113.45/paypal/login/verify.php",
        "https://netflix-billing-update-suspended.example.com/login",
        "http://instagram-verify-badge-appeal.example.net/signin",
        "https://whatsapp-account-recover-otp.example.org/auth",
        "http://dropbox-invoice-password-verify.example.com/login",
        "http://wellsfargo-confirm-credential-urgent.example.net/bank",
        "https://citibank-security-alert-verify-account.example.com/login",
    ]
    urls = benign + malicious
    labels = [0] * len(benign) + [1] * len(malicious)
    return urls, labels


def main() -> None:
    print("=== ScamShield AI Python Backend Evaluation & Benchmark ===")
    urls, labels = build_benchmark_corpus()

    # 1. Feature extraction benchmark (10,000 extractions)
    t0 = time.perf_counter()
    for i in range(10_000):
        extract_feature_vector(urls[i % len(urls)])
    feat_ms = (time.perf_counter() - t0) * 1000.0
    print(f"[BENCH] Python feature extraction (10000 URLs): {feat_ms:.2f} ms ({10_000 / (feat_ms / 1000.0):.0f} URLs/s)")

    # 2. 5-fold Stratified Cross-Validation with RandomForestClassifier (synthetic/canonical 60-URL corpus)
    X = np.array([extract_feature_vector(u) for u in urls], dtype=np.float32)
    y = np.array(labels, dtype=np.int32)
    clf = RandomForestClassifier(n_estimators=150, max_depth=18, min_samples_split=4, random_state=42, n_jobs=1)
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    scores = cross_validate(clf, X, y, cv=cv, scoring=["accuracy", "precision", "recall", "f1", "roc_auc"])
    print(
        "[EVAL] 5-fold CV (60 canonical URLs, RandomForestClassifier): "
        f"acc={scores['test_accuracy'].mean():.4f}, "
        f"prec={scores['test_precision'].mean():.4f}, "
        f"rec={scores['test_recall'].mean():.4f}, "
        f"f1={scores['test_f1'].mean():.4f}, "
        f"roc_auc={scores['test_roc_auc'].mean():.4f}"
    )

    # 3. FastAPI TestClient endpoint & validation verification
    client = TestClient(api_main.app)
    health = client.get("/api/health")
    assert health.status_code == 200 and health.json()["status"] == "ok"

    info = client.get("/api/model-info")
    assert info.status_code == 200 and len(info.json()["features"]) == len(FEATURE_NAMES)

    bad = client.post("/api/scan", json={"url": "javascript:alert(1)"})
    assert bad.status_code == 400

    clean = validate_http_url("https://example.com")
    feats = extract_features_dict(clean)
    indicators, _, _ = explain_url_indicators(clean, feats)
    assert "HTTPS is enabled" in indicators
    print(f"[PASS] FastAPI /api/health, /api/model-info, /api/scan (400 guard), and features.py checks passed.")


if __name__ == "__main__":
    main()
