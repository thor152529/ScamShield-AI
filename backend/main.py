from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import time
from typing import Any, Dict, List, Optional

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from features import (
    FEATURE_NAMES,
    explain_url_indicators,
    extract_features_dict,
    validate_http_url,
)

MODEL_PATH = Path(__file__).resolve().parent / "models" / "scamshield.joblib"

app = FastAPI(
    title="ScamShield AI API",
    description="Random Forest lexical phishing URL & scam detection API",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str


def _load_bundle() -> Optional[Dict[str, Any]]:
    if MODEL_PATH.exists():
        return joblib.load(MODEL_PATH)
    return None


@app.get("/")
def root() -> Dict[str, Any]:
    return {
        "service": "ScamShield AI Backend",
        "status": "running",
        "docs": "/docs",
    }


@app.get("/api/health")
def health() -> Dict[str, Any]:
    bundle = _load_bundle()
    return {
        "status": "ok",
        "service": "ScamShield AI",
        "model_loaded": bundle is not None,
        "model_path": str(MODEL_PATH),
    }


@app.get("/api/model-info")
def model_info() -> Dict[str, Any]:
    bundle = _load_bundle()
    return {
        "model_name": "ScamShield Lexical Random Forest Classifier",
        "algorithm": "RandomForestClassifier (Scikit-learn)",
        "dataset": "Malicious URLs Dataset (Kaggle sid321axn)",
        "training_samples": int(bundle.get("rows_used", 0)) if bundle else 0,
        "features": FEATURE_NAMES,
        "thresholds": {
            "low": "0-39 (LOW)",
            "suspicious": "40-69 (SUSPICIOUS)",
            "high": "70-100 (HIGH)",
        },
        "limitations": (
            "Performs lexical URL analysis only. Does not check live domain registration, "
            "DNS reputation, SSL certificates, or webpage content."
        ),
        "status": "ready" if bundle is not None else "model_not_trained",
    }


@app.post("/api/scan")
def scan_url(payload: ScanRequest) -> Dict[str, Any]:
    started = time.perf_counter()
    try:
        clean_url = validate_http_url(payload.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    bundle = _load_bundle()
    if bundle is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Trained model file backend/models/scamshield.joblib not found. "
                "Run 'python train.py' after placing data/malicious_phish.csv."
            ),
        )

    feats = extract_features_dict(clean_url)
    vector = np.array([[int(feats[name]) for name in FEATURE_NAMES]], dtype=np.float32)
    model = bundle["model"]
    phishing_prob = float(model.predict_proba(vector)[0][1])

    indicators, indicator_details, heuristic_adj = explain_url_indicators(clean_url, feats)
    risk_score = int(min(100, max(4, round(phishing_prob * 70 + heuristic_adj * 0.65))))

    if risk_score >= 70:
        risk_level = "HIGH"
        prediction = "PHISHING"
        recommendation = (
            "Do not enter credentials, OTPs, or payment details. Close this link and "
            "navigate to the official organization website manually."
        )
    elif risk_score >= 40:
        risk_level = "SUSPICIOUS"
        prediction = "SUSPICIOUS"
        recommendation = (
            "Exercise caution: verify the sender and inspect the exact root domain "
            "independently before trusting or signing into this page."
        )
    else:
        risk_level = "LOW"
        prediction = "LEGITIMATE"
        recommendation = (
            "No strong lexical phishing indicators detected. Still verify the domain "
            "spelling and sender context before entering sensitive data."
        )

    latency_ms = max(1, int((time.perf_counter() - started) * 1000))

    return {
        "url": clean_url,
        "normalized_hostname": feats["_hostname"],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "prediction": prediction,
        "phishing_probability": round(phishing_prob, 2),
        "indicators": indicators,
        "indicator_details": indicator_details,
        "recommendation": recommendation,
        "features": {name: (bool(feats[name]) if name.startswith(("has_", "is_")) else int(feats[name])) for name in FEATURE_NAMES},
        "matched_keywords": feats["_matched_keywords"],
        "analysis_scope_note": (
            "Provisional hackathon heuristic score from lexical URL analysis only. "
            "Does not check live DNS, WHOIS, SSL certificates, or webpage content."
        ),
        "engine": "FastAPI + Scikit-learn RandomForestClassifier",
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "latency_ms": latency_ms,
    }
