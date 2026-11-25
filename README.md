# ScamShield AI — Phishing URL & Scam Detector

**Tagline:** *Detect Threats. Browse Smarter.*

ScamShield AI is an explainable cybersecurity URL threat analysis platform built with React, Vite, Tailwind CSS, Express/FastAPI, and a Random Forest lexical classifier.

## System Architecture

1. **Frontend (React + Vite + Tailwind CSS)**: Landing page, interactive URL scanner, visual 0–100 risk gauge, explainable indicators, analytics dashboard, detection pipeline, and documentation.
2. **Integrated Node/Express API (`server.ts`)**: Serves the Vite SPA and provides `/api/health`, `/api/model-info`, and `/api/scan` out of the box (with optional `FASTAPI_URL` proxying).
3. **Standalone Python FastAPI + Scikit-learn Backend (`backend/`)**: Trains a `RandomForestClassifier` on the Kaggle Malicious URLs Dataset (`sid321axn/malicious-urls-dataset`) using 10 lexical URL features and serves predictions at `http://127.0.0.1:8000/api/scan`.

## Windows 10/11 Local Setup Instructions (FastAPI + React)

### Step 1 — Download the Dataset
Run in PowerShell from the project root:

```powershell
New-Item -ItemType Directory -Force data | Out-Null
Invoke-WebRequest `
  -Uri "https://www.kaggle.com/api/v1/datasets/download/sid321axn/malicious-urls-dataset" `
  -OutFile data\dataset.zip
Expand-Archive data\dataset.zip -DestinationPath data -Force
```

Ensure the CSV is located at `data/malicious_phish.csv`.

### Step 2 — Install Python Dependencies & Train the ML Model
Open Terminal 1:

```powershell
cd backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python train.py
```

### Step 3 — Start FastAPI
In Terminal 1:

```powershell
uvicorn main:app --reload
```

FastAPI runs at `http://127.0.0.1:8000` (Swagger docs at `http://127.0.0.1:8000/docs`).

### Step 4 — Start the Web App
Open Terminal 2 from the project root:

```powershell
npm install
npm run dev
```

To point the frontend directly at standalone FastAPI, create `.env.local` with:

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

Or select **Local FastAPI (`127.0.0.1:8000`)** inside the URL Scanner's backend target selector.

## Important Security & Scope Note

ScamShield AI performs **lexical URL analysis** only. It does not check live domain registration (WHOIS), DNS reputation, SSL certificates, or live webpage content. Risk thresholds (`0–39` LOW, `40–69` SUSPICIOUS, `70–100` HIGH) are provisional demo thresholds, and a low-risk score is not proof that a website is safe.
