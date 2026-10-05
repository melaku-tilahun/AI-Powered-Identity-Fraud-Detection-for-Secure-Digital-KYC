---
title: AI-Powered Identity Fraud Detection for Secure Digital KYC
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: streamlit
sdk_version: 1.45.0
app_file: app.py
pinned: true
license: mit
---

# AI-Powered Identity Fraud Detection for Secure Digital KYC: A Zero Trust Approach

**Research Prototype** — 3rd Annual Cybersecurity Awareness Month Conference 2026  
Commercial Bank of Ethiopia | 29–30 October 2026 | Addis Ababa

---

## Overview

This prototype demonstrates an AI-driven, privacy-preserving fraud-risk layer for digital financial onboarding. It shows how graph analytics, machine learning, and rule-based engines can detect suspicious onboarding activity **after** identity verification — addressing patterns that standard KYC cannot catch.

> **Research question:** Can an onboarding event be suspicious even when the identity is valid?

The system evaluates onboarding *activity*, not identity attributes — device reuse, session behaviour, network relationships, and registration velocity — using a hybrid risk-fusion architecture.

---

## Architecture

```
Digital Onboarding
        |
        v
Fayda/eSignet Verification (Simulated)
        |
        v
Signal Collection
        |
        +----------------+
        |                |
        v                v
     Rules           ML Models
                  LR / RF / XGBoost
        |                |
        +--------+-------+
                 |
                 v
          Graph Analytics (NetworkX)
                 |
                 v
            Risk Fusion
                 |
                 v
          Explainability
                 |
                 v
        Risk-Based Decision
        (Approve / Additional Verification / Hold)
```

---

## Demo Scenarios

| Scenario | Risk Score | Decision |
|---|---|---|
| Legitimate Onboarding | ~4/100 | Approve |
| Account Farming | ~94/100 | Hold / Manual Review |
| Automated Onboarding | ~79/100 | Hold / Manual Review |
| Coordinated Fraud | 100/100 | Hold / Manual Review |

---

## Running Locally

```powershell
# Windows
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

```bash
# Linux / macOS
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

Then open **http://localhost:8501**

---

## Privacy & Isolation

This prototype is **intentionally isolated** from Fayda/eSignet, CBE production systems, and real identity data.

- All data is synthetic
- Identifiers are pseudonymous
- No biometric data is used or stored
- The Fayda/eSignet component is a local simulator
- No CBE production systems are accessed

---

## Research Reference

Presented at the 3rd Annual Cybersecurity Awareness Month Conference 2026, Commercial Bank of Ethiopia.  
Contact: melakutilahun15@gmail.com
