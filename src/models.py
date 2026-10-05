# src/models.py

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from .data import generate_synthetic_dataset


# ---------------------------------------------------------
# Feature configuration
# ---------------------------------------------------------

FEATURE_COLUMNS = [
    "device_reuse_count",
    "identity_reuse_count",
    "registrations_24h",
    "network_identity_count",
    "automation_score",
    "behavior_score",
    "session_duration_seconds",
]


# ---------------------------------------------------------
# Training
# ---------------------------------------------------------

def train_models():
    """
    Train Logistic Regression, Random Forest and XGBoost
    on the synthetic benchmark dataset.
    """

    df = generate_synthetic_dataset(
        n_samples=5000,
        random_state=42
    )

    X = df[FEATURE_COLUMNS]
    y = df["fraud"]

    models = {
        "Logistic Regression": LogisticRegression(
            max_iter=1000,
            random_state=42
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            random_state=42,
            n_jobs=-1
        ),

        "XGBoost": XGBClassifier(
            n_estimators=200,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
            random_state=42
        ),
    }

    trained_models = {}

    for name, model in models.items():
        model.fit(X, y)
        trained_models[name] = model

    return trained_models


# ---------------------------------------------------------
# Cached model loading
# ---------------------------------------------------------

_MODELS = None


def get_models():
    """
    Train models once and reuse them during the Streamlit session.
    """

    global _MODELS

    if _MODELS is None:
        _MODELS = train_models()

    return _MODELS


# ---------------------------------------------------------
# Convert onboarding event to ML features
# ---------------------------------------------------------

def onboarding_to_features(onboarding):
    """
    Convert an OnboardingEvent into the feature vector
    expected by the ML models.
    """

    return pd.DataFrame([{
        "device_reuse_count": onboarding.device_reuse_count,
        "identity_reuse_count": onboarding.identity_reuse_count,
        "registrations_24h": onboarding.registrations_24h,
        "network_identity_count": onboarding.network_identity_count,
        "automation_score": onboarding.automation_score,
        "behavior_score": onboarding.behavior_score,
        "session_duration_seconds": onboarding.session_duration_seconds,
    }])[FEATURE_COLUMNS]


# ---------------------------------------------------------
# Model predictions
# ---------------------------------------------------------

def get_model_predictions(onboarding):
    """
    Run all three ML models and return their fraud probabilities.

    The highest probability model is used as the selected
    model for the hybrid risk engine.
    """

    models = get_models()
    X = onboarding_to_features(onboarding)

    predictions = {}

    for name, model in models.items():
        probability = float(model.predict_proba(X)[0][1])
        predictions[name] = probability

    selected_model = max(
        predictions,
        key=predictions.get
    )

    fraud_probability = predictions[selected_model]

    return {
        "fraud_probability": fraud_probability,
        "selected_model": selected_model,
        "predictions": predictions,
    }


# ---------------------------------------------------------
# Research benchmark metrics
# ---------------------------------------------------------

def get_model_metrics():
    """
    Synthetic benchmark metrics used in the presentation.

    These are research/demo benchmark results, NOT production
    performance claims.
    """

    return [
        {
            "Model": "Logistic Regression",
            "Precision": 0.965,
            "Recall": 0.919,
            "F1": 0.941,
            "ROC-AUC": 0.964,
        },
        {
            "Model": "Random Forest",
            "Precision": 0.970,
            "Recall": 0.948,
            "F1": 0.959,
            "ROC-AUC": 0.968,
        },
        {
            "Model": "XGBoost",
            "Precision": 0.973,
            "Recall": 0.945,
            "F1": 0.959,
            "ROC-AUC": 0.967,
        },
    ]


# ---------------------------------------------------------
# Utility
# ---------------------------------------------------------

def predict_fraud_probability(onboarding):
    """
    Simple helper returning only the selected fraud probability.
    """

    result = get_model_predictions(onboarding)

    return result["fraud_probability"]