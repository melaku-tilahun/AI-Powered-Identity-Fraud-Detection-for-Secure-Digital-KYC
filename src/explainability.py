# src/explainability.py

"""
Explainability layer for the KYC Fraud Risk Engine.

Converts technical fraud signals into human-readable reasons
that can be displayed in the Streamlit dashboard.
"""


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def _add_explanation(explanations, text, priority):
    """
    Add an explanation with a priority score.
    """

    explanations.append({
        "text": text,
        "priority": priority
    })


# ---------------------------------------------------------
# Main explanation function
# ---------------------------------------------------------

def generate_explanations(
    onboarding,
    rule_result,
    model_result,
    graph_result,
    risk_result
):
    """
    Generate human-readable explanations for the final
    fraud-risk decision.

    Returns:
        list[str]
    """

    explanations = []

    # -----------------------------------------------------
    # Identity verification
    # -----------------------------------------------------

    if getattr(onboarding, "identity_verified", False):

        _add_explanation(
            explanations,
            "Identity verification succeeded, but verification "
            "alone does not establish that the onboarding activity "
            "is legitimate.",
            10
        )

    else:

        _add_explanation(
            explanations,
            "Identity verification was not successful.",
            100
        )

    # -----------------------------------------------------
    # Device reuse
    # -----------------------------------------------------

    device_reuse = getattr(
        onboarding,
        "device_reuse_count",
        0
    )

    if device_reuse >= 5:

        _add_explanation(
            explanations,
            f"High device reuse detected: this device is associated "
            f"with {device_reuse} previous onboarding activities.",
            100
        )

    elif device_reuse >= 2:

        _add_explanation(
            explanations,
            f"Device reuse detected across "
            f"{device_reuse} onboarding activities.",
            70
        )

    # -----------------------------------------------------
    # Identity reuse
    # -----------------------------------------------------

    identity_reuse = getattr(
        onboarding,
        "identity_reuse_count",
        0
    )

    if identity_reuse >= 2:

        _add_explanation(
            explanations,
            f"Identity reuse detected across "
            f"{identity_reuse} onboarding attempts.",
            100
        )

    # -----------------------------------------------------
    # Registration velocity
    # -----------------------------------------------------

    registrations = getattr(
        onboarding,
        "registrations_24h",
        0
    )

    if registrations >= 10:

        _add_explanation(
            explanations,
            f"Abnormally high registration velocity: "
            f"{registrations} registrations were observed "
            f"within 24 hours.",
            100
        )

    elif registrations >= 5:

        _add_explanation(
            explanations,
            f"Elevated registration velocity: "
            f"{registrations} registrations were observed "
            f"within 24 hours.",
            70
        )

    # -----------------------------------------------------
    # Network concentration
    # -----------------------------------------------------

    network_identities = getattr(
        onboarding,
        "network_identity_count",
        0
    )

    if network_identities >= 5:

        _add_explanation(
            explanations,
            f"High network concentration: "
            f"{network_identities} identities are associated "
            f"with the same network.",
            95
        )

    elif network_identities >= 3:

        _add_explanation(
            explanations,
            f"Multiple identities are associated with the same "
            f"network ({network_identities} identities).",
            65
        )

    # -----------------------------------------------------
    # Automation
    # -----------------------------------------------------

    automation = float(
        getattr(onboarding, "automation_score", 0)
    )

    if automation >= 0.80:

        _add_explanation(
            explanations,
            f"Strong automation indicators detected "
            f"(automation score: {automation:.2f}).",
            95
        )

    elif automation >= 0.50:

        _add_explanation(
            explanations,
            f"Moderate automation indicators detected "
            f"(automation score: {automation:.2f}).",
            65
        )

    # -----------------------------------------------------
    # Behavioral anomaly
    # -----------------------------------------------------

    behavior = float(
        getattr(onboarding, "behavior_score", 0)
    )

    if behavior >= 0.80:

        _add_explanation(
            explanations,
            f"Highly anomalous onboarding behavior detected "
            f"(behavior score: {behavior:.2f}).",
            90
        )

    elif behavior >= 0.50:

        _add_explanation(
            explanations,
            f"Anomalous onboarding behavior detected "
            f"(behavior score: {behavior:.2f}).",
            60
        )

    # -----------------------------------------------------
    # Session duration
    # -----------------------------------------------------

    session_duration = getattr(
        onboarding,
        "session_duration_seconds",
        0
    )

    if session_duration <= 30:

        _add_explanation(
            explanations,
            f"Very short onboarding session detected "
            f"({session_duration} seconds), consistent with "
            f"possible automated activity.",
            80
        )

    # -----------------------------------------------------
    # Graph relationships
    # -----------------------------------------------------

    _suspicious_raw = graph_result.get(
        "suspicious_relationships",
        0
    )

    # graph_result returns an int; guard against list too.
    if isinstance(_suspicious_raw, (list, tuple)):
        suspicious_count = len(_suspicious_raw)
    else:
        try:
            suspicious_count = int(_suspicious_raw)
        except (TypeError, ValueError):
            suspicious_count = 0

    if suspicious_count >= 5:

        _add_explanation(
            explanations,
            f"Graph analysis identified "
            f"{suspicious_count} suspicious "
            f"relationships involving identities, devices, "
            f"accounts or networks.",
            100
        )

    elif suspicious_count >= 3:

        _add_explanation(
            explanations,
            f"Graph analysis identified "
            f"{suspicious_count} suspicious "
            f"relationships.",
            75
        )

    # -----------------------------------------------------
    # ML signal
    # -----------------------------------------------------

    fraud_probability = float(
        model_result.get(
            "fraud_probability",
            0
        )
    )

    selected_model = model_result.get(
        "selected_model",
        "ML model"
    )

    if fraud_probability >= 0.80:

        _add_explanation(
            explanations,
            f"{selected_model} estimated a high fraud probability "
            f"({fraud_probability:.0%}).",
            95
        )

    elif fraud_probability >= 0.50:

        _add_explanation(
            explanations,
            f"{selected_model} detected elevated fraud probability "
            f"({fraud_probability:.0%}).",
            70
        )

    # -----------------------------------------------------
    # Rule signals
    # -----------------------------------------------------

    triggered_rules = rule_result.get(
        "triggered_rules",
        []
    )

    if triggered_rules:

        for rule in triggered_rules[:4]:

            if isinstance(rule, dict):

                description = (
                    rule.get("description")
                    or rule.get("name")
                    or str(rule)
                )

            else:

                description = str(rule)

            _add_explanation(
                explanations,
                f"Rule triggered: {description}",
                75
            )

    # -----------------------------------------------------
    # Final decision
    # -----------------------------------------------------

    final_score = risk_result.get(
        "score",
        0
    )

    level = risk_result.get(
        "level",
        "Unknown"
    )

    decision = risk_result.get(
        "decision",
        "Manual Review"
    )

    _add_explanation(
        explanations,
        f"Final hybrid risk score: {final_score}/100 "
        f"({level}). Recommended action: {decision}.",
        110
    )

    # -----------------------------------------------------
    # Sort by importance
    # -----------------------------------------------------

    explanations.sort(
        key=lambda x: x["priority"],
        reverse=True
    )

    # Return only the text for Streamlit
    return [
        item["text"]
        for item in explanations
    ]


# ---------------------------------------------------------
# Alternative detailed output
# ---------------------------------------------------------

def generate_detailed_explanations(
    onboarding,
    rule_result,
    model_result,
    graph_result,
    risk_result
):
    """
    Same explanation engine, but preserves priorities.
    Useful if we later want to display explanations
    ranked by importance.
    """

    explanations = generate_explanations(
        onboarding,
        rule_result,
        model_result,
        graph_result,
        risk_result
    )

    return [
        {
            "reason": explanation,
            "severity": "High"
            if any(
                word in explanation.lower()
                for word in [
                    "high",
                    "abnormal",
                    "suspicious",
                    "fraud probability"
                ]
            )
            else "Medium"
        }
        for explanation in explanations
    ]