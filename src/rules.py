# src/rules.py

"""
Deterministic fraud-risk rules for digital financial onboarding.
"""


def evaluate_rules(event):
    """
    Evaluate deterministic fraud rules.

    Returns a normalized 0-100 rule risk score and the
    rules that were triggered.
    """

    score = 0
    triggered_rules = []

    def add(condition, points, description):
        nonlocal score

        if condition:
            score += points
            triggered_rules.append(description)

    # -----------------------------------------------------
    # Identity verification
    # -----------------------------------------------------

    if not event.identity_verified:
        add(
            True,
            30,
            "Identity verification failed"
        )

    # -----------------------------------------------------
    # Device reuse
    # -----------------------------------------------------

    add(
        event.device_reuse_count >= 2,
        15,
        "Device is associated with multiple onboarding activities"
    )

    add(
        event.device_reuse_count >= 5,
        15,
        "High device reuse detected"
    )

    # -----------------------------------------------------
    # Identity reuse
    # -----------------------------------------------------

    add(
        event.identity_reuse_count >= 2,
        20,
        "Identity reuse detected"
    )

    # -----------------------------------------------------
    # Registration velocity
    # -----------------------------------------------------

    add(
        event.registrations_24h >= 5,
        10,
        "Elevated registration velocity detected"
    )

    add(
        event.registrations_24h >= 10,
        15,
        "Abnormally high registration velocity detected"
    )

    # -----------------------------------------------------
    # Network concentration
    # -----------------------------------------------------

    add(
        event.network_identity_count >= 3,
        10,
        "Multiple identities associated with the same network"
    )

    add(
        event.network_identity_count >= 5,
        10,
        "High network identity concentration detected"
    )

    # -----------------------------------------------------
    # Automation
    # -----------------------------------------------------

    add(
        event.automation_score >= 0.75,
        15,
        "Strong automation indicators detected"
    )

    add(
        event.automation_score >= 0.90,
        10,
        "Very high automation score detected"
    )

    # -----------------------------------------------------
    # Behavioral anomaly
    # -----------------------------------------------------

    add(
        event.behavior_score >= 0.75,
        15,
        "Behavioral anomaly detected"
    )

    add(
        event.behavior_score >= 0.90,
        10,
        "Severe behavioral anomaly detected"
    )

    # -----------------------------------------------------
    # Session anomaly
    # -----------------------------------------------------

    add(
        event.session_duration_seconds <= 30,
        10,
        "Unusually short onboarding session detected"
    )

    # -----------------------------------------------------
    # Cap score at 100
    # -----------------------------------------------------

    score = min(score, 100)

    return {
        "score": score,
        "triggered_rules": triggered_rules,
        "rule_count": len(triggered_rules),
    }


# ---------------------------------------------------------
# Compatibility helper
# ---------------------------------------------------------

def calculate_rule_score(event):
    """
    Return only the deterministic rule score.
    """

    return evaluate_rules(event)["score"]