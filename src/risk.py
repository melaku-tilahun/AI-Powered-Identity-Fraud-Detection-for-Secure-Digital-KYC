# src/risk.py

"""
Hybrid KYC Fraud Risk Engine.

Combines:
    - deterministic rules
    - machine learning
    - graph analytics
    - behavioral signals

Final score: 0-100
"""


# ---------------------------------------------------------
# Risk level
# ---------------------------------------------------------

def get_risk_level(score):
    score = float(score)

    if score <= 24:
        return "Trusted"

    if score <= 49:
        return "Low"

    if score <= 74:
        return "Elevated"

    return "High"


# ---------------------------------------------------------
# Decision
# ---------------------------------------------------------

def get_decision(level):
    decisions = {
        "Trusted": "Approve",
        "Low": "Approve + Monitor",
        "Elevated": "Additional Verification",
        "High": "Hold / Manual Review",
    }

    return decisions.get(level, "Manual Review")


# ---------------------------------------------------------
# Normalize score
# ---------------------------------------------------------

def normalize_score(value):
    """
    Convert either:
        0-1 probability
    or:
        0-100 score

    into a 0-100 score.
    """

    if value is None:
        return 0.0

    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0

    if value <= 1:
        value *= 100

    return max(0.0, min(100.0, value))


# ---------------------------------------------------------
# Graph relationship count
# ---------------------------------------------------------

def get_relationship_count(graph_result):
    """
    Safely extract the number of suspicious relationships.

    graph_engine may return either:
        suspicious_relationships = [...]
    or:
        suspicious_relationships = 5
    """

    relationships = graph_result.get(
        "suspicious_relationships",
        0
    )

    if isinstance(relationships, int):
        return relationships

    if isinstance(relationships, float):
        return int(relationships)

    if relationships is None:
        return 0

    try:
        return len(relationships)
    except TypeError:
        return 0


# ---------------------------------------------------------
# Hybrid risk calculation
# ---------------------------------------------------------

def calculate_hybrid_risk(
    rule_result,
    model_result,
    graph_result,
    onboarding
):
    """
    Calculate the final hybrid fraud-risk score.

    Weights:

        Rules       25%
        ML          40%
        Graph       25%
        Behavior    10%
    """

    # -----------------------------------------------------
    # Rule score
    # -----------------------------------------------------

    rule_score = normalize_score(
        rule_result.get("score", 0)
    )

    # -----------------------------------------------------
    # ML score
    # -----------------------------------------------------

    model_probability = model_result.get(
        "fraud_probability",
        0
    )

    ml_score = normalize_score(
        model_probability
    )

    # -----------------------------------------------------
    # Graph score
    # -----------------------------------------------------

    graph_score = normalize_score(
        graph_result.get("score", 0)
    )

    # -----------------------------------------------------
    # Behavioral score
    # -----------------------------------------------------

    automation = float(
        getattr(
            onboarding,
            "automation_score",
            0
        )
    )

    behavior = float(
        getattr(
            onboarding,
            "behavior_score",
            0
        )
    )

    behavioral_score = (
        (automation * 0.5) +
        (behavior * 0.5)
    ) * 100

    behavioral_score = normalize_score(
        behavioral_score
    )

    # -----------------------------------------------------
    # Weighted fusion
    # -----------------------------------------------------

    final_score = (
        rule_score * 0.25 +
        ml_score * 0.40 +
        graph_score * 0.25 +
        behavioral_score * 0.10
    )

    # -----------------------------------------------------
    # Coordinated-fraud adjustment
    # -----------------------------------------------------

    relationship_count = get_relationship_count(
        graph_result
    )

    coordination_bonus = 0

    if relationship_count >= 3:
        coordination_bonus = 5

    if relationship_count >= 5:
        coordination_bonus = 10

    final_score += coordination_bonus

    # -----------------------------------------------------
    # Final bounds
    # -----------------------------------------------------

    final_score = max(
        0,
        min(100, final_score)
    )

    final_score = round(
        final_score,
        1
    )

    # -----------------------------------------------------
    # Level + decision
    # -----------------------------------------------------

    level = get_risk_level(
        final_score
    )

    decision = get_decision(
        level
    )

    # -----------------------------------------------------
    # Return
    # -----------------------------------------------------

    return {
        "score": final_score,
        "level": level,
        "decision": decision,

        "rule_score": round(
            rule_score,
            1
        ),

        "ml_score": round(
            ml_score,
            1
        ),

        "graph_score": round(
            graph_score,
            1
        ),

        "behavioral_score": round(
            behavioral_score,
            1
        ),

        "coordination_bonus": coordination_bonus,

        "relationship_count": relationship_count,

        "selected_model": model_result.get(
            "selected_model",
            "Unknown"
        ),
    }


# ---------------------------------------------------------
# Simple helper
# ---------------------------------------------------------

def calculate_risk_score(
    rule_score,
    ml_score,
    graph_score,
    behavioral_score=0
):
    """
    Calculate a hybrid score independently of an
    OnboardingEvent.
    """

    score = (
        normalize_score(rule_score) * 0.25 +
        normalize_score(ml_score) * 0.40 +
        normalize_score(graph_score) * 0.25 +
        normalize_score(behavioral_score) * 0.10
    )

    return round(
        max(0, min(100, score)),
        1
    )