from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Any
import random
import uuid


# ============================================================
# DATA STRUCTURES
# ============================================================

@dataclass
class DemoEvent:
    scenario: str
    identity_id: str
    device_id: str
    account_id: str
    session_id: str
    network_id: str

    identity_verified: bool = True

    device_reuse_count: int = 0
    identity_reuse_count: int = 0
    registrations_24h: int = 1
    network_identity_count: int = 1

    automation_score: float = 0.05
    behavior_score: float = 0.05

    session_duration_seconds: int = 420

    ip_address: str = "10.0.0.10"

    metadata: Dict[str, Any] | None = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


# ============================================================
# ID GENERATORS
# ============================================================

def _identity_id(prefix: str = "ID") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _device_id(prefix: str = "DEV") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _account_id(prefix: str = "ACC") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _session_id(prefix: str = "SES") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _network_id(prefix: str = "NET") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


# ============================================================
# DEMO SCENARIOS
# ============================================================

def get_demo_scenario(scenario: str) -> DemoEvent:
    """
    Return a controlled synthetic onboarding event.

    IMPORTANT:
    These are synthetic research/demo scenarios only.
    No real Fayda, CBE, customer, device, or network data is used.
    """

    if scenario == "Legitimate Onboarding":

        return DemoEvent(
            scenario="Legitimate Onboarding",

            identity_id=_identity_id(),
            device_id=_device_id(),
            account_id=_account_id(),
            session_id=_session_id(),
            network_id=_network_id(),

            identity_verified=True,

            device_reuse_count=0,
            identity_reuse_count=0,
            registrations_24h=1,
            network_identity_count=1,

            automation_score=0.03,
            behavior_score=0.04,

            session_duration_seconds=510,

            ip_address="10.10.10.21",

            metadata={
                "description": "Normal first-time customer onboarding",
                "expected_outcome": "approve",
            },
        )

    # --------------------------------------------------------
    # ACCOUNT FARMING
    # --------------------------------------------------------

    if scenario == "Account Farming":

        return DemoEvent(
            scenario="Account Farming",

            identity_id=_identity_id(),
            device_id="DEV-SHARED-001",
            account_id=_account_id(),
            session_id=_session_id(),
            network_id="NET-LOCAL-001",

            identity_verified=True,

            device_reuse_count=5,
            identity_reuse_count=0,
            registrations_24h=7,
            network_identity_count=6,

            automation_score=0.35,
            behavior_score=0.58,

            session_duration_seconds=95,

            ip_address="10.10.20.31",

            metadata={
                "description": (
                    "Multiple identities are being registered "
                    "from a reused device."
                ),
                "expected_outcome": "additional_verification",
            },
        )

    # --------------------------------------------------------
    # AUTOMATED ONBOARDING
    # --------------------------------------------------------

    if scenario == "Automated Onboarding":

        return DemoEvent(
            scenario="Automated Onboarding",

            identity_id=_identity_id(),
            device_id=_device_id(),
            account_id=_account_id(),
            session_id=_session_id(),
            network_id="NET-AUTO-001",

            identity_verified=True,

            device_reuse_count=1,
            identity_reuse_count=0,
            registrations_24h=12,
            network_identity_count=4,

            automation_score=0.91,
            behavior_score=0.86,

            session_duration_seconds=18,

            ip_address="10.10.30.41",

            metadata={
                "description": (
                    "Rapid onboarding with highly automated "
                    "interaction patterns."
                ),
                "expected_outcome": "additional_verification",
            },
        )

    # --------------------------------------------------------
    # COORDINATED FRAUD
    # --------------------------------------------------------

    if scenario == "Coordinated Fraud":

        return DemoEvent(
            scenario="Coordinated Fraud",

            identity_id="ID-FRAUD-005",
            device_id="DEV-SHARED-001",
            account_id="ACC-FRAUD-005",
            session_id="SES-FRAUD-005",
            network_id="NET-FRAUD-001",

            identity_verified=True,

            device_reuse_count=5,
            identity_reuse_count=0,
            registrations_24h=8,
            network_identity_count=5,

            automation_score=0.88,
            behavior_score=0.92,

            session_duration_seconds=21,

            ip_address="10.10.40.50",

            metadata={
                "description": (
                    "Multiple individually valid identities are "
                    "connected through shared infrastructure."
                ),
                "expected_outcome": "hold",
                "coordinated_identities": [
                    "ID-FRAUD-001",
                    "ID-FRAUD-002",
                    "ID-FRAUD-003",
                    "ID-FRAUD-004",
                    "ID-FRAUD-005",
                ],
                "shared_device": "DEV-SHARED-001",
                "shared_network": "NET-FRAUD-001",
            },
        )

    raise ValueError(
        f"Unknown demo scenario: {scenario}"
    )


# ============================================================
# SYNTHETIC TRAINING DATA
# ============================================================

def generate_synthetic_dataset(
    n_samples: int = 5000,
    random_state: int = 42,
):
    """
    Generate a statistically noisy synthetic dataset for
    research/model-development purposes.

    This intentionally does NOT create perfectly separable
    classes. Fraud and legitimate behavior overlap.
    """

    import numpy as np
    import pandas as pd

    rng = np.random.default_rng(random_state)

    rows = []

    for _ in range(n_samples):

        fraud = rng.random() < 0.30

        if fraud:

            device_reuse = int(
                rng.poisson(2.5)
            )

            registrations = int(
                rng.poisson(5) + 1
            )

            network_identities = int(
                rng.poisson(3) + 1
            )

            automation = float(
                np.clip(
                    rng.normal(0.62, 0.22),
                    0,
                    1,
                )
            )

            behavior = float(
                np.clip(
                    rng.normal(0.58, 0.23),
                    0,
                    1,
                )
            )

            session_duration = int(
                np.clip(
                    rng.normal(100, 70),
                    5,
                    900,
                )
            )

        else:

            device_reuse = int(
                rng.poisson(0.4)
            )

            registrations = int(
                rng.poisson(1.5) + 1
            )

            network_identities = int(
                rng.poisson(1.2) + 1
            )

            automation = float(
                np.clip(
                    rng.normal(0.25, 0.20),
                    0,
                    1,
                )
            )

            behavior = float(
                np.clip(
                    rng.normal(0.25, 0.20),
                    0,
                    1,
                )
            )

            session_duration = int(
                np.clip(
                    rng.normal(400, 180),
                    10,
                    1200,
                )
            )

        # ----------------------------------------------------
        # Add overlap/noise
        # ----------------------------------------------------

        if rng.random() < 0.08:

            device_reuse = int(
                rng.poisson(1.5)
            )

        if rng.random() < 0.08:

            registrations = int(
                rng.poisson(4) + 1
            )

        if rng.random() < 0.08:

            automation = float(
                np.clip(
                    rng.normal(0.55, 0.25),
                    0,
                    1,
                )
            )

        # ----------------------------------------------------
        # Weak label noise
        # ----------------------------------------------------

        actual_fraud = fraud

        if rng.random() < 0.04:
            actual_fraud = not actual_fraud

        rows.append(
            {
                "device_reuse_count": device_reuse,
                "identity_reuse_count": int(
                    rng.poisson(0.2)
                ),
                "registrations_24h": registrations,
                "network_identity_count": network_identities,
                "automation_score": automation,
                "behavior_score": behavior,
                "session_duration_seconds": session_duration,
                "fraud": int(actual_fraud),
            }
        )

    return pd.DataFrame(rows)


# ============================================================
# CONVENIENCE HELPERS
# ============================================================

def scenario_names():
    """Return the scenarios used by the Streamlit demo."""

    return [
        "Legitimate Onboarding",
        "Account Farming",
        "Automated Onboarding",
        "Coordinated Fraud",
    ]


def event_to_dict(event: DemoEvent) -> Dict[str, Any]:
    """Convert a DemoEvent to a normal dictionary."""

    return {
        "scenario": event.scenario,
        "identity_id": event.identity_id,
        "device_id": event.device_id,
        "account_id": event.account_id,
        "session_id": event.session_id,
        "network_id": event.network_id,
        "identity_verified": event.identity_verified,
        "device_reuse_count": event.device_reuse_count,
        "identity_reuse_count": event.identity_reuse_count,
        "registrations_24h": event.registrations_24h,
        "network_identity_count": event.network_identity_count,
        "automation_score": event.automation_score,
        "behavior_score": event.behavior_score,
        "session_duration_seconds": event.session_duration_seconds,
        "ip_address": event.ip_address,
        "metadata": event.metadata,
    }