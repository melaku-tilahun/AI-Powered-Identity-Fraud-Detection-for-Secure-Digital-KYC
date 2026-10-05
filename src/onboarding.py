from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

from src.data import DemoEvent


# ============================================================
# ONBOARDING EVENT
# ============================================================

@dataclass
class OnboardingEvent:
    """
    Normalized onboarding event used throughout the fraud-risk
    pipeline.

    This represents the onboarding activity AFTER the synthetic
    identity-verification step.
    """

    scenario: str

    identity_id: str
    device_id: str
    account_id: str
    session_id: str
    network_id: str

    identity_verified: bool

    device_reuse_count: int
    identity_reuse_count: int
    registrations_24h: int
    network_identity_count: int

    automation_score: float
    behavior_score: float

    session_duration_seconds: int

    ip_address: str

    metadata: Dict[str, Any] = field(
        default_factory=dict
    )

    # --------------------------------------------------------
    # Convenience properties
    # --------------------------------------------------------

    @property
    def device_reuse(self) -> float:
        return min(
            self.device_reuse_count / 5.0,
            1.0,
        )

    @property
    def identity_reuse(self) -> float:
        return min(
            self.identity_reuse_count / 3.0,
            1.0,
        )

    @property
    def registration_velocity(self) -> float:
        return min(
            self.registrations_24h / 10.0,
            1.0,
        )

    @property
    def network_concentration(self) -> float:
        return min(
            self.network_identity_count / 10.0,
            1.0,
        )

    @property
    def session_anomaly(self) -> float:

        seconds = self.session_duration_seconds

        if seconds <= 30:
            return 1.0

        if seconds <= 60:
            return 0.8

        if seconds <= 120:
            return 0.5

        if seconds <= 300:
            return 0.2

        return 0.05

    @property
    def features(self) -> Dict[str, float]:
        return {
            "device_reuse": self.device_reuse,
            "identity_reuse": self.identity_reuse,
            "registration_velocity": self.registration_velocity,
            "network_concentration": self.network_concentration,
            "automation": self.automation_score,
            "behavior": self.behavior_score,
            "session_anomaly": self.session_anomaly,
        }


# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

# Some earlier modules use OnboardingResult.
# Keep it as an alias so both names refer to the same object.
OnboardingResult = OnboardingEvent


# ============================================================
# SYNTHETIC FAYDA / ESIGNET VERIFICATION
# ============================================================

def verify_identity(
    event: DemoEvent,
) -> Dict[str, Any]:
    """
    Simulate a Fayda/eSignet verification response.

    No real Fayda/eSignet service is contacted.
    """

    if not event.identity_verified:

        return {
            "verified": False,
            "verification_status": "FAILED",
            "identity_id": None,
            "provider": "Synthetic Fayda/eSignet Simulator",
        }

    return {
        "verified": True,
        "verification_status": "VERIFIED",
        "identity_id": event.identity_id,
        "provider": "Synthetic Fayda/eSignet Simulator",
    }


# ============================================================
# SIGNAL COLLECTION
# ============================================================

def collect_onboarding_signals(
    event: DemoEvent,
) -> Dict[str, Any]:

    return {
        "device_reuse_count": event.device_reuse_count,
        "identity_reuse_count": event.identity_reuse_count,
        "registrations_24h": event.registrations_24h,
        "network_identity_count": event.network_identity_count,
        "automation_score": event.automation_score,
        "behavior_score": event.behavior_score,
        "session_duration_seconds": (
            event.session_duration_seconds
        ),
    }


# ============================================================
# FEATURE ENGINEERING
# ============================================================

def build_features(
    event: DemoEvent,
    signals: Dict[str, Any],
) -> Dict[str, float]:

    device_reuse = min(
        signals["device_reuse_count"] / 5.0,
        1.0,
    )

    identity_reuse = min(
        signals["identity_reuse_count"] / 3.0,
        1.0,
    )

    registration_velocity = min(
        signals["registrations_24h"] / 10.0,
        1.0,
    )

    network_concentration = min(
        signals["network_identity_count"] / 10.0,
        1.0,
    )

    automation = float(
        signals["automation_score"]
    )

    behavior = float(
        signals["behavior_score"]
    )

    session_seconds = signals[
        "session_duration_seconds"
    ]

    if session_seconds <= 30:
        session_anomaly = 1.0
    elif session_seconds <= 60:
        session_anomaly = 0.8
    elif session_seconds <= 120:
        session_anomaly = 0.5
    elif session_seconds <= 300:
        session_anomaly = 0.2
    else:
        session_anomaly = 0.05

    return {
        "device_reuse": device_reuse,
        "identity_reuse": identity_reuse,
        "registration_velocity": registration_velocity,
        "network_concentration": network_concentration,
        "automation": automation,
        "behavior": behavior,
        "session_anomaly": session_anomaly,
    }


# ============================================================
# MAIN ONBOARDING PIPELINE
# ============================================================

def process_onboarding(
    event: DemoEvent,
) -> OnboardingEvent:
    """
    Process a synthetic onboarding event.

    Pipeline:

        Synthetic Customer
               ↓
        Identity Verification
               ↓
        Signal Collection
               ↓
        Feature Engineering
               ↓
        OnboardingEvent
    """

    verification = verify_identity(event)

    signals = collect_onboarding_signals(event)

    features = build_features(
        event,
        signals,
    )

    metadata = dict(
        event.metadata or {}
    )

    metadata["verification"] = verification
    metadata["raw_signals"] = signals
    metadata["features"] = features

    return OnboardingEvent(
        scenario=event.scenario,

        identity_id=event.identity_id,
        device_id=event.device_id,
        account_id=event.account_id,
        session_id=event.session_id,
        network_id=event.network_id,

        identity_verified=verification["verified"],

        device_reuse_count=event.device_reuse_count,
        identity_reuse_count=event.identity_reuse_count,
        registrations_24h=event.registrations_24h,
        network_identity_count=event.network_identity_count,

        automation_score=event.automation_score,
        behavior_score=event.behavior_score,

        session_duration_seconds=(
            event.session_duration_seconds
        ),

        ip_address=event.ip_address,

        metadata=metadata,
    )


# ============================================================
# HELPERS
# ============================================================

def get_features(
    onboarding: OnboardingEvent,
) -> Dict[str, float]:

    return onboarding.features


def get_verification_result(
    onboarding: OnboardingEvent,
) -> Dict[str, Any]:

    return onboarding.metadata.get(
        "verification",
        {},
    )


def get_raw_signals(
    onboarding: OnboardingEvent,
) -> Dict[str, Any]:

    return onboarding.metadata.get(
        "raw_signals",
        {},
    )


def onboarding_to_dict(
    onboarding: OnboardingEvent,
) -> Dict[str, Any]:

    return {
        "scenario": onboarding.scenario,

        "identity_id": onboarding.identity_id,
        "device_id": onboarding.device_id,
        "account_id": onboarding.account_id,
        "session_id": onboarding.session_id,
        "network_id": onboarding.network_id,

        "identity_verified": onboarding.identity_verified,

        "device_reuse_count": (
            onboarding.device_reuse_count
        ),

        "identity_reuse_count": (
            onboarding.identity_reuse_count
        ),

        "registrations_24h": (
            onboarding.registrations_24h
        ),

        "network_identity_count": (
            onboarding.network_identity_count
        ),

        "automation_score": (
            onboarding.automation_score
        ),

        "behavior_score": (
            onboarding.behavior_score
        ),

        "session_duration_seconds": (
            onboarding.session_duration_seconds
        ),

        "ip_address": onboarding.ip_address,

        "features": onboarding.features,

        "metadata": onboarding.metadata,
    }