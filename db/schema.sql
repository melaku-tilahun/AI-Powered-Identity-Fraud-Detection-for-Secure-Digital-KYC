CREATE TABLE onboarding_events (
    event_id TEXT PRIMARY KEY,
    identity_ref TEXT NOT NULL,
    device_ref TEXT NOT NULL,
    account_ref TEXT NOT NULL,
    session_ref TEXT NOT NULL,
    network_ref TEXT NOT NULL,
    occurred_at TIMESTAMPTZ NOT NULL,
    identity_verified BOOLEAN NOT NULL,
    registrations_24h INTEGER NOT NULL,
    device_reuse_count INTEGER NOT NULL,
    identity_reuse_count INTEGER NOT NULL,
    network_identity_count INTEGER NOT NULL,
    session_duration_seconds INTEGER NOT NULL,
    automation_score NUMERIC(5,4) NOT NULL,
    behavioral_anomaly_score NUMERIC(5,4) NOT NULL,
    prior_fraud_links INTEGER NOT NULL
);

CREATE TABLE risk_assessments (
    assessment_id BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL REFERENCES onboarding_events(event_id),
    rule_score NUMERIC(5,2) NOT NULL,
    ml_probability NUMERIC(7,5) NOT NULL,
    graph_score NUMERIC(5,2) NOT NULL,
    risk_score NUMERIC(5,2) NOT NULL,
    risk_level TEXT NOT NULL,
    decision TEXT NOT NULL,
    reasons JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
