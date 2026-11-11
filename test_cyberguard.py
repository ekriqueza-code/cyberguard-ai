import pandas as pd
from fastapi.testclient import TestClient

from ai_analyst import AISecurityAnalystAgent
from api import API_KEY_DEMO, app
from cyberguard_ml import AnomalyDetectionPipeline, SecurityFeatureEngineer, SyntheticAuthGenerator
from security_scanners import PhishingDetector, VulnerabilityScanner

client = TestClient(app)


def test_ml_pipeline_detects_intrusion():
    gen = SyntheticAuthGenerator(seed=42)
    df = gen.generate(n_normal=500, n_anomalies=40)
    fe = SecurityFeatureEngineer()
    pipeline = AnomalyDetectionPipeline(contamination=0.07)
    pipeline.train_and_evaluate(fe.transform(df), df["is_intrusion"])

    attack = pd.DataFrame(
        (
            {
                "timestamp": "2026-11-10T03:14:22Z",
                "user": "ana.silva@nexuscorp-demo.local",
                "asn_type": "HOSTING_VPS",
                "is_known_device": 0,
                "geo_velocity_kmh": 4200.0,
                "failed_attempts_10m": 5,
                "is_headless_ua": 1,
                "post_auth_sensitive_action": 1,
            },
        )
    )
    res = next(iter(pipeline.score_events(fe.transform(attack)).to_dict(orient="records")))
    assert res["risk_level"] in ("HIGH", "CRITICAL")
    assert res["anomaly_score_0_100"] >= 70.0


def test_phishing_and_vulnerability_scanners():
    phish = PhishingDetector().analyze_url_and_message(
        url="http://nexusc0rp-auth.test",
        message_text="URGENTE: Sua conta sera bloqueada hoje.",
    )
    assert phish["classification"] == "CRITICAL_PHISHING"

    vuln = VulnerabilityScanner().scan_authorized_asset(
        {
            "asset_id": "SRV-01",
            "hostname": "sso.nexuscorp-demo.local",
            "exposed_ports": (22, 443),
            "services": ("OpenSSH 7.4",),
        }
    )
    assert vuln["highest_cvss"] == 9.8


def test_ai_analyst_guardrails():
    analyst = AISecurityAnalystAgent()
    event = {
        "user": "ana.silva@nexuscorp-demo.local",
        "source_ip": "198.51.100.42",
        "asn_type": "HOSTING_VPS",
        "geo_velocity_kmh": 4200.0,
        "failed_attempts_10m": 3,
        "is_headless_ua": 1,
        "post_auth_sensitive_action": 1,
    }
    report = analyst.investigate_incident(event, {"anomaly_score": 97.5, "rf_intrusion_prob": 0.99, "risk_level": "CRITICAL"})
    assert report["guardrail_validated"] is True
    assert report["recovery_plan"]["bypass_automated"] is False


def test_api_authentication_and_health():
    unauth = client.get("/api/v1/incidents")
    assert unauth.status_code == 422

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "online"

    valid = client.get("/api/v1/incidents", headers={"x-api-key": API_KEY_DEMO})
    assert valid.status_code == 200