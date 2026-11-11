from datetime import datetime, timezone
from typing import List, Literal, Optional

import pandas as pd
from fastapi import Depends, FastAPI, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ai_analyst import AISecurityAnalystAgent
from cyberguard_ml import (
    AnomalyDetectionPipeline,
    SecurityFeatureEngineer,
    SyntheticAuthGenerator,
)
from database import (
    AIAnalysis,
    AuditLog,
    AuthenticationEvent,
    AutomatedAction,
    Incident,
    ModelVersion,
    Organization,
    Recommendation,
    SessionLocal,
    ThreatIndicator,
    get_db,
    init_db,
)
from security_scanners import (
    PhishingDetector,
    ThreatIntelligenceEngine,
    VulnerabilityScanner,
)

app = FastAPI(
    title="CyberGuard AI — Integrated Security Platform",
    description="Plataforma Unificada de Cybersecurity, Machine Learning, IA e Resposta Automatizada",
    version="2.0.1",
)

# ==========================================
# BOOTSTRAP DO BANCO, ML E AGENTES
# ==========================================
init_db()

fe = SecurityFeatureEngineer()
ml_pipeline = AnomalyDetectionPipeline(contamination=0.045)
_gen = SyntheticAuthGenerator(seed=42)
_raw_df = _gen.generate(n_normal=2500, n_anomalies=120)
model_metadata = ml_pipeline.train_and_evaluate(
    fe.transform(_raw_df), _raw_df["is_intrusion"]
)

_db_boot = SessionLocal()
try:
    if not _db_boot.query(ModelVersion).filter_by(model_code=model_metadata.model_id).first():
        _db_boot.add(
            ModelVersion(
                model_code=model_metadata.model_id,
                version=model_metadata.version,
                algorithm=model_metadata.algorithm,
                dataset_summary=model_metadata.dataset_summary,
                metrics=model_metadata.metrics,
                retrain_threshold_jsd=model_metadata.retrain_threshold_jsd,
            )
        )
        _db_boot.commit()
finally:
    _db_boot.close()

ai_analyst = AISecurityAnalystAgent()
threat_intel = ThreatIntelligenceEngine()
vuln_scanner = VulnerabilityScanner()
phishing_detector = PhishingDetector()

API_KEY_DEMO = "cg-secret-soc-2026"


def verify_api_key(x_api_key: str = Header(..., description="Use: cg-secret-soc-2026")):
    if x_api_key != API_KEY_DEMO:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Chave de API inválida.",
        )


def get_default_org(db: Session) -> Organization:
    org = db.query(Organization).filter_by(domain="nexuscorp-demo.local").first()
    if not org:
        raise HTTPException(status_code=404, detail="Organização padrão não encontrada.")
    return org


# ==========================================
# SCHEMAS DE ENTRADA (PYDANTIC)
# ==========================================
class AuthEventIn(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    user: str = Field(..., examples=("ana.silva@nexuscorp-demo.local",))
    source_ip: str = Field(..., examples=("198.51.100.42",))
    asn_type: Literal["RESIDENTIAL_ISP", "CORPORATE_VPN", "HOSTING_VPS"] = "HOSTING_VPS"
    is_known_device: int = Field(default=0, ge=0, le=1)
    geo_velocity_kmh: float = Field(default=4200.0, ge=0.0)
    failed_attempts_10m: int = Field(default=2, ge=0)
    is_headless_ua: int = Field(default=1, ge=0, le=1)
    post_auth_sensitive_action: int = Field(default=1, ge=0, le=1)


class PhishingCheckIn(BaseModel):
    url: str = Field(..., examples=("http://nexusc0rp-auth.test",))
    message_text: str = Field(default="URGENTE: Sua conta será bloqueada hoje.")


class AssetScanIn(BaseModel):
    asset_id: str = Field(default="SRV-FIN-01")
    hostname: str = Field(default="sso.nexuscorp-demo.local")
    exposed_ports: List[int] = Field(default=(22, 80, 443))
    services: List[str] = Field(default=("OpenSSH 7.4", "Nginx 1.18.0"))


class ActionApprovalIn(BaseModel):
    approver_email: str = Field(..., examples=("soc.lead@nexuscorp-demo.local",))
    decision: Literal["APPROVED", "REJECTED"]
    notes: Optional[str] = None


# ==========================================
# ENDPOINTS INTEGRADOS COM SQLALCHEMY
# ==========================================
@app.get("/health", tags=["Sistema"])
def health_check(db: Session = Depends(get_db)):
    return {
        "status": "online",
        "database": "cyberguard.db (Connected)",
        "model_id": model_metadata.model_id,
        "total_events_stored": db.query(AuthenticationEvent).count(),
        "open_incidents": db.query(Incident).count(),
    }


@app.post("/api/v1/events/auth", tags=["Módulos 01, 05, 08 & 09 — Detecção e IA"])
def ingest_auth_event(
    payload: AuthEventIn,
    db: Session = Depends(get_db),
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    org = get_default_org(db)
    event_dict = payload.model_dump()

    # 1. Inferência no Pipeline de ML (Módulo 05) — Corrigido
    df_event = pd.DataFrame((event_dict,))
    scored_df = ml_pipeline.score_events(fe.transform(df_event))
    pred_row = next(iter(scored_df.to_dict(orient="records")))
    score = float(pred_row["anomaly_score_0_100"])
    risk_level = pred_row["risk_level"]

    # 2. Grava Evento no Banco de Dados
    db_event = AuthenticationEvent(
        organization_id=org.id,
        user_email=event_dict["user"],
        source_ip=event_dict["source_ip"],
        asn_type=event_dict["asn_type"],
        is_known_device=bool(event_dict["is_known_device"]),
        geo_velocity_kmh=event_dict["geo_velocity_kmh"],
        failed_attempts_10m=event_dict["failed_attempts_10m"],
        anomaly_score=score,
        risk_level=risk_level,
    )
    db.add(db_event)
    db.flush()

    incident_payload = None
    ai_report = None
    pending_action_id = None

    # 3. Se HIGH ou CRITICAL: Abre Incidente, aciona Agente IA e cria Ação Pendente
    if risk_level in ("HIGH", "CRITICAL"):
        ml_summary = {
            "anomaly_score": score,
            "rf_intrusion_prob": float(pred_row["rf_intrusion_prob"]),
            "risk_level": risk_level,
        }
        ai_report = ai_analyst.investigate_incident(event_dict, ml_summary)
        inc_code = ai_report["incident_id"]

        db_incident = Incident(
            organization_id=org.id,
            incident_code=inc_code,
            title=f"Tentativa de Intrusão ({risk_level}) — {event_dict['user']}",
            severity=risk_level,
            risk_score=score,
            status="OPEN_INVESTIGATING",
            target_user=event_dict["user"],
            source_ip=event_dict["source_ip"],
        )
        db.add(db_incident)
        db.flush()

        db.add(
            AIAnalysis(
                organization_id=org.id,
                incident_id=db_incident.id,
                executive_summary=ai_report["executive_summary"],
                mitre_mapping=ai_report["mitre_mapping"],
                confidence_score=ml_summary["rf_intrusion_prob"],
                guardrail_validated=ai_report["guardrail_validated"],
            )
        )

        for rec_text in ai_report["recommended_actions"]:
            db.add(
                Recommendation(
                    organization_id=org.id,
                    incident_id=db_incident.id,
                    action_text=rec_text,
                    priority=risk_level,
                )
            )

        db_action = AutomatedAction(
            organization_id=org.id,
            incident_id=db_incident.id,
            action_type=f"REVOKE_SESSIONS_AND_BLOCK_IP ({event_dict['source_ip']})",
            status="AWAITING_HUMAN_APPROVAL",
        )
        db.add(db_action)
        db.flush()
        pending_action_id = db_action.id

        incident_payload = {
            "incident_id": db_incident.id,
            "incident_code": inc_code,
            "pending_action_id": pending_action_id,
        }

    db.add(
        AuditLog(
            organization_id=org.id,
            actor="CYBERGUARD_API_ENGINE",
            action="AUTH_EVENT_PERSISTED",
            target=event_dict["user"],
            details={"risk_level": risk_level, "score": score, "incident": incident_payload},
        )
    )
    db.commit()

    return {
        "event_id": db_event.id,
        "risk_level": risk_level,
        "anomaly_score": score,
        "incident": incident_payload,
        "ai_investigation": ai_report,
    }


@app.get("/api/v1/threat-intel/{indicator}", tags=["Módulo 02 — Threat Intelligence"])
def check_threat_indicator(
    indicator: str,
    db: Session = Depends(get_db),
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    org = get_default_org(db)
    result = threat_intel.lookup_indicator(indicator)

    if result["malicious"]:
        tdata = result["threat_data"]
        db.add(
            ThreatIndicator(
                organization_id=org.id,
                indicator_value=result["indicator"],
                indicator_type=tdata["type"],
                threat_category=tdata["category"],
                confidence=tdata["confidence"],
                mitre_technique=tdata["mitre"],
            )
        )
        db.commit()
    return result


@app.post("/api/v1/scanner/vulnerabilities", tags=["Módulo 03 — Vulnerability Scanner"])
def scan_vulnerabilities(
    payload: AssetScanIn,
    db: Session = Depends(get_db),
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    return vuln_scanner.scan_authorized_asset(payload.model_dump())


@app.post("/api/v1/scanner/phishing", tags=["Módulo 04 — Phishing Detector"])
def detect_phishing(
    payload: PhishingCheckIn,
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    return phishing_detector.analyze_url_and_message(
        url=payload.url, message_text=payload.message_text
    )


@app.get("/api/v1/incidents", tags=["Módulo 06 — Incidentes Persistidos"])
def list_incidents(
    db: Session = Depends(get_db),
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    items = db.query(Incident).order_by(Incident.created_at.desc()).all()
    return {"total": len(items), "incidents": items}


@app.get("/api/v1/actions/pending", tags=["Módulo 09 — Aprovação Humana"])
def list_pending_actions(
    db: Session = Depends(get_db),
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    actions = db.query(AutomatedAction).filter_by(status="AWAITING_HUMAN_APPROVAL").all()
    return {"total": len(actions), "actions": actions}


@app.post("/api/v1/actions/{action_id}/decide", tags=["Módulo 09 — Aprovação Humana"])
def decide_pending_action(
    action_id: str,
    decision_in: ActionApprovalIn,
    db: Session = Depends(get_db),
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    org = get_default_org(db)
    action_obj = db.query(AutomatedAction).filter_by(id=action_id).first()
    if not action_obj:
        raise HTTPException(status_code=404, detail="Ação não encontrada.")

    action_obj.status = decision_in.decision
    action_obj.approved_by = decision_in.approver_email
    action_obj.decision_notes = decision_in.notes

    inc = db.query(Incident).filter_by(id=action_obj.incident_id).first()
    if inc:
        inc.status = (
            "CONTAINED_AUTHORIZED"
            if decision_in.decision == "APPROVED"
            else "CONTAINMENT_REJECTED"
        )

    db.add(
        AuditLog(
            organization_id=org.id,
            actor=decision_in.approver_email,
            action=f"HUMAN_DECISION_{decision_in.decision}",
            target=action_id,
            details={"notes": decision_in.notes},
        )
    )
    db.commit()
    return {"message": "Decisão gravada no banco de dados.", "status": action_obj.status}


@app.get("/api/v1/audit-logs", tags=["Governança & Auditoria"])
def list_audit_logs(
    db: Session = Depends(get_db),
    x_api_key: str = Header(..., description="Use: cg-secret-soc-2026"),
):
    verify_api_key(x_api_key)
    logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(50).all()
    return {"total": len(logs), "logs": logs}