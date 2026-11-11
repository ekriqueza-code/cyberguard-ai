from datetime import datetime, timezone
import pandas as pd
import streamlit as st

from ai_analyst import AISecurityAnalystAgent
from cyberguard_ml import AnomalyDetectionPipeline, SecurityFeatureEngineer, SyntheticAuthGenerator
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
    init_db,
)
from security_scanners import PhishingDetector, ThreatIntelligenceEngine, VulnerabilityScanner

st.set_page_config(page_title="CyberGuard AI — SOC Platform", page_icon="🛡️", layout="wide")


@st.cache_resource
def bootstrap_platform():
    init_db()
    fe = SecurityFeatureEngineer()
    ml = AnomalyDetectionPipeline(contamination=0.045)
    raw_df = SyntheticAuthGenerator(seed=42).generate(n_normal=2500, n_anomalies=120)
    meta = ml.train_and_evaluate(fe.transform(raw_df), raw_df["is_intrusion"])

    db = SessionLocal()
    try:
        if not db.query(ModelVersion).filter_by(model_code=meta.model_id).first():
            db.add(
                ModelVersion(
                    model_code=meta.model_id,
                    version=meta.version,
                    algorithm=meta.algorithm,
                    dataset_summary=meta.dataset_summary,
                    metrics=meta.metrics,
                    retrain_threshold_jsd=meta.retrain_threshold_jsd,
                )
            )
            db.commit()
    finally:
        db.close()

    return fe, ml, AISecurityAnalystAgent(), ThreatIntelligenceEngine(), VulnerabilityScanner(), PhishingDetector()


fe, ml_pipeline, ai_analyst, threat_intel, vuln_scanner, phishing_detector = bootstrap_platform()


def process_auth_event(event_dict: dict) -> dict:
    scored_df = ml_pipeline.score_events(fe.transform(pd.DataFrame((event_dict,))))
    pred = next(iter(scored_df.to_dict(orient="records")))
    score = float(pred["anomaly_score_0_100"])
    risk = pred["risk_level"]

    db = SessionLocal()
    try:
        org = db.query(Organization).filter_by(domain="nexuscorp-demo.local").first()
        db.add(
            AuthenticationEvent(
                organization_id=org.id,
                user_email=event_dict["user"],
                source_ip=event_dict["source_ip"],
                asn_type=event_dict["asn_type"],
                is_known_device=bool(event_dict["is_known_device"]),
                geo_velocity_kmh=event_dict["geo_velocity_kmh"],
                failed_attempts_10m=event_dict["failed_attempts_10m"],
                anomaly_score=score,
                risk_level=risk,
            )
        )
        if risk in ("HIGH", "CRITICAL"):
            ml_sum = {"anomaly_score": score, "rf_intrusion_prob": float(pred["rf_intrusion_prob"]), "risk_level": risk}
            report = ai_analyst.investigate_incident(event_dict, ml_sum)
            inc = Incident(
                organization_id=org.id,
                incident_code=report["incident_id"],
                title=f"Tentativa de Intrusão ({risk}) — {event_dict['user']}",
                severity=risk,
                risk_score=score,
                status="OPEN_INVESTIGATING",
                target_user=event_dict["user"],
                source_ip=event_dict["source_ip"],
            )
            db.add(inc)
            db.flush()
            db.add(
                AIAnalysis(
                    organization_id=org.id,
                    incident_id=inc.id,
                    executive_summary=report["executive_summary"],
                    mitre_mapping=report["mitre_mapping"],
                    confidence_score=ml_sum["rf_intrusion_prob"],
                    guardrail_validated=report["guardrail_validated"],
                )
            )
            for rec in report["recommended_actions"]:
                db.add(Recommendation(organization_id=org.id, incident_id=inc.id, action_text=rec, priority=risk))
            db.add(
                AutomatedAction(
                    organization_id=org.id,
                    incident_id=inc.id,
                    action_type=f"REVOKE_SESSIONS_AND_BLOCK_IP ({event_dict['source_ip']})",
                    status="AWAITING_HUMAN_APPROVAL",
                )
            )
        db.add(
            AuditLog(
                organization_id=org.id,
                actor="CYBERGUARD_CLOUD_ENGINE",
                action="AUTH_EVENT_EVALUATED",
                target=event_dict["user"],
                details={"risk_level": risk, "score": score},
            )
        )
        db.commit()
    finally:
        db.close()
    return {"risk_level": risk, "score": score}


def approve_pending_action(action_id: str) -> None:
    db_a = SessionLocal()
    try:
        obj = db_a.query(AutomatedAction).filter_by(id=action_id).first()
        if obj:
            obj.status = "APPROVED"
            obj.approved_by = "soc.lead@nexuscorp-demo.local"
            inc = db_a.query(Incident).filter_by(id=obj.incident_id).first()
            if inc:
                inc.status = "CONTAINED_AUTHORIZED"
            db_a.add(
                AuditLog(
                    organization_id=obj.organization_id,
                    actor="soc.lead@nexuscorp-demo.local",
                    action="HUMAN_DECISION_APPROVED",
                    target=action_id,
                    details={"status": "CONTAINED_AUTHORIZED"},
                )
            )
            db_a.commit()
    finally:
        db_a.close()


def reset_demo_database() -> None:
    db_reset = SessionLocal()
    try:
        db_reset.query(AIAnalysis).delete()
        db_reset.query(Recommendation).delete()
        db_reset.query(AutomatedAction).delete()
        db_reset.query(Incident).delete()
        db_reset.query(AuthenticationEvent).delete()
        db_reset.query(ThreatIndicator).delete()
        db_reset.query(AuditLog).delete()
        db_reset.commit()
    finally:
        db_reset.close()


st.title("🛡️ CyberGuard AI — Plataforma Inteligente de Cybersecurity")
st.caption("SOC Operacional | Machine Learning Híbrido | Agente Analista de IA | Governança & Resposta")

with st.sidebar:
    st.header("⚡ Simulador de Telemetria")
    sim_user = st.selectbox(
        "Conta Monitorada",
        ("ana.silva@nexuscorp-demo.local", "carlos.mendes@nexuscorp-demo.local", "beatriz.costa@nexuscorp-demo.local"),
    )
    if st.button("🚨 Simular Ataque ATO (Crítico)", use_container_width=True):
        res = process_auth_event(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user": sim_user,
                "source_ip": "198.51.100.42",
                "asn_type": "HOSTING_VPS",
                "is_known_device": 0,
                "geo_velocity_kmh": 4200.0,
                "failed_attempts_10m": 3,
                "is_headless_ua": 1,
                "post_auth_sensitive_action": 1,
            }
        )
        st.success(f"Ataque detectado! Score: {res['score']} ({res['risk_level']})")

    if st.button("✅ Simular Login Legítimo", use_container_width=True):
        res = process_auth_event(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user": sim_user,
                "source_ip": "177.32.45.10",
                "asn_type": "CORPORATE_VPN",
                "is_known_device": 1,
                "geo_velocity_kmh": 12.0,
                "failed_attempts_10m": 0,
                "is_headless_ua": 0,
                "post_auth_sensitive_action": 0,
            }
        )
        st.info(f"Login legítimo avaliado! Score: {res['score']} ({res['risk_level']})")

    st.divider()
    if st.button("🔄 Atualizar Painel", use_container_width=True):
        st.rerun()

    if st.button("🗑️ Limpar Dados (Resetar Demo)", use_container_width=True):
        reset_demo_database()
        st.rerun()

db = SessionLocal()
try:
    events = db.query(AuthenticationEvent).order_by(AuthenticationEvent.created_at.desc()).all()
    incidents = db.query(Incident).order_by(Incident.created_at.desc()).all()
    analyses = db.query(AIAnalysis).order_by(AIAnalysis.created_at.desc()).all()
    pending_actions = db.query(AutomatedAction).filter_by(status="AWAITING_HUMAN_APPROVAL").all()
    audit_logs = db.query(AuditLog).order_by(AuditLog.created_at.desc()).limit(25).all()
    active_model = db.query(ModelVersion).filter_by(is_active=True).first()
finally:
    db.close()

k1, k2, k3, k4 = st.columns(4)
k1.metric("Eventos Monitorados", len(events))
k2.metric("Incidentes Críticos / Altos", sum(1 for i in incidents if i.severity in ("CRITICAL", "HIGH")))
k3.metric("Incidentes Contidos", sum(1 for i in incidents if i.status == "CONTAINED_AUTHORIZED"))
k4.metric("Tentativas Suspeitas", sum(1 for e in events if e.risk_level != "LOW"))
st.divider()

tab_soc, tab_ai, tab_scanners, tab_gov = st.tabs(
    ("📊 Monitoramento & Aprovação", "🤖 Agente Analista (MITRE)", "🔍 Scanners & Threat Intel", "📜 Governança & ML")
)

with tab_soc:
    c_left, c_right = st.columns((1.3, 1.0))
    with c_left:
        st.subheader("Histórico de Eventos de Autenticação")
        if events:
            df_ev = pd.DataFrame(
                tuple(
                    {
                        "Horário": e.created_at.strftime("%H:%M:%S"),
                        "Usuário": e.user_email,
                        "IP": e.source_ip,
                        "ASN": e.asn_type,
                        "Score": e.anomaly_score,
                        "Risco": e.risk_level,
                    }
                    for e in events
                )
            )
            st.dataframe(df_ev, use_container_width=True, hide_index=True)
            st.bar_chart(df_ev.groupby("Risco").size())
        else:
            st.info("Abra a barra lateral esquerda (>) e clique em Simular Ataque ATO.")

    with c_right:
