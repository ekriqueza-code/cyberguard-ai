import uuid
from datetime import datetime, timezone
from typing import Generator

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, Session

# Banco SQLite local por padrão (basta trocar a URL para PostgreSQL em produção)
DATABASE_URL = "sqlite:///./cyberguard.db"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def generate_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ==========================================
# 1. ORGANIZATIONS & GOVERNANCE (MULTI-TENANT)
# ==========================================
class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(150), nullable=False)
    domain = Column(String(150), unique=True, nullable=False, index=True)
    plan_tier = Column(String(50), default="ENTERPRISE")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class Role(Base):
    __tablename__ = "roles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(80), unique=True, nullable=False)
    description = Column(String(255))


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    resource = Column(String(80), nullable=False)
    action = Column(String(50), nullable=False)


class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(String(36), ForeignKey("roles.id"), nullable=False)
    email = Column(String(180), unique=True, nullable=False, index=True)
    full_name = Column(String(150), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    mfa_enabled = Column(Boolean, default=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


# ==========================================
# 2. ASSETS & MONITORED ACCOUNTS
# ==========================================
class Asset(Base):
    __tablename__ = "assets"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    hostname = Column(String(180), nullable=False)
    ip_address = Column(String(45), nullable=False)
    asset_type = Column(String(50), default="SERVER")
    criticality = Column(String(30), default="HIGH")
    created_at = Column(DateTime, default=utcnow)


class Account(Base):
    __tablename__ = "accounts"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    account_identifier = Column(String(180), nullable=False, index=True)
    provider = Column(String(80), default="CORPORATE_SSO")
    risk_status = Column(String(30), default="NORMAL")
    last_known_ip = Column(String(45))
    created_at = Column(DateTime, default=utcnow)


# ==========================================
# 3. EVENTS, THREAT INTEL & VULNERABILITIES
# ==========================================
class AuthenticationEvent(Base):
    __tablename__ = "authentication_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    account_id = Column(String(36), ForeignKey("accounts.id", ondelete="SET NULL"), nullable=True, index=True)
    user_email = Column(String(180), nullable=False, index=True)
    source_ip = Column(String(45), nullable=False, index=True)
    asn_type = Column(String(50), default="RESIDENTIAL_ISP")
    is_known_device = Column(Boolean, default=True)
    geo_velocity_kmh = Column(Float, default=0.0)
    failed_attempts_10m = Column(Integer, default=0)
    anomaly_score = Column(Float, default=0.0)
    risk_level = Column(String(20), default="LOW", index=True)
    created_at = Column(DateTime, default=utcnow, index=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    module_source = Column(String(60), nullable=False)
    event_type = Column(String(80), nullable=False)
    severity = Column(String(20), default="LOW", index=True)
    raw_payload = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utcnow, index=True)


class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    indicator_value = Column(String(255), nullable=False, index=True)
    indicator_type = Column(String(30), nullable=False)
    threat_category = Column(String(120), nullable=False)
    confidence = Column(Integer, default=80)
    mitre_technique = Column(String(50))
    created_at = Column(DateTime, default=utcnow)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    cve_id = Column(String(40), nullable=False, index=True)
    cvss_score = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False)
    remediation = Column(Text, nullable=False)
    status = Column(String(30), default="OPEN")
    detected_at = Column(DateTime, default=utcnow)


# ==========================================
# 4. INCIDENTS, AI ANALYST & RESPONSES
# ==========================================
class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_code = Column(String(30), unique=True, nullable=False, index=True)
    title = Column(String(200), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    risk_score = Column(Float, nullable=False)
    status = Column(String(40), default="OPEN_INVESTIGATING", index=True)
    target_user = Column(String(180))
    source_ip = Column(String(45))
    created_at = Column(DateTime, default=utcnow)


class AIAnalysis(Base):
    __tablename__ = "ai_analyses"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    executive_summary = Column(Text, nullable=False)
    mitre_mapping = Column(JSON, nullable=False)
    confidence_score = Column(Float, nullable=False)
    guardrail_validated = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)


class Recommendation(Base):
    __tablename__ = "recommendations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_text = Column(Text, nullable=False)
    priority = Column(String(20), default="HIGH")
    is_applied = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)


class AutomatedAction(Base):
    __tablename__ = "automated_actions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    incident_id = Column(String(36), ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    action_type = Column(String(80), nullable=False)
    status = Column(String(40), default="AWAITING_HUMAN_APPROVAL", index=True)
    approved_by = Column(String(180), nullable=True)
    decision_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)


# ==========================================
# 5. AUDIT LOGS, ML GOVERNANCE & NOTIFICATIONS
# ==========================================
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True)
    actor = Column(String(180), nullable=False)
    action = Column(String(100), nullable=False, index=True)
    target = Column(String(180), nullable=False)
    details = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=utcnow, index=True)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    model_code = Column(String(60), unique=True, nullable=False)
    version = Column(String(30), nullable=False)
    algorithm = Column(String(120), nullable=False)
    dataset_summary = Column(String(255), nullable=False)
    metrics = Column(JSON, nullable=False)
    retrain_threshold_jsd = Column(Float, default=0.15)
    is_active = Column(Boolean, default=True)
    trained_at = Column(DateTime, default=utcnow)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    organization_id = Column(String(36), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True)
    channel = Column(String(40), default="DASHBOARD_ALERT")
    title = Column(String(180), nullable=False)
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)


Index("idx_auth_org_risk", AuthenticationEvent.organization_id, AuthenticationEvent.risk_level)
Index("idx_incident_org_status", Incident.organization_id, Incident.status)


def init_db() -> None:
    """Cria todas as 17 tabelas e popula dados iniciais da organização demo."""
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()
    try:
        if not db.query(Organization).filter_by(domain="nexuscorp-demo.local").first():
            org = Organization(
                name="NexusCorp Financial (Demo)",
                domain="nexuscorp-demo.local",
                plan_tier="ENTERPRISE",
            )
            db.add(org)
            db.flush()

            admin_role = Role(name="SOC_ADMIN", description="Administrador completo do SOC")
            analyst_role = Role(name="SECURITY_ANALYST", description="Analista de segurança e investigação")
            db.add_all((admin_role, analyst_role))
            db.flush()

            perm = Permission(role_id=admin_role.id, resource="AUTOMATED_ACTIONS", action="APPROVE")
            admin_user = User(
                organization_id=org.id,
                role_id=admin_role.id,
                email="soc.lead@nexuscorp-demo.local",
                full_name="Líder SOC NexusCorp",
                hashed_password="argon2id$demo_hashed_secret_key",
            )
            audit = AuditLog(
                organization_id=org.id,
                actor="SYSTEM_BOOTSTRAP",
                action="DATABASE_INITIALIZED",
                target="cyberguard.db",
                details={"tables_created": 17, "tenant": org.domain},
            )
            db.add_all((perm, admin_user, audit))
            db.commit()
    finally:
        db.close()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    db = SessionLocal()
    org_count = db.query(Organization).count()
    user_count = db.query(User).count()
    audit_count = db.query(AuditLog).count()
    db.close()

    print("=== BANCO DE DADOS CYBERGUARD AI INICIALIZADO COM SUCESSO ===")
    print("Arquivo SQLite criado: cyberguard.db")
    print(f"Total de tabelas estruturadas: {len(Base.metadata.tables)}")
    print(f"Organizações ativas: {org_count} | Usuários: {user_count} | Logs de Auditoria: {audit_count}")