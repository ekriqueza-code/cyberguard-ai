import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List


@dataclass
class AgentDecisionRecord:
    decision_id: str
    timestamp: str
    incident_id: str
    tools_invoked: List[str]
    mitre_techniques: List[str]
    risk_assessment: str
    confidence_score: float
    validated: bool


class CyberSecurityKnowledgeBase:
    """Camada RAG Local: Base técnica de táticas MITRE ATT&CK e Playbooks de Recuperação."""

    MITRE_CATALOG: Dict[str, Dict[str, str]] = {
        "HOSTING_VPS": {
            "technique_id": "T1090 / T1583.003",
            "name": "Virtual Private Server Infrastructure",
            "description": "Uso de infraestrutura de nuvem ou VPS comercial para mascarar a origem real do tráfego.",
        },
        "IMPOSSIBLE_TRAVEL": {
            "technique_id": "T1078",
            "name": "Valid Accounts (Anomalous Geolocation)",
            "description": "Autenticação realizada a partir de localização fisicamente incompatível com a sessão anterior.",
        },
        "PASSWORD_SPRAY": {
            "technique_id": "T1110.003",
            "name": "Password Spraying",
            "description": "Múltiplas tentativas de autenticação de baixa frequência para evitar bloqueio automático de conta.",
        },
        "HEADLESS_AUTOMATION": {
            "technique_id": "T1059 / T1110",
            "name": "Automated Browser / Scripted Access",
            "description": "Uso de navegadores sem interface (Headless) ou scripts automatizados durante o fluxo de login.",
        },
        "POST_AUTH_PERSISTENCE": {
            "technique_id": "T1098 / T1114.003",
            "name": "Account Manipulation & Email Forwarding Rule",
            "description": "Alteração imediata de configurações sensíveis ou regras de encaminhamento após o login.",
        },
    }

    @classmethod
    def query_mitre(cls, indicator_keys: List[str]) -> List[Dict[str, str]]:
        return [cls.MITRE_CATALOG[k] for k in indicator_keys if k in cls.MITRE_CATALOG]


class ControlledSecurityTools:
    """Ferramentas permitidas (Allowlist) que o Agente de IA pode acionar durante a investigação."""

    @staticmethod
    def inspect_network_reputation(source_ip: str, asn_type: str) -> Dict[str, Any]:
        is_suspicious = asn_type == "HOSTING_VPS" or source_ip.startswith("198.51.100.")
        return {
            "tool": "inspect_network_reputation",
            "source_ip": source_ip,
            "asn_classification": asn_type,
            "threat_intel_match": is_suspicious,
            "reputation_note": "IP associado a bloco de hospedagem/VPS frequentemente usado em automação."
            if is_suspicious
            else "Provedor residencial ou VPN corporativa reconhecida.",
        }

    @staticmethod
    def evaluate_behavioral_signals(event: Dict[str, Any]) -> List[str]:
        signals = []
        if event.get("asn_type") == "HOSTING_VPS":
            signals.append("HOSTING_VPS")
        if float(event.get("geo_velocity_kmh", 0)) > 800.0:
            signals.append("IMPOSSIBLE_TRAVEL")
        if int(event.get("failed_attempts_10m", 0)) >= 5:
            signals.append("PASSWORD_SPRAY")
        if int(event.get("is_headless_ua", 0)) == 1:
            signals.append("HEADLESS_AUTOMATION")
        if int(event.get("post_auth_sensitive_action", 0)) == 1:
            signals.append("POST_AUTH_PERSISTENCE")
        return signals

    @staticmethod
    def build_account_recovery_plan(user_email: str, severity: str) -> Dict[str, Any]:
        """Módulo 07 — Gera checklist oficial e seguro de recuperação de conta."""
        steps = [
            "1. Encerrar todas as sessões ativas e revogar tokens OAuth/Refresh Tokens no provedor de identidade oficial.",
            "2. Realizar redefinição de senha através do portal oficial da organização utilizando dispositivo confiável.",
            "3. Validar e reconfigurar o segundo fator de autenticação (preferencialmente FIDO2/Passkey ou aplicativo autenticador).",
            "4. Auditar regras de encaminhamento de e-mail, filtros de caixa de entrada e dispositivos registrados recentemente.",
        ]
        if severity in ("HIGH", "CRITICAL"):
            steps.append(
                "5. Notificar o time de SOC e revisar logs de acesso a dados sensíveis nas últimas 24 horas."
            )
        return {
            "module": "MÓDULO 07 — ACCOUNT RECOVERY ASSISTANT",
            "target_account": user_email,
            "official_channel_only": True,
            "bypass_automated": False,
            "recovery_checklist": steps,
        }


class AISecurityAnalystAgent:
    """Módulo 08 — Agente Inteligente de Análise, Correlação e Resposta Assistida."""

    MAX_TOOL_CALLS = 5

    def __init__(self):
        self.operational_memory: List[Dict[str, Any]] = []
        self.decision_history: List[AgentDecisionRecord] = []
        self.allowed_tools: Dict[str, Callable] = {
            "inspect_network_reputation": ControlledSecurityTools.inspect_network_reputation,
            "evaluate_behavioral_signals": ControlledSecurityTools.evaluate_behavioral_signals,
            "build_account_recovery_plan": ControlledSecurityTools.build_account_recovery_plan,
        }

    def _validate_report(self, report: Dict[str, Any]) -> bool:
        """Camada de validação (Guardrails) antes de liberar a resposta do agente."""
        required_keys = ["incident_id", "executive_summary", "mitre_mapping", "recommended_actions", "recovery_plan"]
        has_all_keys = all(k in report and bool(report[k]) for k in required_keys)
        no_destructive_bypass = report["recovery_plan"].get("bypass_automated") is False
        return has_all_keys and no_destructive_bypass

    def investigate_incident(self, event: Dict[str, Any], ml_result: Dict[str, Any]) -> Dict[str, Any]:
        incident_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
        tools_used: List[str] = []

        # Passo 1: Acionar ferramenta de reputação de rede
        net_intel = self.allowed_tools["inspect_network_reputation"](
            source_ip=event["source_ip"],
            asn_type=event["asn_type"],
        )
        tools_used.append("inspect_network_reputation")

        # Passo 2: Extrair sinais comportamentais e consultar RAG (MITRE ATT&CK)
        signals = self.allowed_tools["evaluate_behavioral_signals"](event)
        tools_used.append("evaluate_behavioral_signals")
        mitre_details = CyberSecurityKnowledgeBase.query_mitre(signals)

        # Passo 3: Gerar plano oficial de recuperação (Módulo 07)
        severity = ml_result.get("risk_level", "MODERATE")
        recovery_plan = self.allowed_tools["build_account_recovery_plan"](
            user_email=event["user"],
            severity=severity,
        )
        tools_used.append("build_account_recovery_plan")

        if len(tools_used) > self.MAX_TOOL_CALLS:
            raise RuntimeError("Limite de execução de ferramentas do agente excedido.")

        # Passo 4: Síntese analítica contextual
        score = ml_result.get("anomaly_score", 0.0)
        summary = (
            f"Detectada atividade de risco {severity} (Score: {score}/100) na conta '{event['user']}' "
            f"originada do IP {event['source_ip']} ({event['asn_type']}). "
            f"Foram correlacionados {len(signals)} indicadores comportamentais: {', '.join(signals) or 'Nenhum desvio crítico'}."
        )

        recommended_actions = [
            "Preservar evidências completas do evento e metadados de sessão.",
            f"Solicitar aprovação humana no Módulo 09 para bloqueio temporário do IP {event['source_ip']}.",
            f"Executar o checklist assistido de recuperação de conta para {event['user']}.",
        ]

        report = {
            "incident_id": incident_id,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "target_user": event["user"],
            "severity": severity,
            "risk_score": score,
            "executive_summary": summary,
            "network_intelligence": net_intel,
            "mitre_mapping": mitre_details,
            "recommended_actions": recommended_actions,
            "recovery_plan": recovery_plan,
        }

        # Passo 5: Validação e registro na memória operacional
        is_valid = self._validate_report(report)
        report["guardrail_validated"] = is_valid

        decision_rec = AgentDecisionRecord(
            decision_id=f"DEC-{uuid.uuid4().hex[:6].upper()}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            incident_id=incident_id,
            tools_invoked=tools_used,
            mitre_techniques=[m["technique_id"] for m in mitre_details],
            risk_assessment=severity,
            confidence_score=round(float(ml_result.get("rf_intrusion_prob", 0.0)), 4),
            validated=is_valid,
        )
        self.decision_history.append(decision_rec)
        self.operational_memory.append({"incident_id": incident_id, "user": event["user"], "severity": severity})

        return report


if __name__ == "__main__":
    # Teste integrado com o Motor de ML (Módulo 05)
    import pandas as pd
    from cyberguard_ml import AnomalyDetectionPipeline, SecurityFeatureEngineer, SyntheticAuthGenerator

    gen = SyntheticAuthGenerator(seed=42)
    raw_df = gen.generate(n_normal=2500, n_anomalies=120)

    fe = SecurityFeatureEngineer()
    pipeline = AnomalyDetectionPipeline(contamination=0.045)
    pipeline.train_and_evaluate(fe.transform(raw_df), raw_df["is_intrusion"])

    sample_event = {
        "timestamp": "2026-11-10T03:14:22Z",
        "user": "ana.silva@nexuscorp-demo.local",
        "source_ip": "198.51.100.42",
        "asn_type": "HOSTING_VPS",
        "is_known_device": 0,
        "geo_velocity_kmh": 4200.0,
        "failed_attempts_10m": 2,
        "is_headless_ua": 1,
        "post_auth_sensitive_action": 1,
    }
    ml_pred = pipeline.score_events(fe.transform(pd.DataFrame([sample_event]))).iloc.to_dict()
    ml_pred["anomaly_score"] = ml_pred.pop("anomaly_score_0_100")

    analyst = AISecurityAnalystAgent()
    investigation_report = analyst.investigate_incident(sample_event, ml_pred)

    print("=== RELATÓRIO DO AGENTE ANALISTA DE SEGURANÇA (MÓDULO 08) ===")
    print(json.dumps(investigation_report, indent=2, ensure_ascii=False))