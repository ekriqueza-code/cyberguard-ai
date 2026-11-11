
import pandas as pd
import requests
import streamlit as st

from database import (
    AIAnalysis,
    AuditLog,
    AuthenticationEvent,
    AutomatedAction,
    Incident,
    ModelVersion,
    SessionLocal,
)

API_BASE_URL = "http://127.0.0.1:8000"
API_HEADERS = {"x-api-key": "cg-secret-soc-2026"}

st.set_page_config(
    page_title="CyberGuard AI — SOC Platform",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ CyberGuard AI — Plataforma Inteligente de Cybersecurity")
st.caption("SOC Operacional | Machine Learning Híbrido | Agente Analista de IA | Governança & Resposta")

# ==========================================
# BARRA LATERAL — SIMULADOR DE EVENTOS EM TEMPO REAL
# ==========================================
with st.sidebar:
    st.header("⚡ Simulador de Telemetria")
    st.write("Envie eventos sintéticos para a API avaliar com ML e IA:")

    sim_user = st.selectbox(
        "Conta Monitorada",
        (
            "ana.silva@nexuscorp-demo.local",
            "carlos.mendes@nexuscorp-demo.local",
            "beatriz.costa@nexuscorp-demo.local",
        ),
    )

    if st.button("🚨 Simular Ataque ATO (Crítico)", use_container_width=True):
        payload = {
            "user": sim_user,
            "source_ip": "198.51.100.42",
            "asn_type": "HOSTING_VPS",
            "is_known_device": 0,
            "geo_velocity_kmh": 4200.0,
            "failed_attempts_10m": 3,
            "is_headless_ua": 1,
            "post_auth_sensitive_action": 1,
        }
        try:
            resp = requests.post(f"{API_BASE_URL}/api/v1/events/auth", json=payload, headers=API_HEADERS, timeout=5)
            if resp.status_code == 200:
                st.success("Ataque simulado enviado! Incidente e Análise de IA gerados.")
            else:
                st.error(f"Erro na API: {resp.text}")
        except Exception as exc:
            st.error(f"API offline em {API_BASE_URL}: {exc}")

    if st.button("✅ Simular Login Legítimo", use_container_width=True):
        payload = {
            "user": sim_user,
            "source_ip": "177.32.45.10",
            "asn_type": "CORPORATE_VPN",
            "is_known_device": 1,
            "geo_velocity_kmh": 12.0,
            "failed_attempts_10m": 0,
            "is_headless_ua": 0,
            "post_auth_sensitive_action": 0,
        }
        try:
            resp = requests.post(f"{API_BASE_URL}/api/v1/events/auth", json=payload, headers=API_HEADERS, timeout=5)
            if resp.status_code == 200:
                st.info("Login legítimo registrado com risco LOW.")
        except Exception as exc:
            st.error(f"API offline em {API_BASE_URL}: {exc}")

    st.divider()
    if st.button("🔄 Atualizar Painel", use_container_width=True):
        st.rerun()

# ==========================================
# CONSULTA AO BANCO DE DADOS (SQLITE)
# ==========================================
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

# ==========================================
# KPIs PRINCIPAIS (MÓDULO 10)
# ==========================================
total_events = len(events)
critical_incidents = sum(1 for i in incidents if i.severity in ("CRITICAL", "HIGH"))
resolved_incidents = sum(1 for i in incidents if i.status == "CONTAINED_AUTHORIZED")
suspicious_attempts = sum(1 for e in events if e.risk_level != "LOW")

k1, k2, k3, k4 = st.columns(4)
k1.metric("Eventos Monitorados", total_events)
k2.metric("Incidentes Críticos / Altos", critical_incidents)
k3.metric("Incidentes Contidos", resolved_incidents)
k4.metric("Tentativas Suspeitas", suspicious_attempts)

st.divider()

# ==========================================
# ABAS DOS MÓDULOS INTEGRADOS
# ==========================================
tab_soc, tab_ai, tab_scanners, tab_gov = st.tabs(
    (
        "📊 Monitoramento & Aprovação (Módulos 01, 06 & 09)",
        "🤖 Agente Analista & Recuperação (Módulos 07 & 08)",
        "🔍 Threat Intel, Vulns & Phishing (Módulos 02, 03 & 04)",
        "📜 Governança, ML & Auditoria (Módulo 05)",
    )
)

with tab_soc:
    col_left, col_right = st.columns((1.3, 1.0))

    with col_left:
        st.subheader("Histórico de Eventos de Autenticação")
        if events:
            df_ev = pd.DataFrame(
                tuple(
                    {
                        "Horário (UTC)": e.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                        "Usuário": e.user_email,
                        "IP Origem": e.source_ip,
                        "ASN": e.asn_type,
                        "Score ML": e.anomaly_score,
                        "Risco": e.risk_level,
                    }
                    for e in events
                )
            )
            st.dataframe(df_ev, use_container_width=True, hide_index=True)

            st.subheader("Distribuição por Nível de Risco")
            risk_counts = df_ev.groupby("Risco").size()
            st.bar_chart(risk_counts)
        else:
            st.info("Nenhum evento registrado ainda. Use o botão na barra lateral para simular um evento.")

    with col_right:
        st.subheader("🚨 Contenções Aguardando Aprovação Humana")
        if pending_actions:
            for act in pending_actions:
                with st.container(border=True):
                    st.markdown(f"**Ação Proposta:** `{act.action_type}`")
                    st.caption(f"ID da Ação: {act.id} | Status: {act.status}")
                    c_app, c_rej = st.columns(2)
                    if c_app.button("✅ Aprovar Bloqueio", key=f"app_{act.id}", use_container_width=True):
                        requests.post(
                            f"{API_BASE_URL}/api/v1/actions/{act.id}/decide",
                            json={
                                "approver_email": "soc.lead@nexuscorp-demo.local",
                                "decision": "APPROVED",
                                "notes": "Aprovado via SOC Dashboard.",
                            },
                            headers=API_HEADERS,
                            timeout=5,
                        )
                        st.rerun()
                    if c_rej.button("❌ Rejeitar", key=f"rej_{act.id}", use_container_width=True):
                        requests.post(
                            f"{API_BASE_URL}/api/v1/actions/{act.id}/decide",
                            json={
                                "approver_email": "soc.lead@nexuscorp-demo.local",
                                "decision": "REJECTED",
                                "notes": "Falso positivo descartado pelo analista.",
                            },
                            headers=API_HEADERS,
                            timeout=5,
                        )
                        st.rerun()
        else:
            st.success("Nenhuma ação crítica pendente de aprovação no momento.")

        st.subheader("Incidentes Registrados")
        if incidents:
            df_inc = pd.DataFrame(
                tuple(
                    {
                        "Código": i.incident_code,
                        "Alvo": i.target_user,
                        "Severidade": i.severity,
                        "Score": i.risk_score,
                        "Status": i.status,
                    }
                    for i in incidents
                )
            )
            st.dataframe(df_inc, use_container_width=True, hide_index=True)

with tab_ai:
    st.subheader("Relatórios Investigativos do Agente Analista de Segurança")
    if analyses:
        for item in analyses:
            with st.expander(f"Relatório Investigativo — Confiança ML: {item.confidence_score * 100:.1f}%", expanded=True):
                st.write(item.executive_summary)
                st.markdown("**Técnicas MITRE ATT&CK Mapeadas:**")
                st.json(item.mitre_mapping)
                st.markdown("**Checklist Oficial de Recuperação de Conta (Módulo 07):**")
                st.markdown(
                    "- Encerrar todas as sessões ativas e revogar tokens OAuth no provedor oficial.\n"
                    "- Redefinir senha via portal corporativo em dispositivo confiável.\n"
                    "- Reconfigurar MFA (FIDO2/Passkey ou App Autenticador).\n"
                    "- Auditar regras de encaminhamento de e-mail e dispositivos conectados."
                )
    else:
        st.info("Simule um ataque crítico na barra lateral para acionar o Agente Analista de IA.")

with tab_scanners:
    c_phish, c_ti, c_vuln = st.columns(3)

    with c_phish:
        st.subheader("🎣 Detector de Phishing")
        url_input = st.text_input("URL Suspeita", value="http://nexusc0rp-auth.test")
        msg_input = st.text_area("Texto da Mensagem", value="URGENTE: Sua conta será bloqueada hoje. Atualize sua senha.")
        if st.button("Analisar Phishing", use_container_width=True):
            r = requests.post(
                f"{API_BASE_URL}/api/v1/scanner/phishing",
                json={"url": url_input, "message_text": msg_input},
                headers=API_HEADERS,
                timeout=5,
            ).json()
            st.metric("Score de Phishing", f"{r['phishing_score_0_100']}/100", r["classification"])
            for ind in r["explained_indicators"]:
                st.warning(ind)

    with c_ti:
        st.subheader("🌐 Threat Intelligence")
        ioc_input = st.text_input("IP ou Domínio (IoC)", value="198.51.100.42")
        if st.button("Consultar IoC", use_container_width=True):
            r = requests.get(
                f"{API_BASE_URL}/api/v1/threat-intel/{ioc_input}",
                headers=API_HEADERS,
                timeout=5,
            ).json()
            if r["malicious"]:
                st.error("Indicador Malicioso Confirmado!")
            else:
                st.success("Nenhuma ameaça conhecida encontrada.")
            st.json(r["threat_data"])

    with c_vuln:
        st.subheader("🔎 Scanner de Vulnerabilidades")
        host_input = st.text_input("Hostname Autorizado", value="sso.nexuscorp-demo.local")
        svc_select = st.multiselect(
            "Serviços Inventariados",
            ("OpenSSH 7.4", "PostgreSQL 12.1", "Nginx 1.18.0"),
            default=("OpenSSH 7.4", "Nginx 1.18.0"),
        )
        if st.button("Avaliar Ativo", use_container_width=True):
            r = requests.post(
                f"{API_BASE_URL}/api/v1/scanner/vulnerabilities",
                json={
                    "asset_id": "SRV-01",
                    "hostname": host_input,
                    "exposed_ports": (22, 443),
                    "services": svc_select,
                },
                headers=API_HEADERS,
                timeout=5,
            ).json()
            st.metric("Maior CVSS Encontrado", r["highest_cvss"])
            st.json(r["findings"])

with tab_gov:
    st.subheader("Governança de Modelos de Machine Learning")
    if active_model:
        st.write(f"**Modelo Ativo:** `{active_model.model_code}` | **Algoritmo:** {active_model.algorithm}")
        st.json(active_model.metrics)

    st.subheader("Trilha de Auditoria Imutável (AuditLogs)")
    if audit_logs:
        df_aud = pd.DataFrame(
            tuple(
                {
                    "Data/Hora": a.created_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "Ator": a.actor,
                    "Ação": a.action,
                    "Alvo": a.target,
                }
                for a in audit_logs
            )
        )
        st.dataframe(df_aud, use_container_width=True, hide_index=True)
        