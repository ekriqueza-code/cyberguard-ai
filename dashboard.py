)
            )
            st.dataframe(df_ev, use_container_width=True, hide_index=True)

            st.subheader("Distribuição por Nível de Risco")
            risk_counts = df_ev.groupby("Risco").size()
            st.bar_chart(risk_counts)
        else:
            st.info("Nenhum evento registrado ainda. Abra a barra lateral esquerda (>) e clique em Simular Ataque.")

    with col_right:
        st.subheader("🚨 Contenções Aguardando Aprovação Humana")
        if pending_actions:
            for act in pending_actions:
                with st.container(border=True):
                    st.markdown(f"**Ação Proposta:** `{act.action_type}`")
                    st.caption(f"ID da Ação: {act.id} | Status: {act.status}")
                    c_app, c_rej = st.columns(2)
                    if c_app.button("✅ Aprovar Bloqueio", key=f"app_{act.id}", use_container_width=True):
                        db_act = SessionLocal()
                        try:
                            target_act = db_act.query(AutomatedAction).filter_by(id=act.id).first()
                            if target_act:
                                target_act.status = "APPROVED"
                                target_act.approved_by = "soc.lead@nexuscorp-demo.local"
                                inc = db_act.query(Incident).filter_by(id=target_act.incident_id).first()
                                if inc:
                                    inc.status = "CONTAINED_AUTHORIZED"
                                db_act.add(
                                    AuditLog(
                                        organization_id=target_act.organization_id,
                                        actor="soc.lead@nexuscorp-demo.local",
                                        action="HUMAN_DECISION_APPROVED",
                                        target=act.id,
                                        details={"status": "CONTAINED_AUTHORIZED"},
                                    )
                                )
                                db_act.commit()
                        finally:
                            db_act.close()
                        st.rerun()

                    if c_rej.button("❌ Rejeitar", key=f"rej_{act.id}", use_container_width=True):
                        db_act = SessionLocal()
                        try:
                            target_act = db_act.query(AutomatedAction).filter_by(id=act.id).first()
                            if target_act:
                                target_act.status = "REJECTED"
                                target_act.approved_by = "soc.lead@nexuscorp-demo.local"
                                inc = db_act.query(Incident).filter_by(id=target_act.incident_id).first()
                                if inc:
                                    inc.status = "CONTAINMENT_REJECTED"
                                db_act.commit()
                        finally:
                            db_act.close()
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
            r = phishing_detector.analyze_url_and_message(url=url_input, message_text=msg_input)
            st.metric("Score de Phishing", f"{r['phishing_score_0_100']}/100", r["classification"])
            for ind in r["explained_indicators"]:
                st.warning(ind)

    with c_ti:
        st.subheader("🌐 Threat Intelligence")
        ioc_input = st.text_input("IP ou Domínio (IoC)", value="198.51.100.42")
        if st.button("Consultar IoC", use_container_width=True):
            r = threat_intel.lookup_indicator(ioc_input)
            if r["malicious"]:
                st.error("Indicador Malicioso Confirmado!")
                db_ti = SessionLocal()
                try:
                    org = db_ti.query(Organization).filter_by(domain="nexuscorp-demo.local").first()
                    tdata = r["threat_data"]
                    db_ti.add(
                        ThreatIndicator(
                            organization_id=org.id,
                            indicator_value=r["indicator"],
                            indicator_type=tdata["type"],
                            threat_category=tdata["category"],
                            confidence=tdata["confidence"],
                            mitre_technique=tdata["mitre"],
                        )
                    )
                    db_ti.commit()
                finally:
                    db_ti.close()
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
            r = vuln_scanner.scan_authorized_asset(
                {
                    "asset_id": "SRV-01",
                    "hostname": host_input,
                    "exposed_ports": (22, 443),
                    "services": svc_select,
                }
            )
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
