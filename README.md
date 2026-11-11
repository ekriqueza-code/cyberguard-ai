https://cyberguard-ai-rxby85itp6pacp8i7i8en5.streamlit.app/
# cyberguard-ai# 🛡️ CyberGuard AI — Intelligent Security Operations & Threat Detection Platform

Plataforma modular e integrada de **Cybersecurity**, **Data Science** e **Inteligência Artificial** projetada para monitoramento de contas, detecção híbrida de anomalias, inteligência de ameaças, análise de vulnerabilidades e resposta automatizada com supervisão humana (*Human-in-the-Loop*).

---

## 🏗️ Arquitetura da Plataforma

O **CyberGuard AI** opera como uma aplicação modular unificada sobre um banco de dados relacional multi-tenant (`SQLAlchemy`), expondo uma API RESTful (`FastAPI`) e um painel operacional interativo (`Streamlit`).

```text
cyberguard-ai/
├── cyberguard_ml.py       # Módulo 05: Pipeline híbrido (Isolation Forest + Random Forest) e Data Drift
├── ai_analyst.py          # Módulos 07 & 08: Agente Analista com RAG (MITRE ATT&CK) e Guardrails
├── security_scanners.py   # Módulos 02, 03 & 04: Threat Intel, Vulnerability Scanner (CVSS) e Phishing Detector
├── database.py            # Schema relacional com 17 entidades, RBAC, Multi-Tenancy e Audit Logs
├── api.py                 # Módulos 01, 06 & 09: Backend FastAPI, Orquestração e Resposta Automatizada
├── dashboard.py           # Módulo 10: SOC Dashboard interativo em Streamlit
├── test_cyberguard.py     # Suíte de testes automatizados com Pytest
└── requirements.txt       # Dependências do projeto
```

---

## 🚀 Módulos Implementados

1. **Account Guardian (Módulo 01):** Monitoramento contínuo de eventos de autenticação, detecção de dispositivos desconhecidos, horários atípicos e cálculo de viagem impossível (*Impossible Travel*).
2. **Threat Intelligence (Módulo 02):** Consulta e correlação de Indicadores de Comprometimento (IoCs — IPs e domínios maliciosos).
3. **Vulnerability Scanner (Módulo 03):** Avaliação autorizada de inventário de ativos, portas expostas e priorização por **CVE** e **CVSS v3.1**.
4. **Phishing Detector (Módulo 04):** Análise heurística de URLs, detecção de *typosquatting*, entropia de domínio e gatilhos de engenharia social com explicabilidade.
5. **Anomaly Detection (Módulo 05):** Modelo híbrido calibrado (**Isolation Forest** + **Random Forest**) com *Feature Engineering* cíclico e monitoramento de *Data Drift* via Divergência de Jensen-Shannon.
6. **Incident Response (Módulo 06):** Abertura automática de incidentes críticos, preservação de evidências e rastreamento de status.
7. **Account Recovery Assistant (Módulo 07):** Geração de checklists oficiais e seguros para recuperação de contas comprometidas sem bypass automatizado.
8. **AI Security Analyst (Módulo 08):** Agente investigativo com ferramentas controladas (*Tool Allowlist*), mapeamento automático para o framework **MITRE ATT&CK** e camada de validação (*Guardrails*).
9. **Automated Response Engine (Módulo 09):** Políticas proporcionais ao nível de risco com fluxo obrigatório de **aprovação humana** antes de ações de contenção.
10. **Security Dashboard (Módulo 10):** Painel gerencial e operacional com KPIs em tempo real, simulador de telemetria e fila de aprovações.

---

## ⚙️ Como Executar Localmente

### 1. Instalar dependências
```bash
pip install -r requirements.txt
```

### 2. Iniciar o Backend (FastAPI)
```bash
uvicorn api:app --reload
```
Acesse a documentação interativa em: `http://127.0.0`

### 3. Iniciar o Painel SOC (Streamlit)
Em outro terminal, execute:
```bash
streamlit run dashboard.py
```
Acesse o painel em: `http://localhost:8501`

### 4. Executar Testes Automatizados
```bash
pytest -v
```

---

## 🔒 Ética e Governança

Este projeto foi desenvolvido estritamente para fins educacionais, pesquisa defensiva (Blue Team / SOC) e demonstração de arquitetura SaaS. Todas as simulações utilizam exclusivamente dados sintéticos e ambientes controlados.
