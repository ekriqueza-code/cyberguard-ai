import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse


# ==========================================
# MÓDULO 02 — THREAT INTELLIGENCE
# ==========================================
class ThreatIntelligenceEngine:
    """Consulta indicadores de comprometimento (IoCs) e classifica ameaças."""

    KNOWN_IOCS: Dict[str, Dict[str, Any]] = {
        "198.51.100.42": {
            "type": "IPv4",
            "category": "Credential Stuffing & Brute Force Node",
            "confidence": 95,
            "source": "CyberGuard Threat Feed / AbuseIPDB Simulation",
            "mitre": "T1110.003",
        },
        "nexusc0rp-auth.test": {
            "type": "DOMAIN",
            "category": "Typosquatting / Phishing Kit",
            "confidence": 98,
            "source": "Certificate Transparency Monitor",
            "mitre": "T1566.002",
        },
        "203.0.113.88": {
            "type": "IPv4",
            "category": "C2 Command & Control Infrastructure",
            "confidence": 92,
            "source": "OpenCTI Community Feed",
            "mitre": "T1071.001",
        },
    }

    def lookup_indicator(self, indicator: str) -> Dict[str, Any]:
        cleaned = indicator.strip().lower()
        match = self.KNOWN_IOCS.get(cleaned)
        if match:
            return {
                "indicator": cleaned,
                "malicious": True,
                "threat_data": match,
                "checked_at": datetime.now(timezone.utc).isoformat(),
            }
        return {
            "indicator": cleaned,
            "malicious": False,
            "threat_data": {"category": "No known threat match", "confidence": 10},
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }


# ==========================================
# MÓDULO 03 — VULNERABILITY SCANNER (AUTORIZADO)
# ==========================================
class VulnerabilityScanner:
    """Analisa ativos autorizados, serviços expostos e prioriza por CVSS."""

    VULNERABILITY_SIGNATURES: Dict[str, Dict[str, Any]] = {
        "OpenSSH 7.4": {
            "cve": "CVE-2023-38408",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Execução remota de código via encaminhamento de agente SSH (ssh-agent).",
            "remediation": "Atualizar imediatamente para OpenSSH 9.3p2 ou superior e desabilitar forwarding não utilizado.",
        },
        "PostgreSQL 12.1": {
            "cve": "CVE-2024-0985",
            "cvss_score": 8.0,
            "severity": "HIGH",
            "description": "Elevação de privilégios em comandos REFRESH MATERIALIZED VIEW CONCURRENTLY.",
            "remediation": "Aplicar patch de segurança da série 12.18+ e restringir acesso de rede à porta 5432.",
        },
        "Nginx 1.18.0": {
            "cve": "CVE-2021-23017",
            "cvss_score": 7.7,
            "severity": "HIGH",
            "description": "Falha de gravação fora dos limites no resolver DNS do Nginx.",
            "remediation": "Atualizar Nginx para versão 1.24+ e revisar diretivas resolver.",
        },
    }

    def scan_authorized_asset(self, asset: Dict[str, Any]) -> Dict[str, Any]:
        """Avalia o inventário de serviços declarados de um ativo autorizado."""
        findings = list()
        exposed_ports = asset.get("exposed_ports", list())
        services = asset.get("services", list())

        for svc in services:
            if svc in self.VULNERABILITY_SIGNATURES:
                findings.append({"service": svc, **self.VULNERABILITY_SIGNATURES[svc]})

        if 22 in exposed_ports or 3389 in exposed_ports:
            findings.append({
                "service": "Administrative Remote Access (SSH/RDP)",
                "cve": "CONFIG-EXPOSURE-01",
                "cvss_score": 7.5,
                "severity": "HIGH",
                "description": "Porta administrativa exposta diretamente sem VPN ou Zero Trust Proxy.",
                "remediation": "Restringir portas 22/3389 apenas a IPs da VPN corporativa ou Bastion Host.",
            })

        findings.sort(key=lambda x: x["cvss_score"], reverse=True)
        max_cvss = findings[0]["cvss_score"] if findings else 0.0

        return {
            "asset_id": asset.get("asset_id", "ASSET-UNKNOWN"),
            "hostname": asset.get("hostname"),
            "authorized_scan": True,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total_vulnerabilities": len(findings),
            "highest_cvss": max_cvss,
            "findings": findings,
        }


# ==========================================
# MÓDULO 04 — PHISHING DETECTOR
# ==========================================
class PhishingDetector:
    """Analisa URLs, domínios e mensagens suspeitas com explicabilidade."""

    URGENCY_KEYWORDS = (
        "urgente", "bloqueada", "suspensa", "atualize", "reembolso",
        "fatura", "verifique", "senha expira", "imediato", "clique aqui",
    )
    SUSPICIOUS_TLDS = (".xyz", ".top", ".buzz", ".click", ".test", ".tk", ".ml")

    @staticmethod
    def _calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        counts = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    def analyze_url_and_message(self, url: str, message_text: str = "", protected_brand: str = "nexuscorp") -> Dict[str, Any]:
        indicators: List[str] = list()
        score = 0

        parsed = urlparse(url if "://" in url else f"http://{url}")
        domain = parsed.netloc.lower()

        if parsed.scheme == "http":
            score += 20
            indicators.append("Protocolo inseguro (HTTP sem criptografia TLS).")

        if any(domain.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
            score += 30
            indicators.append(f"Domínio utiliza TLD de alto risco ({domain.split('.')[-1]}).")

        normalized_domain = domain.replace("0", "o").replace("1", "i").replace("-", "")
        if protected_brand in normalized_domain and protected_brand not in domain:
            score += 45
            indicators.append(f"Possível Typosquatting detectado imitando a marca '{protected_brand}'.")

        if self._calculate_entropy(domain) > 3.8:
            score += 15
            indicators.append("Alta entropia no nome do domínio (padrão comum em domínios gerados automaticamente).")

        msg_lower = message_text.lower()
        matched_words = [w for w in self.URGENCY_KEYWORDS if w in msg_lower]
        if matched_words:
            score += min(30, len(matched_words) * 10)
            indicators.append(f"Gatilhos psicológicos de urgência encontrados na mensagem: {', '.join(matched_words)}.")

        final_score = min(100, score)
        classification = (
            "CRITICAL_PHISHING" if final_score >= 75
            else "SUSPICIOUS" if final_score >= 40
            else "SAFE"
        )

        return {
            "url_analyzed": url,
            "domain": domain,
            "phishing_score_0_100": final_score,
            "classification": classification,
            "explained_indicators": indicators,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }


if __name__ == "__main__":
    ti = ThreatIntelligenceEngine()
    print("=== MÓDULO 02: THREAT INTELLIGENCE ===")
    print(ti.lookup_indicator("198.51.100.42"))

    scanner = VulnerabilityScanner()
    print("\n=== MÓDULO 03: VULNERABILITY SCANNER ===")
    print(scanner.scan_authorized_asset({
        "asset_id": "SRV-FIN-01",
        "hostname": "sso.nexuscorp-demo.local",
        "exposed_ports": (22, 80, 443),
        "services": ("OpenSSH 7.4", "Nginx 1.18.0"),
    }))

    phish = PhishingDetector()
    print("\n=== MÓDULO 04: PHISHING DETECTOR ===")
    print(phish.analyze_url_and_message(
        url="http://nexusc0rp-auth.test",
        message_text="URGENTE: Sua conta será bloqueada hoje. Atualize sua senha imediatamente.",
    ))