"""
AI Narrative Generator
Uses Claude to generate human-readable threat intelligence narratives
"""
import os
import json
import httpx
import anthropic
from typing import Dict, List, Any


class NarrativeGenerator:
    def __init__(self):
        cert = os.environ.get("SSL_CERT_FILE")
        kwargs = {"api_key": os.getenv("ANTHROPIC_API_KEY")}
        if cert:
            kwargs["http_client"] = httpx.Client(verify=cert)
        try:
            self._client = anthropic.Anthropic(**kwargs)
            self._available = bool(os.getenv("ANTHROPIC_API_KEY"))
        except Exception:
            self._client = None
            self._available = False

    def _ask(self, prompt: str, max_tokens: int = 800) -> str:
        if not self._available or not self._client:
            return "[AI narrative unavailable — add ANTHROPIC_API_KEY to enable]"
        try:
            response = self._client.messages.create(
                model="claude-sonnet-4-6",
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            return f"[AI narrative error: {e}]"

    def executive_summary(self, data: Dict) -> str:
        prompt = f"""You are a senior threat intelligence analyst for a telecom operator.
Write a concise 3-paragraph executive summary based on this threat data.
Use professional language suitable for C-suite executives.
Focus on business impact, not technical details.

Data: {json.dumps(data, indent=2)[:2000]}

Format:
Paragraph 1: Overall threat landscape this period
Paragraph 2: Key threats specific to telecom/ISP operations
Paragraph 3: Recommended priority actions"""
        return self._ask(prompt)

    def bgp_analysis(self, anomalies: List[Dict]) -> str:
        prompt = f"""You are a network security expert analyzing BGP routing anomalies for an ISP.
Analyze these BGP anomalies and write a 2-paragraph assessment.
Focus on: route hijacking indicators, impact on subscribers, recommended mitigations.

Anomalies: {json.dumps(anomalies, indent=2)[:1500]}"""
        return self._ask(prompt, max_tokens=500)

    def cve_analysis(self, cves: List[Dict]) -> str:
        prompt = f"""You are a telecom security engineer. Analyze these CVEs affecting telecom infrastructure.
Write a prioritized 2-paragraph assessment covering:
- Which CVEs need immediate patching
- Impact on telecom operations (core network, RAN, BSS/OSS)

CVEs: {json.dumps(cves[:10], indent=2)[:2000]}"""
        return self._ask(prompt, max_tokens=600)

    def apt_analysis(self, threat_actors: List[Dict], campaigns: List[Dict]) -> str:
        prompt = f"""You are a threat intelligence analyst specializing in APT groups targeting telecom.
Write a 2-paragraph assessment of active APT threats to telecom operators based on this data.
Include: actor capabilities, likely targets in telecom, TTPs to watch for.

Threat Actors: {json.dumps(threat_actors[:5], indent=2)[:1000]}
Campaigns: {json.dumps(campaigns[:5], indent=2)[:1000]}"""
        return self._ask(prompt, max_tokens=600)

    def ss7_analysis(self, attack_patterns: List[Dict]) -> str:
        prompt = f"""You are a telecom security expert specializing in SS7/Diameter security.
Write a 2-paragraph threat assessment based on these SS7 attack patterns.
Focus on: subscriber impact, regulatory implications, detection methods.

Attack Patterns: {json.dumps(attack_patterns, indent=2)[:1500]}"""
        return self._ask(prompt, max_tokens=500)

    def ddos_analysis(self, attacks: List[Dict]) -> str:
        prompt = f"""You are a DDoS mitigation specialist at a major ISP.
Write a 2-paragraph assessment of current DDoS threats.
Cover: attack vectors, infrastructure at risk, mitigation recommendations.

Attack Data: {json.dumps(attacks[:10], indent=2)[:1500]}"""
        return self._ask(prompt, max_tokens=500)

    def ioc_summary(self, indicators: List[Dict]) -> str:
        prompt = f"""You are a threat intelligence analyst. Summarize these IOCs in 1 paragraph.
Highlight: predominant IOC types, threat categories, confidence levels, actionable items.

IOCs: {json.dumps(indicators[:20], indent=2)[:1500]}"""
        return self._ask(prompt, max_tokens=400)

    def malware_analysis(self, malware_list: List[Dict]) -> str:
        prompt = f"""You are a malware analyst. Write a 2-paragraph assessment of active malware threats.
Focus on threats relevant to telecom infrastructure and subscribers.

Malware: {json.dumps(malware_list[:10], indent=2)[:1500]}"""
        return self._ask(prompt, max_tokens=500)

    def general_analysis(self, report_type: str, data: Dict) -> str:
        """Generic paragraph-form threat assessment for any report type."""
        prompt = f"""You are a senior telecom security analyst.
Write a concise 2-paragraph threat assessment for a {report_type} report.
Focus on key risks, telecom-specific impact, and priority actions.

Data: {json.dumps(data, indent=2)[:1500]}"""
        return self._ask(prompt, max_tokens=600)

    def recommendations(self, report_type: str, data: Dict) -> List[str]:
        prompt = f"""You are a telecom security consultant.
Based on this {report_type} threat data, provide exactly 5 specific, actionable recommendations.
Format as a numbered list. Be specific and technical.

Data summary: {json.dumps(data, indent=2)[:1000]}"""
        response = self._ask(prompt, max_tokens=500)
        lines = [l.strip() for l in response.split("\n") if l.strip() and l.strip()[0].isdigit()]
        return lines[:5] if lines else [response]
