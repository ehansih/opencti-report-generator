"""5G Security Threat Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from collectors.opencti_client import OpenCTIClient
from reportlab.lib.units import cm


class FiveGSecurityGenerator(BaseReportGenerator):
    report_name = "5G Security Threat Report"
    schedule    = "monthly"

    FIVEG_THREATS = [
        {"area": "5G Core (SBA)",       "threat": "API endpoint abuse",             "severity": "CRITICAL", "mitre": "T1190"},
        {"area": "5G Core (SBA)",       "threat": "NF service impersonation",       "severity": "CRITICAL", "mitre": "T1557"},
        {"area": "Network Slicing",     "threat": "Slice isolation bypass",         "severity": "CRITICAL", "mitre": "T1078"},
        {"area": "Network Slicing",     "threat": "Cross-slice resource exhaustion","severity": "HIGH",     "mitre": "T1499"},
        {"area": "gNB / RAN",          "threat": "Rogue base station (gNB spoof)",  "severity": "HIGH",     "mitre": "T1200"},
        {"area": "O-RAN",              "threat": "xApp compromise in RIC",          "severity": "HIGH",     "mitre": "T1059"},
        {"area": "O-RAN",              "threat": "Open fronthaul interception",     "severity": "HIGH",     "mitre": "T1040"},
        {"area": "MEC",                "threat": "Edge compute VM escape",          "severity": "HIGH",     "mitre": "T1611"},
        {"area": "MEC",                "threat": "MEC API abuse for location data", "severity": "HIGH",     "mitre": "T1119"},
        {"area": "Roaming (N32)",      "threat": "PRINS protocol attack",          "severity": "HIGH",     "mitre": "T1557"},
        {"area": "SIM / eSIM",         "threat": "Remote SIM provisioning abuse",  "severity": "MEDIUM",   "mitre": "T1539"},
        {"area": "Diameter / N26",     "threat": "EPC-5GC interworking attacks",   "severity": "HIGH",     "mitre": "T1190"},
        {"area": "Containerized CNFs", "threat": "Container escape from CNF",      "severity": "HIGH",     "mitre": "T1611"},
        {"area": "Containerized CNFs", "threat": "Kubernetes API server abuse",    "severity": "HIGH",     "mitre": "T1609"},
        {"area": "AI/ML in 5G",        "threat": "Model poisoning of network AI",  "severity": "MEDIUM",   "mitre": "T1565"},
    ]

    def collect_data(self):
        cti = OpenCTIClient()
        return {
            "fiveg_threats":   self.FIVEG_THREATS,
            "attack_patterns": cti.get_attack_patterns(limit=30),
        }

    def build_sections(self, data):
        f       = self.pdf
        threats = data.get("fiveg_threats", [])
        s       = []

        critical = [t for t in threats if t.get("severity") == "CRITICAL"]
        high     = [t for t in threats if t.get("severity") == "HIGH"]

        s += f.h1("5G Threat Overview")
        s.append(f._stat_boxes({
            "5G Attack Surfaces": len(set(t["area"] for t in threats)),
            "Total Threat Vectors": len(threats),
            "Critical Severity":    len(critical),
            "High Severity":        len(high),
        }))
        s.append(f.space())

        s += f.h1("AI Threat Assessment")
        s.append(f.text(self.ai.general_analysis("5G Security", data)))
        s.append(f.space())

        s += f.h1("5G Attack Surface Map")
        rows = [[t["area"], t["threat"], t["severity"], t["mitre"]] for t in threats]
        s.append(f._table(
            ["5G Area", "Threat", "Severity", "MITRE ATT&CK"],
            rows, [3.5*cm, 7*cm, 2.5*cm, 2*cm]
        ))
        s.append(f.space())

        s += f.h1("5G Service-Based Architecture (SBA) Risks")
        s += f.bullet([
            "SBA exposes all NF interfaces as HTTP/2 REST APIs — massive attack surface vs legacy SS7",
            "NRF (Network Repository Function) is critical — compromise enables NF impersonation",
            "No native mutual TLS enforcement between NFs in many deployments",
            "OAuth2 token theft allows cross-NF lateral movement",
            "Recommend: mTLS between all NFs + NF profile integrity checks via NRF",
        ])
        s.append(f.space())

        s += f.h1("O-RAN Security Concerns")
        s += f.bullet([
            "Open RAN disaggregation introduces multiple new vendor software stacks",
            "xApps in RIC have direct network control capability — high-impact if compromised",
            "Open Fronthaul (eCPRI) has no authentication by default",
            "Multi-vendor O-RAN increases supply chain attack surface",
            "ORAN-SC security working group (O-RAN WG11) guidelines should be followed",
        ])
        s.append(f.space())

        s += f.h1("Network Slicing Isolation Requirements")
        s += f.bullet([
            "Each slice must have isolated User Plane Function (UPF) and session management",
            "Cross-slice traffic inspection at SMF level required",
            "Resource quotas per slice to prevent DoS from slice exhaustion",
            "Slice credentials (S-NSSAI) must not be reusable across tenants",
            "Monitor inter-slice signaling for anomalous lateral probing",
        ])
        s.append(f.space())

        s += f.h1("Cloud-Native 5G Core Hardening")
        s += f.bullet([
            "Harden Kubernetes: RBAC, PodSecurityPolicy, network policies between pods",
            "Use container image signing (Cosign/Notary) for all CNF images",
            "Deploy runtime security (Falco) to detect container escape attempts",
            "Encrypt etcd at rest — contains all cluster state including secrets",
            "Rotate service account tokens and secrets regularly",
            "Implement OPA/Gatekeeper policies for CNF admission control",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("5G Security", data)
        s += f.bullet(recs)

        return s
