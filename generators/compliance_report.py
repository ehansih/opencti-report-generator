"""Telecom Regulatory Compliance Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm


class ComplianceReportGenerator(BaseReportGenerator):
    report_name = "Telecom Regulatory Compliance Report"
    schedule    = "monthly"

    REGULATIONS = [
        {
            "name": "GSMA FS.11",
            "scope": "Global",
            "focus": "SS7 Baseline Security Controls",
            "status": "Mandatory for GSMA members",
            "key_controls": ["SS7 firewall", "Category 1-3 attack blocking", "SRI filtering"],
        },
        {
            "name": "GSMA FS.19",
            "scope": "Global",
            "focus": "Diameter Security Controls",
            "status": "Mandatory for 4G operators",
            "key_controls": ["Diameter firewall", "AVP filtering", "realm-based access control"],
        },
        {
            "name": "GSMA FS.20",
            "scope": "Global",
            "focus": "GTP Security Controls",
            "status": "Recommended",
            "key_controls": ["GTP stateful inspection", "TEID validation", "Gi/SGi filtering"],
        },
        {
            "name": "GSMA FS.40",
            "scope": "Global",
            "focus": "5G Security Guidelines",
            "status": "Recommended for 5G operators",
            "key_controls": ["SBA mTLS", "NRF auth", "slice isolation"],
        },
        {
            "name": "NIS2 Directive",
            "scope": "European Union",
            "focus": "Network & Information Security for critical sectors",
            "status": "Mandatory — deadline Oct 2024",
            "key_controls": ["Incident reporting <24h", "Supply chain security", "Risk management"],
        },
        {
            "name": "BEREC Guidelines",
            "scope": "European Union",
            "focus": "Telecom security incident reporting",
            "status": "Mandatory for EU operators",
            "key_controls": ["Annual security reports", "Incident notification", "Audit requirements"],
        },
        {
            "name": "FCC CSRIC VII",
            "scope": "United States",
            "focus": "SS7 and Diameter security recommendations",
            "status": "Recommended (enforcement pending)",
            "key_controls": ["SS7 firewall", "Network monitoring", "Third-party audits"],
        },
        {
            "name": "ENISA Guidelines",
            "scope": "European Union",
            "focus": "Telecom sector security measures",
            "status": "Reference framework",
            "key_controls": ["Security governance", "Technical measures", "Incident management"],
        },
        {
            "name": "GDPR",
            "scope": "European Union / Global",
            "focus": "Data protection and breach notification",
            "status": "Mandatory — fines up to 4% global turnover",
            "key_controls": ["Breach notification 72h", "Data minimization", "DPO appointment"],
        },
        {
            "name": "PCI-DSS v4.0",
            "scope": "Global (payment processing)",
            "focus": "Cardholder data protection in billing systems",
            "status": "Mandatory if processing payments",
            "key_controls": ["Network segmentation", "Encryption", "Penetration testing"],
        },
    ]

    COMPLIANCE_CHECKS = [
        {"control": "SS7 Firewall Deployed",               "category": "GSMA FS.11",  "priority": "CRITICAL"},
        {"control": "Diameter Firewall Deployed",          "category": "GSMA FS.19",  "priority": "CRITICAL"},
        {"control": "GTP Inspection Enabled",              "category": "GSMA FS.20",  "priority": "HIGH"},
        {"control": "NIS2 Incident Reporting Process",     "category": "NIS2",        "priority": "CRITICAL"},
        {"control": "GDPR Data Breach Plan in Place",      "category": "GDPR",        "priority": "CRITICAL"},
        {"control": "Annual Pen Test (SS7/Diameter)",      "category": "GSMA",        "priority": "HIGH"},
        {"control": "Supply Chain Security Assessment",    "category": "NIS2/GSMA",   "priority": "HIGH"},
        {"control": "Network Monitoring 24/7 SOC",        "category": "NIS2/ENISA",  "priority": "HIGH"},
        {"control": "SBOM for Network Software",          "category": "NIS2",        "priority": "MEDIUM"},
        {"control": "Zero Trust Architecture Roadmap",    "category": "Best Practice","priority": "MEDIUM"},
    ]

    def collect_data(self):
        return {
            "regulations":       self.REGULATIONS,
            "compliance_checks": self.COMPLIANCE_CHECKS,
        }

    def build_sections(self, data):
        f      = self.pdf
        regs   = data.get("regulations", [])
        checks = data.get("compliance_checks", [])
        s      = []

        critical_checks = [c for c in checks if c.get("priority") == "CRITICAL"]

        s += f.h1("Compliance Overview")
        s.append(f._stat_boxes({
            "Regulations Tracked":   len(regs),
            "Control Checks":        len(checks),
            "Critical Controls":     len(critical_checks),
            "Regulatory Bodies":     4,
        }))
        s.append(f.space())

        s += f.h1("AI Compliance Assessment")
        s.append(f.text(self.ai.general_analysis("Regulatory Compliance", data)))
        s.append(f.space())

        s += f.h1("Applicable Regulations & Standards")
        for reg in regs:
            s.append(f.h2(f"{reg['name']} — {reg['focus']}"))
            s.append(f.text(f"Scope: {reg['scope']} | Status: {reg['status']}"))
            s += f.bullet([f"Key controls: {', '.join(reg['key_controls'])}"])
        s.append(f.space())

        s += f.h1("Compliance Control Checklist")
        rows = [[c["control"], c["category"], c["priority"]] for c in checks]
        s.append(f._table(
            ["Control", "Regulation", "Priority"],
            rows, [9*cm, 4*cm, 3*cm]
        ))
        s.append(f.space())

        s += f.h1("NIS2 — Key Telecom Requirements")
        s += f.bullet([
            "Article 21: Mandatory security risk management measures for essential entities",
            "Article 23: Incident notification — early warning within 24h, full report within 72h",
            "Article 24: Supply chain security must be assessed and managed",
            "Telecom operators are classified as 'essential entities' under NIS2",
            "National CSIRT notification required for significant incidents",
            "Fines: up to €10M or 2% global annual turnover for non-compliance",
        ])
        s.append(f.space())

        s += f.h1("GSMA Security Assurance Scheme (NESAS)")
        s += f.bullet([
            "NESAS provides security assurance for telecom network products",
            "3GPP SCAS (Security Assurance Specification) defines per-NF security requirements",
            "Recommended to require NESAS certification for all 5G core equipment procurement",
            "NESAS audit covers: development process security + product security testing",
            "Operators should verify vendor NESAS certificates before deployment",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("Telecom Compliance", data)
        s += f.bullet(recs)

        return s
