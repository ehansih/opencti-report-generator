"""SS7/Diameter/GTP Threat Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm
from collectors.external_feeds import SS7Collector


class SS7ThreatGenerator(BaseReportGenerator):
    report_name = "SS7/Diameter/GTP Threat Report"
    schedule    = "monthly"

    def collect_data(self):
        ss7 = SS7Collector()
        return {
            "attack_patterns":   ss7.get_known_attack_patterns(),
            "roaming_risks":     ss7.get_roaming_risk_indicators(),
        }

    def build_sections(self, data):
        f        = self.pdf
        patterns = data.get("attack_patterns", [])
        roaming  = data.get("roaming_risks", [])
        s        = []

        critical = [p for p in patterns if p.get("severity") == "CRITICAL"]
        high     = [p for p in patterns if p.get("severity") == "HIGH"]

        s += f.h1("SS7/Diameter Threat Overview")
        s.append(f._stat_boxes({
            "Known Attack Vectors":  len(patterns),
            "Critical Severity":     len(critical),
            "High Severity":         len(high),
            "Roaming Risk Indicators": len(roaming),
        }))
        s.append(f.space())

        s += f.h1("AI Threat Assessment")
        s.append(f.text(self.ai.ss7_analysis(patterns)))
        s.append(f.space())

        s += f.h1("Known SS7/Diameter/GTP Attack Vectors")
        rows = [[
            p.get("attack",""), p.get("protocol",""),
            p.get("message",""), p.get("severity",""),
            p.get("description","")
        ] for p in patterns]
        s.append(f._table(
            ["Attack", "Protocol", "Message Type", "Severity", "Description"],
            rows, [3.5*cm, 2*cm, 3*cm, 2*cm, 7.5*cm]
        ))
        s.append(f.space())

        s += f.h1("Roaming Partner Risk Indicators")
        for r in roaming:
            s.append(f.h2(r.get("indicator", "")))
            s.append(f.text(f"Risk: {r.get('risk','')}"))
        s.append(f.space())

        s += f.h1("SS7 Firewall Recommendations")
        s += f.bullet([
            "Deploy SS7 firewall with ITU-T Q.784 category filtering",
            "Implement GSMA FS.11 SS7 security guidelines",
            "Block all Category 1 (basic) and Category 2 (roaming) SS7 attacks",
            "Monitor for SRI (SendRoutingInfo) from non-roaming partners",
            "Implement Home Routing for SMS to prevent SS7-based OTP interception",
            "Deploy Diameter firewall (GSMA FS.19) for 4G/5G core",
            "Enable GTP stateful inspection on Gi/SGi interface",
            "Regular SS7/Diameter penetration testing (at least annually)",
            "Join GSMA Fraud and Security Group (FASG) for threat sharing",
        ])
        s.append(f.space())

        s += f.h1("Regulatory Requirements")
        s += f.bullet([
            "GSMA FS.11 — SS7 Baseline Security Controls",
            "GSMA FS.19 — Diameter Security Controls",
            "GSMA FS.20 — GTP Security Controls",
            "BEREC Guidelines on Telecom Security (EU)",
            "FCC CSRIC VII — SS7 Security Recommendations (US)",
            "ENISA Telecom Security Guidelines",
        ])

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("SS7/Diameter", data)
        s += f.bullet(recs)

        return s
