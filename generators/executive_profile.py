"""Monthly Executive Threat Profile — Board-level summary"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from collectors.opencti_client import OpenCTIClient
from collectors.external_feeds import CVECollector, BGPCollector
from reportlab.lib.units import cm
from datetime import datetime


class ExecutiveThreatProfileGenerator(BaseReportGenerator):
    report_name = "Monthly Executive Threat Profile"
    schedule    = "monthly"

    def collect_data(self):
        cti = OpenCTIClient()
        return {
            "stats":        cti.get_summary_stats(),
            "threat_actors":cti.get_threat_actors(limit=5),
            "campaigns":    cti.get_campaigns(limit=5),
            "cves":         CVECollector().get_recent_cves(days=30),
            "bgp_events":   BGPCollector().get_hijack_events(days=30),
        }

    def build_sections(self, data):
        f       = self.pdf
        stats   = data.get("stats", {})
        actors  = data.get("threat_actors", [])
        cves    = data.get("cves", [])
        bgp     = data.get("bgp_events", [])
        s       = []

        critical_cves = [c for c in cves if c.get("severity") == "CRITICAL"]
        month = datetime.now().strftime("%B %Y")

        s += f.h1(f"Threat Landscape — {month}")
        s.append(f._stat_boxes({
            "Threat Actors (tracked)": len(actors),
            "Critical CVEs (30d)":     len(critical_cves),
            "BGP Hijack Events (30d)": len(bgp),
            "Total IOCs (OpenCTI)":    stats.get("indicators", "N/A"),
        }))
        s.append(f.space())

        s += f.h1("Executive Summary")
        s.append(f.text(self.ai.executive_summary(data)))
        s.append(f.space())

        s += f.h1("Top 3 Risks This Month")
        s += f.bullet([
            "CRITICAL: Nation-state APT activity targeting telecom infrastructure continues at elevated levels",
            "HIGH: Multiple critical CVEs in network equipment requiring immediate patching",
            "HIGH: Increased dark web activity around telecom subscriber data and SIM swap services",
        ])
        s.append(f.space())

        s += f.h1("Threat Actor Spotlight")
        if actors:
            rows = [[
                a.get("name",""), a.get("threat_actor_types",""),
                a.get("sophistication",""), a.get("primary_motivation","")
            ] for a in actors[:5]]
            s.append(f._table(
                ["Threat Actor", "Type", "Sophistication", "Motivation"],
                rows, [5*cm, 4*cm, 4*cm, 5*cm]
            ))
        else:
            s.append(f.text("No threat actor data available from OpenCTI. Connect OpenCTI for live intelligence."))
        s.append(f.space())

        s += f.h1("Critical Vulnerabilities Requiring Board Attention")
        if critical_cves:
            rows = [[
                c.get("id",""), c.get("vendor","").title(),
                str(c.get("cvss_score","")), c.get("description","")[:80]
            ] for c in critical_cves[:5]]
            s.append(f._table(
                ["CVE ID", "Vendor", "CVSS", "Summary"],
                rows, [3*cm, 3*cm, 1.5*cm, 10.5*cm]
            ))
        else:
            s.append(f.text("No critical CVEs in the past 30 days."))
        s.append(f.space())

        s += f.h1("Key Strategic Recommendations")
        recs = self.ai.recommendations("Executive Strategic", data)
        s += f.bullet(recs)
        s.append(f.space())

        s += f.h1("Investment Priorities")
        s += f.bullet([
            "Tier 1 (Immediate): SS7/Diameter firewall upgrade and tuning — highest ROI for threat reduction",
            "Tier 1 (Immediate): Patch critical CVEs in Cisco/Nokia/Ericsson equipment within 72 hours",
            "Tier 2 (Q1): Implement 24/7 threat intelligence monitoring with automated IOC enrichment",
            "Tier 2 (Q1): Deploy SIM swap fraud detection ML model in customer care systems",
            "Tier 3 (H1): Begin 5G security architecture review and O-RAN risk assessment",
            "Tier 3 (H1): Evaluate dark web monitoring subscription (Recorded Future/Intel471)",
        ])
        s.append(f.space())

        s += f.h1("Regulatory Risk")
        s += f.bullet([
            "NIS2 Directive enforcement — ensure incident reporting process is operational",
            "GSMA FS.11 compliance audit due — SS7 firewall policy review required",
            "GDPR: Review subscriber data handling processes for any gaps",
        ])

        return s
