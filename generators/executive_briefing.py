"""Executive Threat Briefing — 1-page C-suite summary"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm
from collectors.opencti_client import OpenCTIClient
from collectors.external_feeds import CISACollector


class ExecutiveBriefingGenerator(BaseReportGenerator):
    report_name = "Executive Threat Briefing"
    schedule    = "weekly"

    def collect_data(self):
        cti = OpenCTIClient()
        return {
            "stats":        cti.get_summary_stats(),
            "reports":      cti.get_reports(days=7),
            "threat_actors":cti.get_threat_actors(limit=5),
            "campaigns":    cti.get_campaigns(limit=5),
            "cisa_kev":     CISACollector().get_kev_catalog(days=7),
            "connected":    cti.test_connection()
        }

    def build_sections(self, data):
        f = self.pdf
        stats  = data.get("stats", {})
        actors = data.get("threat_actors", [])
        camps  = data.get("campaigns", [])
        kev    = data.get("cisa_kev", [])

        s = []

        # Stats bar
        s += f.h1("Intelligence Summary")
        s.append(f._stat_boxes({
            "Reports":         stats.get("reports", 0),
            "IOCs":            stats.get("indicators", 0),
            "Malware Families":stats.get("malware", 0),
            "Threat Actors":   stats.get("threat_actors", 0),
            "Vulnerabilities": stats.get("vulnerabilities", 0),
            "Campaigns":       stats.get("campaigns", 0),
        }))
        s.append(f.space())

        # AI Executive Summary
        s += f.h1("Executive Summary")
        summary = self.ai.executive_summary(data)
        s.append(f.text(summary))
        s.append(f.space())

        # Active Threat Actors
        if actors:
            s += f.h1("Active Threat Actors")
            rows = [[a.get("name",""), a.get("threat_actor_types",""), a.get("sophistication",""), a.get("primary_motivation","")] for a in actors[:8]]
            s.append(f._table(["Actor", "Type", "Sophistication", "Motivation"], rows, [5*cm, 4*cm, 4*cm, 5*cm]))
            s.append(f.space())

        # CISA KEV
        if kev:
            s += f.h1("CISA Known Exploited Vulnerabilities (Last 7 Days)")
            rows = [[v.get("cveID",""), v.get("vendorProject",""), v.get("product",""), v.get("dateAdded",""), v.get("dueDate","")] for v in kev[:10]]
            s.append(f._table(["CVE ID", "Vendor", "Product", "Added", "Due Date"], rows, [3*cm, 3.5*cm, 4*cm, 3*cm, 3*cm]))
            s.append(f.space())

        # Active Campaigns
        if camps:
            s += f.h1("Active Campaigns")
            for c in camps[:5]:
                s.append(f.h2(c.get("name", "Unknown")))
                s.append(f.text(c.get("description", "No description available.")[:400]))

        # Recommendations
        s += f.h1("Priority Recommendations")
        recs = self.ai.recommendations("Executive Briefing", data)
        s += f.bullet(recs)

        return s
