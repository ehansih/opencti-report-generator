"""Telecom Vendor CVE Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm
from collectors.external_feeds import CVECollector, CISACollector
from collectors.opencti_client import OpenCTIClient


class TelecomCVEGenerator(BaseReportGenerator):
    report_name = "Telecom Vendor CVE Report"
    schedule    = "weekly"

    def collect_data(self):
        return {
            "vendor_cves": CVECollector().get_recent_cves(days=30),
            "cisa_kev":    CISACollector().get_kev_catalog(days=30),
            "opencti_vulns": OpenCTIClient().get_vulnerabilities(days=30),
        }

    def build_sections(self, data):
        f    = self.pdf
        cves = data.get("vendor_cves", [])
        kev  = data.get("cisa_kev", [])
        s    = []

        critical = [c for c in cves if c.get("severity") == "CRITICAL"]
        high     = [c for c in cves if c.get("severity") == "HIGH"]

        s += f.h1("Vulnerability Summary")
        s.append(f._stat_boxes({
            "Total CVEs": len(cves),
            "Critical":   len(critical),
            "High":       len(high),
            "CISA KEV":   len(kev),
        }))
        s.append(f.space())

        s += f.h1("AI Analysis")
        s.append(f.text(self.ai.cve_analysis(cves)))
        s.append(f.space())

        if critical or high:
            s += f.h1("Critical & High Severity CVEs — Immediate Action Required")
            priority = (critical + high)[:15]
            rows = [[
                c.get("id",""), c.get("vendor","").title(),
                str(c.get("cvss_score","")), c.get("severity",""),
                c.get("description","")[:100]
            ] for c in priority]
            s.append(f._table(
                ["CVE ID", "Vendor", "CVSS", "Severity", "Description"],
                rows, [3*cm, 2.5*cm, 1.5*cm, 2*cm, 9*cm]
            ))
            s.append(f.space())

        s += f.h1("Telecom Vendor Coverage")
        s += f.bullet([
            "Cisco IOS/IOS-XE/NX-OS — Core routers, switches, ASR platforms",
            "Nokia SR-OS — Mobile core, IP/MPLS backbone",
            "Ericsson EPC/5GC — LTE/5G core network functions",
            "Huawei VRP — Transmission and access equipment",
            "Juniper JunOS — Internet backbone and peering routers",
            "Fortinet FortiOS — Security gateways and firewalls",
            "Palo Alto PAN-OS — Next-gen firewalls",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("Telecom CVE", data)
        s += f.bullet(recs)

        return s
