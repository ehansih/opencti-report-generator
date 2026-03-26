"""Supply Chain Security Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from collectors.opencti_client import OpenCTIClient
from reportlab.lib.units import cm


class SupplyChainGenerator(BaseReportGenerator):
    report_name = "Supply Chain Security Report"
    schedule    = "monthly"

    VENDOR_RISKS = [
        {"vendor": "Huawei",          "risk": "HIGH",     "concern": "Geopolitical restrictions; UK/US/EU exclusion orders for 5G core"},
        {"vendor": "ZTE",             "risk": "HIGH",     "concern": "US FCC prohibited; multiple government bans for core network"},
        {"vendor": "Cisco",           "risk": "MEDIUM",   "concern": "Multiple critical IOS-XE vulnerabilities (CVE-2023-20198)"},
        {"vendor": "Nokia",           "risk": "MEDIUM",   "concern": "Open RAN component supply chain visibility gaps"},
        {"vendor": "Ericsson",        "risk": "MEDIUM",   "concern": "Previous FCPA violations; software supply chain complexity"},
        {"vendor": "Kontron (SYSGO)", "risk": "MEDIUM",   "concern": "VxWorks/embedded OS component third-party risks"},
        {"vendor": "Ribbon Comms",    "risk": "LOW",      "concern": "Session border controller code review gaps"},
        {"vendor": "Open Source (ONF)","risk": "MEDIUM",  "concern": "ONOS, OMEC components — dependency chain attack surface"},
    ]

    SOFTWARE_RISKS = [
        {"component": "Open-source dependencies", "risk": "HIGH",     "example": "Log4j-style vulnerabilities in BSS/OSS stacks"},
        {"component": "Container base images",    "risk": "HIGH",     "example": "Unvetted Docker Hub images in 5G CNF deployments"},
        {"component": "Build pipeline integrity", "risk": "CRITICAL", "example": "SolarWinds-style build system compromise"},
        {"component": "3rd party APIs",           "risk": "MEDIUM",   "example": "External roaming/fraud APIs with data exfiltration risk"},
        {"component": "Network management SW",    "risk": "HIGH",     "example": "NMS backdoors allowing persistent access"},
        {"component": "Firmware/BIOS",            "risk": "HIGH",     "example": "Persistence via compromised vendor firmware updates"},
    ]

    def collect_data(self):
        cti = OpenCTIClient()
        return {
            "vendor_risks":    self.VENDOR_RISKS,
            "software_risks":  self.SOFTWARE_RISKS,
            "threat_actors":   cti.get_threat_actors(limit=10),
        }

    def build_sections(self, data):
        f        = self.pdf
        vendors  = data.get("vendor_risks", [])
        sw_risks = data.get("software_risks", [])
        s        = []

        high_vendors  = [v for v in vendors if v.get("risk") == "HIGH"]
        critical_sw   = [r for r in sw_risks if r.get("risk") == "CRITICAL"]

        s += f.h1("Supply Chain Risk Overview")
        s.append(f._stat_boxes({
            "Vendors Assessed":     len(vendors),
            "High Risk Vendors":    len(high_vendors),
            "Software Risk Areas":  len(sw_risks),
            "Critical SW Risks":    len(critical_sw),
        }))
        s.append(f.space())

        s += f.h1("AI Risk Assessment")
        s.append(f.text(self.ai.general_analysis("Supply Chain Security", data)))
        s.append(f.space())

        s += f.h1("Vendor Risk Assessment")
        rows = [[v["vendor"], v["risk"], v["concern"]] for v in vendors]
        s.append(f._table(
            ["Vendor", "Risk Level", "Key Concern"],
            rows, [3.5*cm, 2.5*cm, 12*cm]
        ))
        s.append(f.space())

        s += f.h1("Software Supply Chain Risks")
        rows = [[r["component"], r["risk"], r["example"]] for r in sw_risks]
        s.append(f._table(
            ["Component", "Risk", "Example Scenario"],
            rows, [5*cm, 2.5*cm, 10.5*cm]
        ))
        s.append(f.space())

        s += f.h1("Nation-State Supply Chain Threats")
        s += f.bullet([
            "Salt Typhoon (China) demonstrated persistent access via telecom vendor equipment",
            "Volt Typhoon pre-positioned in critical infrastructure via living-off-the-land",
            "Supply chain compromise allows persistent access that survives software updates",
            "Hardware implants in network equipment documented by NSA/GCHQ advisories",
            "Firmware tampering can survive factory resets and OS reinstalls",
        ])
        s.append(f.space())

        s += f.h1("Supply Chain Security Controls")
        s += f.bullet([
            "Implement Software Bill of Materials (SBOM) for all network function software",
            "Require SBOM from all vendors with quarterly updates",
            "Verify firmware integrity via cryptographic signatures before deployment",
            "Deploy network segmentation — management plane isolated from data plane",
            "Conduct vendor security assessments annually (CREST/CBEST certified)",
            "Monitor vendor networks for known IOCs using STIX/TAXII feeds",
            "Implement zero-trust for vendor remote access (PAM + MFA + session recording)",
            "Join GSMA FS.40 (5G Security Guidelines) vendor assurance program",
            "Participate in NCSC/CISA Trusted Vendors programs for equipment sourcing",
            "Conduct hardware integrity checks on critical network elements (anti-tamper seals, PCB inspection)",
        ])
        s.append(f.space())

        s += f.h1("SBOM Implementation Roadmap")
        s += f.bullet([
            "Phase 1: Inventory all network software components and their versions",
            "Phase 2: Require SBOM in all new vendor contracts (NTIA minimum elements)",
            "Phase 3: Automate SBOM ingestion and CVE correlation",
            "Phase 4: Continuous monitoring — alert on new CVEs in SBOM components",
            "Phase 5: Extend to hardware BOM (HBOM) for critical network elements",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("Supply Chain Security", data)
        s += f.bullet(recs)

        return s
