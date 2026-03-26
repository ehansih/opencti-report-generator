"""APT Campaign Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm
from collectors.opencti_client import OpenCTIClient


class APTCampaignGenerator(BaseReportGenerator):
    report_name = "APT Campaign Intelligence Report"
    schedule    = "monthly"

    # Known APT groups targeting telecom
    TELECOM_APTS = [
        {"name": "Salt Typhoon (China)",   "target": "Telecom carriers, ISPs", "ttps": ["T1190", "T1078", "T1505"], "active": True},
        {"name": "Volt Typhoon (China)",   "target": "Critical infrastructure", "ttps": ["T1133", "T1021"], "active": True},
        {"name": "APT28/Fancy Bear (Russia)", "target": "Telecom, ISPs", "ttps": ["T1566", "T1190"], "active": True},
        {"name": "Sandworm (Russia)",      "target": "Telecom infrastructure", "ttps": ["T1486", "T1561"], "active": True},
        {"name": "Lazarus Group (DPRK)",   "target": "Telecom for financial gain", "ttps": ["T1189", "T1203"], "active": True},
        {"name": "APT33/Elfin (Iran)",     "target": "Telecom operators", "ttps": ["T1078", "T1071"], "active": True},
        {"name": "LightBasin (Unknown)",   "target": "Telecom globally", "ttps": ["T1059", "T1105"], "active": True},
    ]

    def collect_data(self):
        cti = OpenCTIClient()
        return {
            "threat_actors":   cti.get_threat_actors(limit=20),
            "campaigns":       cti.get_campaigns(limit=20),
            "intrusion_sets":  cti.get_intrusion_sets(limit=20),
            "attack_patterns": cti.get_attack_patterns(limit=50),
            "telecom_apts":    self.TELECOM_APTS,
        }

    def build_sections(self, data):
        f      = self.pdf
        actors = data.get("threat_actors", [])
        camps  = data.get("campaigns", [])
        apts   = data.get("telecom_apts", [])
        s      = []

        s += f.h1("APT Threat Overview")
        s.append(f._stat_boxes({
            "Threat Actors (OpenCTI)":  len(actors),
            "Active Campaigns":         len(camps),
            "Telecom-Targeting APTs":   len([a for a in apts if a.get("active")]),
        }))
        s.append(f.space())

        s += f.h1("AI Threat Assessment")
        s.append(f.text(self.ai.apt_analysis(actors, camps)))
        s.append(f.space())

        s += f.h1("APT Groups Actively Targeting Telecom")
        rows = [[
            a["name"], a["target"],
            ", ".join(a.get("ttps", [])),
            "ACTIVE" if a.get("active") else "DORMANT"
        ] for a in apts]
        s.append(f._table(
            ["APT Group", "Primary Targets", "Key TTPs", "Status"],
            rows, [5.5*cm, 5*cm, 4*cm, 2.5*cm]
        ))
        s.append(f.space())

        if actors:
            s += f.h1("Threat Actors in OpenCTI")
            rows = [[
                a.get("name",""), a.get("threat_actor_types",""),
                a.get("sophistication",""), a.get("primary_motivation","")
            ] for a in actors[:10]]
            s.append(f._table(
                ["Name", "Type", "Sophistication", "Motivation"],
                rows, [5*cm, 4*cm, 4*cm, 5*cm]
            ))
            s.append(f.space())

        s += f.h1("Telecom-Specific Attack Techniques (MITRE ATT&CK)")
        s += f.bullet([
            "T1190 — Exploit Public-Facing Application (web portals, OSS/BSS)",
            "T1078 — Valid Accounts (compromised admin credentials)",
            "T1505.003 — Web Shell (persistence on exposed management systems)",
            "T1021.004 — SSH (lateral movement via network management)",
            "T1046 — Network Service Discovery (internal network mapping)",
            "T1110 — Brute Force (attacking management interfaces)",
            "T1040 — Network Sniffing (interception on core network segments)",
            "T1048 — Exfiltration Over Alternative Protocol (DNS tunneling)",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("APT Campaign", data)
        s += f.bullet(recs)

        return s
