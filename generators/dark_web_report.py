"""Dark Web Monitoring Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from collectors.opencti_client import OpenCTIClient
from collectors.external_feeds import MalwareBazaarCollector
from reportlab.lib.units import cm


class DarkWebMonitorGenerator(BaseReportGenerator):
    report_name = "Dark Web Monitoring Report"
    schedule    = "weekly"

    MONITORED_CATEGORIES = [
        {"category": "Credential Dumps",   "description": "Leaked employee/customer credentials sold on dark web markets"},
        {"category": "Network Access",     "description": "Initial access brokers selling VPN/RDP access to telecom networks"},
        {"category": "Customer PII",       "description": "Subscriber data (MSISDN, IMSI, home address) listings"},
        {"category": "Insider Threats",    "description": "Telecom insiders offering SIM swaps or subscriber lookups for hire"},
        {"category": "Exploit Kits",       "description": "Telecom-specific 0-days and exploit kits advertised on forums"},
        {"category": "Ransomware Groups",  "description": "Active ransomware groups listing telecom victims and data"},
        {"category": "Source Code Leaks",  "description": "Proprietary BSS/OSS source code or network configs leaked"},
        {"category": "Hacking Services",   "description": "Hack-for-hire services targeting telecom subscribers"},
    ]

    THREAT_ACTORS_DARK_WEB = [
        {"alias": "TelecomBreach_TA",  "forum": "BreachForums",  "activity": "Selling telecom subscriber databases", "risk": "HIGH"},
        {"alias": "SIMSwapKing",       "forum": "Telegram",      "activity": "Offering SIM swap services for hire",  "risk": "CRITICAL"},
        {"alias": "CoreNetworkAccess", "forum": "XSS.is",        "activity": "Selling initial access to ISP networks","risk": "CRITICAL"},
        {"alias": "SS7_Oracle",        "forum": "Exploit.in",    "activity": "Offering SS7 lookup services",         "risk": "HIGH"},
        {"alias": "TelcoRansom",       "forum": "Ransomhub",     "activity": "Ransomware targeting telecom sector",  "risk": "CRITICAL"},
    ]

    def collect_data(self):
        cti = OpenCTIClient()
        mb  = MalwareBazaarCollector()
        return {
            "monitored_categories": self.MONITORED_CATEGORIES,
            "threat_actors":        self.THREAT_ACTORS_DARK_WEB,
            "recent_malware":       mb.get_recent_samples(limit=10),
            "opencti_reports":      cti.get_reports(limit=10),
        }

    def build_sections(self, data):
        f       = self.pdf
        cats    = data.get("monitored_categories", [])
        actors  = data.get("threat_actors", [])
        malware = data.get("recent_malware", [])
        s       = []

        critical_actors = [a for a in actors if a.get("risk") == "CRITICAL"]

        s += f.h1("Dark Web Monitoring Overview")
        s.append(f._stat_boxes({
            "Monitored Categories": len(cats),
            "Known Threat Actors":  len(actors),
            "Critical Risk Actors": len(critical_actors),
            "Recent Malware Samples": len(malware),
        }))
        s.append(f.space())

        s += f.h1("AI Threat Assessment")
        s.append(f.text(self.ai.general_analysis("Dark Web Monitoring", data)))
        s.append(f.space())

        s += f.h1("Monitored Dark Web Categories")
        rows = [[c["category"], c["description"]] for c in cats]
        s.append(f._table(
            ["Category", "Description"],
            rows, [4.5*cm, 13.5*cm]
        ))
        s.append(f.space())

        s += f.h1("Known Threat Actors — Telecom Focus")
        rows = [[a["alias"], a["forum"], a["activity"], a["risk"]] for a in actors]
        s.append(f._table(
            ["Alias", "Forum/Platform", "Activity", "Risk Level"],
            rows, [4*cm, 3*cm, 7*cm, 2.5*cm]
        ))
        s.append(f.space())

        s += f.h1("Dark Web Forum Intelligence")
        s += f.bullet([
            "BreachForums remains primary marketplace for telecom subscriber data",
            "Telegram channels offer SIM swap-as-a-service with pricing (~$50-500/swap)",
            "XSS.is and Exploit.in host network access listings for telecom companies",
            "RansomHub and LockBit3 have both claimed telecom victims in past 12 months",
            "SS7 lookup services advertised openly on several forums — location & OTP interception",
        ])
        s.append(f.space())

        s += f.h1("Credential Exposure Indicators")
        s += f.bullet([
            "Monitor HaveIBeenPwned and DeHashed for corporate email domain leaks",
            "Set up alerts on Flare.io / DarkOwl for company name mentions",
            "Monitor paste sites (Pastebin, Ghostbin) for MSISDN/IMSI ranges",
            "Track dark web markets for listings mentioning company infrastructure",
            "Subscribe to Intel471, Recorded Future, or Flashpoint for continuous monitoring",
        ])
        s.append(f.space())

        s += f.h1("Recommended Dark Web Monitoring Tools")
        s += f.bullet([
            "Intel471 Titan — Actor and malware tracking with dark web coverage",
            "Recorded Future — Automated dark web intelligence with telecom threat module",
            "Flare.io — Dark web, Telegram, and paste site monitoring",
            "DarkOwl VisionUI — Dark web search with credential monitoring",
            "CISA JCDC — Government threat sharing for critical infrastructure",
            "OpenCTI — Correlate dark web indicators with internal observables",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("Dark Web Monitoring", data)
        s += f.bullet(recs)

        return s
