"""Subscriber & Roaming Threat Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from collectors.external_feeds import SS7Collector
from reportlab.lib.units import cm


class SubscriberThreatGenerator(BaseReportGenerator):
    report_name = "Subscriber & Roaming Threat Report"
    schedule    = "weekly"

    SUBSCRIBER_THREATS = [
        {"threat": "SIM Swap Fraud",       "vector": "Social Engineering / SS7", "impact": "Account takeover, OTP bypass",          "severity": "CRITICAL"},
        {"threat": "IMSI Catchers",        "vector": "Rogue BTS",               "impact": "Call/SMS interception, location track",  "severity": "CRITICAL"},
        {"threat": "SS7 Location Tracking","vector": "SS7 SRI/PSI abuse",       "impact": "Real-time subscriber tracking",          "severity": "HIGH"},
        {"threat": "OTP Interception",     "vector": "SS7 SRI-SM",              "impact": "Banking fraud, account takeover",        "severity": "CRITICAL"},
        {"threat": "Silent SMS",           "vector": "MT-FSM abuse",            "impact": "Covert location disclosure",             "severity": "HIGH"},
        {"threat": "MSRN Enumeration",     "vector": "SS7 PRN flooding",        "impact": "Call interception setup",                "severity": "HIGH"},
        {"threat": "Roaming Bypass",       "vector": "Fake roaming partner",    "impact": "Subscriber data exfiltration",           "severity": "HIGH"},
        {"threat": "VoLTE Eavesdropping",  "vector": "IMS misconfiguration",    "impact": "Voice call interception over 4G",        "severity": "MEDIUM"},
        {"threat": "USSD Phishing",        "vector": "Malicious USSD codes",    "impact": "Financial fraud via mobile banking",     "severity": "MEDIUM"},
        {"threat": "SMS Phishing (Smishing)","vector": "Bulk SMS abuse",        "impact": "Credential theft, malware install",      "severity": "HIGH"},
    ]

    def collect_data(self):
        ss7 = SS7Collector()
        return {
            "subscriber_threats": self.SUBSCRIBER_THREATS,
            "roaming_risks":      ss7.get_roaming_risk_indicators(),
        }

    def build_sections(self, data):
        f        = self.pdf
        threats  = data.get("subscriber_threats", [])
        roaming  = data.get("roaming_risks", [])
        s        = []

        critical = [t for t in threats if t.get("severity") == "CRITICAL"]
        high     = [t for t in threats if t.get("severity") == "HIGH"]

        s += f.h1("Subscriber Threat Overview")
        s.append(f._stat_boxes({
            "Total Threat Vectors": len(threats),
            "Critical":             len(critical),
            "High":                 len(high),
            "Roaming Risk Indicators": len(roaming),
        }))
        s.append(f.space())

        s += f.h1("AI Threat Assessment")
        s.append(f.text(self.ai.general_analysis("Subscriber Threats", data)))
        s.append(f.space())

        s += f.h1("Subscriber Attack Vectors")
        rows = [[
            t["threat"], t["vector"], t["severity"], t["impact"]
        ] for t in threats]
        s.append(f._table(
            ["Threat", "Attack Vector", "Severity", "Impact"],
            rows, [4*cm, 4.5*cm, 2.5*cm, 7*cm]
        ))
        s.append(f.space())

        s += f.h1("SIM Swap Fraud — Deep Dive")
        s += f.bullet([
            "Attackers socially engineer customer care to transfer victim's number to attacker SIM",
            "Once swapped, all OTP SMS are received by attacker — enables banking fraud",
            "Average time from swap to account drain: < 30 minutes",
            "Telecom operators are primary target — customer care staff bribed or manipulated",
            "Indicators: sudden drop in subscriber signal, CS complaints about no service",
        ])
        s.append(f.space())

        s += f.h1("Roaming Partner Risk Indicators")
        for r in roaming:
            s.append(f.h2(r.get("indicator", "")))
            s.append(f.text(f"Risk: {r.get('risk', '')}"))
        s.append(f.space())

        s += f.h1("Subscriber Protection Recommendations")
        s += f.bullet([
            "Implement SIM swap velocity checks — flag >1 swap per 30 days",
            "Require in-store ID verification with biometric for SIM swaps",
            "Deploy real-time SIM swap fraud scoring using ML on CS interactions",
            "Enable customer alerts via app/email before SIM swap completes",
            "Implement SS7 firewall rules to block SRI/PSI from non-home network",
            "Deploy IMSI catcher detection (AIMSICD monitoring) at key sites",
            "Implement silent SMS detection and blocking at HLR/VLR level",
            "Educate customers on smishing — add SMS sender verification (SHAKEN/STIR for SMS)",
            "Deploy anti-spoofing on originating SMS — reject unauthenticated A-numbers",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("Subscriber Fraud", data)
        s += f.bullet(recs)

        return s
