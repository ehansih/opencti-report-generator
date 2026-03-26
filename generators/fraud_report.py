"""Telecom Fraud Intelligence Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm


class TelecomFraudGenerator(BaseReportGenerator):
    report_name = "Telecom Fraud Intelligence Report"
    schedule    = "weekly"

    FRAUD_TYPES = [
        {"type": "IRSF",           "full": "International Revenue Share Fraud",    "loss": "$10B+/year",  "severity": "CRITICAL"},
        {"type": "SIM Swap",       "full": "SIM Card Hijacking",                   "loss": "$1B+/year",   "severity": "CRITICAL"},
        {"type": "Wangiri",        "full": "One-Ring Call Back Fraud",             "loss": "$500M+/year", "severity": "HIGH"},
        {"type": "PBX Hacking",    "full": "PABX/VoIP System Compromise",         "loss": "$3.8B/year",  "severity": "HIGH"},
        {"type": "CLI Spoofing",   "full": "Calling Line ID Falsification",        "loss": "Enabler",     "severity": "HIGH"},
        {"type": "Bypass Fraud",   "full": "GSM Gateway/SIM Box",                 "loss": "$2.7B/year",  "severity": "HIGH"},
        {"type": "Account Takeover","full": "Online Account Hijacking",            "loss": "$6B+/year",   "severity": "CRITICAL"},
        {"type": "Premium SMS",    "full": "Unauthorized Premium Rate SMS",        "loss": "$1.5B+/year", "severity": "MEDIUM"},
        {"type": "Roaming Fraud",  "full": "Fraudulent Roaming Usage",            "loss": "$500M+/year", "severity": "HIGH"},
        {"type": "Subscription Fraud","full": "False Identity New Account Fraud", "loss": "$1.9B/year",  "severity": "HIGH"},
        {"type": "Data Refiling",  "full": "Grey Route Data Traffic",             "loss": "Revenue loss","severity": "MEDIUM"},
        {"type": "Flash Calls",    "full": "OTP Bypass via Flash Calls",          "loss": "OTP fraud",   "severity": "HIGH"},
    ]

    IRSF_INDICATORS = [
        "Sudden spike in international call volume to high-risk destinations",
        "Calls to premium-rate numbers in +881, +882, +870 satellite ranges",
        "Short duration calls (< 5 seconds) in high volume — PDD fraud",
        "High volume calls to Caribbean, Pacific Island, or Eastern European ranges",
        "Off-hours call spikes (2-6am local time)",
        "Single subscriber generating >50 international calls/hour",
    ]

    def collect_data(self):
        return {
            "fraud_types":     self.FRAUD_TYPES,
            "irsf_indicators": self.IRSF_INDICATORS,
        }

    def build_sections(self, data):
        f      = self.pdf
        frauds = data.get("fraud_types", [])
        irsf   = data.get("irsf_indicators", [])
        s      = []

        critical = [f_ for f_ in frauds if f_.get("severity") == "CRITICAL"]
        high     = [f_ for f_ in frauds if f_.get("severity") == "HIGH"]

        s += f.h1("Fraud Threat Overview")
        s.append(f._stat_boxes({
            "Fraud Categories":   len(frauds),
            "Critical Types":     len(critical),
            "High Impact Types":  len(high),
            "Industry Loss/Year": "$32B+",
        }))
        s.append(f.space())

        s += f.h1("AI Fraud Assessment")
        s.append(f.text(self.ai.general_analysis("Telecom Fraud", data)))
        s.append(f.space())

        s += f.h1("Fraud Type Classification & Financial Impact")
        rows = [[
            f_["type"], f_["full"], f_["loss"], f_["severity"]
        ] for f_ in frauds]
        s.append(f._table(
            ["Fraud Type", "Full Name", "Industry Loss", "Severity"],
            rows, [3*cm, 6.5*cm, 3*cm, 2.5*cm]
        ))
        s.append(f.space())

        s += f.h1("IRSF — Highest Priority Fraud for Telecoms")
        s += f.bullet([
            "IRSF generates traffic to premium-rate numbers in countries with revenue sharing",
            "Fraudsters compromise PBX, VoIP accounts, or subscriber credentials to generate calls",
            "Operators bear the cost of terminating calls; fraudsters share premium revenue",
            "Can generate millions in losses within hours before detection",
        ])
        s.append(f.space())

        s += f.h1("IRSF Detection Indicators")
        s += f.bullet(irsf)
        s.append(f.space())

        s += f.h1("SIM Swap Fraud Chain")
        s += f.bullet([
            "1. Fraudster obtains victim's personal data (phishing, dark web purchase)",
            "2. Contacts operator customer care posing as victim — requests SIM swap",
            "3. Operator transfers number to new SIM under fraudster's control",
            "4. All SMS OTPs now delivered to fraudster — banking/crypto accounts drained",
            "5. Detection window: average 6+ hours before victim notices",
        ])
        s.append(f.space())

        s += f.h1("Bypass Fraud (SIM Box) Detection")
        s += f.bullet([
            "SIM boxes route international VoIP calls as local calls — bypass interconnect charges",
            "Indicators: CLI presents as local number but call quality is VoIP-grade",
            "Test call analysis: send test calls to known SIM box destinations, measure CLI delivery",
            "ML-based CLI pattern analysis to detect sequential number usage (SIM box signature)",
            "Partner with GSMA FASG for known SIM box operator blacklists",
        ])
        s.append(f.space())

        s += f.h1("Fraud Prevention Framework")
        s += f.bullet([
            "Deploy real-time fraud management system (FMS) with ML scoring",
            "Implement velocity checks: call volume, destinations, spend per subscriber",
            "Join i3forum and GSMA Fraud Forum for shared blacklists and intelligence",
            "Implement STIR/SHAKEN for CLI authentication (mandatory in US, recommended globally)",
            "Subscribe to CFCA (Communications Fraud Control Association) fraud databases",
            "Deploy SIM swap fraud scoring at CRM level — flag high-risk swap requests",
            "Implement out-of-band customer verification for high-value account changes",
            "Block calls to IRSF high-risk number ranges using industry blacklists (GSMA IREG)",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("Telecom Fraud", data)
        s += f.bullet(recs)

        return s
