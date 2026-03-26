"""BGP Hijacking Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm
from collectors.external_feeds import BGPCollector


class BGPHijackingGenerator(BaseReportGenerator):
    report_name = "BGP Hijacking Intelligence Report"
    schedule    = "daily"

    def collect_data(self):
        bgp = BGPCollector()
        asn = os.getenv("ORG_ASN", "AS0")
        return {
            "asn": asn,
            "anomalies": bgp.get_route_anomalies(asn),
        }

    def build_sections(self, data):
        f   = self.pdf
        asn = data.get("asn", "N/A")
        anomalies = data.get("anomalies", [])
        s = []

        s += f.h1("BGP Routing Overview")
        s.append(f._stat_boxes({
            "Monitored ASN": asn,
            "Anomalies Detected": len(anomalies),
            "Data Source": "RIPE Stat",
        }))
        s.append(f.space())

        s += f.h1("AI Analysis")
        s.append(f.text(self.ai.bgp_analysis(anomalies)))
        s.append(f.space())

        s += f.h1("BGP Security Best Practices")
        s += f.bullet([
            "Implement RPKI (Resource Public Key Infrastructure) for all prefixes",
            "Deploy BGPsec to cryptographically sign BGP announcements",
            "Enable route filtering with IRR (Internet Routing Registry) data",
            "Monitor BGP looking glass for unauthorized route announcements",
            "Implement max-prefix limits on all BGP sessions",
            "Subscribe to RIPE NCC routing anomaly alerts",
            "Peer with route servers at IXPs that enforce RPKI",
        ])
        s.append(f.space())

        s += f.h1("Known BGP Hijacking Techniques")
        rows = [
            ["Prefix Hijacking", "HIGH", "Attacker announces victim's prefix"],
            ["Sub-prefix Hijacking", "CRITICAL", "More specific prefix announced to attract traffic"],
            ["Route Leak", "MEDIUM", "Routes propagated beyond intended scope"],
            ["AS Path Manipulation", "HIGH", "Fake AS paths to influence routing decisions"],
            ["BGP Community Abuse", "MEDIUM", "Misuse of BGP communities to affect routing"],
        ]
        s.append(f._table(["Attack Type", "Severity", "Description"], rows, [5*cm, 3*cm, 10*cm]))
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("BGP Hijacking", data)
        s += f.bullet(recs)

        return s
