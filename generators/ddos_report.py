"""DDoS Attack Intelligence Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm
from collectors.external_feeds import DDoSCollector


class DDoSReportGenerator(BaseReportGenerator):
    report_name = "DDoS Attack Intelligence Report"
    schedule    = "weekly"

    def collect_data(self):
        ddos = DDoSCollector()
        return {
            "active_attacks":   ddos.get_active_attacks(),
            "amplification":    ddos.get_amplification_sources(),
        }

    def build_sections(self, data):
        f      = self.pdf
        attacks = data.get("active_attacks", [])
        amp     = data.get("amplification", {})
        s       = []

        s += f.h1("DDoS Threat Overview")
        s.append(f._stat_boxes({
            "Active Attacks":       len(attacks),
            "Amplification Vectors": len(amp),
        }))
        s.append(f.space())

        s += f.h1("AI Threat Assessment")
        s.append(f.text(self.ai.ddos_analysis(attacks)))
        s.append(f.space())

        s += f.h1("DDoS Attack Types Targeting Telecom")
        rows = [
            ["Volumetric", "CRITICAL", "Floods bandwidth — UDP floods, DNS amplification, NTP amplification"],
            ["Protocol",   "HIGH",     "Exhausts network equipment resources — SYN flood, fragmentation"],
            ["Application","HIGH",     "HTTP floods targeting BSS/OSS web portals"],
            ["Reflection", "HIGH",     "Amplified attacks using open resolvers, memcached, SSDP"],
            ["BGP Flood",  "CRITICAL", "Routing table exhaustion attacks on peering routers"],
            ["GTP Flood",  "HIGH",     "Floods mobile core GTP interfaces to degrade subscriber service"],
            ["Signaling",  "MEDIUM",   "SS7/Diameter signaling storms causing core network congestion"],
        ]
        s.append(f._table(["Attack Type", "Severity", "Description"], rows, [3.5*cm, 2.5*cm, 12*cm]))
        s.append(f.space())

        s += f.h1("Amplification Vectors")
        rows = [[proto, d.get("port",""), d.get("factor","")] for proto, d in amp.items()]
        s.append(f._table(["Protocol", "Port", "Amplification Factor"], rows, [6*cm, 3*cm, 9*cm]))
        s.append(f.space())

        s += f.h1("Mitigation Architecture")
        s += f.bullet([
            "Deploy scrubbing centers with >1Tbps capacity at upstream peering points",
            "Implement BCP38/BCP84 ingress filtering to prevent IP spoofing",
            "Enable RTBH (Remotely Triggered Black Hole) for rapid /32 blocking",
            "Deploy FlowSpec (RFC 5575) for surgical traffic filtering",
            "Implement rate limiting on DNS resolvers (max 50 queries/s per source)",
            "Close memcached UDP port 11211 or rate-limit to prevent amplification",
            "Use anycast for DNS to distribute and absorb volumetric attacks",
            "Peer at multiple IXPs for traffic diversion during attacks",
            "Subscribe to DDoS intelligence feeds for early warning",
        ])
        s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("DDoS", data)
        s += f.bullet(recs)

        return s
