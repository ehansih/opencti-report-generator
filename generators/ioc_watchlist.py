"""IOC Watchlist Report"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from generators.base_generator import BaseReportGenerator
from reportlab.lib.units import cm
from collectors.opencti_client import OpenCTIClient
from collectors.external_feeds import URLHausCollector, MalwareBazaarCollector


class IOCWatchlistGenerator(BaseReportGenerator):
    report_name = "IOC Watchlist Report"
    schedule    = "daily"

    def collect_data(self):
        cti = OpenCTIClient()
        return {
            "indicators":   cti.get_indicators(days=7, limit=100),
            "malware":      cti.get_malware(limit=30),
            "urlhaus":      URLHausCollector().get_recent_urls(limit=30),
            "malwarebazaar":MalwareBazaarCollector().get_recent_samples(limit=20),
        }

    def build_sections(self, data):
        f    = self.pdf
        iocs = data.get("indicators", [])
        mw   = data.get("malware", [])
        urls = data.get("urlhaus", [])
        s    = []

        # Count by type
        type_counts = {}
        for ioc in iocs:
            t = ioc.get("pattern_type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        s += f.h1("IOC Summary")
        s.append(f._stat_boxes({
            "Total IOCs":    len(iocs),
            "Malware Families": len(mw),
            "Malicious URLs": len(urls),
            "MalwareBazaar": len(data.get("malwarebazaar", [])),
        }))
        s.append(f.space())

        s += f.h1("AI Summary")
        s.append(f.text(self.ai.ioc_summary(iocs)))
        s.append(f.space())

        if iocs:
            s += f.h1("Top IOCs — Last 7 Days")
            high_conf = sorted(iocs, key=lambda x: x.get("x_opencti_score", 0), reverse=True)[:20]
            rows = [[
                i.get("name","")[:50],
                i.get("pattern_type",""),
                str(i.get("x_opencti_score","")),
                i.get("validFrom","")[:10] if i.get("validFrom") else ""
            ] for i in high_conf]
            s.append(f._table(
                ["Indicator", "Type", "Score", "Valid From"],
                rows, [8*cm, 3*cm, 2*cm, 3*cm]
            ))
            s.append(f.space())

        if mw:
            s += f.h1("Active Malware Families")
            s.append(f.text(self.ai.malware_analysis(mw)))
            rows = [[
                m.get("name",""),
                ", ".join(m.get("malware_types", [])),
                str(m.get("is_family",""))
            ] for m in mw[:15]]
            s.append(f._table(
                ["Malware Name", "Type", "Is Family"],
                rows, [6*cm, 8*cm, 4*cm]
            ))
            s.append(f.space())

        if urls:
            s += f.h1("URLhaus — Active Malicious URLs")
            rows = [[
                u.get("url","")[:60],
                u.get("threat",""),
                u.get("url_status",""),
                u.get("date_added","")[:10] if u.get("date_added") else ""
            ] for u in urls[:15]]
            s.append(f._table(
                ["URL", "Threat", "Status", "Date Added"],
                rows, [8*cm, 3*cm, 2.5*cm, 2.5*cm]
            ))
            s.append(f.space())

        s += f.h1("Recommendations")
        recs = self.ai.recommendations("IOC Watchlist", data)
        s += f.bullet(recs)

        return s
