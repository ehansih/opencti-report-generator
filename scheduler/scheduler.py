"""APScheduler-based report scheduler for OpenCTI Report Generator"""
import os, sys, logging
from datetime import datetime
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)


def _run(GeneratorClass, label):
    try:
        log.info(f"Starting report: {label}")
        gen = GeneratorClass()
        path = gen.generate(output_dir=REPORT_DIR)
        log.info(f"Report saved: {path}")
        return path
    except Exception as e:
        log.error(f"Report failed [{label}]: {e}")
        return None


def run_all_reports():
    """Run all reports immediately (used for on-demand or startup)."""
    from generators.executive_briefing  import ExecutiveBriefingGenerator
    from generators.bgp_hijacking       import BGPHijackingGenerator
    from generators.cve_report          import TelecomCVEGenerator
    from generators.ss7_report          import SS7ThreatGenerator
    from generators.apt_report          import APTCampaignGenerator
    from generators.ioc_watchlist       import IOCWatchlistGenerator
    from generators.ddos_report         import DDoSReportGenerator
    from generators.subscriber_report   import SubscriberThreatGenerator
    from generators.fiveg_report        import FiveGSecurityGenerator
    from generators.fraud_report        import TelecomFraudGenerator
    from generators.dark_web_report     import DarkWebMonitorGenerator
    from generators.supply_chain_report import SupplyChainGenerator
    from generators.compliance_report   import ComplianceReportGenerator
    from generators.executive_profile   import ExecutiveThreatProfileGenerator

    ALL = [
        (ExecutiveBriefingGenerator,      "Executive Briefing"),
        (BGPHijackingGenerator,           "BGP Hijacking"),
        (TelecomCVEGenerator,             "Telecom CVE"),
        (SS7ThreatGenerator,              "SS7/Diameter"),
        (APTCampaignGenerator,            "APT Campaign"),
        (IOCWatchlistGenerator,           "IOC Watchlist"),
        (DDoSReportGenerator,             "DDoS"),
        (SubscriberThreatGenerator,       "Subscriber Threats"),
        (FiveGSecurityGenerator,          "5G Security"),
        (TelecomFraudGenerator,           "Telecom Fraud"),
        (DarkWebMonitorGenerator,         "Dark Web"),
        (SupplyChainGenerator,            "Supply Chain"),
        (ComplianceReportGenerator,       "Compliance"),
        (ExecutiveThreatProfileGenerator, "Executive Profile"),
    ]

    results = []
    for cls, label in ALL:
        path = _run(cls, label)
        results.append({"label": label, "path": path, "ok": path is not None})
    return results


def create_scheduler():
    """Create and configure the APScheduler instance."""
    scheduler = BackgroundScheduler(timezone="UTC")

    # ── Daily reports (06:00 UTC) ──────────────────────────────────────────
    from generators.bgp_hijacking  import BGPHijackingGenerator
    from generators.ioc_watchlist  import IOCWatchlistGenerator

    scheduler.add_job(
        lambda: _run(BGPHijackingGenerator, "BGP Hijacking"),
        CronTrigger(hour=6, minute=0),
        id="bgp_daily", name="BGP Hijacking Report (daily)",
    )
    scheduler.add_job(
        lambda: _run(IOCWatchlistGenerator, "IOC Watchlist"),
        CronTrigger(hour=6, minute=15),
        id="ioc_daily", name="IOC Watchlist Report (daily)",
    )

    # ── Weekly reports (Monday 07:00 UTC) ──────────────────────────────────
    from generators.executive_briefing import ExecutiveBriefingGenerator
    from generators.cve_report         import TelecomCVEGenerator
    from generators.ddos_report        import DDoSReportGenerator
    from generators.subscriber_report  import SubscriberThreatGenerator
    from generators.fraud_report       import TelecomFraudGenerator
    from generators.dark_web_report    import DarkWebMonitorGenerator

    weekly_jobs = [
        (ExecutiveBriefingGenerator,  "Executive Briefing",  0),
        (TelecomCVEGenerator,         "Telecom CVE",         15),
        (DDoSReportGenerator,         "DDoS",                30),
        (SubscriberThreatGenerator,   "Subscriber Threats",  45),
        (TelecomFraudGenerator,       "Telecom Fraud",       60),
        (DarkWebMonitorGenerator,     "Dark Web",            75),
    ]
    for cls, label, offset_min in weekly_jobs:
        h, m = divmod(7 * 60 + offset_min, 60)
        scheduler.add_job(
            lambda c=cls, l=label: _run(c, l),
            CronTrigger(day_of_week="mon", hour=h, minute=m),
            id=f"weekly_{label.replace(' ','_').lower()}",
            name=f"{label} Report (weekly)",
        )

    # ── Monthly reports (1st of month, 08:00 UTC) ─────────────────────────
    from generators.ss7_report          import SS7ThreatGenerator
    from generators.apt_report          import APTCampaignGenerator
    from generators.fiveg_report        import FiveGSecurityGenerator
    from generators.supply_chain_report import SupplyChainGenerator
    from generators.compliance_report   import ComplianceReportGenerator
    from generators.executive_profile   import ExecutiveThreatProfileGenerator

    monthly_jobs = [
        (SS7ThreatGenerator,              "SS7/Diameter",    0),
        (APTCampaignGenerator,            "APT Campaign",    20),
        (FiveGSecurityGenerator,          "5G Security",     40),
        (SupplyChainGenerator,            "Supply Chain",    60),
        (ComplianceReportGenerator,       "Compliance",      80),
        (ExecutiveThreatProfileGenerator, "Executive Profile",100),
    ]
    for cls, label, offset_min in monthly_jobs:
        h, m = divmod(8 * 60 + offset_min, 60)
        scheduler.add_job(
            lambda c=cls, l=label: _run(c, l),
            CronTrigger(day=1, hour=h, minute=m),
            id=f"monthly_{label.replace(' ','_').lower()}",
            name=f"{label} Report (monthly)",
        )

    return scheduler


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OpenCTI Report Scheduler")
    parser.add_argument("--run-now", action="store_true", help="Run all reports immediately and exit")
    args = parser.parse_args()

    if args.run_now:
        print("Running all reports now...")
        results = run_all_reports()
        for r in results:
            status = "OK" if r["ok"] else "FAILED"
            print(f"  [{status}] {r['label']} -> {r['path']}")
        sys.exit(0)

    scheduler = create_scheduler()
    scheduler.start()
    log.info("Scheduler started. Reports will run on schedule.")
    log.info("Press Ctrl+C to stop.")

    try:
        import time
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        log.info("Scheduler stopped.")
