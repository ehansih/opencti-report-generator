"""Flask web dashboard for OpenCTI Report Generator"""
import os, sys, json, threading
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from flask import Flask, render_template, jsonify, send_file, abort, request
from scheduler.scheduler import create_scheduler, run_all_reports, _run

app = Flask(__name__)

REPORT_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
os.makedirs(REPORT_DIR, exist_ok=True)

_scheduler = None
_scheduler_lock = threading.Lock()

# ── Report registry (all generators) ─────────────────────────────────────────
def _get_generator(name):
    MAP = {
        "executive_briefing":  ("generators.executive_briefing",  "ExecutiveBriefingGenerator"),
        "bgp_hijacking":       ("generators.bgp_hijacking",       "BGPHijackingGenerator"),
        "cve_report":          ("generators.cve_report",          "TelecomCVEGenerator"),
        "ss7_report":          ("generators.ss7_report",          "SS7ThreatGenerator"),
        "apt_report":          ("generators.apt_report",          "APTCampaignGenerator"),
        "ioc_watchlist":       ("generators.ioc_watchlist",       "IOCWatchlistGenerator"),
        "ddos_report":         ("generators.ddos_report",         "DDoSReportGenerator"),
        "subscriber_report":   ("generators.subscriber_report",   "SubscriberThreatGenerator"),
        "fiveg_report":        ("generators.fiveg_report",        "FiveGSecurityGenerator"),
        "fraud_report":        ("generators.fraud_report",        "TelecomFraudGenerator"),
        "dark_web_report":     ("generators.dark_web_report",     "DarkWebMonitorGenerator"),
        "supply_chain_report": ("generators.supply_chain_report", "SupplyChainGenerator"),
        "compliance_report":   ("generators.compliance_report",   "ComplianceReportGenerator"),
        "executive_profile":   ("generators.executive_profile",   "ExecutiveThreatProfileGenerator"),
    }
    if name not in MAP:
        return None
    mod_name, cls_name = MAP[name]
    import importlib
    mod = importlib.import_module(mod_name)
    return getattr(mod, cls_name)


def _list_reports():
    """Return metadata for all PDF files in the reports directory."""
    reports = []
    for p in sorted(Path(REPORT_DIR).glob("*.pdf"), key=os.path.getmtime, reverse=True):
        stat = p.stat()
        reports.append({
            "filename": p.name,
            "size_kb":  round(stat.st_size / 1024, 1),
            "generated": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M UTC"),
        })
    return reports


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html", reports=_list_reports())


@app.route("/api/reports")
def api_reports():
    return jsonify(_list_reports())


@app.route("/api/download/<filename>")
def download(filename):
    safe = os.path.basename(filename)
    path = os.path.join(REPORT_DIR, safe)
    if not os.path.exists(path) or not safe.endswith(".pdf"):
        abort(404)
    return send_file(path, as_attachment=True, download_name=safe, mimetype="application/pdf")


@app.route("/api/generate/<report_name>", methods=["POST"])
def generate_report(report_name):
    cls = _get_generator(report_name)
    if not cls:
        return jsonify({"error": f"Unknown report: {report_name}"}), 404

    def _bg():
        _run(cls, report_name)

    t = threading.Thread(target=_bg, daemon=True)
    t.start()
    return jsonify({"status": "started", "report": report_name})


@app.route("/api/generate-all", methods=["POST"])
def generate_all():
    def _bg():
        run_all_reports()

    t = threading.Thread(target=_bg, daemon=True)
    t.start()
    return jsonify({"status": "started", "message": "All reports queued for generation"})


@app.route("/api/scheduler/status")
def scheduler_status():
    global _scheduler
    if _scheduler and _scheduler.running:
        jobs = [{"id": j.id, "name": j.name, "next_run": str(j.next_run_time)} for j in _scheduler.get_jobs()]
        return jsonify({"running": True, "jobs": jobs})
    return jsonify({"running": False, "jobs": []})


@app.route("/api/scheduler/start", methods=["POST"])
def scheduler_start():
    global _scheduler
    with _scheduler_lock:
        if _scheduler and _scheduler.running:
            return jsonify({"status": "already_running"})
        _scheduler = create_scheduler()
        _scheduler.start()
    return jsonify({"status": "started"})


@app.route("/api/scheduler/stop", methods=["POST"])
def scheduler_stop():
    global _scheduler
    with _scheduler_lock:
        if _scheduler and _scheduler.running:
            _scheduler.shutdown()
    return jsonify({"status": "stopped"})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "reports_dir": REPORT_DIR})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    app.run(host="0.0.0.0", port=port, debug=False)
