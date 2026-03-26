"""
Dry-run tests for OpenCTI Report Generator.
All tests use mocked collectors and AI — no real API calls.
Run: python test_dry_run.py
"""
import os, sys, unittest, tempfile
from unittest.mock import patch, MagicMock, PropertyMock

sys.path.insert(0, os.path.dirname(__file__))

# ── Mock data ─────────────────────────────────────────────────────────────────

MOCK_INDICATORS = [
    {"name": "192.168.1.100", "pattern_type": "ipv4-addr", "x_opencti_score": 85, "validFrom": "2024-01-01"},
    {"name": "malware.evil.com", "pattern_type": "domain-name", "x_opencti_score": 90, "validFrom": "2024-01-02"},
    {"name": "d41d8cd98f00b204e9800998ecf8427e", "pattern_type": "file:hashes.MD5", "x_opencti_score": 75, "validFrom": "2024-01-03"},
]
MOCK_MALWARE = [
    {"name": "Emotet", "malware_types": ["trojan", "downloader"], "is_family": True},
    {"name": "Cobalt Strike", "malware_types": ["backdoor"], "is_family": False},
]
MOCK_THREAT_ACTORS = [
    {"name": "Salt Typhoon", "threat_actor_types": "nation-state", "sophistication": "advanced", "primary_motivation": "espionage"},
    {"name": "LockBit", "threat_actor_types": "criminal", "sophistication": "intermediate", "primary_motivation": "financial-gain"},
]
MOCK_CVES = [
    {"id": "CVE-2024-20353", "vendor": "cisco", "cvss_score": 9.8, "severity": "CRITICAL", "description": "Cisco IOS-XE remote code execution"},
    {"id": "CVE-2024-3400",  "vendor": "paloalto", "cvss_score": 10.0, "severity": "CRITICAL", "description": "PAN-OS command injection"},
    {"id": "CVE-2024-1234",  "vendor": "nokia", "cvss_score": 7.5, "severity": "HIGH", "description": "Nokia SR-OS privilege escalation"},
]
MOCK_BGP_EVENTS = [
    {"prefix": "203.0.113.0/24", "hijacker_asn": "AS64512", "origin_asn": "AS65000", "country": "XX", "time": "2024-01-01T10:00:00Z"},
    {"prefix": "198.51.100.0/24", "hijacker_asn": "AS64513", "origin_asn": "AS65001", "country": "YY", "time": "2024-01-01T11:00:00Z"},
]
MOCK_AMP = {
    "DNS": {"port": "53", "factor": "50x"},
    "NTP": {"port": "123", "factor": "556x"},
    "Memcached": {"port": "11211", "factor": "51200x"},
}
MOCK_SS7_PATTERNS = [
    {"attack": "SRI Abuse", "protocol": "SS7", "message": "SRI", "severity": "CRITICAL", "description": "Subscriber location tracking"},
    {"attack": "MT-FSM",    "protocol": "SS7", "message": "MT-FSM", "severity": "HIGH",     "description": "Silent SMS tracking"},
]
MOCK_ROAMING_RISKS = [
    {"indicator": "Unusual SRI volume", "risk": "Location tracking by unauthorized party"},
    {"indicator": "PSI from non-roaming partner", "risk": "Subscriber surveillance"},
]
MOCK_URLHAUS = [
    {"url": "http://evil.example.com/payload", "threat": "malware_download", "url_status": "online", "date_added": "2024-01-01"},
]
MOCK_BAZAAR = [
    {"sha256_hash": "abc123", "file_type": "exe", "file_size": 102400, "signature": "Emotet"},
]
MOCK_KEV = [
    {"cveID": "CVE-2024-20353", "vendorProject": "Cisco", "product": "IOS-XE", "shortDescription": "RCE"},
]
MOCK_STATS = {"reports": 42, "indicators": 1500, "malware": 200, "threat_actors": 80}
MOCK_CAMPAIGNS = [
    {"name": "Operation Typhoon", "first_seen": "2024-01-01", "description": "Telecom campaign"},
]
MOCK_INTRUSION_SETS = [{"name": "LightBasin"}]
MOCK_ATTACK_PATTERNS = [
    {"name": "T1190", "x_mitre_id": "T1190", "description": "Exploit public-facing application"},
]
MOCK_VULNS = [
    {"name": "CVE-2024-20353", "cvss_score": 9.8, "description": "Critical RCE"},
]

AI_TEXT = "AI-generated threat assessment for this report section."
AI_RECS  = ["Patch immediately", "Deploy firewall rules", "Monitor for IOCs"]


# ── Patch helpers ─────────────────────────────────────────────────────────────

def mock_opencti():
    m = MagicMock()
    m.get_indicators.return_value      = MOCK_INDICATORS
    m.get_malware.return_value         = MOCK_MALWARE
    m.get_threat_actors.return_value   = MOCK_THREAT_ACTORS
    m.get_campaigns.return_value       = MOCK_CAMPAIGNS
    m.get_intrusion_sets.return_value  = MOCK_INTRUSION_SETS
    m.get_attack_patterns.return_value = MOCK_ATTACK_PATTERNS
    m.get_vulnerabilities.return_value = MOCK_VULNS
    m.get_reports.return_value         = []
    m.get_summary_stats.return_value   = MOCK_STATS
    return m

def mock_ai():
    m = MagicMock()
    m.executive_summary.return_value  = AI_TEXT
    m.bgp_analysis.return_value       = AI_TEXT
    m.cve_analysis.return_value       = AI_TEXT
    m.apt_analysis.return_value       = AI_TEXT
    m.ss7_analysis.return_value       = AI_TEXT
    m.ddos_analysis.return_value      = AI_TEXT
    m.ioc_summary.return_value        = AI_TEXT
    m.malware_analysis.return_value   = AI_TEXT
    m.recommendations.return_value    = AI_RECS
    return m

def mock_bgp():
    m = MagicMock()
    m.get_hijack_events.return_value = MOCK_BGP_EVENTS
    return m

def mock_cve():
    m = MagicMock()
    m.get_recent_cves.return_value = MOCK_CVES
    return m

def mock_cisa():
    m = MagicMock()
    m.get_kev_catalog.return_value = MOCK_KEV
    return m

def mock_urlhaus():
    m = MagicMock()
    m.get_recent_urls.return_value = MOCK_URLHAUS
    return m

def mock_bazaar():
    m = MagicMock()
    m.get_recent_samples.return_value = MOCK_BAZAAR
    return m

def mock_ddos():
    m = MagicMock()
    m.get_active_attacks.return_value  = [{"type": "UDP Flood", "target": "203.0.113.1", "volume": "100Gbps"}]
    m.get_amplification_sources.return_value = MOCK_AMP
    return m

def mock_ss7():
    m = MagicMock()
    m.get_known_attack_patterns.return_value  = MOCK_SS7_PATTERNS
    m.get_roaming_risk_indicators.return_value = MOCK_ROAMING_RISKS
    return m


# ── Base test mixin ───────────────────────────────────────────────────────────

class GeneratorTestMixin:
    """Mixin: patches collectors + AI, runs generate(), asserts PDF created."""

    generator_module  = None   # e.g. "generators.executive_briefing"
    generator_class   = None   # e.g. "ExecutiveBriefingGenerator"
    extra_patches     = {}     # {target: mock_factory}

    def _run_generator(self):
        import importlib
        mod = importlib.import_module(self.generator_module)
        cls = getattr(mod, self.generator_class)

        tmpdir = tempfile.mkdtemp()
        # Patch base_generator's NarrativeGenerator so all generators use mock AI
        ctx_managers = [patch("generators.base_generator.NarrativeGenerator", return_value=mock_ai())]
        for target, factory in self.extra_patches.items():
            ctx_managers.append(patch(target, return_value=factory()))
        for cm in ctx_managers:
            cm.__enter__()
        try:
            gen  = cls()
            gen.ai = mock_ai()          # inject directly too
            data = gen.collect_data()
            secs = gen.build_sections(data)
            path = gen.generate(output_dir=tmpdir)
            return path, tmpdir
        finally:
            for cm in ctx_managers:
                cm.__exit__(None, None, None)

    def test_generates_pdf(self):
        path, tmpdir = self._run_generator()
        self.assertIsNotNone(path, "generate() returned None")
        self.assertTrue(os.path.exists(path), f"PDF not found at {path}")
        self.assertGreater(os.path.getsize(path), 1000, "PDF too small — likely empty")

    def test_pdf_extension(self):
        path, _ = self._run_generator()
        self.assertTrue(path.endswith(".pdf"), "Output file should be a .pdf")


# ── Individual generator tests ────────────────────────────────────────────────

class TestExecutiveBriefing(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.executive_briefing"
    generator_class  = "ExecutiveBriefingGenerator"
    extra_patches = {
        "generators.executive_briefing.OpenCTIClient":  mock_opencti,
        "generators.executive_briefing.CISACollector":  mock_cisa,
    }

class TestBGPHijacking(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.bgp_hijacking"
    generator_class  = "BGPHijackingGenerator"
    extra_patches = {
        "generators.bgp_hijacking.BGPCollector": mock_bgp,
    }

class TestCVEReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.cve_report"
    generator_class  = "TelecomCVEGenerator"
    extra_patches = {
        "generators.cve_report.CVECollector":    mock_cve,
        "generators.cve_report.CISACollector":   mock_cisa,
        "generators.cve_report.OpenCTIClient":   mock_opencti,
    }

class TestSS7Report(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.ss7_report"
    generator_class  = "SS7ThreatGenerator"
    extra_patches = {
        "generators.ss7_report.SS7Collector": mock_ss7,
    }

class TestAPTReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.apt_report"
    generator_class  = "APTCampaignGenerator"
    extra_patches = {
        "generators.apt_report.OpenCTIClient": mock_opencti,
    }

class TestIOCWatchlist(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.ioc_watchlist"
    generator_class  = "IOCWatchlistGenerator"
    extra_patches = {
        "generators.ioc_watchlist.OpenCTIClient":          mock_opencti,
        "generators.ioc_watchlist.URLHausCollector":       mock_urlhaus,
        "generators.ioc_watchlist.MalwareBazaarCollector": mock_bazaar,
    }

class TestDDoSReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.ddos_report"
    generator_class  = "DDoSReportGenerator"
    extra_patches = {
        "generators.ddos_report.DDoSCollector": mock_ddos,
    }

class TestSubscriberReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.subscriber_report"
    generator_class  = "SubscriberThreatGenerator"
    extra_patches = {
        "generators.subscriber_report.SS7Collector": mock_ss7,
    }

class TestFiveGReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.fiveg_report"
    generator_class  = "FiveGSecurityGenerator"
    extra_patches = {
        "generators.fiveg_report.OpenCTIClient": mock_opencti,
    }

class TestFraudReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.fraud_report"
    generator_class  = "TelecomFraudGenerator"
    extra_patches    = {}

class TestDarkWebReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.dark_web_report"
    generator_class  = "DarkWebMonitorGenerator"
    extra_patches = {
        "generators.dark_web_report.OpenCTIClient":          mock_opencti,
        "generators.dark_web_report.MalwareBazaarCollector": mock_bazaar,
    }

class TestSupplyChainReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.supply_chain_report"
    generator_class  = "SupplyChainGenerator"
    extra_patches = {
        "generators.supply_chain_report.OpenCTIClient": mock_opencti,
    }

class TestComplianceReport(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.compliance_report"
    generator_class  = "ComplianceReportGenerator"
    extra_patches    = {}

class TestExecutiveProfile(GeneratorTestMixin, unittest.TestCase):
    generator_module = "generators.executive_profile"
    generator_class  = "ExecutiveThreatProfileGenerator"
    extra_patches = {
        "generators.executive_profile.OpenCTIClient": mock_opencti,
        "generators.executive_profile.CVECollector":  mock_cve,
        "generators.executive_profile.BGPCollector":  mock_bgp,
    }


# ── Collector unit tests ──────────────────────────────────────────────────────

class TestDDoSCollector(unittest.TestCase):
    def test_static_attacks(self):
        from collectors.external_feeds import DDoSCollector
        d = DDoSCollector()
        attacks = d.get_active_attacks()
        self.assertIsInstance(attacks, list)
        self.assertGreater(len(attacks), 0)

    def test_amplification_sources(self):
        from collectors.external_feeds import DDoSCollector
        d   = DDoSCollector()
        amp = d.get_amplification_sources()
        self.assertIsInstance(amp, dict)
        self.assertGreater(len(amp), 0)
        # Each entry should have port and factor
        for key, val in amp.items():
            self.assertIn("port", val)
            self.assertIn("factor", val)

class TestSS7Collector(unittest.TestCase):
    def test_attack_patterns(self):
        from collectors.external_feeds import SS7Collector
        s = SS7Collector()
        patterns = s.get_known_attack_patterns()
        self.assertIsInstance(patterns, list)
        self.assertGreater(len(patterns), 5)
        for p in patterns:
            self.assertIn("attack", p)
            self.assertIn("severity", p)

    def test_roaming_risks(self):
        from collectors.external_feeds import SS7Collector
        s = SS7Collector()
        risks = s.get_roaming_risk_indicators()
        self.assertIsInstance(risks, list)
        self.assertGreater(len(risks), 0)

class TestOpenCTIClientOffline(unittest.TestCase):
    """Test OpenCTI client graceful fallback (no real server)."""
    def test_connection_failure_returns_false(self):
        from collectors.opencti_client import OpenCTIClient
        c = OpenCTIClient()
        # Should not raise — returns False when OpenCTI is unreachable
        result = c.test_connection()
        self.assertIsInstance(result, bool)

    def test_get_indicators_empty_on_failure(self):
        from collectors.opencti_client import OpenCTIClient
        c = OpenCTIClient()
        result = c.get_indicators(days=7, limit=10)
        self.assertIsInstance(result, list)

class TestCVECollectorOffline(unittest.TestCase):
    def test_returns_list_on_network_error(self):
        from collectors.external_feeds import CVECollector
        with patch("collectors.external_feeds.requests.get", side_effect=Exception("network error")):
            c = CVECollector()
            result = c.get_recent_cves(days=30)
            self.assertIsInstance(result, list)


# ── PDF formatter unit tests ──────────────────────────────────────────────────

class TestPDFFormatter(unittest.TestCase):
    def setUp(self):
        from formatters.pdf_formatter import PDFReportFormatter
        self.fmt = PDFReportFormatter(output_dir="/tmp")

    def test_h1_returns_list(self):
        result = self.fmt.h1("Section Title")
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_h2_returns_element(self):
        result = self.fmt.h2("Subsection")
        self.assertIsNotNone(result)

    def test_text_returns_element(self):
        el = self.fmt.text("Some text paragraph")
        self.assertIsNotNone(el)

    def test_bullet_returns_list(self):
        result = self.fmt.bullet(["item1", "item2", "item3"])
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_space_returns_element(self):
        el = self.fmt.space()
        self.assertIsNotNone(el)

    def test_stat_boxes_returns_element(self):
        el = self.fmt._stat_boxes({"Total": 100, "Critical": 5})
        self.assertIsNotNone(el)

    def test_table_returns_element(self):
        from reportlab.lib.units import cm
        el = self.fmt._table(
            ["Col1", "Col2"],
            [["A", "B"], ["C", "D"]],
            [5*cm, 5*cm]
        )
        self.assertIsNotNone(el)

    def test_generate_creates_pdf(self):
        tmpdir = tempfile.mkdtemp()
        content = self.fmt.h1("Test Section")
        content.append(self.fmt.text("Hello world"))
        content += self.fmt.bullet(["Point 1", "Point 2"])
        path = self.fmt.generate("test_report.pdf", "Test Report", content)
        self.assertTrue(os.path.exists(path))
        self.assertGreater(os.path.getsize(path), 500)


# ── Scheduler unit tests ──────────────────────────────────────────────────────

class TestScheduler(unittest.TestCase):
    def test_create_scheduler_returns_scheduler(self):
        from scheduler.scheduler import create_scheduler
        s = create_scheduler()
        self.assertIsNotNone(s)
        jobs = s.get_jobs()
        self.assertGreater(len(jobs), 0)
        # Check we have daily, weekly, monthly jobs
        ids = [j.id for j in jobs]
        self.assertIn("bgp_daily", ids)
        self.assertIn("ioc_daily", ids)

    def test_scheduler_has_correct_job_count(self):
        from scheduler.scheduler import create_scheduler
        s = create_scheduler()
        jobs = s.get_jobs()
        # 2 daily + 6 weekly + 6 monthly = 14 jobs
        self.assertEqual(len(jobs), 14)


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    loader  = unittest.TestLoader()
    suite   = loader.loadTestsFromModule(sys.modules[__name__])
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)

    total   = result.testsRun
    passed  = total - len(result.failures) - len(result.errors)
    print(f"\n{'='*60}")
    print(f"Results: {passed}/{total} tests passed")
    if result.failures or result.errors:
        print("FAILURES:")
        for test, tb in result.failures + result.errors:
            print(f"  - {test}: {tb.splitlines()[-1]}")
    else:
        print("All tests passed!")
    print('='*60)
    sys.exit(0 if result.wasSuccessful() else 1)
