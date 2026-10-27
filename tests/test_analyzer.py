import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from analyzer import analyze_indicators, extract_urls, risk_level, risk_score, url_findings

class AnalyzerTests(unittest.TestCase):
    def test_detects_otp_and_urgency(self):
        flags, _ = analyze_indicators("URGENT: share your OTP immediately")
        self.assertTrue(any("OTP" in flag for flag in flags))
        self.assertTrue(any("urgency" in flag.lower() or "threat" in flag.lower() for flag in flags))

    def test_extracts_multiple_unique_urls_and_trims_punctuation(self):
        urls = extract_urls("Visit http://example.com/login, then www.example.org. Also http://example.com/login")
        self.assertEqual(urls, ["http://example.com/login", "www.example.org"])

    def test_url_at_symbol_and_ip_address(self):
        self.assertTrue(any("@ symbol" in x for x in url_findings("http://user@example.com/path")))
        self.assertTrue(any("IP address" in x for x in url_findings("http://192.168.1.10/login")))

    def test_shortener_and_executable_path(self):
        self.assertTrue(any("shortening" in x.lower() for x in url_findings("https://bit.ly/abc")))
        self.assertTrue(any("executable" in x.lower() for x in url_findings("https://example.com/update.apk")))

    def test_malformed_url_is_explained(self):
        self.assertTrue(url_findings("not-a-url"))

    def test_score_is_bounded_and_monotonic_for_warnings(self):
        base = risk_score(20, 0, 0)
        more_warnings = risk_score(20, 2, 1)
        self.assertGreater(more_warnings, base)
        self.assertGreaterEqual(base, 0)
        self.assertLessEqual(risk_score(1000, 100, 100), 100)

    def test_risk_bands(self):
        self.assertEqual(risk_level(10)[0], "Fewer detected risk signals")
        self.assertEqual(risk_level(40)[0], "Caution advised")
        self.assertEqual(risk_level(80)[0], "High risk signals")

if __name__ == "__main__":
    unittest.main()
