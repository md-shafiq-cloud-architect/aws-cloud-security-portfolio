import unittest
from sra_compliance_engine import MasterSRAComplianceEngine, build_compliant_enterprise_baseline

class TestSRAComplianceEngine(unittest.TestCase):
    def setUp(self):
        self.engine = MasterSRAComplianceEngine()
        self.baseline = build_compliant_enterprise_baseline()

    def test_compliant_baseline_passes_all_rules(self):
        report = self.engine.evaluate(self.baseline)
        self.assertEqual(report["overall_status"], "COMPLIANT")
        self.assertEqual(report["compliance_score_percent"], 100.0)
        self.assertEqual(report["failed_count"], 0)

    def test_non_compliant_manual_iam_user(self):
        non_compliant_env = self.baseline.copy()
        non_compliant_env["manual_iam_users_count"] = 2
        report = self.engine.evaluate(non_compliant_env)
        self.assertEqual(report["overall_status"], "NON_COMPLIANT")
        self.assertGreater(report["failed_count"], 0)

    def test_missing_telemetry_attribute_handled(self):
        incomplete_env = self.baseline.copy()
        del incomplete_env["idc_mfa_enforced"]
        report = self.engine.evaluate(incomplete_env)
        self.assertEqual(report["overall_status"], "NON_COMPLIANT")
        self.assertTrue(any("Missing telemetry attribute" in r["reason"] for r in report["failed_rules"]))

if __name__ == "__main__":
    unittest.main()
  
