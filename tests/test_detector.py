import unittest
from datetime import datetime, timezone
from src.models import PersistenceEvent
from src.detector import detect, metrics
from src.reporting import markdown_report


class PersistenceDetectionTests(unittest.TestCase):
    def event(self, **overrides):
        base = dict(
            event_id="evt-test",
            timestamp=datetime(2026, 9, 10, tzinfo=timezone.utc),
            host="LAB-01",
            user="synthetic\\tester",
            event_type="scheduled_task",
            object_name="SyntheticTask",
            action="create",
            signer_status="trusted",
            parent_process="services.exe",
        )
        base.update(overrides)
        return PersistenceEvent(**base)

    def test_scheduled_task_detected(self):
        findings = detect([self.event()])
        self.assertEqual(len(findings), 1)
        self.assertIn("T1053.005", findings[0].attack_techniques)

    def test_run_key_detected(self):
        findings = detect([self.event(event_type="run_key")])
        self.assertEqual(findings[0].title, "Autostart persistence change")

    def test_service_detected(self):
        findings = detect([self.event(event_type="service")])
        self.assertIn("T1543.003", findings[0].attack_techniques)

    def test_benign_file_event_ignored(self):
        findings = detect([self.event(event_type="file")])
        self.assertEqual(findings, [])

    def test_unsigned_increases_score(self):
        trusted = detect([self.event(event_id="a")])[0].score
        unsigned = detect([self.event(event_id="b", signer_status="unsigned")])[0].score
        self.assertGreater(unsigned, trusted)

    def test_script_parent_increases_score(self):
        base = detect([self.event(event_id="a")])[0].score
        scripted = detect([self.event(event_id="b", parent_process="powershell.exe")])[0].score
        self.assertGreater(scripted, base)

    def test_finding_id_is_deterministic(self):
        first = detect([self.event()])[0].finding_id
        second = detect([self.event()])[0].finding_id
        self.assertEqual(first, second)

    def test_score_is_bounded(self):
        finding = detect([self.event(signer_status="unsigned", parent_process="powershell.exe")])[0]
        self.assertLessEqual(finding.score, 100)

    def test_metrics(self):
        findings = detect([self.event(event_id="a", host="H1"), self.event(event_id="b", host="H2", event_type="service")])
        result = metrics(findings)
        self.assertEqual(result["total_findings"], 2)
        self.assertEqual(result["affected_hosts"], 2)

    def test_report_contains_investigation_caveat(self):
        report = markdown_report(detect([self.event()]))
        self.assertIn("not proof of compromise", report)


if __name__ == "__main__":
    unittest.main()
