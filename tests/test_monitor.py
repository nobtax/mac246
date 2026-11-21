
import tempfile
import unittest
from pathlib import Path

from log_monitor.monitor import analyze_logs, THRESHOLD


class TestSSHLogMonitor(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def write_logs(self, content):
        self.log_file.write_text(
            content, encoding="utf-8"
        )

    def test_suspicious_login_attempts(self):
        logs = "\n".join(
            f"Failed password for root from "
            f"192.0.2.10 port 5000{i} ssh2"
            for i in range(5)
        )
        self.write_logs(logs)

        results = analyze_logs(self.log_file)

        self.assertEqual(results["192.0.2.10"], 5)
        self.assertGreaterEqual(
            results["192.0.2.10"], THRESHOLD
        )

    def test_normal_login_activity(self):
        self.write_logs(
            "Failed password for user from "
            "198.51.100.20 port 50001 ssh2"
        )

        results = analyze_logs(self.log_file)

        self.assertEqual(results["198.51.100.20"], 1)
        self.assertLess(
            results["198.51.100.20"], THRESHOLD
        )

    def test_no_failed_logins(self):
        self.write_logs(
            "Accepted password for user from "
            "192.0.2.30 port 50001 ssh2"
        )

        results = analyze_logs(self.log_file)

        self.assertEqual(len(results), 0)

    def test_multiple_ip_addresses(self):
        self.write_logs(
            "Failed password for root from "
            "192.0.2.10 port 50001 ssh2\n"
            "Failed password for user from "
            "198.51.100.20 port 50002 ssh2"
        )

        results = analyze_logs(self.log_file)

        self.assertEqual(len(results), 2)
        self.assertEqual(results["192.0.2.10"], 1)
        self.assertEqual(results["198.51.100.20"], 1)

    def test_missing_log_file(self):
        with self.assertRaises(FileNotFoundError):
            analyze_logs(
                Path(self.temp_dir.name) / "missing.log"
            )


if __name__ == "__main__":
    unittest.main()
