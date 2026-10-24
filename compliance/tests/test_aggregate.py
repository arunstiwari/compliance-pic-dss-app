"""Regression tests for the compliance gate.

Fixtures hold real Gitleaks/Semgrep/Checkov output for the vulnerable baseline and
the fixed overlay, plus representative Trivy, ZAP, SBOM and PR-review reports.

Run: python -m unittest discover -s compliance/tests
"""
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import aggregate  # noqa: E402

FIX = HERE / "fixtures"


def run(state, *extra):
    with tempfile.TemporaryDirectory() as out:
        code = aggregate.main(["--reports-dir", str(FIX / state), "--out-dir", out, *extra])
        results = json.loads((Path(out) / "compliance-results.json").read_text())
        md = (Path(out) / "compliance-matrix.md").read_text()
    return code, results, md


class GateTests(unittest.TestCase):
    def test_vulnerable_baseline_fails_expected_controls(self):
        code, res, _ = run("vulnerable")
        self.assertEqual(code, 1)
        failed = set(res["blocking_failures"])
        for ctrl in ["pci-dss:6.2.4", "pci-dss:6.3.3", "pci-dss:8.6.2", "pci-dss:3.5.1",
                     "pci-dss:4.2.1", "pci-dss:10.2.1", "pci-dss:2.2.6", "pci-dss:1.3.1",
                     "iso27001:A.5.17", "iso27001:A.8.8", "iso27001:A.8.28", "iso27001:A.8.24"]:
            self.assertIn(ctrl, failed)

    def test_fixed_overlay_passes_strict_gate(self):
        code, res, md = run("fixed", "--strict")
        self.assertEqual(code, 0, res["blocking_failures"])
        self.assertIn("accepted exception", md)  # the justified Checkov skip is surfaced

    def test_secret_values_never_rendered(self):
        _, _, md = run("vulnerable")
        self.assertNotIn("pgk_live_", md)

    def test_missing_reports_fail_only_in_strict_mode(self):
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(aggregate.main(["--reports-dir", empty]), 1)  # A.8.25 pipeline-complete
            self.assertEqual(aggregate.main(["--reports-dir", empty, "--strict"]), 1)


if __name__ == "__main__":
    unittest.main()
