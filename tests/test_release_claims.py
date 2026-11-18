# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=1960ac2705b655ddab1c961e835884cd owner="Cristian Cezar Mois\u00e9s"
"""Truthfulness checks for release and reproducibility documentation."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseClaimDocumentationTests(unittest.TestCase):
    def test_readme_does_not_treat_pinning_as_reproducibility_proof(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("fully reproducible", readme.lower())
        self.assertNotIn("release-ready split parts", readme.lower())
        self.assertNotIn("*Reproducible. Hardened.", readme)
        self.assertIn("two independent clean full ISO builds", readme)
        self.assertIn("Reproducibility for this candidate is\n**BLOCKED**", readme)

    def test_bundle_is_described_as_transport_not_release_qualification(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("checksum-addressed split transport parts", readme)
        self.assertIn("packaging evidence, not\nrelease readiness", readme)


if __name__ == "__main__":
    unittest.main()
