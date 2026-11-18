# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=5c3890b91b80513ea25ea115bcf06736 owner="Cristian Cezar Mois\u00e9s"
"""Consistency checks for first-party and aggregate-image license boundaries."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LicensingDocumentationTests(unittest.TestCase):
    def test_audited_project_matrix_is_synchronized(self) -> None:
        english = (ROOT / "docs/LICENSING.md").read_text(encoding="utf-8")
        portuguese = (ROOT / "docs/LICENSING.pt-BR.md").read_text(encoding="utf-8")
        for project in (
            "Evelin",
            "Esquema",
            "VaptVupt",
            "VaptVupt Codec",
            "libvuptsdk",
            "Mirim",
            "Cofre Soberano PQ",
            "BTP",
        ):
            self.assertIn(f"| {project} |", english)
            self.assertIn(f"| {project} |", portuguese)

    def test_public_notice_is_not_a_commercial_grant(self) -> None:
        english = (ROOT / "docs/LICENSING.md").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
        self.assertIn("it is not a public commercial grant", english)
        self.assertIn("grants no private\ncommercial terms", notice)
        self.assertIn("BTP remains Apache-2.0/CC-BY-4.0", notice)

    def test_esquema_keeps_canonical_gpl_later_scope(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        english = (ROOT / "docs/LICENSING.md").read_text(encoding="utf-8")
        portuguese = (ROOT / "docs/LICENSING.pt-BR.md").read_text(encoding="utf-8")
        notice = (ROOT / "NOTICE").read_text(encoding="utf-8")

        self.assertIn(
            "| Esquema | GPL-3.0-or-later | None declared by the canonical source",
            english,
        )
        self.assertIn(
            "| Esquema | GPL-3.0-or-later | Nenhuma declarada pela fonte canônica",
            portuguese,
        )
        self.assertIn("Esquema remains\nGPL-3.0-or-later", readme)
        self.assertIn(
            "canonical Esquema source observed in Phase 30 is\nGPL-3.0-or-later",
            notice,
        )
        self.assertNotIn("| Esquema | AGPL-3.0-or-later", english)
        self.assertNotIn("| Esquema | AGPL-3.0-or-later", portuguese)

    def test_readme_banner_scopes_dual_license_to_first_party_code(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("first-party OS code: AGPL-3.0-or-later", readme)
        self.assertIn(
            "Every dependency and packaged program retains its own license", readme
        )


if __name__ == "__main__":
    unittest.main()
