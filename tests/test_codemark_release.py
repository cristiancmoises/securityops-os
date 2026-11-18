# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=cec1cebc80a2526dad16579076976e6a owner="Cristian Cezar Mois\u00e9s"
"""Verify the release source integrity gate."""

from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CODEMARK = ROOT / "tools" / "codemark.pyz"
CODEMARK_SHA256 = "d6c9dd09db850a704ff0a33a7a3c75f287d014281ccc4f63a4b9249e873da163"


class CodeMarkReleaseTest(unittest.TestCase):
    def test_reviewed_source_verifies_with_pinned_tool(self) -> None:
        self.assertEqual(hashlib.sha256(CODEMARK.read_bytes()).hexdigest(), CODEMARK_SHA256)
        result = subprocess.run(
            [sys.executable, str(CODEMARK), "verify", str(ROOT), "--json"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_bundle_stops_before_build_if_marked_source_changes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-codemark-test-") as temporary:
            tree = Path(temporary) / "source"
            shutil.copytree(
                ROOT,
                tree,
                ignore=shutil.ignore_patterns(".git", "out", "__pycache__"),
            )
            with (tree / "build.sh").open("a", encoding="utf-8") as source:
                source.write("\n# unexpected change\n")

            fake_bin = Path(temporary) / "bin"
            fake_bin.mkdir()
            for name in ("guix", "guile"):
                executable = fake_bin / name
                executable.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
                executable.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = str(fake_bin) + os.pathsep + environment["PATH"]
            result = subprocess.run(
                ["bash", "make-iso.sh", "--bundle"],
                cwd=tree,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
                timeout=30,
            )
            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn("Verifying CodeMark source manifest", result.stdout)
            self.assertIn('"ok": false', result.stdout)
            self.assertIn('"build.sh"', result.stdout)
            self.assertNotIn("Reproducible build:", result.stdout)


if __name__ == "__main__":
    unittest.main()
