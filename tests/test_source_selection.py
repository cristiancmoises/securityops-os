# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=73bed64ebd345b6babecfb9302560d9a owner="Cristian Cezar Mois\u00e9s"
"""Test the production selector; only harmless synthetic files enter the Store."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = (
    "out", ".git", ".claude", ".aider", ".aider.conf.yml", ".codex",
    ".codex-config", "continue", "__pycache__", "module.pyc", "module.pyo",
    "GET_THE_ISO.md", ".env", ".env.local", "id_example", "example.key",
    "example.pem", "example.token", "example_token", "example.iso", ".dsh",
    ".agents", "AGENTS.md", "CODEX_TASK.md", "build", "evidence", "qemu.log",
    ".ai-memory", ".agent-private", ".prompts", ".second-brain",
    "AGENTS.local.md", "CLAUDE.md", "CLAUDE.local.md",
    "MAINTAINER_PROMPT.md", "TASK_PROMPT.md", "NEXT_PROMPT.md",
    "securityops-os-phase28-handoff-v3", "securityops-os-phase46-codex-guix-kit-v1",
    "securityops-os-phase46-codex-guix-kit-v1.tar.gz",
)
ALLOWED = (
    "config.scm", "channels.guix", "securityopsctl", "build.sh", "make-iso.sh",
    "README.md", "evidence-policy.md", "builder.scm", "qemu.scm", "AGENTS.txt",
    "securityops-os-phase46-notes.md", "environment.scm",
    "substitutes.securityops.com.br.pub", "ci.guix.gnu.org.pub",
)


class SourceSelectionTests(unittest.TestCase):
    def tool(self, name):
        path = shutil.which(name)
        self.assertIsNotNone(path, f"{name} is required; missing capability is not PASS")
        return path

    def test_basename_policy_keeps_all_old_masks_and_positive_controls(self):
        names = EXCLUDED + ALLOWED
        expression = """
          (use-modules (securityops source-selection))
          (for-each (lambda (path)
                      (display (if (securityops-source-file? path #f) "1" "0")))
                    (cdr (command-line)))
        """
        for prefix in ("/fixture/", "/fixture/securityops/nested/"):
            with self.subTest(prefix=prefix):
                result = subprocess.run(
                    [self.tool("guile"), "--no-auto-compile", "-L", str(ROOT),
                     "-c", expression, *(prefix + name for name in names)],
                    check=False, timeout=30, capture_output=True, text=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, "0" * len(EXCLUDED) + "1" * len(ALLOWED))

    def test_config_keeps_its_source_anchor_and_uses_shared_policy(self):
        # Read Scheme data, not the blocked OS graph, and compare the actual
        # local-file form.  Full OS evaluation remains a separate required gate.
        expression = """
          (use-modules (ice-9 match) (guix gexp))
          (call-with-input-file (cadr (command-line))
            (lambda (port)
              (let loop ((form (read port)))
                (match form
                  (('define '%config-src value)
                   (unless (equal? value
                             '(local-file "." "securityops-src" #:recursive? #t
                                          #:select? securityops-source-file?))
                     (error "embedded source wiring changed")))
                  ((? eof-object?) (error "embedded source definition missing"))
                  (_ (loop (read port)))))))
        """
        with tempfile.TemporaryDirectory(prefix="securityops-source-wiring-") as temp:
            script = Path(temp) / "check.scm"
            script.write_text(expression, encoding="utf-8")
            result = subprocess.run(
                [self.tool("guix"), "repl", "-q", "--", str(script), str(ROOT / "config.scm")],
                check=False, timeout=60, capture_output=True, text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(securityops source-selection)", (ROOT / "config.scm").read_text())

    def test_real_local_file_lowering_prunes_directories_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory(prefix="securityops-source-fixture-") as temp:
            fixture = Path(temp) / "source"
            fixture.mkdir()
            expected = set(ALLOWED) | {
                "securityops/settings.json", "securityops/source-selection.scm",
                "securityops/installer/security-ops-install", "assets/sec.png",
                "docs/README.md", "external-link",
            }
            for name in expected - {"external-link"}:
                path = fixture / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"synthetic public input: {name}\n", encoding="utf-8")
            for index, name in enumerate(EXCLUDED):
                # Exercise both rejected regular files and directory pruning.
                (fixture / name).write_text(f"excluded public marker {index}\n")
                nested = fixture / "nested" / name
                nested.mkdir(parents=True)
                (nested / "child.txt").write_text("excluded synthetic descendant\n")
            outside = Path(temp) / "outside.txt"
            outside.write_text("synthetic outside-link target; never secret\n")
            (fixture / "external-link").symlink_to(outside)
            script = Path(temp) / "lower.scm"
            script.write_text("""
              (use-modules (guix gexp) (guix store) (securityops source-selection))
              (with-store store
                (display (run-with-store store
                  (lower-object
                    (local-file (cadr (command-line)) "securityops-source-fixture"
                                #:recursive? #t #:select? securityops-source-file?))))
                (newline))
            """, encoding="utf-8")
            result = subprocess.run(
                [self.tool("guix"), "repl", "-L", str(ROOT), "-q", "--",
                 str(script), str(fixture)],
                check=False, timeout=60, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            output = Path(result.stdout.strip())
            self.assertEqual(output.parent, Path("/gnu/store"), result.stdout)
            self.assertTrue(output.is_dir())
            actual = set()
            actual_dirs = set()
            for directory, dirs, files in os.walk(output, followlinks=False):
                for name in files:
                    actual.add((Path(directory) / name).relative_to(output).as_posix())
                for name in dirs:
                    actual_dirs.add((Path(directory) / name).relative_to(output).as_posix())
            self.assertEqual(actual, expected)
            self.assertEqual(actual_dirs, {"securityops", "securityops/installer",
                                           "assets", "docs", "nested"})
            for name in expected - {"external-link"}:
                self.assertEqual((output / name).read_bytes(), (fixture / name).read_bytes())
            self.assertTrue((output / "external-link").is_symlink())
            self.assertEqual(os.readlink(output / "external-link"), str(outside))
            # This proves serialization kept the link, not that later consumers
            # cannot dereference it.  No content/secret scan claim follows.
            print(json.dumps({"store_fixture": str(output),
                              "files": sorted(actual), "directories": sorted(actual_dirs)},
                             sort_keys=True))


if __name__ == "__main__":
    unittest.main()
