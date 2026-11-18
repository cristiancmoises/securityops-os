# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=763d40a46a39596494f9aef3c85efe16 owner="Cristian Cezar Mois\u00e9s"
"""Execute runtime-policy expressions, without claiming complete OS evaluation."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_desktop_choices import generate


ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "tests/hardening-check.scm"


class HardeningTests(unittest.TestCase):
    def run_tool(self, tool, args, *, cwd=ROOT, env=None):
        executable = shutil.which(tool)
        self.assertIsNotNone(executable, f"{tool} is required, not a passing skip")
        result = subprocess.run([executable, *args], cwd=cwd, env=env,
                                timeout=90, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_live_and_each_supported_installer_policy(self):
        with tempfile.TemporaryDirectory(prefix="securityops-hardening-") as temp:
            outputs = []
            for desktop in ("sway", "xmonad-xlibre", "kde"):
                output = Path(temp) / f"{desktop}.scm"
                generated = generate(output, desktop)
                self.assertEqual(generated.returncode, 0, generated.stderr)
                outputs.append(str(output))
            result = self.run_tool("guix", ["repl", "-q", "-L", str(ROOT), "--",
                                   str(CHECK), str(ROOT / "config.scm"), *outputs])
            self.assertIn("policy expressions verified: live + 3 generated", result)

    def test_actual_module_survives_store_source_selection_without_checkout_fallback(self):
        with tempfile.TemporaryDirectory(prefix="securityops-hardening-store-") as temp:
            folder = Path(temp)
            source = folder / "source"
            (source / "securityops").mkdir(parents=True)
            for name in ("hardening.scm", "source-selection.scm"):
                shutil.copyfile(ROOT / "securityops" / name, source / "securityops" / name)
            shutil.copyfile(ROOT / "config.scm", source / "config.scm")
            shutil.copyfile(CHECK, source / "check.scm")
            generated = generate(source / "installed.scm", "xmonad-xlibre")
            self.assertEqual(generated.returncode, 0, generated.stderr)
            script = folder / "lower.scm"
            script.write_text("""
              (use-modules (guix gexp) (guix store) (securityops source-selection))
              (with-store store
                (display (run-with-store store (lower-object
                  (local-file (cadr (command-line)) "securityops-hardening-fixture"
                              #:recursive? #t #:select? securityops-source-file?))))
                (newline))
            """)
            output = Path(self.run_tool("guix", ["repl", "-q", "-L", str(ROOT),
                                                "--", str(script), str(source)]).strip())
            self.assertEqual(output.parent, Path("/gnu/store"))
            self.assertEqual((output / "securityops/hardening.scm").read_bytes(),
                             (ROOT / "securityops/hardening.scm").read_bytes())
            environment = {key: value for key, value in os.environ.items()
                           if key not in ("GUILE_LOAD_PATH", "GUILE_LOAD_COMPILED_PATH")}
            home = folder / "home"
            home.mkdir(mode=0o700)
            environment.update(HOME=str(home), GUILE_AUTO_COMPILE="0")
            probe = """
              (use-modules (securityops hardening))
              (unless (string-prefix? (cadr (command-line))
                        (search-path %load-path "securityops/hardening.scm"))
                (error "module escaped selected source"))
            """
            self.run_tool("guile", ["--no-auto-compile", "-L", str(output), "-c", probe,
                                    str(output)], cwd=home, env=environment)
            result = self.run_tool("guix", ["repl", "-q", "-L", str(output), "--",
                                   str(output / "check.scm"), str(output / "config.scm"),
                                   str(output / "installed.scm")], cwd=home, env=environment)
            self.assertIn("policy expressions verified: live + 1 generated", result)
            print(json.dumps({"hardening_source_fixture": str(output)}))


if __name__ == "__main__":
    unittest.main()
