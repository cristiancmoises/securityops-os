# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=f1811e0abbca5bf48bad32791634cf0a owner="Cristian Cezar Mois\u00e9s"
"""Effective live/installed package selection, not application or ISO execution."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from test_desktop_choices import generate


ROOT = Path(__file__).resolve().parents[1]


class LivePackagesTests(unittest.TestCase):
    def run_packages(self, configuration):
        guix = shutil.which("guix")
        self.assertIsNotNone(guix, "Guix is required, not a passing capability skip")
        environment = os.environ.copy()
        environment["GUIX_DAEMON_SOCKET"] = "/nonexistent/securityops-test-no-daemon"
        return subprocess.run(
            [guix, "repl", "-q", "-L", str(ROOT), "--",
             str(ROOT / "tests/live-packages-check.scm"), str(ROOT), str(configuration)],
            cwd=ROOT, env=environment, capture_output=True, text=True, timeout=90,
        )

    def check_packages(self, configuration):
        result = self.run_packages(configuration)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("PACKAGE_SELECTION_OK", result.stdout)
        self.assertIn("SELECTED guixvis 0.8.0\n", result.stdout)
        self.assertEqual(result.stdout.count("SELECTED "), 7)

    def test_live_os_contains_reviewed_package_objects_once(self):
        self.check_packages(ROOT / "config.scm")

    def test_generated_systems_retain_reviewed_packages(self):
        with tempfile.TemporaryDirectory(prefix="securityops-app-selection-") as temporary:
            for desktop in ("sway", "xmonad-xlibre", "kde"):
                with self.subTest(desktop=desktop):
                    configuration = Path(temporary) / (desktop + ".scm")
                    generated = generate(configuration, desktop)
                    self.assertEqual(generated.returncode, 0, generated.stderr)
                    self.check_packages(configuration)

    def test_same_version_alternate_tor_provider_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="securityops-wrong-tor-") as temporary:
            configuration = Path(temporary) / "wrong-provider.scm"
            configuration.write_text('''
(use-modules (gnu system) (guix packages) (srfi srfi-1)
             (securityops packages tor))
(let* ((original (load (string-append (cadr (command-line)) "/config.scm")))
       (alternate (package (inherit torbrowser) (synopsis "Test alternate provider")))
       (items (operating-system-packages original))
       (item-package (lambda (item) (if (pair? item) (car item) item)))
       (tor? (lambda (item)
               (string=? (package-name (item-package item)) "torbrowser")))
       (matches (filter tor? items)))
  (unless (and (= 1 (length matches))
               (eq? (item-package (car matches)) torbrowser)
               (not (eq? alternate torbrowser))
               (string=? (package-name alternate) (package-name torbrowser))
               (string=? (package-version alternate) (package-version torbrowser)))
    (error "wrong-provider fixture preconditions failed"))
  (operating-system
    (inherit original)
    (packages
     (map (lambda (item)
            (if (tor? item)
                (if (pair? item)
                    (cons alternate (cdr item))
                    alternate)
                item)) items))))
''', encoding="utf-8")
            result = self.run_packages(configuration)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(
                'reviewed package missing, shadowed or duplicated "torbrowser"',
                result.stderr,
            )
            self.assertEqual(result.stdout.count("SELECTED "), 5)
            self.assertNotIn("PACKAGE_SELECTION_OK", result.stdout)

    def test_same_version_alternate_guixvis_provider_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="securityops-wrong-guixvis-") as temporary:
            configuration = Path(temporary) / "wrong-provider.scm"
            configuration.write_text('''
(use-modules (gnu system) (guix packages) (srfi srfi-1)
             (securityops packages guixvis))
(let* ((original (load (string-append (cadr (command-line)) "/config.scm")))
       (alternate (package (inherit guixvis) (synopsis "Test alternate provider")))
       (item-package (lambda (item) (if (pair? item) (car item) item)))
       (guixvis? (lambda (item)
                   (string=? (package-name (item-package item)) "guixvis")))
       (items (operating-system-packages original))
       (matches (filter guixvis? items)))
  (unless (and (= 1 (length matches))
               (eq? (item-package (car matches)) guixvis)
               (not (eq? alternate guixvis))
               (string=? (package-version alternate) (package-version guixvis)))
    (error "wrong-provider fixture preconditions failed"))
  (operating-system
    (inherit original)
    (packages
     (map (lambda (item)
            (if (guixvis? item)
                (if (pair? item) (cons alternate (cdr item)) alternate)
                item)) items))))
''', encoding="utf-8")
            result = self.run_packages(configuration)
            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn(
                'reviewed package missing, shadowed or duplicated "guixvis"',
                result.stderr,
            )
            self.assertEqual(result.stdout.count("SELECTED "), 6)
            self.assertNotIn("PACKAGE_SELECTION_OK", result.stdout)
