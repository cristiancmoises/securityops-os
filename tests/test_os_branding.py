# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=a1facb6d1e065106af7f076ce22e7168 owner="Cristian Cezar Mois\u00e9s"
"""Distribution-identity regression tests for Security Ops OS."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_UNAME_OS = "Security Ops OS"


class BrandingSchemeTestCase(unittest.TestCase):
    def run_guile(self, expression: str) -> subprocess.CompletedProcess[str]:
        guile = shutil.which("guile")
        if guile is None:
            self.skipTest("guile is unavailable")
        return subprocess.run(
            [guile, "--no-auto-compile", "-L", str(ROOT), "-c", expression],
            cwd=ROOT,
            check=False,
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_identity_strings_are_canonical_and_keep_foundation_visible(self) -> None:
        completed = self.run_guile(
            "(use-modules (securityops branding)) "
            "(display %securityops-uname-operating-system) (newline) "
            "(display %securityops-os-release-text)"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        lines = completed.stdout.splitlines()
        self.assertEqual(lines[0], EXPECTED_UNAME_OS)
        fields = dict(line.split("=", 1) for line in lines[1:])
        self.assertEqual(fields["NAME"], '"Security Ops OS"')
        self.assertEqual(fields["ID"], "securityops")
        self.assertEqual(fields["ID_LIKE"], "guix")
        self.assertEqual(fields["SECURITYOPS_SYSTEM_MANAGER"], '"GNU Guix"')
        self.assertEqual(fields["SECURITYOPS_KERNEL"], '"Linux"')
        self.assertEqual(len(fields), len(lines) - 1, "duplicate os-release key")

    def test_essential_service_replaces_exactly_the_os_release_entry(self) -> None:
        completed = self.run_guile(
            "(use-modules (gnu) (gnu services) (gnu services base) "
            "(srfi srfi-1) (securityops branding)) "
            "(define os (operating-system "
            "(host-name \"branding-test\") (timezone \"Etc/UTC\") "
            "(locale \"en_US.utf8\") "
            "(bootloader (bootloader-configuration "
            "(bootloader grub-bootloader) (targets (list \"/dev/vda\")))) "
            "(file-systems (cons (file-system (mount-point \"/\") "
            "(device \"/dev/vda1\") (type \"ext4\")) %base-file-systems)))) "
            "(define services "
            "(securityops-operating-system-essential-services os)) "
            "(define etc-service (find (lambda (item) "
            "(eq? (service-kind item) etc-service-type)) services)) "
            "(define release-entry (assoc \"os-release\" "
            "(service-value etc-service))) "
            "(unless (eq? (cadr release-entry) %securityops-os-release) "
            "(error \"unbranded os-release\")) "
            "(display \"ok\")"
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "ok")

    def test_live_configuration_uses_source_built_identity_components(self) -> None:
        configuration = (ROOT / "config.scm").read_text(encoding="utf-8")
        self.assertIn("(securityops branding)", configuration)
        self.assertIn("(list securityops-coreutils)", configuration)
        self.assertIn("(issue %securityops-issue)", configuration)
        self.assertIn(
            "(securityops-operating-system-essential-services "
            "this-operating-system)",
            configuration,
        )
        # Shell aliases and ambient environment overrides would be bypassable.
        self.assertNotIn("alias uname=", configuration)
        self.assertNotIn("UNAME_SYSNAME", configuration)

    def test_installer_configuration_has_branding_parity(self) -> None:
        generator = (ROOT / "securityops/installer/gen-config.sh").read_text(
            encoding="utf-8"
        )
        self.assertIn("(securityops branding)", generator)
        self.assertIn("(list securityops-coreutils)", generator)
        self.assertIn("(issue %securityops-issue)", generator)
        self.assertIn(
            "(securityops-operating-system-essential-services "
            "this-operating-system)",
            generator,
        )


if __name__ == "__main__":
    unittest.main()
