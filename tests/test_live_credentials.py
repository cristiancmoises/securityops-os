# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=02fd8e7e7e7b57659b07b4e763ab70b4 owner="Cristian Cezar Mois\u00e9s"
"""Fail-closed checks for the volatile Security Ops OS live credential."""

from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "securityops/services/live-credentials.scm"
CONFIG = ROOT / "config.scm"
SESSIONS = ROOT / "securityops/sessions.scm"
LEGACY_SLIM_THEME = ROOT / "theme/slim/securityops/slim.theme"


class LiveCredentialTests(unittest.TestCase):
    def test_module_never_embeds_a_reusable_password(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn('open-file "/dev/urandom" "rb"', source)
        self.assertIn("Rejection sampling avoids modulo bias", source)
        self.assertIn("open-pipe* OPEN_WRITE", source)
        self.assertIn("display password pipe", source)
        self.assertNotIn("securityops:securityops", source)
        self.assertNotIn("securityopslive", source)
        self.assertNotIn("setenv", source)
        self.assertNotIn("(use-modules (guix build utils)", source)

    def test_greeter_dependency_waits_for_provisioning_completion(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn("(let ((status (system* #$provisioner)))", source)
        self.assertIn("(and (zero? status) #t)", source)
        self.assertNotIn("make-forkexec-constructor", source)

    def test_credential_is_volatile_and_not_a_store_input(self) -> None:
        source = MODULE.read_text(encoding="utf-8")
        self.assertIn('"/run/securityops/live-console-credential"', source)
        self.assertNotIn("local-file", source)
        self.assertNotIn("plain-file", source)
        self.assertIn("#o400", source)
        self.assertIn('terminal "/dev/tty1"', source)
        self.assertNotIn('terminal "/dev/console"', source)
        self.assertIn("(chown credential-file 0 0)", source)

    def test_module_compiles_without_unbound_variables(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-live-credential-") as root:
            result = subprocess.run(
                [
                    "guild",
                    "compile",
                    "-L",
                    str(ROOT),
                    "-Wunbound-variable",
                    "-o",
                    str(Path(root) / "live-credentials.go"),
                    str(MODULE),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_live_config_has_no_static_password_or_global_nopasswd(self) -> None:
        config = CONFIG.read_text(encoding="utf-8")
        sessions = SESSIONS.read_text(encoding="utf-8")
        self.assertNotIn("securityopslive", config)
        self.assertNotIn("NOPASSWD: ALL", config)
        self.assertNotIn("pass: securityops", config)
        self.assertNotIn("pass: securityops", sessions)
        self.assertIn("securityops-live-credential", config)
        self.assertIn("trusted VT1", sessions)

    def test_root_is_explicitly_locked_and_empty_logins_are_disabled(self) -> None:
        config = CONFIG.read_text(encoding="utf-8")
        self.assertIn("(define %locked-root-account", config)
        self.assertIn('(name "root")', config)
        self.assertIn('(password "!")', config)
        self.assertIn("(uid 0)", config)
        self.assertIn("(users (cons* %locked-root-account", config)
        self.assertIn("(login-service-type config =>", config)
        self.assertIn("(allow-empty-passwords? #f)", config)

    def test_vt1_is_reserved_for_the_trusted_credential_display(self) -> None:
        config = CONFIG.read_text(encoding="utf-8")
        self.assertIn("(delete mingetty-service-type)", config)
        self.assertNotIn('(mingetty-configuration (tty "tty1"))', config)
        self.assertIn('(not (string=? "tty1" (car tty+font)))', config)
        for terminal in range(2, 7):
            self.assertIn(f'(mingetty-configuration (tty "tty{terminal}"))', config)

    def test_legacy_theme_cannot_advertise_a_reusable_password(self) -> None:
        theme = LEGACY_SLIM_THEME.read_text(encoding="utf-8")
        self.assertIn("historical SLiM login theme", theme)
        self.assertIn("one-boot password: trusted VT1", theme)
        self.assertNotIn("password: securityops", theme)
        self.assertNotIn('Password is\n# "securityops"', theme)


if __name__ == "__main__":
    unittest.main()
