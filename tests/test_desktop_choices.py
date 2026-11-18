# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=6316292c94a05ad9852236a2d293281f owner="Cristian Cezar Mois\u00e9s"
"""Phase 29 desktop-choice and XLibre fail-closed regressions."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SESSIONS = ROOT / "securityops/sessions.scm"
CONFIG = ROOT / "config.scm"
CHANNELS = ROOT / "channels.guix"
INSTALLER = ROOT / "securityops/installer/security-ops-install"
GENERATOR = ROOT / "securityops/installer/gen-config.sh"


def generate(output: Path, desktop: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "bash",
            str(GENERATOR),
            "--out",
            str(output),
            "--host",
            "desktop-test",
            "--user",
            "tester",
            "--fullname",
            "Desktop Test",
            "--locale",
            "en_US.UTF-8",
            "--tz",
            "UTC",
            "--keymap",
            "us",
            "--xkbvariant",
            "",
            "--desktop",
            desktop,
            "--fs",
            "ext4",
            "--encrypt",
            "no",
            "--root-uuid",
            "11111111-1111-1111-1111-111111111111",
            "--efi-uuid",
            "2222-3333",
            "--luks-uuid",
            "",
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )


class DesktopChoiceTests(unittest.TestCase):
    def test_live_greeter_exposes_exact_immutable_session_choices(self) -> None:
        sessions = SESSIONS.read_text(encoding="utf-8")
        self.assertIn('"--sessions" #$%sessions-dir', sessions)
        self.assertIn('"--cmd" #$%sway-launch', sessions)
        self.assertNotIn("--remember-session", sessions)
        for entry in (
            "10-sway.desktop",
            "20-xmonad-xlibre.desktop",
            "30-kde-wayland.desktop",
        ):
            self.assertEqual(sessions.count(entry), 1)
        self.assertIn("Security Ops XMonad + XLibre (X11)", sessions)
        self.assertIn("Security Ops KDE Plasma (Wayland)", sessions)
        self.assertIn("trusted VT1", sessions)
        self.assertNotIn("pass: securityops", sessions)

    def test_xmonad_session_uses_xlibre_and_kde_uses_wayland(self) -> None:
        sessions = SESSIONS.read_text(encoding="utf-8")
        self.assertIn("#:use-module (xlibre)", sessions)
        self.assertIn("(xorg-wrapper", sessions)
        self.assertIn("(xlibre-configuration", sessions)
        self.assertIn('xlibre-server xmonad', CONFIG.read_text(encoding="utf-8"))
        self.assertIn('plasma-workspace "/bin/startplasma-wayland"', sessions)
        self.assertIn("XDG_SESSION_TYPE=wayland", sessions)
        self.assertIn("XDG_SESSION_TYPE=x11", sessions)
        self.assertNotIn("/tmp/sway.log", sessions)
        self.assertIn("$XDG_STATE_HOME/securityops/sessions", sessions)

    def test_xlibre_is_pinned_through_the_securityops_channel(self) -> None:
        channels = CHANNELS.read_text(encoding="utf-8")
        self.assertNotIn("(name 'guix-xlibre)", channels)
        self.assertIn(
            '(name \'securityops)',
            channels,
        )
        self.assertIn(
            '(commit "017b9e3aa09bbafca341dfba7c91ca96211e8020")',
            channels,
        )
        securityops_entry = channels.split("(name 'securityops)", 1)[1].split(
            ";; gocix", 1
        )[0]
        self.assertIn("make-channel-introduction", securityops_entry)
        self.assertIn("(xlibre)", CONFIG.read_text(encoding="utf-8"))

    def test_installer_offers_no_stale_or_masqueraded_xorg_choice(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        menu = installer.split('DESKTOP=$(menu "Desktop / window manager:"', 1)[1].split(
            ") || exit 1", 1
        )[0]
        self.assertIn('"sway"', menu)
        self.assertIn('"xmonad-xlibre"', menu)
        self.assertIn('"kde"', menu)
        self.assertNotIn('"i3"', menu)
        self.assertIn("pinned XLibre server", menu)
        self.assertIn("XMonad/KDE users must log out and select Sway", installer)

    def test_generator_rejects_every_unknown_desktop_before_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-desktop-invalid-") as root:
            for choice in ("i3", "xmonad", "xorg", "", "kde;display"):
                output = Path(root) / (choice.replace("/", "_") or "empty")
                result = generate(output, choice)
                self.assertEqual(result.returncode, 2, (choice, result.stderr))
                self.assertIn("unsupported desktop choice", result.stderr)
                self.assertFalse(output.exists())

    def test_generated_choice_matrix_is_parseable_and_choice_bound(self) -> None:
        guile = shutil.which("guile")
        if guile is None:
            self.skipTest("Guile is unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-desktop-matrix-") as root:
            generated_sources: dict[str, str] = {}
            for desktop in ("sway", "xmonad-xlibre", "kde"):
                output = Path(root) / f"{desktop}.scm"
                result = generate(output, desktop)
                self.assertEqual(result.returncode, 0, result.stderr)
                parse = subprocess.run(
                    [
                        guile,
                        "-c",
                        "(call-with-input-file (cadr (command-line)) "
                        "(lambda (p) (let loop () (let ((x (read p))) "
                        "(unless (eof-object? x) (loop))))))",
                        str(output),
                    ],
                    cwd=ROOT,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(parse.returncode, 0, parse.stderr)
                source = output.read_text(encoding="utf-8")
                generated_sources[desktop] = source
                self.assertIn(f'(define %selected-desktop "{desktop}")', source)
                self.assertIn('extra-special-file "/etc/securityops/desktop"', source)
                self.assertNotIn("@@", source)

            self.assertIn("(xlibre-configuration", generated_sources["xmonad-xlibre"])
            self.assertIn("(xlibre)", generated_sources["xmonad-xlibre"])
            self.assertIn("xlibre-video-amdgpu", generated_sources["xmonad-xlibre"])
            self.assertNotIn("(xlibre-configuration", generated_sources["sway"])
            self.assertNotIn("(xlibre-configuration", generated_sources["kde"])
            self.assertNotIn("(xlibre)", generated_sources["sway"])
            self.assertNotIn("(xlibre)", generated_sources["kde"])
            self.assertIn("plasma-workspace", generated_sources["kde"])
            self.assertIn("swayidle", generated_sources["sway"])

    def test_security_and_localized_docs_disclose_desktop_tradeoffs(self) -> None:
        english = (ROOT / "docs/DESKTOPS.md").read_text(encoding="utf-8")
        portuguese = (ROOT / "docs/DESKTOPS.pt-BR.md").read_text(encoding="utf-8")
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        self.assertIn("same-display", english)
        self.assertIn("published channel", english)
        self.assertIn("clientes no mesmo display", portuguese)
        self.assertIn("introdução publicada", portuguese)
        self.assertIn("X11 observation/injection", security)


if __name__ == "__main__":
    unittest.main()
