# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=5c7da734b25952779157670dec425b89 owner="Cristian Cezar Mois\u00e9s"
"""Installer credential, private-state, and locked-account regressions."""

from pathlib import Path
import fcntl
import json
import os
import re
import selectors
import signal
import shutil
import subprocess
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "securityops/installer/gen-config.sh"
INSTALLER = ROOT / "securityops/installer/security-ops-install"
PRIVATE_STATE = ROOT / "securityops/installer/private-state.sh"
COW_HELPER = ROOT / "securityops/installer/cow-system-init.scm"
BOOTLOADER = ROOT / "securityops/bootloader.scm"
PROFILE = Path("/run/current-system/profile")
BASH = shutil.which("bash") or str(PROFILE / "bin/bash")


def installer_function(name: str) -> str:
    """Return one top-level Bash function from the installer."""
    lines = INSTALLER.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"{name}(){{")
    for end in range(start + 1, len(lines)):
        if lines[end] == "}":
            return "\n".join(lines[start : end + 1]) + "\n"
    raise AssertionError(f"unterminated installer function: {name}")


def generate_config(
    output: Path,
    *,
    keymap: str = "us",
    xkbvariant: str = "",
    desktop: str = "sway",
    filesystem: str = "ext4",
    encrypt: str = "no",
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(GENERATOR),
            "--out",
            str(output),
            "--host",
            "test-host",
            "--user",
            "tester",
            "--fullname",
            "Test User",
            "--locale",
            "en_US.UTF-8",
            "--tz",
            "UTC",
            "--keymap",
            keymap,
            "--xkbvariant",
            xkbvariant,
            "--desktop",
            desktop,
            "--fs",
            filesystem,
            "--encrypt",
            encrypt,
            "--root-uuid",
            "11111111-1111-1111-1111-111111111111",
            "--efi-uuid",
            "2222-3333",
            "--luks-uuid",
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" if encrypt == "yes" else "",
        ],
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )


class InstallerCredentialTests(unittest.TestCase):
    def test_privileged_shebang_rejects_exported_function_overrides(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertTrue(
            installer.startswith("#!/run/current-system/profile/bin/bash -p\n")
        )
        self.assertIn("while builtin read", installer)
        self.assertIn("builtin unset -f", installer)

        with tempfile.TemporaryDirectory(prefix="securityops-clean-shell-") as temporary:
            root = Path(temporary)
            probe = root / "probe"
            marker = root / "function-hijack"
            probe.write_text(
                "#!/run/current-system/profile/bin/bash -p\n"
                "set -eu\n"
                "while builtin read -r _ _ inherited_function; do\n"
                "  builtin unset -f -- \"$inherited_function\"\n"
                "done < <(builtin declare -F)\n"
                "builtin unset inherited_function\n"
                "[[ -z $(builtin declare -F) ]]\n",
                encoding="utf-8",
            )
            probe.chmod(0o700)
            hostile = (
                f"touch {str(marker)!r}; return 97"
            )
            environment = os.environ.copy()
            for name in ("builtin", "read", "unset", "declare"):
                environment[f"BASH_FUNC_{name}%%"] = f"() {{ {hostile}; }}"
            result = subprocess.run(
                [str(probe)],
                cwd=root,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(marker.exists())

            # Invoke the actual source file through its kernel shebang too.  A
            # checkout is intentionally not the immutable profile entry, so it
            # must fail at that trust check, after proving no hostile function
            # ran before the check.
            actual = subprocess.run(
                [str(INSTALLER)],
                cwd=root,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(actual.returncode, 0)
            self.assertNotEqual(actual.returncode, 97)
            self.assertFalse(marker.exists())
            self.assertRegex(
                actual.stderr,
                r"(?:fixed profile installer is missing or mutable|"
                r"run the immutable installer from the active system profile)",
            )

    def test_privileged_parent_cannot_reexport_functions_into_generator(self) -> None:
        self.assertTrue(
            GENERATOR.read_text(encoding="utf-8").startswith(
                "#!/run/current-system/profile/bin/bash -p\n"
            )
        )
        self.assertTrue(
            PRIVATE_STATE.read_text(encoding="utf-8").startswith(
                "#!/run/current-system/profile/bin/bash -p\n"
            )
        )
        with tempfile.TemporaryDirectory(prefix="securityops-child-functions-") as temporary:
            root = Path(temporary)
            output = root / "config.scm"
            marker = root / "child-imported-function"
            environment = os.environ.copy()
            hostile = f"touch {str(marker)!r}; return 96"
            for name in ("builtin", "set", "declare", "sed"):
                environment[f"BASH_FUNC_{name}%%"] = f"() {{ {hostile}; }}"
            # The privileged-mode parent leaves raw BASH_FUNC_* records in its
            # environment.  Execute the real sibling across that exact boundary
            # and prove its own `-p' shebang refuses to import them.
            result = subprocess.run(
                [
                    str(PROFILE / "bin/bash"),
                    "--noprofile",
                    "--norc",
                    "-p",
                    "-c",
                    '"$1" --out "$2" --host test-host --user tester '
                    '--fullname "Test User" --locale en_US.UTF-8 --tz UTC '
                    '--keymap us --xkbvariant "" --desktop sway --fs ext4 '
                    '--encrypt no --root-uuid 11111111-1111-1111-1111-111111111111 '
                    '--efi-uuid 2222-3333 --luks-uuid ""',
                    "privileged-parent",
                    str(GENERATOR),
                    str(output),
                ],
                cwd=root,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(output.is_file())
            self.assertFalse(marker.exists())

    def test_plaintext_and_verifier_never_enter_generator(self) -> None:
        generator = GENERATOR.read_text(encoding="utf-8")
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("password-fd", generator)
        self.assertNotIn("UHASH", generator)
        self.assertNotIn("openssl passwd", generator)
        self.assertIn("mkpasswd --method=yescrypt --password-fd=9", installer)
        self.assertIn('9<<<"$UPASS"', installer)
        self.assertIn("unset UPASS UPASS2", installer)
        self.assertNotIn("SO_UPASS", installer)
        self.assertNotIn("SO_RPASS", installer)

    def test_generated_system_declaratively_locks_root_and_admin(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-config-test-") as temporary:
            output = Path(temporary) / "config.scm"
            result = generate_config(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            generated = output.read_text(encoding="utf-8")
            self.assertIn("(define %installed-locked-root-account", generated)
            self.assertIn('(name "root")', generated)
            self.assertIn("(uid 0)", generated)
            self.assertIn("(users (cons* %installed-locked-root-account", generated)
            self.assertEqual(generated.count('(password "!")'), 2)
            self.assertEqual(generated.count('(name "root")'), 1)
            self.assertNotIn('(password "")', generated)
            self.assertNotRegex(generated, r'\(password "\$(?:6|y)\$')
            self.assertNotIn("validation-user-password", generated)
            self.assertNotIn("synthetic-test-value", generated)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_generated_system_rejects_empty_passwords_and_brands_console(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-config-test-") as temporary:
            output = Path(temporary) / "config.scm"
            result = generate_config(output)
            self.assertEqual(result.returncode, 0, result.stderr)
            generated = output.read_text(encoding="utf-8")
            self.assertIn("(allow-empty-passwords? #f)", generated)
            self.assertNotIn("(allow-empty-passwords? #t)", generated)
            self.assertIn('(label (string-append "Security Ops OS " %release-version))', generated)
            self.assertIn('(motd (plain-file "securityops-motd" %securityops-issue))', generated)
            self.assertIn("(nongnu system linux-initrd)", generated)
            self.assertIn("(initrd microcode-initrd)", generated)
            self.assertIn(
                "(firmware (list linux-firmware intel-microcode amd-microcode))",
                generated,
            )
            self.assertIn(
                'Defaults secure_path=\\"/run/privileged/bin:/run/setuid-programs:'
                '/run/current-system/profile/bin:/run/current-system/profile/sbin\\"',
                generated,
            )
            self.assertIn("%wheel ALL=(ALL) ALL", generated)
            self.assertNotIn("NOPASSWD", generated)

    def test_verifier_activation_occurs_only_after_successful_system_init(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        init_call = installer.index('-s "$COW_INIT_HELPER" /mnt /mnt/etc/config.scm')
        success_gate = installer.index('if [ "$rc" -eq 0 ]', init_call)
        activation = installer.index("chpasswd --encrypted --root /mnt", success_gate)
        self.assertLess(init_call, success_gate)
        self.assertLess(success_gate, activation)
        self.assertIn("cmp -s - \"$ADMIN_HASH_FILE\"", installer)
        self.assertNotIn('"$(dirname "$0")/gen-config.sh"', installer)
        self.assertIn('"$CONFIG_GENERATOR"', installer)

    def test_runtime_directory_rejects_precreated_symlink(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-runtime-test-") as temporary:
            root = Path(temporary)
            real = root / "real"
            real.mkdir(mode=0o700)
            link = root / "runtime"
            link.symlink_to(real, target_is_directory=True)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; securityops_private_directory "$2"',
                    "private-state-test",
                    str(PRIVATE_STATE),
                    str(link),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing symlink runtime directory", result.stderr)
            self.assertEqual(real.stat().st_mode & 0o777, 0o700)

    def test_runtime_directory_rejects_permissive_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-runtime-test-") as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir(mode=0o755)
            result = subprocess.run(
                [
                    "bash",
                    "-c",
                    'source "$1"; securityops_private_directory "$2"',
                    "private-state-test",
                    str(PRIVATE_STATE),
                    str(runtime),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("unsafe runtime directory metadata", result.stderr)

    def test_fake_path_cannot_supply_privileged_sudo(self) -> None:
        with tempfile.TemporaryDirectory(prefix="securityops-path-test-") as temporary:
            fake = Path(temporary) / "sudo"
            marker = Path(temporary) / "executed"
            fake.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
            fake.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = temporary
            result = subprocess.run(
                [
                    BASH,
                    "-c",
                    'source "$1"; securityops_trusted_setuid_sudo || true',
                    "private-state-test",
                    str(PRIVATE_STATE),
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotEqual(result.stdout.strip(), str(fake))
            self.assertFalse(marker.exists())
            installer = INSTALLER.read_text(encoding="utf-8")
            self.assertNotRegex(installer, re.compile(r"exec\s+sudo\b"))
            self.assertNotIn('profile/sbin:$PATH', installer)

    def test_flock_supervisor_does_not_leak_lock_to_long_lived_child(self) -> None:
        flock = PROFILE / "bin/flock"
        python = PROFILE / "bin/python3"
        sleep = PROFILE / "bin/sleep"
        true = PROFILE / "bin/true"
        if not all(path.exists() for path in (flock, python, sleep, true)):
            self.skipTest("fixed Guix flock test tools are unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-flock-") as temporary:
            lock = Path(temporary) / "installer.lock"
            lock.touch(mode=0o600)
            program = (
                "import subprocess; "
                f"p=subprocess.Popen([{str(sleep)!r}, '5'], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, "
                "stderr=subprocess.DEVNULL, start_new_session=True); print(p.pid)"
            )
            owner = subprocess.run(
                [
                    str(flock),
                    "-n",
                    "-E",
                    "75",
                    "--close",
                    str(lock),
                    str(python),
                    "-I",
                    "-S",
                    "-c",
                    program,
                ],
                cwd=ROOT,
                env={"PATH": str(PROFILE / "bin")},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(owner.returncode, 0, owner.stderr)
            child_pid = int(owner.stdout.strip())
            try:
                reacquired = subprocess.run(
                    [str(flock), "-n", str(lock), str(true)],
                    cwd=ROOT,
                    env={"PATH": str(PROFILE / "bin")},
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(reacquired.returncode, 0, reacquired.stderr)
                fd_directory = Path(f"/proc/{child_pid}/fd")
                if fd_directory.exists():
                    inherited = []
                    for descriptor in fd_directory.iterdir():
                        try:
                            inherited.append(str(descriptor.resolve()))
                        except FileNotFoundError:
                            pass
                    self.assertNotIn(str(lock.resolve()), inherited)
            finally:
                try:
                    os.kill(child_pid, 15)
                except ProcessLookupError:
                    pass
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('exec "$TRUSTED_FLOCK" -n -E 75 --close', installer)
        self.assertNotIn('exec 3>>"$LOG"', installer)
        self.assertNotIn('exec 8>>"$LOCK_FILE"', installer)

    def test_lock_marker_is_bound_to_exact_flock_parent_and_inode(self) -> None:
        flock = PROFILE / "bin/flock"
        python = PROFILE / "bin/python3"
        if not all(path.exists() for path in (flock, python)):
            self.skipTest("fixed Guix lock test tools are unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-lock-binding-") as temporary:
            lock = Path(temporary) / "installer.lock"
            lock.touch(mode=0o600)
            verify = (
                'source "$1"; '
                'securityops_verify_flock_supervisor "$2" "$3" "$4" "$PPID"'
            )
            supervised = subprocess.run(
                [
                    str(flock),
                    "--close",
                    str(lock),
                    BASH,
                    "-c",
                    verify,
                    "lock-child",
                    str(PRIVATE_STATE),
                    str(lock),
                    str(flock.resolve()),
                    str(python.resolve()),
                ],
                cwd=ROOT,
                env={"PATH": str(PROFILE / "bin")},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(supervised.returncode, 0, supervised.stderr)

            holder = subprocess.Popen(
                [str(flock), "--close", str(lock), str(python), "-I", "-S", "-c",
                 'import os; os.write(1, b"1"); os.read(0, 1)'],
                cwd=ROOT,
                env={"PATH": str(PROFILE / "bin")},
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            try:
                # Readiness comes from the child after flock acquired the lock.
                # No delay can prove that the competing holder actually exists.
                with selectors.DefaultSelector() as ready:
                    ready.register(holder.stdout, selectors.EVENT_READ)
                    self.assertTrue(ready.select(5), "lock holder did not become ready")
                self.assertEqual(os.read(holder.stdout.fileno(), 1), b"1")
                self.assertIsNone(holder.poll())
                with lock.open("rb") as contender:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(contender.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                # A forged internal marker in process B sees contention from A,
                # but B's direct parent does not own this lock and must fail.
                piggyback = subprocess.run(
                    [
                        BASH,
                        "-c",
                        verify,
                        "lock-piggyback",
                        str(PRIVATE_STATE),
                        str(lock),
                        str(flock.resolve()),
                        str(python.resolve()),
                    ],
                    cwd=ROOT,
                    env={"PATH": str(PROFILE / "bin")},
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(piggyback.returncode, 0)
                self.assertEqual(piggyback.returncode, 1)
                self.assertEqual(piggyback.stderr, "")
            finally:
                # The parent owns the sole pipe writer. EOF ends the payload;
                # flock can then reap it before we collect flock itself. Killing
                # only flock would orphan its child, including on assertion failure.
                try:
                    holder.stdin.close()
                    self.assertEqual(holder.wait(timeout=10), 0)
                finally:
                    holder.stdout.close()

        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("securityops_verify_flock_supervisor", installer)
        self.assertIn('"$LOCK_FILE" "$TRUSTED_FLOCK" "$TRUSTED_PYTHON" "$PPID"', installer)

    def test_real_profile_symlinks_resolve_to_immutable_store_targets(self) -> None:
        python = PROFILE / "bin/python3"
        guile = PROFILE / "bin/guile"
        if not python.exists() or not guile.exists():
            self.skipTest("Guix system profile is unavailable")
        self.assertTrue(python.is_symlink())
        self.assertTrue(guile.is_symlink())
        result = subprocess.run(
            [
                BASH,
                "-c",
                'source "$1"; '
                'securityops_resolve_store_path "$2" executable; '
                'securityops_resolve_store_path "$3" executable',
                "private-state-test",
                str(PRIVATE_STATE),
                str(python),
                str(guile),
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        resolved = result.stdout.splitlines()
        self.assertEqual(len(resolved), 2)
        self.assertTrue(all(path.startswith("/gnu/store/") for path in resolved))
        profile_root = PROFILE.resolve()
        root_result = subprocess.run(
            [
                BASH,
                "-c",
                'source "$1"; securityops_resolve_store_path "$2" directory',
                "private-state-test",
                str(PRIVATE_STATE),
                str(profile_root),
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(root_result.returncode, 0, root_result.stderr)
        self.assertEqual(root_result.stdout.strip(), str(profile_root))

    def test_isolated_python_ignores_malicious_current_directory_module(self) -> None:
        python = PROFILE / "bin/python3"
        if not python.exists():
            self.skipTest("Guix Python is unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-python-cwd-") as temporary:
            directory = Path(temporary)
            marker = directory / "imported"
            (directory / "json.py").write_text(
                f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n",
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    str(python),
                    "-I",
                    "-S",
                    "-c",
                    "import json; print(json.loads('{\"isolated\": true}')[\"isolated\"])",
                ],
                cwd=directory,
                env={"PATH": str(PROFILE / "bin")},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "True")
            self.assertFalse(marker.exists())
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('KERNEL_VERSION=$("$TRUSTED_PYTHON" -I -S -c', installer)

    def test_guile_modules_import_with_scrubbed_environment(self) -> None:
        guile = PROFILE / "bin/guile"
        site = PROFILE / "share/guile/site/3.0"
        ccache = PROFILE / "lib/guile/3.0/site-ccache"
        extensions = PROFILE / "lib/guile/3.0/extensions"
        if not all(path.exists() for path in (guile, site, ccache, extensions)):
            self.skipTest("Guix Guile module tree is unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-empty-home-") as temporary:
            result = subprocess.run(
                [
                    str(guile),
                    "-L",
                    str(site),
                    "-C",
                    str(ccache),
                    "-c",
                    "(use-modules (gnu build install) (gnu build linux-container) "
                    "(gnu services herd) (gcrypt hash) (guix base16) "
                    "(guix build syscalls) (shepherd system) (sqlite3))",
                ],
                cwd=temporary,
                env={
                    "HOME": temporary,
                    "XDG_CONFIG_HOME": str(Path(temporary) / "xdg"),
                    "GUILE_EXTENSIONS_PATH": str(extensions),
                },
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('"$TRUSTED_GUILE" -L "$TRUSTED_GUILE_SITE" -C "$TRUSTED_GUILE_CCACHE"', installer)
        self.assertIn('-s "$COW_INIT_HELPER"', installer)
        for module in ("(gcrypt hash)", "(guix base16)", "(sqlite3)"):
            self.assertIn(module, installer)

    def test_privileged_home_and_guix_configuration_are_not_inherited(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        helper = COW_HELPER.read_text(encoding="utf-8")
        for variable in (
            "HOME",
            "XDG_CONFIG_HOME",
            "GUIX_PROFILE",
            "GUIX_DAEMON_SOCKET",
            "GUIX_BUILD_OPTIONS",
            "SSL_CERT_FILE",
            "CURL_CA_BUNDLE",
        ):
            self.assertRegex(installer, rf"(?:unset[\s\S]*|export ){re.escape(variable)}")
        self.assertIn('export HOME="$PRIVILEGED_HOME"', installer)
        self.assertIn('export XDG_CONFIG_HOME="$PRIVILEGED_XDG_CONFIG_HOME"', installer)
        self.assertIn('"time-machine" "-C" channels', helper)
        self.assertIn('(string-append "--substitute-urls=" substitute-urls)', helper)
        self.assertNotIn('(getenv "HOME")', helper)

    def test_gecos_rejects_delimiters_controls_and_unbounded_input(self) -> None:
        python = PROFILE / "bin/python3"
        if not python.exists():
            self.skipTest("fixed Guix Python is unavailable")
        cases = [
            ("Cristian Moisés", True),
            ("", True),
            ("name:root", False),
            ("pasted\nsecond line", False),
            ("control\x7f", False),
            ("control\u0085next", False),
            ("x" * 129, False),
            ("á" * 128, True),
        ]
        for value, accepted in cases:
            result = subprocess.run(
                [
                    BASH,
                    "-c",
                    'source "$1"; securityops_valid_gecos "$2" "$3"',
                    "private-state-test",
                    str(PRIVATE_STATE),
                    value,
                    str(python.resolve()),
                ],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode == 0, accepted, value)

    def test_scheme_looking_gecos_remains_data_and_cannot_execute(self) -> None:
        guile = PROFILE / "bin/guile"
        if not guile.exists():
            self.skipTest("Guix Guile is unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-gecos-escape-") as temporary:
            root = Path(temporary)
            output = root / "config.scm"
            marker = root / "generator-command-ran"
            payload = f'Eve\\\" ) (system* "touch" "{marker}") ; ('
            result = subprocess.run(
                [
                    str(GENERATOR),
                    "--out",
                    str(output),
                    "--host",
                    "test-host",
                    "--user",
                    "tester",
                    "--fullname",
                    payload,
                    "--locale",
                    "en_US.UTF-8",
                    "--tz",
                    "UTC",
                    "--keymap",
                    "us",
                    "--xkbvariant",
                    "",
                    "--desktop",
                    "sway",
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
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = subprocess.run(
                [
                    str(guile),
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
            self.assertEqual(parsed.returncode, 0, parsed.stderr)
            self.assertFalse(marker.exists())
            source = output.read_text(encoding="utf-8")
            self.assertIn(str(marker), source)
            self.assertIn(r'(system* \"touch\"', source)

    def test_hostname_username_and_password_policy_are_locale_independent(self) -> None:
        available_locales = subprocess.run(
            [str(PROFILE / "bin/locale"), "-a"],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        ).stdout.splitlines()
        locales = ["C"]
        for candidate in ("en_US.utf8", "pt_BR.utf8", "en_US.UTF-8", "pt_BR.UTF-8"):
            if candidate in available_locales and candidate not in locales:
                locales.append(candidate)
        for locale_name in locales:
            environment = {"PATH": str(PROFILE / "bin"), "LC_ALL": locale_name}
            for function, value, accepted in (
                ("securityops_valid_hostname", "host-01", True),
                ("securityops_valid_hostname", "éhost", False),
                ("securityops_valid_hostname", "host١", False),
                ("securityops_valid_username", "operator_1", True),
                ("securityops_valid_username", "aß", False),
                ("securityops_valid_username", "é", False),
            ):
                result = subprocess.run(
                    [
                        BASH,
                        "-c",
                        f'source "$1"; {function} "$2"',
                        "locale-policy-test",
                        str(PRIVATE_STATE),
                        value,
                    ],
                    cwd=ROOT,
                    env=environment,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode == 0, accepted, (locale_name, value))

        def password_ok(value: str, minimum: int) -> bool:
            completed = subprocess.run(
                [
                    BASH,
                    "-c",
                    'source "$1"; securityops_password_meets_policy '
                    '"$2" "$3" 1024 operator host-01',
                    "password-policy-test",
                    str(PRIVATE_STATE),
                    value,
                    str(minimum),
                ],
                cwd=ROOT,
                env={"PATH": str(PROFILE / "bin"), "LC_ALL": "pt_BR.UTF-8"},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            return completed.returncode == 0

        self.assertFalse(password_ok("Eleven-Byte", 12))
        self.assertTrue(password_ok("Twelve+Bytes!", 12))
        self.assertFalse(password_ok("a" * 20, 20))
        self.assertFalse(password_ok("1234567890abcdefghXY", 20))
        self.assertTrue(password_ok("Long LUKS phrase #2026", 20))
        self.assertFalse(password_ok("x" * 1025, 20))

    def test_admin_and_luks_secret_boundaries_match_runtime_consumers(self) -> None:
        def accepted(function: str, value: str) -> bool:
            result = subprocess.run(
                [
                    BASH,
                    "-c",
                    f'source "$1"; {function} "$2" operator host-01',
                    "secret-boundary-test",
                    str(PRIVATE_STATE),
                    value,
                ],
                cwd=ROOT,
                env={"PATH": str(PROFILE / "bin"), "LC_ALL": "pt_BR.UTF-8"},
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            return result.returncode == 0

        admin_12 = "Adm1n+Pass!x"
        admin_128 = ("A9-z_+q!" * 16)[:128]
        luks_20 = "LUKS-phrase+2026_Xy!"
        luks_254 = ("L9-x_+Q!" * 32)[:254]
        self.assertTrue(accepted("securityops_admin_password_meets_policy", admin_12))
        self.assertTrue(accepted("securityops_admin_password_meets_policy", admin_128))
        self.assertFalse(accepted("securityops_admin_password_meets_policy", "A9-z_+q!" * 17))
        self.assertFalse(accepted("securityops_admin_password_meets_policy", "Adm1n+Páss!"))
        self.assertFalse(accepted("securityops_admin_password_meets_policy", "Admin\x7fPass!2"))
        self.assertTrue(accepted("securityops_luks_passphrase_meets_policy", luks_20))
        self.assertTrue(accepted("securityops_luks_passphrase_meets_policy", luks_254))
        self.assertFalse(accepted("securityops_luks_passphrase_meets_policy", luks_254 + "X"))
        self.assertFalse(accepted("securityops_luks_passphrase_meets_policy", "LUKS-phrase+emoji-🔒2026"))
        self.assertFalse(accepted("securityops_luks_passphrase_meets_policy", "LUKS-phrase\ninvalid-2026"))

        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("US layout at first GRUB prompt", installer)
        self.assertIn('apply_live_keyboard_layout us ""', installer)
        self.assertIn("securityops_luks_passphrase_meets_policy", installer)

    def test_luks2_argon2id_profile_is_exact_and_read_back(self) -> None:
        candidates = sorted(Path("/gnu/store").glob("*-cryptsetup-*/sbin/cryptsetup"))
        if not candidates:
            self.skipTest("source-built cryptsetup is unavailable")
        cryptsetup = candidates[-1]
        passphrase = "Ephemeral-LUKS-test+2026_Xy!"
        with tempfile.TemporaryDirectory(prefix="securityops-luks-profile-") as temporary:
            image = Path(temporary) / "luks.img"
            with image.open("wb") as output:
                output.truncate(128 * 1024 * 1024)
            formatted = subprocess.run(
                [
                    str(cryptsetup),
                    "luksFormat",
                    "--type",
                    "luks2",
                    "--cipher",
                    "aes-xts-plain64",
                    "--key-size",
                    "512",
                    "--pbkdf",
                    "argon2id",
                    "--pbkdf-memory",
                    "65536",
                    "--pbkdf-parallel",
                    "1",
                    "--pbkdf-force-iterations",
                    "4",
                    "--batch-mode",
                    "--key-file=-",
                    str(image),
                ],
                input=passphrase,
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
            )
            self.assertEqual(formatted.returncode, 0, formatted.stderr)
            dumped = subprocess.run(
                [str(cryptsetup), "luksDump", "--dump-json-metadata", str(image)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
            self.assertEqual(dumped.returncode, 0, dumped.stderr)
            metadata = json.loads(dumped.stdout)
            self.assertEqual(len(metadata["keyslots"]), 1)
            kdf = next(iter(metadata["keyslots"].values()))["kdf"]
            self.assertEqual(
                {name: kdf[name] for name in ("type", "time", "memory", "cpus")},
                {"type": "argon2id", "time": 4, "memory": 65536, "cpus": 1},
            )

        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("--pbkdf argon2id --pbkdf-memory 65536", installer)
        self.assertIn('"time": 4, "memory": 65536, "cpus": 1', installer)
        self.assertNotIn("GRUB 2.12", installer)

    def test_authenticated_source_copy_preserves_symlinks_without_dereference(self) -> None:
        cp = PROFILE / "bin/cp"
        if not cp.exists():
            self.skipTest("Guix Coreutils is unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-source-copy-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            outside = root / "live-secret"
            outside.write_text("must-not-be-copied", encoding="utf-8")
            (source / "external").symlink_to(outside)
            destination = root / "copied"
            result = subprocess.run(
                [str(cp), "-a", "--", str(source), str(destination)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((destination / "external").is_symlink())
            self.assertEqual(os.readlink(destination / "external"), str(outside))
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn('cp -a -- "$SRC" /mnt/etc/securityops/src', installer)
        self.assertNotIn('cp -aL "$SRC"', installer)

    def test_guix_iso_bare_root_uuid_decodes_and_protects_all_matches(self) -> None:
        python = PROFILE / "bin/python3"
        if not python.exists() or not Path("/dev/loop0").exists() or not Path("/dev/loop1").exists():
            self.skipTest("Guix Python or two harmless block nodes are unavailable")
        function = installer_function("resolve_root_devices")
        with tempfile.TemporaryDirectory(prefix="securityops-blkid-mock-") as temporary:
            directory = Path(temporary)
            query = directory / "query"
            fake_blkid = directory / "blkid"
            fake_blkid.write_text(
                "#!/run/current-system/profile/bin/bash\n"
                f"printf '%s\\n' \"$*\" > {query!s}\n"
                "printf '%s\\n' /dev/loop1 /dev/loop0\n",
                encoding="utf-8",
            )
            fake_blkid.chmod(0o755)
            script = (
                f"TRUSTED_PYTHON={python!s}\n"
                f"{function}\n"
                'resolve_root_devices "$1"\n'
            )
            environment = {"PATH": f"{directory}:{PROFILE / 'bin'}"}
            result = subprocess.run(
                [
                    BASH,
                    "-c",
                    script,
                    "root-decode-test",
                    "31393730-3031-3031-3232-313433343239",
                ],
                cwd=ROOT,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.splitlines(), ["/dev/loop0", "/dev/loop1"])
            self.assertIn("UUID=1970-01-01-22-14-34-29", query.read_text(encoding="utf-8"))

    def test_cmdline_parser_requires_exactly_one_root_argument(self) -> None:
        function = installer_function("cmdline_root_spec")
        with tempfile.TemporaryDirectory(prefix="securityops-cmdline-") as temporary:
            cmdline = Path(temporary) / "cmdline"
            cmdline.write_text(
                "quiet root=31393730-3031-3031-3232-313433343239 loglevel=4\n",
                encoding="utf-8",
            )
            accepted = subprocess.run(
                [BASH, "-c", function + '\ncmdline_root_spec "$1"', "cmdline-test", str(cmdline)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(
                accepted.stdout.strip(), "31393730-3031-3031-3232-313433343239"
            )
            for bad in (
                "quiet\n",
                "root=/dev/vda root=/dev/vdb\n",
                "root=/dev/vda root=/dev/vda\n",
            ):
                cmdline.write_text(bad, encoding="utf-8")
                rejected = subprocess.run(
                    [BASH, "-c", function + '\ncmdline_root_spec "$1"', "cmdline-test", str(cmdline)],
                    cwd=ROOT,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertNotEqual(rejected.returncode, 0, bad)

    def test_disk_identity_and_partition_geometry_fail_closed(self) -> None:
        source = (
            'source "$1"; '
            "securityops_same_disk_identity "
            "/dev/vda 8:0 /sys/devices/vda 21474836480 42 wwn serial "
            "/dev/vda disk 8:0 /sys/devices/vda 21474836480 42 wwn serial; "
            "securityops_valid_partition_geometry "
            "$((64*1024*1024*1024)) $((1024*1024)) $((512*1024*1024)) "
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b "
            "$((513*1024*1024)) $((64*1024*1024*1024-513*1024*1024-17408)) "
            "0fc63daf-8483-4772-8e79-3d69d8477de4"
        )
        result = subprocess.run(
            [BASH, "-c", source, "disk-values-test", str(PRIVATE_STATE)],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        undersized = subprocess.run(
            [
                BASH,
                "-c",
                'source "$1"; securityops_valid_partition_geometry '
                "$((20*1024*1024*1024)) $((1024*1024)) $((512*1024*1024)) "
                "c12a7328-f81f-11d2-ba4b-00a0c93ec93b "
                "$((513*1024*1024)) $((20*1024*1024*1024-513*1024*1024-17408)) "
                "0fc63daf-8483-4772-8e79-3d69d8477de4",
                "disk-values-test",
                str(PRIVATE_STATE),
            ],
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(undersized.returncode, 0)
        for changed_identity in (
            "/dev/vdb disk 8:0 /sys/devices/vda 21474836480 42 wwn serial",
            "/dev/vda disk 8:0 /sys/devices/vda 21474836480 43 wwn serial",
            "/dev/vda disk 8:0 /sys/devices/vda 21474836480 42 other serial",
        ):
            command = (
                'source "$1"; securityops_same_disk_identity '
                "/dev/vda 8:0 /sys/devices/vda 21474836480 42 wwn serial "
                + changed_identity
            )
            rejected = subprocess.run(
                [BASH, "-c", command, "disk-values-test", str(PRIVATE_STATE)],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(rejected.returncode, 0, changed_identity)
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("blockdev --getdiskseq", installer)
        self.assertIn("device_tree_busy_reason", installer)
        self.assertIn("blockdev --rereadpt", installer)
        self.assertIn("validate_created_partition_layout", installer)
        self.assertNotIn('partprobe "$DISK" || true', installer)

    def test_active_swap_is_rejected_by_device_tree_check(self) -> None:
        swap = Path("/dev/zram0")
        if not swap.exists() or "/dev/zram0" not in Path("/proc/swaps").read_text(encoding="utf-8"):
            self.skipTest("no active block-device swap is available")
        function = installer_function("device_tree_busy_reason")
        result = subprocess.run(
            [BASH, "-c", function + '\ndevice_tree_busy_reason "$1"', "busy-test", str(swap)],
            cwd=ROOT,
            env={"PATH": str(PROFILE / "bin")},
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("active swap", result.stdout)

    def test_unsigned_release_requires_explicit_secure_boot_disabled(self) -> None:
        function = installer_function("secure_boot_state")
        with tempfile.TemporaryDirectory(prefix="securityops-secureboot-") as temporary:
            efivars = Path(temporary)

            def state() -> str:
                result = subprocess.run(
                    [BASH, "-c", function + '\nsecure_boot_state "$1"', "secureboot-test", str(efivars)],
                    cwd=ROOT,
                    env={"PATH": str(PROFILE / "bin")},
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout.strip()

            self.assertEqual(state(), "unavailable")
            first = efivars / "SecureBoot-test-a"
            first.write_bytes(b"")
            self.assertEqual(state(), "invalid")
            first.write_bytes(b"\x07\x00\x00\x00")
            self.assertEqual(state(), "invalid")
            first.write_bytes(b"\x07\x00\x00\x00\x00")
            self.assertEqual(state(), "disabled")
            first.write_bytes(b"\x07\x00\x00\x00\x01")
            self.assertEqual(state(), "enabled")
            first.write_bytes(b"\x07\x00\x00\x00\x02")
            self.assertEqual(state(), "invalid")
            first.write_bytes(b"\x07\x00\x00\x00\x00\xff")
            self.assertEqual(state(), "invalid")
            first.unlink()
            target = efivars / "not-an-efivar"
            target.write_bytes(b"\x07\x00\x00\x00\x00")
            first.symlink_to(target)
            self.assertEqual(state(), "invalid")
            first.unlink()
            target.unlink()
            first.write_bytes(b"\x07\x00\x00\x00\x00")
            (efivars / "SecureBoot-test-b").write_bytes(b"\x07\x00\x00\x00\x00")
            self.assertEqual(state(), "invalid")

        installer = INSTALLER.read_text(encoding="utf-8")
        gate = installer[installer.index("SECURE_BOOT_STATE=$(secure_boot_state ") :]
        self.assertIn("enabled)", gate)
        self.assertIn("unavailable)", gate)
        self.assertIn("signed GRUB/kernel chain", gate)
        self.assertNotRegex(gate, re.compile(r"disabled\|unavailable\)"))

    def test_mount_namespace_helper_has_fixed_authenticated_command(self) -> None:
        helper = COW_HELPER.read_text(encoding="utf-8")
        installer = INSTALLER.read_text(encoding="utf-8")
        self.assertIn("(list guix-executable", helper)
        self.assertIn("(immutable-store-executable? guix-executable)", helper)
        self.assertIn("(define-module (securityops installer cow-system-init)", helper)
        self.assertIn(
            '(when (string=? "cow-system-init.scm" (basename (car (command-line))))',
            helper,
        )
        self.assertIn('"$INSTALLER_START_TIME" "$TRUSTED_FLOCK" "$TRUSTED_GUIX"', installer)
        self.assertNotIn('(list "/run/current-system/profile/bin/guix"', helper)
        self.assertIn('"time-machine" "-C" channels', helper)
        self.assertIn('"system" "init" "-L" source', helper)
        self.assertEqual(helper.count('"--fallback" "--"'), 1)
        self.assertIn("mount-cow-store target backing-directory", helper)
        self.assertIn("unmount-cow-store target backing-directory", helper)
        self.assertIn("(copy-file backup temporary)", helper)
        self.assertIn("(rename-file temporary database-file)", helper)
        self.assertNotIn("installer-system-init-options", helper)
        self.assertNotIn("herd start cow-store", installer)

    def test_cow_lifecycle_lock_outlives_launcher_and_blocks_retry(self) -> None:
        flock = PROFILE / "bin/flock"
        setsid = PROFILE / "bin/setsid"
        sleep = PROFILE / "bin/sleep"
        true = PROFILE / "bin/true"
        if not all(path.exists() for path in (flock, setsid, sleep, true)):
            self.skipTest("fixed Guix lifecycle tools are unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-cow-lock-") as temporary:
            lock = Path(temporary) / "cow.lock"
            lock.touch(mode=0o600)
            launcher = subprocess.Popen(
                [
                    BASH,
                    "-c",
                    '"$1" "$2" -n -E 75 --no-fork "$3" "$4" 30 & '
                    'printf "%s\\n" "$!"; wait',
                    "cow-lock-launcher",
                    str(setsid),
                    str(flock),
                    str(lock),
                    str(sleep),
                ],
                cwd=ROOT,
                env={"PATH": str(PROFILE / "bin")},
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            assert launcher.stdout is not None
            lifecycle_pid = int(launcher.stdout.readline().strip())
            try:
                time.sleep(0.2)
                os.kill(launcher.pid, signal.SIGKILL)
                launcher.wait(timeout=10)
                launcher.stdout.close()
                if launcher.stderr is not None:
                    launcher.stderr.close()
                blocked = subprocess.run(
                    [str(flock), "-n", "-E", "75", str(lock), str(true)],
                    cwd=ROOT,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(blocked.returncode, 75)
            finally:
                try:
                    os.killpg(lifecycle_pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                reacquired = subprocess.run(
                    [str(flock), "-n", "-E", "75", str(lock), str(true)],
                    cwd=ROOT,
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=10,
                )
                if reacquired.returncode == 0:
                    break
                time.sleep(0.05)
            self.assertEqual(reacquired.returncode, 0, reacquired.stderr)

        installer = INSTALLER.read_text(encoding="utf-8")
        helper = COW_HELPER.read_text(encoding="utf-8")
        self.assertIn('"$TRUSTED_SETSID" "$TRUSTED_FLOCK" -n -E 75 --no-fork', installer)
        self.assertIn('"$TRUSTED_FLOCK" -n -E 75 --no-fork "$COW_LOCK_FILE"', installer)
        self.assertIn("verify-lifecycle-supervisor!", helper)
        self.assertIn('~2,\'0x:~2,\'0x:~a', helper)

    def test_signal_is_latched_across_async_helper_pid_capture(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        active = installer.index("COW_HELPER_ACTIVE=1", installer.index("# 7. Install"))
        guard = installer.index("COW_HELPER_LAUNCH_IN_PROGRESS=1", active)
        spawn = installer.index('GUILE_EXTENSIONS_PATH="$TRUSTED_GUILE_EXTENSIONS"', guard)
        capture = installer.index("COW_HELPER_PID=$!", spawn)
        authenticated = installer.index('if [ "$helper_identity_ok" != 1 ]', capture)
        release = installer.index(
            "COW_HELPER_LAUNCH_IN_PROGRESS=0",
            installer.index("unset helper_identity_ok", authenticated),
        )
        replay = installer.index('if [ -n "$COW_PENDING_SIGNAL_STATUS" ]', release)
        self.assertLess(active, guard)
        self.assertLess(guard, spawn)
        self.assertLess(spawn, capture)
        self.assertLess(capture, authenticated)
        self.assertLess(authenticated, release)
        self.assertLess(release, replay)

        # Deliver TERM at the precise async-list -> `$!' capture boundary.  The
        # trap must latch, allow PID capture, then reap the child before cleanup.
        with tempfile.TemporaryDirectory(prefix="securityops-launch-signal-") as temporary:
            cleanup = Path(temporary) / "cleanup-witness"
            fixture = r'''
set -Eeuo pipefail
launch=0
active=0
pending_status=""
pending_name=""
child=""
on_signal() {
  local status=$1 name=$2
  if [ "$launch" = 1 ]; then
    pending_status=$status
    pending_name=$name
    return 0
  fi
  if [ "$active" = 1 ]; then
    kill -TERM "$child" 2>/dev/null || true
    wait "$child" 2>/dev/null || true
    active=0
  fi
  : >"$1_cleanup"
  exit "$status"
}
trap 'on_signal 143 TERM' TERM
active=1
launch=1
/run/current-system/profile/bin/sleep 30 &
/run/current-system/profile/bin/kill -TERM "$$"
child=$!
printf '%s\n' "$child"
launch=0
if [ -n "$pending_status" ]; then
  status=$pending_status
  name=$pending_name
  pending_status=""
  pending_name=""
  on_signal "$status" "$name"
fi
'''
            # Pass the witness path through the positional value used by the
            # small fixture without putting any secret or capability in argv.
            fixture = fixture.replace('$1_cleanup', str(cleanup))
            result = subprocess.run(
                [BASH, "-c", fixture, "launch-signal-test"],
                cwd=ROOT,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 143, result.stderr)
            child_pid = int(result.stdout.strip())
            self.assertTrue(cleanup.exists())
            self.assertFalse(Path(f"/proc/{child_pid}").exists())

    def test_worker_identity_is_durable_and_gates_every_cleanup_step(self) -> None:
        helper = COW_HELPER.read_text(encoding="utf-8")
        self.assertIn("version=2", helper)
        self.assertIn('"worker-pid" "worker-start"', helper)
        self.assertIn("'command-worker-running", helper)
        self.assertIn("terminate-command-worker!", helper)
        self.assertIn("terminate-worker-process-group worker-pid-text worker-start", helper)
        self.assertGreaterEqual(helper.count("(command-boundary-clean?)"), 7)
        worker_journal = helper.index("'command-worker-running")
        worker_gate = helper.index("(write 'ready gate-write)", worker_journal)
        worker_exec = helper.index("(apply execl (car command) command)")
        self.assertLess(worker_journal, worker_gate)
        # The exec text appears before the supervisor branch in source, but the
        # worker remains blocked on gate-read until the later durable journal.
        self.assertLess(worker_exec, worker_journal)
        cleanup = helper.index("(block-signals %termination-signals)", worker_gate)
        terminate_supervisor = helper.index(
            "(cleanup-step 'terminate-command-supervisor", cleanup
        )
        terminate_worker = helper.index(
            "(cleanup-step 'terminate-command-worker", terminate_supervisor
        )
        stop_daemon = helper.index("'stop-container-daemon", terminate_worker)
        restore_database = helper.index("'restore-database", stop_daemon)
        self.assertLess(terminate_supervisor, terminate_worker)
        self.assertLess(terminate_worker, stop_daemon)
        self.assertLess(stop_daemon, restore_database)
        self.assertIn("supervisor-parent-start", helper)
        self.assertIn("(not (pid-matches?", helper)

    def test_cow_journal_rejects_pid_one_before_group_signaling(self) -> None:
        guile = PROFILE / "bin/guile"
        site = PROFILE / "share/guile/site/3.0"
        ccache = PROFILE / "lib/guile/3.0/site-ccache"
        extensions = PROFILE / "lib/guile/3.0/extensions"
        if not all(path.exists() for path in (guile, site, ccache, extensions)):
            self.skipTest("Guix Guile module tree is unavailable")
        program = r'''
(use-modules (securityops installer cow-system-init))
(define module (resolve-module '(securityops installer cow-system-init)))
(define pid-matches? (@@ (securityops installer cow-system-init) pid-matches?))
(define validated-recorded-group
  (@@ (securityops installer cow-system-init) validated-recorded-group))
(when (pid-matches? "1" "1") (primitive-exit 20))
(catch #t
  (lambda ()
    (validated-recorded-group "1" "1" 'malformed-test)
    (primitive-exit 21))
  (lambda _ (primitive-exit 0)))
'''
        result = subprocess.run(
            [
                str(guile),
                "--no-auto-compile",
                "-L",
                str(ROOT),
                "-L",
                str(site),
                "-C",
                str(ccache),
                "-c",
                program,
            ],
            cwd=ROOT,
            env={
                "HOME": str(ROOT),
                "GUILE_EXTENSIONS_PATH": str(extensions),
                "LC_ALL": "C",
            },
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        helper = COW_HELPER.read_text(encoding="utf-8")
        self.assertGreaterEqual(helper.count("(> pid 1)"), 2)

    def test_account_and_boot_filesystems_sync_before_verifier_deletion(self) -> None:
        installer = INSTALLER.read_text(encoding="utf-8")
        activation = installer.index("chpasswd --encrypted --root /mnt")
        comparison = installer.index('cmp -s - "$ADMIN_HASH_FILE"', activation)
        shadow_sync = installer.index('"$TRUSTED_SYNC" -f /mnt/etc/shadow', comparison)
        root_sync = installer.index('  "$TRUSTED_SYNC" -f /mnt >>', shadow_sync + 1)
        esp_check = installer.index('findmnt -nro MAJ:MIN -M /mnt/boot/efi', root_sync)
        esp_sync = installer.index('"$TRUSTED_SYNC" -f /mnt/boot/efi', esp_check)
        verifier_delete = installer.index('rm -f -- "$ADMIN_HASH_FILE"', esp_sync)
        final_sync = installer.index('"$TRUSTED_SYNC" >>"$LOG"', verifier_delete)
        target_cleanup = installer.index("cleanup_target_state ||", final_sync)
        success_prompt = installer.index(
            "Security Ops OS is synchronized and installer-owned target state is closed",
            target_cleanup,
        )
        self.assertLess(activation, comparison)
        self.assertLess(comparison, shadow_sync)
        self.assertLess(shadow_sync, root_sync)
        self.assertLess(root_sync, esp_check)
        self.assertLess(esp_check, esp_sync)
        self.assertLess(esp_sync, verifier_delete)
        self.assertLess(verifier_delete, final_sync)
        self.assertLess(final_sync, target_cleanup)
        self.assertLess(target_cleanup, success_prompt)

    def test_generated_choice_matrix_is_parseable_and_uses_branded_efi(self) -> None:
        guile = PROFILE / "bin/guile"
        if not guile.exists():
            self.skipTest("Guix Guile is unavailable")
        cases = [
            ("us", "", "sway", "ext4", "yes"),
            ("br", "abnt2", "xmonad-xlibre", "btrfs", "no"),
            ("gb", "", "kde", "xfs", "yes"),
            ("de", "", "sway", "btrfs", "no"),
            ("fr", "", "xmonad-xlibre", "xfs", "yes"),
            ("es", "", "kde", "ext4", "no"),
        ]
        with tempfile.TemporaryDirectory(prefix="securityops-choice-matrix-") as temporary:
            for index, (keymap, variant, desktop, filesystem, encrypt) in enumerate(cases):
                output = Path(temporary) / f"config-{index}.scm"
                generated = generate_config(
                    output,
                    keymap=keymap,
                    xkbvariant=variant,
                    desktop=desktop,
                    filesystem=filesystem,
                    encrypt=encrypt,
                )
                self.assertEqual(generated.returncode, 0, generated.stderr)
                parsed = subprocess.run(
                    [
                        str(guile),
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
                self.assertEqual(parsed.returncode, 0, parsed.stderr)
                source = output.read_text(encoding="utf-8")
                self.assertIn("(bootloader securityops-grub-efi-bootloader)", source)
                self.assertIn('(password "!")', source)

        bootloader = BOOTLOADER.read_text(encoding="utf-8")
        self.assertIn('"--bootloader-id=SecurityOps"', bootloader)
        self.assertNotIn('"--bootloader-id=Guix"', bootloader)

    def test_purified_child_environment_can_start_time_machine_frontend(self) -> None:
        guix = PROFILE / "bin/guix"
        certificate_file = PROFILE / "etc/ssl/certs/ca-certificates.crt"
        certificate_directory = PROFILE / "etc/ssl/certs"
        if not all(path.exists() for path in (guix, certificate_file, certificate_directory)):
            self.skipTest("Guix or its fixed CA bundle is unavailable")
        with tempfile.TemporaryDirectory(prefix="securityops-guix-child-") as temporary:
            root = Path(temporary)
            names = ("home", "xdg-config", "xdg-cache", "xdg-data", "xdg-state", "xdg-runtime", "tmp")
            for name in names:
                (root / name).mkdir(mode=0o700)
            environment = {
                "PATH": f"{PROFILE / 'bin'}:{PROFILE / 'sbin'}",
                "HOME": str(root / "home"),
                "XDG_CONFIG_HOME": str(root / "xdg-config"),
                "XDG_CACHE_HOME": str(root / "xdg-cache"),
                "XDG_DATA_HOME": str(root / "xdg-data"),
                "XDG_STATE_HOME": str(root / "xdg-state"),
                "XDG_RUNTIME_DIR": str(root / "xdg-runtime"),
                "TMPDIR": str(root / "tmp"),
                "LC_ALL": "en_US.UTF-8",
                "LANG": "en_US.UTF-8",
                "SSL_CERT_FILE": str(certificate_file.resolve()),
                "SSL_CERT_DIR": str(certificate_directory.resolve()),
                "GIT_SSL_CAINFO": str(certificate_file.resolve()),
            }
            result = subprocess.run(
                [str(guix), "time-machine", "--help"],
                cwd=root,
                env=environment,
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("guix time-machine", result.stdout)
        helper = COW_HELPER.read_text(encoding="utf-8")
        self.assertIn("(configure-child-environment certificate-file certificate-directory", helper)
        self.assertIn("private-root", helper)
        for name in ("HOME", "XDG_CONFIG_HOME", "TMPDIR", "SSL_CERT_FILE", "GIT_SSL_CAINFO"):
            self.assertIn(f'("{name}" .', helper)


if __name__ == "__main__":
    unittest.main()
