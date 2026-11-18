# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=ede36fd0b87956f4b8aad19b113ad075 owner="Cristian Cezar Mois\u00e9s"
"""Unit tests for the Security Ops OS maintainer CLI."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader(
    "securityopsctl_under_test", str(ROOT / "securityopsctl")
)
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
CTL = importlib.util.module_from_spec(SPEC)
sys.modules[LOADER.name] = CTL
LOADER.exec_module(CTL)

# Literal URL oracles: neither an implicit .0 nor a version alias is accepted.
KERNEL_URL_CASES = (
    ("7.3", "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.tar.xz"),
    ("7.0", "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.0.tar.xz"),
    ("7.1", "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.tar.xz"),
    ("7.3.0", "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.0.tar.xz"),
    ("7.1.9", "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.9.tar.xz"),
    ("7.3.3", "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.3.tar.xz"),
    ("7.2.11", "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.2.11.tar.xz"),
)
INVALID_KERNEL_VERSIONS = (
    "", "7", "7.1.", ".7.3", "7..3", "7.3.1.0", "7.1.9-rc1", "7.3-rc.1",
    "07.1.9", "7.01.9", "7.3.01", "0.1.2", "0.3", "7.03", "7.3\n",
    "7.3\r", "7.3\x00", " 7.3", "7.3 ", "７.３", "7.٣", "../7.3",
)


class SettingsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.settings = CTL.load_settings(ROOT / "securityops" / "settings.json")

    def test_repository_settings_are_valid_and_canonical(self) -> None:
        CTL.validate_settings(self.settings)
        serialized = CTL.serialize_settings(self.settings)
        self.assertEqual(serialized, (ROOT / "securityops" / "settings.json").read_text())
        self.assertRegex(self.settings["kernel"]["version"], CTL.KERNEL_VERSION_RE)
        self.assertEqual(
            self.settings["kernel"]["url"],
            CTL.kernel_url(self.settings["kernel"]["version"]),
        )

    def test_kernel_url_accepts_only_stable_canonical_versions(self) -> None:
        for version, expected in KERNEL_URL_CASES:
            with self.subTest(version=version):
                self.assertEqual(CTL.kernel_url(version), expected)
        for invalid in (*INVALID_KERNEL_VERSIONS, None, 7.3):
            with self.subTest(invalid=invalid), self.assertRaises(CTL.ValidationError):
                CTL.kernel_url(invalid)

    def test_kernel_settings_accept_literal_initial_and_patch_releases(self) -> None:
        original = copy.deepcopy(self.settings)
        for version, url in KERNEL_URL_CASES:
            with self.subTest(version=version):
                data = copy.deepcopy(original)
                # Consistent zero hashes are fixtures, not admitted kernel sources.
                metadata = {
                    "version": version, "url": url,
                    "nix_base32": "0" * 52, "sha256": "0" * 64,
                }
                CTL.set_kernel(data, metadata)
                CTL.validate_settings(data)
                self.assertEqual(data["kernel"], metadata)
                self.assertEqual(data["release"], original["release"])
        self.assertEqual(self.settings, original)

    def test_initial_kernel_release_keeps_url_and_release_boundaries(self) -> None:
        original = copy.deepcopy(self.settings)
        for url in (
            "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.0.tar.xz",
            "https://example.invalid/linux-7.3.tar.xz",
        ):
            with self.subTest(url=url), self.assertRaises(CTL.ValidationError):
                CTL.set_kernel(self.settings, {
                    "version": "7.3", "url": url,
                    "nix_base32": "0" * 52, "sha256": "0" * 64,
                })
            self.assertEqual(self.settings, original)
        with self.assertRaises(CTL.ValidationError):
            CTL.set_release(self.settings, "7.3", "r12")
        self.assertEqual(self.settings, original)

    def test_package_specs_and_base_names(self) -> None:
        for valid in (
            "hello",
            "hello@2.12.3",
            "glib:debug",
            "hello@2.12.3:debug",
        ):
            with self.subTest(valid=valid):
                CTL.validate_package_specification(valid)
        self.assertEqual(CTL.package_spec_base("hello@2.12.3"), "hello")
        self.assertEqual(CTL.package_spec_base("glib:debug"), "glib")
        self.assertEqual(CTL.package_spec_key("glib:debug"), ("glib", "debug"))
        self.assertEqual(CTL.package_spec_key("glib"), ("glib", "out"))
        for invalid in ("hello@@2", "glib::debug", "glib:debug@2", "-hello", "hello/x"):
            with self.subTest(invalid=invalid), self.assertRaises(CTL.ValidationError):
                CTL.validate_package_specification(invalid)
        with self.assertRaises(CTL.ValidationError):
            CTL.validate_package_name("hello@2.12.3")

    def test_package_transitions_replace_conflicting_versions(self) -> None:
        data = copy.deepcopy(self.settings)
        data["packages"] = {"add": [], "remove": []}
        CTL.update_package_overrides(
            data, additions=("hello@2.12.3", "glib:debug", "glib:doc")
        )
        self.assertEqual(
            data["packages"]["add"],
            ["glib:debug", "glib:doc", "hello@2.12.3"],
        )

        CTL.update_package_overrides(data, additions=("hello@2.13.0",))
        self.assertEqual(
            data["packages"]["add"],
            ["glib:debug", "glib:doc", "hello@2.13.0"],
        )

        CTL.update_package_overrides(data, removals=("hello",))
        self.assertEqual(data["packages"]["add"], ["glib:debug", "glib:doc"])
        self.assertEqual(data["packages"]["remove"], ["hello"])

        CTL.update_package_overrides(data, additions=("hello@2.12.3",))
        self.assertEqual(data["packages"]["remove"], [])
        self.assertIn("hello@2.12.3", data["packages"]["add"])

        CTL.update_package_overrides(data, resets=("glib",))
        self.assertNotIn("glib:debug", data["packages"]["add"])
        self.assertNotIn("glib:doc", data["packages"]["add"])
        CTL.validate_settings(data)

    def test_package_mutations_preserve_unrelated_nonempty_overrides(self) -> None:
        data = copy.deepcopy(self.settings)
        data["packages"] = {"add": ["thunar@4.20.8"], "remove": ["icecat"]}
        CTL.update_package_overrides(data, additions=("hello@2.12.3",))
        self.assertEqual(data["packages"], {
            "add": ["hello@2.12.3", "thunar@4.20.8"], "remove": ["icecat"]})
        CTL.update_package_overrides(data, resets=("hello",))
        self.assertEqual(data["packages"], {
            "add": ["thunar@4.20.8"], "remove": ["icecat"]})
        CTL.validate_settings(data)

    def test_overlap_uses_addition_base_name(self) -> None:
        data = copy.deepcopy(self.settings)
        data["packages"] = {"add": ["hello@2.12.3"], "remove": ["hello"]}
        with self.assertRaisesRegex(CTL.ValidationError, "overlap"):
            CTL.validate_settings(data)

    def test_duplicate_package_output_specifications_are_rejected(self) -> None:
        data = copy.deepcopy(self.settings)
        data["packages"]["add"] = ["hello@2.12.3", "hello@2.13.0"]
        with self.assertRaisesRegex(CTL.ValidationError, "multiple specifications"):
            CTL.validate_settings(data)

    def test_schema_unknown_key_and_hash_validation(self) -> None:
        unknown = copy.deepcopy(self.settings)
        unknown["surprise"] = True
        with self.assertRaises(CTL.ValidationError):
            CTL.validate_settings(unknown)
        bad_hash = copy.deepcopy(self.settings)
        bad_hash["kernel"]["sha256"] = "0" * 63
        with self.assertRaises(CTL.ValidationError):
            CTL.validate_settings(bad_hash)
        mismatched_hash = copy.deepcopy(self.settings)
        mismatched_hash["kernel"]["nix_base32"] = "0" * 52
        with self.assertRaisesRegex(CTL.ValidationError, "different bytes"):
            CTL.validate_settings(mismatched_hash)

    def test_release_set_validates_and_preserves_optional_label(self) -> None:
        data = copy.deepcopy(self.settings)
        original_label = data["release"]["desktop_label"]
        CTL.set_release(data, "1.14.0", "r12")
        self.assertEqual(data["release"]["version"], "1.14.0")
        self.assertEqual(data["release"]["build_revision"], "r12")
        self.assertEqual(data["release"]["desktop_label"], original_label)
        CTL.set_release(data, "1.14.1", "r13", "sway-minimal")
        self.assertEqual(data["release"]["desktop_label"], "sway-minimal")
        CTL.validate_settings(data)
        CTL.set_release(data, "1.15.0-rc.1", "r14", "sway")
        self.assertEqual(data["release"]["version"], "1.15.0-rc.1")
        CTL.validate_settings(data)
        with self.assertRaises(CTL.ValidationError):
            CTL.set_release(data, "v1.14.1", "r13")
        with self.assertRaises(CTL.ValidationError):
            CTL.set_release(data, "1.14.1", "13")
        with self.assertRaises(CTL.ValidationError):
            CTL.set_release(data, "1.15.0-rc.0", "r14")
        with self.assertRaises(CTL.ValidationError):
            CTL.set_release(data, "1.15.0-beta.1", "r14")


class TemporaryRepositoryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "securityops").mkdir()
        fixture = CTL.load_settings(ROOT / "securityops" / "settings.json")
        fixture["packages"] = {"add": [], "remove": []}
        (root / "securityops" / "settings.json").write_text(
            CTL.serialize_settings(fixture), encoding="utf-8"
        )
        (root / "securityops" / "settings.scm").write_text(
            (ROOT / "securityops" / "settings.scm").read_text(), encoding="utf-8"
        )
        builder = root / "make-iso.sh"
        builder.write_text(
            "#!/bin/sh\n"
            "# SECURITYOPS_ISO_LOCK_HELD SECURITYOPS_ISO_LOCK_FD\n"
            "exit 0\n",
            encoding="utf-8",
        )
        builder.chmod(0o755)
        (root / "build.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (root / "channels.guix").write_text("()\n", encoding="utf-8")
        self.repository = CTL.Repository(root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_atomic_write_and_dry_run(self) -> None:
        original = self.repository.settings_path.read_text()

        def add_hello(data):
            CTL.update_package_overrides(data, additions=("hello@2.12.3",))

        with contextlib.redirect_stdout(io.StringIO()):
            changed, _ = CTL.mutate_settings(self.repository, add_hello, dry_run=True)
        self.assertTrue(changed)
        self.assertEqual(self.repository.settings_path.read_text(), original)

        with contextlib.redirect_stdout(io.StringIO()):
            CTL.mutate_settings(self.repository, add_hello)
        updated = CTL.load_settings(self.repository.settings_path)
        self.assertEqual(updated["packages"]["add"], ["hello@2.12.3"])
        self.assertEqual(list((self.repository.root / "securityops").glob(".settings.json.*")), [])

    def test_build_lock_rejects_a_second_owner(self) -> None:
        with CTL.BuildLock(self.repository):
            with self.assertRaises(CTL.BuildBusyError):
                with CTL.BuildLock(self.repository):
                    pass

    def test_atomic_writer_refuses_destination_symlink(self) -> None:
        target = self.repository.root / "outside.json"
        target.write_text("do not replace", encoding="utf-8")
        self.repository.settings_path.unlink()
        self.repository.settings_path.symlink_to(target)
        with self.assertRaises(CTL.MaintainerError):
            CTL.atomic_write_settings(
                self.repository.settings_path,
                CTL.load_settings(ROOT / "securityops" / "settings.json"),
            )
        self.assertEqual(target.read_text(), "do not replace")

    def test_settings_reader_reports_invalid_utf8(self) -> None:
        self.repository.settings_path.write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(CTL.ValidationError, "valid UTF-8"):
            CTL.load_settings(self.repository.settings_path)

    def test_build_invocation_uses_native_resource_flags(self) -> None:
        command = CTL.build_invocation(
            self.repository, bundle=True, prune_old=True, jobs=2, cores=4
        )
        self.assertEqual(
            command,
            [
                str(self.repository.build_script),
                "--bundle",
                "--prune-old",
                "--jobs",
                "2",
                "--cores",
                "4",
            ],
        )

    def test_run_build_hands_off_held_descriptor(self) -> None:
        observed = {}

        def fake_runner(command, **kwargs):
            observed["command"] = command
            observed.update(kwargs)
            return subprocess.CompletedProcess(command, 0)

        with CTL.BuildLock(self.repository) as lock:
            with contextlib.redirect_stdout(io.StringIO()):
                result = CTL.run_build(
                    self.repository,
                    jobs=2,
                    held_lock=lock,
                    runner=fake_runner,
                )
            self.assertEqual(result, 0)
            self.assertEqual(observed["pass_fds"], (lock.descriptor,))
            self.assertEqual(
                observed["env"][CTL.LOCK_FD_ENV], str(lock.descriptor)
            )
            self.assertEqual(observed["env"][CTL.LOCK_HELD_ENV], "1")

    def test_mutation_lock_is_held_through_failed_build_and_change_remains(self) -> None:
        arguments = CTL.argparse.Namespace(
            build=True,
            bundle=False,
            prune_old=False,
            jobs=1,
            cores=1,
            dry_run=False,
        )

        def transform(data):
            CTL.update_package_overrides(data, additions=("hello@2.12.3",))

        def failing_runner(command, **kwargs):
            self.assertEqual(CTL.probe_build_lock(self.repository), "active")
            self.assertIn(CTL.LOCK_FD_ENV, kwargs["env"])
            return subprocess.CompletedProcess(command, 7)

        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = CTL.mutate_and_optionally_build(
                arguments, self.repository, transform, runner=failing_runner
            )
        self.assertEqual(result, 7)
        self.assertIn("remain recorded", stderr.getvalue())
        self.assertEqual(
            CTL.load_settings(self.repository.settings_path)["packages"]["add"],
            ["hello@2.12.3"],
        )
        self.assertEqual(CTL.probe_build_lock(self.repository), "idle")

    def test_fetch_kernel_metadata_uses_guix_hash_and_local_sha256(self) -> None:
        source = self.repository.root / "abc-linux-7.1.9.tar.xz"
        source.write_bytes(b"kernel test source")
        # Independent native Guix SHA-256/base32 reference for the literal
        # payload above, not an expectation generated by the helper under test.
        expected_hex = (
            "6242baaf60538c52d93344b8e677f30da3e3c35a6cb518f08715e4be01aec140"
        )
        nix_hash = "0h61mq0vxr0mhzq1idbcbb1y78qdydvydf246gcm532kc2pvlhk2"
        executable = "/fixture/guix"

        def fake_which(name):
            self.assertEqual(name, "guix")
            return executable

        def fake_runner(command, **kwargs):
            self.assertEqual(
                command,
                [
                    executable,
                    "download",
                    "--format=nix-base32",
                    "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.9.tar.xz",
                ],
            )
            return subprocess.CompletedProcess(
                command, 0, stdout=f"{source}\n{nix_hash}\n"
            )

        # This is a unit boundary test, not evidence of an installed Guix or
        # an authenticated download. Real Guix integration remains separate.
        with (
            contextlib.redirect_stdout(io.StringIO()),
            mock.patch.object(CTL.shutil, "which", side_effect=fake_which),
        ):
            metadata = CTL.fetch_kernel_metadata(
                "7.1.9", self.repository, runner=fake_runner
            )
        self.assertEqual(metadata["nix_base32"], nix_hash)
        self.assertEqual(metadata["sha256"], expected_hex)

    def test_fetch_kernel_metadata_requires_guix_before_running_download(self) -> None:
        called = False

        def runner(command, **kwargs):
            nonlocal called
            called = True
            raise AssertionError("download must not run without Guix")

        original = self.repository.settings_path.read_bytes()
        for version in ("7.1.9", "7.3"):
            with (
                self.subTest(version=version),
                mock.patch.object(CTL.shutil, "which", return_value=None),
                self.assertRaisesRegex(CTL.MaintainerError, "guix is required"),
            ):
                CTL.fetch_kernel_metadata(version, self.repository, runner=runner)
            self.assertFalse(called)
            self.assertEqual(self.repository.settings_path.read_bytes(), original)

    def test_fetch_kernel_metadata_rejects_reported_hash_mismatch(self) -> None:
        source = self.repository.root / "abc-linux-7.1.9.tar.xz"
        source.write_bytes(b"tampered kernel test source")

        def runner(command, **kwargs):
            return subprocess.CompletedProcess(
                command,
                0,
                stdout="{}\n{}\n".format(
                    source, "0h61mq0vxr0mhzq1idbcbb1y78qdydvydf246gcm532kc2pvlhk2"
                ),
            )

        with (
            mock.patch.object(CTL.shutil, "which", return_value="/fixture/guix"),
            contextlib.redirect_stdout(io.StringIO()),
            self.assertRaisesRegex(CTL.MaintainerError, "does not match"),
        ):
            CTL.fetch_kernel_metadata("7.1.9", self.repository, runner=runner)


class IntegrationShapeTestCase(unittest.TestCase):
    def test_release_parser_exposes_standard_build_flags(self) -> None:
        arguments = CTL.create_parser().parse_args(
            [
                "release",
                "set",
                "1.14.0",
                "--revision",
                "r12",
                "--desktop-label",
                "wezterm",
                "--dry-run",
                "--build",
                "--bundle",
                "--jobs",
                "2",
                "--cores",
                "4",
            ]
        )
        self.assertEqual(arguments.command, "release")
        self.assertEqual(arguments.release_command, "set")
        self.assertTrue(arguments.build)
        self.assertEqual(arguments.jobs, 2)

    def test_full_validation_commands_pin_both_substituters_and_dry_run(self) -> None:
        installer_config = Path("/tmp/securityops-dummy-installer-config.scm")
        commands = CTL.full_validation_commands(
            CTL.REPOSITORY, "/bin/guix", installer_config
        )
        self.assertEqual(len(commands), 3)
        for command in commands:
            cache_argument = "--substitute-urls={}".format(CTL.SUBSTITUTE_URLS)
            self.assertEqual(command.count(cache_argument), 2)
            self.assertIn("--dry-run", command)
            self.assertIn("--fallback", command)
        self.assertIn("(@ (securityops kernel) linux-securityops)", commands[0])
        self.assertIn("image", commands[1])
        self.assertIn("iso9660", commands[1])
        self.assertIn("build", commands[2])
        self.assertEqual(commands[2][-1], str(installer_config))

    def test_dummy_installer_config_generation_is_safe_and_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = CTL.generate_installer_validation_config(
                CTL.REPOSITORY, Path(temporary)
            )
            generated = output.read_text(encoding="utf-8")
            self.assertIn("(operating-system", generated)
            self.assertIn("11111111-2222-3333-4444-555555555555", generated)
            self.assertIn('(search-path %load-path "channels.guix")', generated)
            self.assertIn("(local-file %pinned-channels-source)", generated)
            self.assertNotIn("validation-user-password", generated)
            self.assertIn("(define %installed-locked-root-account", generated)
            self.assertIn('(password "!")', generated)
            self.assertIn("(users (cons* %installed-locked-root-account", generated)
            self.assertIn("(allow-empty-passwords? #f)", generated)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)

    def test_guile_adapter_accepts_version_and_output_specs(self) -> None:
        guile = shutil.which("guile")
        if not guile:
            self.skipTest("guile is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "securityops").mkdir()
            shutil.copy2(
                ROOT / "securityops" / "settings.scm",
                root / "securityops" / "settings.scm",
            )
            data = CTL.load_settings(ROOT / "securityops" / "settings.json")
            data["packages"]["add"] = ["glib:debug", "glib:doc", "hello@2.12.3"]
            (root / "securityops" / "settings.json").write_text(
                CTL.serialize_settings(data), encoding="utf-8"
            )
            command = [
                guile,
                "--no-auto-compile",
                "-L",
                str(root),
                "-c",
                "(use-modules (securityops settings)) "
                "(write %package-additions)",
            ]
            completed = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("hello@2.12.3", completed.stdout)
            self.assertIn("glib:debug", completed.stdout)
            self.assertIn("glib:doc", completed.stdout)

    def test_public_key_files_match_pinned_integrity_values(self) -> None:
        for relative_name, (expected_hash, expected_q) in CTL.KEY_INTEGRITY.items():
            path = ROOT / relative_name
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected_hash)
            self.assertIn(expected_q, path.read_text().upper())

    def test_guile_adapter_validates_kernel_versions_independently(self) -> None:
        guile = shutil.which("guile")
        if not guile:
            self.skipTest("guile is unavailable; native kernel adapter validation blocked")
        baseline = CTL.load_settings(ROOT / "securityops" / "settings.json")
        cases = []
        for version, url in KERNEL_URL_CASES:
            data = copy.deepcopy(baseline)
            data["kernel"] = {
                "version": version, "url": url,
                "nix_base32": "0" * 52, "sha256": "0" * 64,
            }
            cases.append((version, data, None))
        for version in INVALID_KERNEL_VERSIONS:
            data = copy.deepcopy(baseline)
            data["kernel"]["version"] = version
            cases.append((repr(version), data, "kernel.version"))
        for label, section, key, value, error in (
            ("wrong URL", "kernel", "url",
             "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.3.0.tar.xz",
             "kernel.url"),
            ("untrusted host", "kernel", "url",
             "https://example.invalid/linux-7.3.tar.xz", "kernel.url"),
            ("release grammar", "release", "version", "7.3", "release.version"),
        ):
            data = copy.deepcopy(cases[0][1])
            data[section][key] = value
            cases.append((label, data, error))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "securityops").mkdir()
            shutil.copy2(ROOT / "securityops" / "settings.scm",
                         root / "securityops" / "settings.scm")
            for label, data, error in cases:
                with self.subTest(case=label):
                    # Bypass Python validation: Guile is the independent oracle.
                    (root / "securityops" / "settings.json").write_text(
                        json.dumps(data), encoding="utf-8")
                    completed = subprocess.run(
                        [guile, "--no-auto-compile", "-L", str(root), "-c",
                         "(use-modules (securityops settings)) (write (list %kernel-version %kernel-url))"],
                        env={"PATH": "/usr/bin:/bin", "HOME": str(root),
                             "GUILE_AUTO_COMPILE": "0", "LC_ALL": "C.UTF-8",
                             **({"GUILE_LOAD_PATH": os.environ["GUILE_LOAD_PATH"]}
                                if "GUILE_LOAD_PATH" in os.environ else {})},
                        text=True, capture_output=True,
                        timeout=10, check=False,
                    )
                    if error is None:
                        self.assertEqual(completed.returncode, 0, completed.stderr)
                        self.assertEqual(
                            completed.stdout,
                            '("{}" "{}")'.format(data["kernel"]["version"],
                                                 data["kernel"]["url"]),
                        )
                    else:
                        self.assertNotEqual(completed.returncode, 0)
                        self.assertIn(error, completed.stderr)


if __name__ == "__main__":
    unittest.main()
