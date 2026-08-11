"""Unit tests for the Security Ops OS maintainer CLI."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LOADER = importlib.machinery.SourceFileLoader(
    "securityopsctl_under_test", str(ROOT / "securityopsctl")
)
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
assert SPEC is not None
CTL = importlib.util.module_from_spec(SPEC)
sys.modules[LOADER.name] = CTL
LOADER.exec_module(CTL)


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
        self.assertEqual(
            CTL.kernel_url("7.1.9"),
            "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.9.tar.xz",
        )
        for invalid in ("7.1", "7.1.9-rc1", "07.1.9", "7.01.9", "0.1.2"):
            with self.subTest(invalid=invalid), self.assertRaises(CTL.ValidationError):
                CTL.kernel_url(invalid)

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
        with self.assertRaises(CTL.ValidationError):
            CTL.set_release(data, "v1.14.1", "r13")
        with self.assertRaises(CTL.ValidationError):
            CTL.set_release(data, "1.14.1", "13")


class TemporaryRepositoryTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        (root / "securityops").mkdir()
        (root / "securityops" / "settings.json").write_text(
            (ROOT / "securityops" / "settings.json").read_text(), encoding="utf-8"
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
        (root / "channels.scm").write_text("()\n", encoding="utf-8")
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
        expected_hex = hashlib.sha256(source.read_bytes()).hexdigest()
        nix_hash = CTL.nix_base32_sha256(expected_hex)

        def fake_runner(command, **kwargs):
            self.assertEqual(command[1:3], ["download", "--format=nix-base32"])
            self.assertEqual(
                command[-1],
                "https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.9.tar.xz",
            )
            return subprocess.CompletedProcess(
                command, 0, stdout="{}\n{}\n".format(source, nix_hash)
            )

        with contextlib.redirect_stdout(io.StringIO()):
            metadata = CTL.fetch_kernel_metadata(
                "7.1.9", self.repository, runner=fake_runner
            )
        self.assertEqual(metadata["nix_base32"], nix_hash)
        self.assertEqual(metadata["sha256"], expected_hex)


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
            self.assertIn('(search-path %load-path "channels.scm")', generated)
            self.assertIn("(local-file %pinned-channels-source)", generated)
            self.assertNotIn("validation-user-password", generated)
            self.assertNotIn("validation-root-password", generated)
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


if __name__ == "__main__":
    unittest.main()
