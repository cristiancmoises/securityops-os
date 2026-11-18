# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=12ae00d5b0cf56b2bbaca30d62efd8f4 owner="Cristian Cezar Mois\u00e9s"
"""Discovery boundary regression; dispatch is intercepted, not an OS build."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from test_securityopsctl import CTL

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "securityops/validate-full.scm"
IMAGE_ENTRY = ROOT / "securityops/build-image.scm"
CHECK = ROOT / "tests/full-validation-check.scm"
CACHE = "--substitute-urls=https://substitutes.securityops.com.br https://substitutes.securityops.co https://ci.guix.gnu.org"


class GuixDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="securityops-discovery-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / "source"
        (self.root / "securityops/packages").mkdir(parents=True)
        (self.root / "out/cache").mkdir(parents=True)
        (self.root / "securityops/packages/probe.scm").write_text('''
          (define-module (securityops packages probe)
            #:use-module (guix packages) #:use-module (gnu packages base)
            #:export (discovery-fixture))
          (define discovery-fixture (package (inherit hello) (name "discovery-fixture")))
        ''')
        (self.root / "out/cache/sentinel.scm").write_text('''
          (define-module (out cache sentinel))
          (display "CACHE_SENTINEL_LOADED\\n")
          (error "cache must never be discovered")
        ''')
        (self.root / "securityops/explicit.scm").write_text('''
          (define-module (securityops explicit) #:export (value))
          (define value 42)
        ''')
        (self.root / "config.scm").write_text("(error \"test never evaluates OS\")\n")
        self.installer = self.base / "installer-config.scm"
        self.installer.write_text("(error \"test never evaluates installer\")\n")
        self.installer.chmod(0o600)
        self.env = {k: v for k, v in os.environ.items() if k not in (
            "GUIX_PACKAGE_PATH", "GUIX_EXTENSIONS_PATH", "GUILE_LOAD_PATH",
            "GUILE_LOAD_COMPILED_PATH")}
        self.env.update(HOME=str(self.base), GUILE_AUTO_COMPILE="0")

    def commands(self):
        return [
            ["build", "--dry-run", CACHE, "--fallback", "-e",
             "(@ (securityops kernel) linux-securityops)"],
            ["system", "image", "--dry-run", CACHE, "--fallback", "-t", "iso9660",
             "--label=SECURITY_OPS_LIVE", str(self.root / "config.scm")],
            ["system", "build", "--dry-run", CACHE, "--fallback", str(self.installer)],
        ]

    def run_entry(self, command, *, mode="normal", root=None, entry=ENTRY):
        self.assertTrue(entry.is_file(), "required discovery boundary is absent")
        guix = shutil.which("guix")
        self.assertIsNotNone(guix, "Guix is required, not a passing skip")
        selected = str(root or self.root)
        result = subprocess.run(
            [guix, "repl", "-q", "-L", selected, "--", str(CHECK), mode,
             str(entry), selected, *command], env=self.env, cwd=self.base,
            timeout=60, check=False, capture_output=True, text=True)
        self.assertNotIn("CACHE_SENTINEL_LOADED", result.stdout + result.stderr)
        return result

    def test_image_entry_preserves_resource_order_duplicates_and_fixed_command(self):
        for resources in ([], ["--cores=4"], ["--max-jobs=2"],
                          ["--max-jobs=2", "--cores=4"],
                          ["--cores=3", "--max-jobs=1", "--cores=4"]):
            with self.subTest(resources=resources):
                result = self.run_entry(resources, mode="image", entry=IMAGE_ENTRY)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("DISPATCH_CHECKED", result.stdout)

    def test_image_entry_preserves_failure_status(self):
        result = self.run_entry([], mode="image-exit-7", entry=IMAGE_ENTRY)
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("DISPATCH_CHECKED", result.stdout)

    def test_image_entry_rejects_other_operations_and_malformed_resources(self):
        for argument in ("system", "reconfigure", "--dry-run", "--help", "-L",
                         str(self.root / "config.scm"), "--no-substitutes",
                         "--substitute-urls=https://example.invalid",
                         "--cores=0", "--cores=-1", "--cores=01", "--cores=",
                         "--cores=2\n", "--cores=２", "--max-jobs=2;false",
                         "--max-jobs", "--cores=1 --max-jobs=2"):
            with self.subTest(argument=argument):
                result = self.run_entry([argument], mode="image", entry=IMAGE_ENTRY)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("DISPATCH_CHECKED", result.stdout)

    def test_image_entry_rejects_aliases_and_symlinked_package_directory(self):
        alias = self.base / "image-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for root in (str(alias), str(self.root) + "/", str(self.root / "absent")):
            with self.subTest(root=root):
                result = self.run_entry([], mode="image", entry=IMAGE_ENTRY, root=root)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("DISPATCH_CHECKED", result.stdout)
        packages = self.root / "securityops/packages"
        packages.rename(self.base / "external-packages")
        packages.symlink_to(self.base / "external-packages", target_is_directory=True)
        result = self.run_entry([], mode="image", entry=IMAGE_ENTRY)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)

    def test_image_entry_rejects_changed_discovery_and_duplicate_import_roots(self):
        for mode in ("image-unexpected-path", "image-duplicate-root"):
            with self.subTest(mode=mode):
                result = self.run_entry([], mode=mode, entry=IMAGE_ENTRY)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("DISPATCH_CHECKED", result.stdout)
        self.env["GUIX_PACKAGE_PATH"] = str(self.base)
        result = self.run_entry([], mode="image", entry=IMAGE_ENTRY)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)

    def test_real_image_dispatch_discovers_packages_without_cache_or_daemon(self):
        self.assertTrue(IMAGE_ENTRY.is_file(), "required image boundary is absent")
        guix = shutil.which("guix")
        self.assertIsNotNone(guix, "Guix is required, not a passing skip")
        (self.root / "config.scm").write_text('''
          (use-modules (gnu packages) (guix packages) (securityops explicit))
          (unless (= value 42) (error "explicit import lost"))
          (for-each (lambda (name)
                      (unless (string=? name (package-name (specification->package name)))
                        (error "package resolution failed")))
                    '("discovery-fixture" "hello"))
          (display "PACKAGES_AND_IMPORTS_CHECKED_BEFORE_OS\\n")
          (force-output)
          (primitive-exit 78)
        ''')
        result = subprocess.run(
            [guix, "repl", "-q", "-L", str(self.root), "--", str(IMAGE_ENTRY),
             str(self.root), "--cores=2", "--max-jobs=1"], cwd=self.root,
            env={**self.env, "GUIX_DAEMON_SOCKET": str(self.base / "absent.socket")},
            timeout=60, check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 78, result.stdout + result.stderr)
        self.assertIn("PACKAGES_AND_IMPORTS_CHECKED_BEFORE_OS", result.stdout)
        self.assertNotIn("CACHE_SENTINEL_LOADED", result.stdout + result.stderr)
        self.assertFalse(list((self.root / "out").glob("*.iso")))

    def test_cli_routes_all_three_fixed_operations_through_discovery_boundary(self):
        commands = CTL.full_validation_commands(CTL.REPOSITORY, "/bin/guix", self.installer)
        for command in commands:
            inner = command[command.index("--") + 1:]
            self.assertEqual(inner[:5], ["repl", "-q", "-L", str(ROOT), "--"])
            self.assertEqual(inner[5:7], [str(ENTRY), str(ROOT)])
            self.assertNotIn("-L", inner[7:])
            self.assertEqual(command.count(CACHE), 2)

    def test_three_operations_keep_packages_channels_imports_and_exact_arguments(self):
        for command in self.commands():
            with self.subTest(command=command[:2]):
                result = self.run_entry(command)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("DISPATCH_CHECKED", result.stdout)

    def test_guix_failure_status_is_not_converted_to_success(self):
        result = self.run_entry(self.commands()[0], mode="exit-7")
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("DISPATCH_CHECKED", result.stdout)

    def test_unexpected_operation_flags_substitutes_and_paths_never_dispatch(self):
        kernel, image, installer = self.commands()
        invalid = [kernel + ["-L", str(self.root)], kernel + ["--help"],
                   [x for x in kernel if x != "--dry-run"],
                   [x.replace(CACHE, "--substitute-urls=https://example.invalid") for x in kernel],
                   ["system", "reconfigure", *installer[2:]],
                   image[:-1] + [str(self.installer)],
                   installer[:-1] + [str(self.base / "absent.scm")]]
        for command in invalid:
            with self.subTest(command=command):
                result = self.run_entry(command)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("DISPATCH_CHECKED", result.stdout)

    def test_noncanonical_root_and_symlinked_package_directory_are_rejected(self):
        alias = self.base / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        for root in (str(alias), str(self.root) + "/"):
            with self.subTest(root=root):
                result = self.run_entry(self.commands()[0], root=root)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("DISPATCH_CHECKED", result.stdout)
        packages = self.root / "securityops/packages"
        packages.rename(self.root / "securityops/moved-packages")
        packages.symlink_to("moved-packages", target_is_directory=True)
        result = self.run_entry(self.commands()[0])
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)

    def test_unexpected_discovery_entry_is_rejected(self):
        result = self.run_entry(self.commands()[0], mode="unexpected-path")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)

    def test_nonprivate_or_aliased_installer_input_is_rejected(self):
        command = self.commands()[2]
        self.installer.chmod(0o644)
        result = self.run_entry(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)
        self.installer.chmod(0o600)
        link = self.base / "hardlink.scm"
        os.link(self.installer, link)
        result = self.run_entry(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)
        link.unlink()
        self.base.chmod(0o755)
        result = self.run_entry(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)
        self.base.chmod(0o700)
        self.installer.rename(self.base / "real.scm")
        self.installer.symlink_to("real.scm")
        result = self.run_entry(command)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("DISPATCH_CHECKED", result.stdout)

    def test_inherited_module_and_extension_paths_fail_before_full_validation(self):
        for variable in ("GUIX_PACKAGE_PATH", "GUIX_EXTENSIONS_PATH", "GUILE_LOAD_PATH",
                         "GUILE_LOAD_COMPILED_PATH", "GUILE_EXTENSIONS_PATH"):
            with self.subTest(variable=variable):
                result = subprocess.run(
                    [sys.executable, "-I", "-B", str(ROOT / "securityopsctl"), "validate", "--full"],
                    env={**self.env, variable: str(self.root)}, cwd=self.base,
                    timeout=20, capture_output=True, text=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("full validation refuses inherited module paths", result.stderr)
                self.assertNotIn(">> pinned", result.stdout)

    def test_immutable_guile_paths_and_empty_overrides_keep_existing_environment(self):
        guard = getattr(CTL, "validate_full_environment", None)
        self.assertTrue(callable(guard), "missing immutable-path compatibility guard")
        guile = shutil.which("guile")
        self.assertIsNotNone(guile, "Guile is required")
        item = Path(guile).resolve().parent.parent
        environment = {
            "GUILE_LOAD_PATH": str(item / "share/guile/3.0"),
            "GUILE_LOAD_COMPILED_PATH": str(item / "lib/guile/3.0/ccache"),
            "GUILE_EXTENSIONS_PATH": str(item / "lib/guile/3.0/extensions"),
            "GUIX_PACKAGE_PATH": "",
        }
        original = environment.copy()
        guard(environment)
        self.assertEqual(environment, original, "operator environment must not be rewritten")
        guard({"GUIX_PACKAGE_PATH": ""})
        for bad in (str(self.root), "relative", str(item) + ":", ":" + str(item),
                    str(item) + "/../escape", "/gnu/store/not-an-item", "/gnu/store"):
            with self.subTest(path=bad), self.assertRaises(CTL.ValidationError):
                guard({"GUILE_LOAD_PATH": bad})

    def test_empty_extension_and_guile_paths_cannot_add_current_directory(self):
        for variable in ("GUIX_EXTENSIONS_PATH", "GUILE_LOAD_PATH",
                         "GUILE_LOAD_COMPILED_PATH", "GUILE_EXTENSIONS_PATH"):
            with self.subTest(variable=variable), self.assertRaises(CTL.ValidationError):
                CTL.validate_full_environment({variable: ""})


if __name__ == "__main__":
    unittest.main()
