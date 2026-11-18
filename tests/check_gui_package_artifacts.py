#!/usr/bin/env python3
# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=3062fcb12894589f83c24390217b0642 owner="Cristian Cezar Mois\u00e9s"
"""Check built GUI packages without starting their applications or GUIs.

Run explicitly with both Store outputs; this is not a substitute for live tests.
The import probe uses the generated shell environment, replacing only its final
exec with a test program. No application entry point is executed.
"""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


SOURCES = {
    "qt": {
        "securityops-guix-center": "securityops_guix_center.py",
        "securityops-phase37-matrix": "phase37_matrix.py",
        "securityops-phase38-gates": "phase38_gate_runner.py",
        "securityops-phase39-gates": "phase39_gate_runner.py",
        "securityops-phase40-bootstrap": "phase40_bootstrap.py",
        "securityops-phase41-ceremony": "phase41_bootstrap.py",
        "securityops-phase42-ceremony": "phase42_bootstrap.py",
        "securityops-phase43-custody": "phase43_bootstrap.py",
        "securityops-phase44-gate1": "phase44_bootstrap.py",
        "securityops-phase44-dossier": "phase44_dossier_bootstrap.py",
        "securityops-phase44-admission": "phase44_admission_bootstrap.py",
        "securityops-phase45-execute": "phase45_bootstrap.py",
    },
    "gtk": {"security-ops-installer2": "security_ops_installer2.py"},
}


class PackageArtifacts(unittest.TestCase):
    outputs = {}

    def test_primary_launchers_exist(self):
        for kind, root in self.outputs.items():
            with self.subTest(package=kind):
                actual = {path.name for entry_kind, path in self.launchers() if entry_kind == kind}
                self.assertEqual(actual, set(SOURCES[kind]))
                for name in SOURCES[kind]:
                    self.assertTrue((root / "bin" / name).is_file())
                    self.assertTrue(os.access(root / "bin" / name, os.X_OK))

    def launchers(self):
        for kind, root in self.outputs.items():
            for path in sorted((root / "bin").glob("security*")):
                if path.is_file() and path.stat().st_mode & 0o111:
                    yield kind, path

    def test_wrapper_interpreters_are_store_bash(self):
        for _, path in self.launchers():
            with self.subTest(path=path.name):
                line = path.read_text().splitlines()[0]
                self.assertRegex(line, r"^#!/gnu/store/[a-z0-9]{32}-bash[^/]*/bin/bash$")
                shell = Path(line[2:])
                self.assertTrue(shell.is_file())
                self.assertTrue(os.access(shell, os.X_OK))
                result = subprocess.run([str(shell), "--noprofile", "--norc", "-n", str(path)],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_inner_interpreters_are_isolated_store_python(self):
        for _, path in self.launchers():
            with self.subTest(path=path.name):
                inner = path.with_name("." + path.name + "-real")
                self.assertTrue(inner.is_file())
                self.assertTrue(os.access(inner, os.X_OK))
                self.assertEqual(inner.stat().st_mode & 0o7777, 0o555)
                line = inner.read_text().splitlines()[0]
                self.assertRegex(line, r"^#!/gnu/store/[a-z0-9]{32}-python[^/]*/bin/python3 -I$")
                self.assertTrue(Path(line[2:].split()[0]).is_file())

    def test_runtime_paths_are_nonempty_declared_store_directories(self):
        for kind, path in self.launchers():
            text = path.read_text()
            variables = ("GUIX_PYTHONPATH", "QT_PLUGIN_PATH") if kind == "qt" else (
                "GUIX_PYTHONPATH", "GI_TYPELIB_PATH", "XDG_DATA_DIRS")
            for variable in variables:
                with self.subTest(path=path.name, variable=variable):
                    match = re.search(r'^export ' + variable + r'="([^"\n]*)"$', text, re.M)
                    self.assertIsNotNone(match)
                    value = match.group(1)
                    self.assertNotIn("$", value, "runtime paths must not inherit user values")
                    for directory in value.split(":"):
                        self.assertRegex(directory, r"^/gnu/store/[a-z0-9]{32}-[^/]+/")
                        self.assertTrue(Path(directory).is_dir(), directory)

    def test_installed_source_bodies_are_preserved(self):
        repository = Path(__file__).resolve().parents[1]
        for kind, root in self.outputs.items():
            folder = "guix-center" if kind == "qt" else "installer2"
            mapping = {"." + name + "-real": source for name, source in SOURCES[kind].items()}
            if kind == "qt":
                mapping["securityops_guix_center.py"] = "securityops_guix_center.py"
            for installed, original in mapping.items():
                with self.subTest(path=installed):
                    source = (repository / "securityops" / folder / original).read_bytes()
                    body = source.removeprefix(b"#!/usr/bin/env python3\n")
                    self.assertEqual((root / "bin" / installed).read_bytes().partition(b"\n")[2], body)

    def test_framework_and_sibling_imports_under_generated_environment(self):
        for kind, wrapper in self.launchers():
            inner = wrapper.with_name("." + wrapper.name + "-real")
            source = wrapper.read_text()
            interpreter = inner.read_text().splitlines()[0]
            with self.subTest(package=kind, launcher=wrapper.name):
                self.assertRegex(source.splitlines()[0], r"^#!/gnu/store/[^/]+/bin/bash$")
                self.assertRegex(interpreter, r"^#!/gnu/store/[^/]+/bin/python3 -I$")
                self.assertEqual(len(re.findall(r"^exec -a .*", source, re.M)), 1)
                with tempfile.TemporaryDirectory(prefix="gui-package-import-") as temporary:
                    directory = Path(temporary)
                    probe = directory / "probe.py"
                    body = ("import PySide6, shiboken6\nfrom PySide6 import QtCore, QtGui, QtWidgets\n"
                            "modules = (PySide6, shiboken6, QtCore, QtGui, QtWidgets)\n") if kind == "qt" else (
                            "import gi\ngi.require_version('Gtk', '4.0')\n"
                            "from gi.repository import Gtk\nmodules = (gi,)\n")
                    probe.write_text(interpreter + "\n" + body +
                                     "assert all(m.__file__.startswith('/gnu/store/') for m in modules)\n"
                                     "import runpy\n"
                                     f"runpy.run_path({str(inner)!r}, run_name='packaging_probe')\n"
                                     "print('IMPORTS_OK')\n")
                    probe.chmod(0o500)
                    instrumented = directory / "wrapper"
                    instrumented.write_text(re.sub(r"^exec -a .*", 'exec "' + str(probe) + '"', source, flags=re.M))
                    instrumented.chmod(0o500)
                    environment = {"HOME": temporary, "TMPDIR": temporary, "PATH": "/nonexistent",
                                   "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1"}
                    for variable in ("PYTHONPATH", "PYTHONHOME", "GUIX_PYTHONPATH", "QT_PLUGIN_PATH",
                                     "GI_TYPELIB_PATH", "XDG_DATA_DIRS"):
                        environment[variable] = str(directory / "untrusted-sentinel")
                    result = subprocess.run([str(instrumented)], env=environment,
                                            capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "IMPORTS_OK")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--guix-center", required=True, type=Path)
    parser.add_argument("--installer2", required=True, type=Path)
    arguments = parser.parse_args()
    for path in (arguments.guix_center, arguments.installer2):
        if not path.is_dir() or not str(path).startswith("/gnu/store/"):
            parser.error("expected existing immutable Store package outputs")
    PackageArtifacts.outputs = {"qt": arguments.guix_center, "gtk": arguments.installer2}
    unittest.main(argv=[__file__], verbosity=2)
