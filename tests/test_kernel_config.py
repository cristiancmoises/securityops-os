# CodeMark v1 project=4c63e0fe-589c-4944-8449-97e211a38b72 file=d7cd8bee6ae75ad9a2ac880e85380545 owner="Cristian Cezar Mois\u00e9s"
"""Execute the actual Guile build guard against positive and hostile configs."""

from pathlib import Path
import json
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
POLICY = ["CONFIG_HZ=1000", "CONFIG_HZ_1000=y",
          "# CONFIG_HZ_250 is not set", "# CONFIG_VFIO_NOIOMMU is not set"]
DMA_POLICY = ["CONFIG_CPU_MITIGATIONS=y", "CONFIG_IOMMU_DEFAULT_DMA_STRICT=y",
              "# CONFIG_IOMMU_DEFAULT_DMA_LAZY is not set",
              "# CONFIG_IOMMU_DEFAULT_PASSTHROUGH is not set"]


class KernelConfigTests(unittest.TestCase):
    def check_config(self, lines, *, required=None, success=False):
        guile = shutil.which("guile")
        self.assertIsNotNone(guile, "Guile is required, not a passing capability skip")
        expected = POLICY if required is None else required
        literals = " ".join(json.dumps(line) for line in expected)
        expression = (
            "(use-modules (securityops kernel-config)) "
            f"(verify-required-kconfig (cadr (command-line)) '({literals}))"
        )
        with tempfile.TemporaryDirectory(prefix="securityops-kconfig-test-") as temp:
            config = Path(temp) / ".config"
            config.write_text("\n".join(lines) + "\n", encoding="utf-8")
            result = subprocess.run(
                [guile, "--no-auto-compile", "-L", str(ROOT), "-c", expression,
                 str(config)], cwd=ROOT, check=False, timeout=20,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("explicit values verified", result.stdout)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout)
            self.assertNotIn("explicit values verified", result.stdout)

    def test_valid_policy_allows_comments_unrelated_defaults_and_reordering(self):
        self.check_config(["# Generated config", "CONFIG_UNRELATED=m"]
                          + list(reversed(POLICY)), success=True)

    def test_missing_enabled_symbol_is_rejected(self):
        self.check_config(POLICY[1:])

    def test_absent_unknown_disabled_symbol_is_rejected(self):
        self.check_config(POLICY, required=POLICY + ["# CONFIG_UNKNOWN is not set"])

    def test_enabled_noiommu_is_rejected(self):
        self.check_config(POLICY[:-1] + ["CONFIG_VFIO_NOIOMMU=y"])

    def test_modular_noiommu_is_rejected(self):
        self.check_config(POLICY[:-1] + ["CONFIG_VFIO_NOIOMMU=m"])

    def test_wrong_hz_despite_choice_is_rejected(self):
        self.check_config(["CONFIG_HZ=250"] + POLICY[1:])

    def test_identical_duplicate_is_rejected(self):
        self.check_config(POLICY + [POLICY[0]])

    def test_conflicting_duplicate_is_rejected(self):
        self.check_config(POLICY + ["CONFIG_VFIO_NOIOMMU=y"])

    def test_whitespace_alias_cannot_hide_conflicting_duplicate(self):
        self.check_config(POLICY + [" CONFIG_HZ =250"])

    def test_duplicate_required_key_is_rejected(self):
        self.check_config(POLICY, required=POLICY + ["CONFIG_HZ=250"])

    def test_crlf_is_not_silently_normalized(self):
        self.check_config([line + "\r" for line in POLICY])

    def test_malformed_and_empty_policy_are_rejected(self):
        self.check_config(POLICY, required=["CONFIG_HZ"])
        self.check_config(POLICY, required=[])

    def test_oversized_config_is_rejected(self):
        self.check_config(POLICY + ["#" * (4 * 1024 * 1024)])

    def test_real_recipe_has_both_guards_and_explicit_overrides(self):
        recipe = (ROOT / "securityops/kernel.scm").read_text(encoding="utf-8")
        for line in POLICY + DMA_POLICY:
            self.assertIn(json.dumps(line), recipe)
        self.assertIn("add-after 'configure 'verify-securityops-config", recipe)
        self.assertIn("add-after 'build 'verify-securityops-config-after-build", recipe)
        self.assertEqual(recipe.count('".config" \'#$%securityops-kernel-configs'), 2)
        self.assertIn("(cons '(securityops kernel-config) imported-modules)", recipe)

    def test_strict_dma_and_mitigations_cannot_be_disabled_or_ignored(self):
        required = POLICY + DMA_POLICY
        self.check_config(required, required=required, success=True)
        for line in DMA_POLICY:
            with self.subTest(missing=line):
                self.check_config([value for value in required if value != line],
                                  required=required)
            bad = (line.replace("# ", "").replace(" is not set", "=y")
                   if line.startswith("# ")
                   else "# " + line.split("=")[0] + " is not set")
            with self.subTest(disabled_or_enabled=bad):
                self.check_config([bad if value == line else value for value in required],
                                  required=required)

    def test_guard_is_declared_in_actual_builder_imports(self):
        recipe = (ROOT / "securityops/kernel.scm").read_text(encoding="utf-8")
        self.assertIn("#:imported-modules imported-modules %default-gnu-imported-modules",
                      recipe)
        self.assertIn("(cons '(securityops kernel-config) imported-modules)", recipe)

    def test_actual_builder_imports_supply_guard_without_checkout(self):
        guix = shutil.which("guix")
        self.assertIsNotNone(guix, "Guix is required, not a passing skip")
        result = subprocess.run(
            [guix, "repl", "-q", "-L", str(ROOT), "--",
             str(ROOT / "tests/kernel-guard-build.scm")],
            cwd=ROOT, check=False, timeout=90, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        output = Path(result.stdout.strip())
        self.assertEqual(output.parent, Path("/gnu/store"))
        self.assertEqual(output.read_text(), "positive=1\nnegative=3\n")
        print(json.dumps({"kernel_guard_fixture": str(output)}))


if __name__ == "__main__":
    unittest.main()
